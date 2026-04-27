#!/usr/bin/env python3
"""
WIDS – Wi-Fi Intrusion Detection System with per-session Parquet ML logging.
"""
from __future__ import annotations

import itertools
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

try:
    from rich import box
    from rich.console import Console
    from rich.layout import Layout
    from rich.live import Live
    from rich.panel import Panel
    from rich.rule import Rule
    from rich.table import Table
    from rich.text import Text
except ImportError:
    sys.exit("Missing 'rich'. Install: sudo pip install rich --break-system-packages")

try:
    import pandas as pd
    import fastparquet
except ImportError:
    sys.exit("Missing 'pandas' or 'fastparquet'. Install: sudo pip install pandas fastparquet --break-system-packages")

console = Console()

# ---------- Configuration ----------
CFG: dict = {
    "monitor_iface": os.environ.get("WIDS_MONITOR_IFACE", "wlan1"),
    "scan_iface":    os.environ.get("WIDS_SCAN_IFACE", "wlan0"),
    "home_ssid":     os.environ.get("WIDS_HOME_SSID", "Hell`s WiFi"),
    "home_password": os.environ.get("WIDS_HOME_PASSWORD", "rectum_obliterator_666"),
    "base_log_dir":  Path("/var/log/wids/sessions"),
    "ml_flush_sec":  30,
    "ml_max_file_mb": 128,
    "deauth_threshold":       5,
    "probe_threshold":       20,
    "auth_fail_threshold":    5,
    "window_sec":            10,
    "rssi_jump_db":          12,
    "beacon_int_delta":       5,
    "channel_check_interval":300,
    "dashboard_refresh":      1.0,
    "heartbeat_interval":    30,
    "export_interval_min":   30,
    "max_alerts":           400,
    "max_events":           600,
    "fps_window_sec":        10,
    "arp_scan_threshold":    20,
    "arp_scan_window":        5,
    "port_scan_threshold":   15,
    "port_scan_window":      10,
    "dhcp_starve_threshold":  8,
    "dhcp_starve_window":    10,
    "handshake_timeout_sec":  5,
    "client_inventory_interval": 300,
}

SESSION_DIR: Path = CFG["base_log_dir"]

# ---------- Lookup tables ----------
_OUI: Dict[str, str] = {
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
    "AC:87:A3": "Apple",        "F8:FF:C2": "Apple",        "3C:15:C2": "Apple",
    "00:1C:BF": "Intel",        "10:02:B5": "Intel",        "34:DE:1A": "Intel",
    "60:F6:77": "Qualcomm",     "00:17:C9": "Qualcomm",
    "00:26:82": "TP-Link",      "50:C7:BF": "TP-Link",      "E8:65:D4": "TP-Link",
    "00:18:4D": "Netgear",      "A0:21:B7": "Netgear",      "28:C6:8E": "Netgear",
    "DC:9F:DB": "Ubiquiti",     "24:A4:3C": "Ubiquiti",     "FC:EC:DA": "Ubiquiti",
    "4C:1F:CC": "Huawei",       "28:6E:D4": "Huawei",
    "28:D2:44": "ASUS",         "04:D4:C4": "ASUS",
    "00:1C:C0": "D-Link",       "1C:BD:B9": "D-Link",
    "50:32:37": "Samsung",      "FC:00:12": "Samsung",
    "54:60:09": "Google",       "F4:F5:D8": "Google",
    "00:50:F2": "Microsoft",    "00:15:5D": "MS/HyperV",
    "00:0C:E7": "Cisco",        "00:23:69": "Cisco",
}

REASON_CODES: Dict[int, str] = {
    1: "Unspecified",     2: "Auth expired",     3: "Leaving BSS",     4: "Inactivity",
    5: "AP full",         6: "Class2 unauth",    7: "Class3 unassoc",  8: "STA leaving",
    9: "Assoc w/o auth",  12: "Invalid IE",      13: "MIC failure",
    14: "4-way timeout",  15: "GrpKey timeout",  16: "IE mismatch",
    17: "Bad grp cipher", 18: "Bad pair cipher", 19: "Bad AKMP",
    22: "802.1X failed",  23: "Cipher unsup",    45: "Left neighbor",
}

AUTH_ALGS: Dict[int, str] = {
    0: "Open", 1: "Shared Key", 2: "FT", 3: "SAE", 4: "FT-SAE",
}

AKM_TYPES: Dict[int, str] = {
    1: "802.1X", 2: "PSK", 3: "FT/802.1X", 4: "FT/PSK",
    5: "802.1X-S256", 6: "PSK-S256", 8: "SAE", 9: "FT-SAE", 18: "OWE",
}

# ---------- OUI loading ----------
def _load_system_oui() -> None:
    for path in ["/usr/share/ieee-data/oui.txt", "/usr/share/wireshark/manuf", "/usr/share/arp-scan/ieee-oui.txt"]:
        if not os.path.exists(path):
            continue
        try:
            with open(path) as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "(hex)" in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            oui = parts[0].replace("-", ":")
                            vendor = " ".join(parts[2:]).strip()[:20]
                            if oui not in _OUI and vendor:
                                _OUI[oui] = vendor
                    else:
                        parts = re.split(r"\s+", line, maxsplit=1)
                        if len(parts) >= 2:
                            oui = parts[0].upper().replace("-", ":").replace("_", ":")[:8]
                            vendor = parts[1].strip()[:20]
                            if oui not in _OUI and vendor:
                                _OUI[oui] = vendor
        except Exception:
            pass

def oui_lookup(mac: str) -> str:
    return _OUI.get(mac.upper().replace("-", ":")[:8], "Unknown")

def is_randomized_mac(mac: str) -> bool:
    try:
        return bool(int(mac.replace(":", "").replace("-", "")[0:2], 16) & 0x02)
    except:
        return False

def freq_to_chan(freq: int) -> int:
    if not freq:
        return 0
    if 2412 <= freq <= 2472:
        return (freq - 2412) // 5 + 1
    if freq == 2484:
        return 14
    if 5180 <= freq <= 5825:
        return (freq - 5180) // 5 + 36
    if 5955 <= freq <= 7115:
        return (freq - 5955) // 5 + 1
    return 0

def freq_to_band(freq: int) -> str:
    if not freq:
        return "?"
    if 2400 <= freq < 2500:
        return "2.4G"
    if 5150 <= freq < 5900:
        return "5G"
    if 5925 <= freq < 7125:
        return "6G"
    return "?"

# ---------- Data records ----------
@dataclass
class AlertRecord:
    ts: datetime; severity: str; category: str; message: str; bssid: str = ""; mac: str = ""

@dataclass
class EventRecord:
    ts: datetime; kind: str; mac: str; detail: str

@dataclass
class APRecord:
    bssid: str
    ssid: str = ""; channel: int = 0; freq: int = 0; band: str = "?"
    rssi: int = -999; rssi_prev: int = -999
    datarate: float = 0.0; mcs_index: int = -1
    beacon_interval: int = 0; security: str = "?"; security_prev: str = "?"
    mfpc: bool = False; mfpr: bool = False
    akms_type: str = ""
    auth_algs_seen: Set[int] = field(default_factory=set)
    ibss: bool = False; hidden: bool = False
    vendor: str = ""
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    frame_count: int = 0; retry_frames: int = 0
    reputation: int = 100; is_home: bool = False; transition_mode: bool = False

@dataclass
class ClientRecord:
    mac: str; vendor: str = ""; randomized: bool = False
    probed_ssids: Set[str] = field(default_factory=set)
    associated_bssid: str = ""
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    auth_failures: int = 0; frame_count: int = 0; eapol_count: int = 0
    data_frames: int = 0; retry_frames: int = 0
    last_rssi: int = -999; last_freq: int = 0; last_datarate: float = 0.0
    is_new: bool = True

# ---------- Global state ----------
class WIDSState:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.start_time = datetime.now()
        self.aps: Dict[str, APRecord] = {}
        self.clients: Dict[str, ClientRecord] = {}
        self.home_bssid = ""
        self.home_channel = 0
        self.alerts: deque[AlertRecord] = deque(maxlen=CFG["max_alerts"])
        self.events: deque[EventRecord] = deque(maxlen=CFG["max_events"])
        self.conn_log: deque[Tuple[datetime, str, str, str]] = deque(maxlen=60)
        self.deauth_times: Dict[str, List[float]] = defaultdict(list)
        self.disassoc_times: Dict[str, List[float]] = defaultdict(list)
        self.auth_fail_times: Dict[str, List[float]] = defaultdict(list)
        self.probe_times: Dict[str, List[Tuple[float, str]]] = defaultdict(list)
        self.total_frames = 0
        self.alert_counts: Dict[str, int] = defaultdict(int)
        self.frame_type_counts: Dict[str, int] = defaultdict(int)
        self.new_bssids_boot: Set[str] = set()
        self.fps_ts: deque[float] = deque(maxlen=500)
        self._pulse_iter = itertools.cycle("◐◓◑◒"); self._pulse_char = "◐"; self._pulse_active = False
        self.last_export = time.time()
        self.running = True
        self.arp_request_times: Dict[str, List[float]] = defaultdict(list)
        self.ip_mac_table: Dict[str, str] = {}
        self.port_scan_times: Dict[str, List[Tuple[float, int]]] = defaultdict(list)
        self.dhcp_discover_times: Dict[str, List[float]] = defaultdict(list)
        try:
            self.own_ips: set = set(subprocess.check_output(
                ["hostname", "-I"], text=True, stderr=subprocess.DEVNULL).split())
        except:
            self.own_ips = set()
        self.hs_states: Dict[Tuple[str, str], dict] = {}
        self.transition_alerted_bssids: Set[str] = set()
        # Extended tracking
        self.reason_code_counts: Dict[int, int] = defaultdict(int)
        self.auth_alg_counts: Dict[int, int] = defaultdict(int)
        self.data_frame_count: int = 0
        self.total_data_bytes: int = 0
        self.channel_ap_map: Dict[int, Set[str]] = defaultdict(set)
        self.connected_clients_cache: List[Tuple[str, str, str]] = []
        self.connected_clients_ts: float = 0.0

    def tick(self) -> None:
        now = time.time()
        self.total_frames += 1
        self.fps_ts.append(now)
        self._pulse_char = next(self._pulse_iter); self._pulse_active = True

    def fps(self) -> float:
        cutoff = time.time() - CFG["fps_window_sec"]
        return sum(1 for t in self.fps_ts if t >= cutoff) / CFG["fps_window_sec"]

    def add_alert(self, severity: str, category: str, message: str, bssid: str = "", mac: str = "") -> None:
        a = AlertRecord(ts=datetime.now(), severity=severity, category=category,
                        message=message, bssid=bssid, mac=mac)
        with self.lock:
            self.alerts.appendleft(a)
            self.alert_counts[category] += 1
        LOG.write_alert(a)
        if ML:
            ML.log_alert(a.ts.timestamp(), severity, category, message, bssid, mac)

    def add_event(self, kind: str, mac: str, detail: str) -> None:
        with self.lock:
            self.events.appendleft(EventRecord(ts=datetime.now(), kind=kind, mac=mac, detail=detail))
        if ML:
            ML.log_event(datetime.now().timestamp(), kind, mac, detail)

    def add_conn(self, kind: str, mac: str, bssid: str) -> None:
        with self.lock:
            self.conn_log.appendleft((datetime.now(), kind, mac, bssid))

    def get_or_create_ap(self, bssid: str) -> APRecord:
        with self.lock:
            if bssid not in self.aps:
                self.aps[bssid] = APRecord(bssid=bssid, vendor=oui_lookup(bssid))
                self.new_bssids_boot.add(bssid)
            return self.aps[bssid]

    def get_or_create_client(self, mac: str) -> ClientRecord:
        with self.lock:
            if mac not in self.clients:
                c = ClientRecord(mac=mac, vendor=oui_lookup(mac),
                                 randomized=is_randomized_mac(mac), is_new=True)
                self.clients[mac] = c
                self.add_event("new_device", mac,
                               f"[NEW] {c.vendor}  rand={'yes' if c.randomized else 'no'}")
            return self.clients[mac]

    def prune(self, lst: List[float]) -> List[float]:
        cutoff = time.time() - CFG["window_sec"]
        return [t for t in lst if t >= cutoff]

    def uptime_str(self) -> str:
        d = datetime.now() - self.start_time
        h, r = divmod(int(d.total_seconds()), 3600)
        m, s = divmod(r, 60)
        return f"{h:02d}:{m:02d}:{s:02d}"

STATE = WIDSState()

# ---------- Human-readable alert log ----------
class AlertLog:
    def __init__(self, path: Path) -> None:
        self.path = path; self._lock = threading.Lock()

    def write_alert(self, a: AlertRecord) -> None:
        try:
            with self._lock:
                with open(self.path, "a") as f:
                    f.write(f'{a.ts.strftime("%Y-%m-%d %H:%M:%S")} [{a.severity}] [{a.category}] {a.message}\n')
        except Exception:
            pass

# ---------- ML Parquet writer ----------
class MLLogger:
    def __init__(self, session_dir: Path, flush_sec: float, max_file_mb: float) -> None:
        self.session_dir = session_dir
        self.max_file_bytes = max_file_mb * 1024 * 1024
        self._buffer: List[dict] = []
        self._lock = threading.Lock()
        self._file_counter = 1
        self._current_path = self.session_dir / f"ml_data_{self._file_counter}.parquet"
        self._running = True
        self._thread = threading.Thread(target=self._flush_loop, daemon=True)
        self._thread.start()

    def _serialise(self, df: pd.DataFrame) -> None:
        if (self._current_path.exists()
                and self._current_path.stat().st_size + 1024 * 1024 > self.max_file_bytes):
            self._file_counter += 1
            self._current_path = self.session_dir / f"ml_data_{self._file_counter}.parquet"
        try:
            if self._current_path.exists():
                fastparquet.write(str(self._current_path), df, append=True, file_scheme="simple")
            else:
                fastparquet.write(str(self._current_path), df, file_scheme="simple")
        except Exception:
            pass

    def _flush(self) -> None:
        with self._lock:
            if not self._buffer:
                return
            rows, self._buffer = self._buffer, []
        df = pd.DataFrame(rows)
        type_map = {
            "timestamp": "float64", "frame_subtype": "Int8", "rssi": "Int16",
            "channel": "Int8", "freq": "Int32", "datarate": "float32", "mcs_index": "Int8",
            "eapol_key_type": "Int8", "mfpc": "boolean", "mfpr": "boolean",
            "retry": "boolean", "pwrmgt": "boolean", "protected_frame": "boolean",
            "duration_us": "Int32", "seq_num": "Int32", "beacon_interval": "Int16",
            "reason_code": "Int8", "status_code": "Int16", "auth_alg": "Int8",
            "frame_len": "Int32",
        }
        for col, dtype in type_map.items():
            if col in df.columns:
                try:
                    df[col] = df[col].astype(dtype)
                except Exception:
                    pass
        # fastparquet can't encode Arrow-backed string columns; force to numpy object
        for col in df.columns:
            if col not in type_map and df[col].dtype != object:
                try:
                    df[col] = df[col].astype(object)
                except Exception:
                    pass
        self._serialise(df)

    def _flush_loop(self) -> None:
        while self._running:
            time.sleep(CFG["ml_flush_sec"])
            self._flush()

    def stop(self) -> None:
        self._running = False
        self._flush()

    def _append(self, row: dict) -> None:
        with self._lock:
            self._buffer.append(row)

    def log_mgmt_frame(self, ts: float, subtype: int, bssid: str, sa: str, da: str,
                       ssid: str, rssi: int,
                       channel: Optional[int] = None, ta: Optional[str] = None,
                       ra: Optional[str] = None, freq: Optional[int] = None,
                       datarate: Optional[float] = None, mcs_index: Optional[int] = None,
                       retry: Optional[bool] = None, pwrmgt: Optional[bool] = None,
                       protected_frame: Optional[bool] = None, duration_us: Optional[int] = None,
                       seq_num: Optional[int] = None, beacon_interval: Optional[int] = None,
                       reason_code: Optional[int] = None, status_code: Optional[int] = None,
                       auth_alg: Optional[int] = None, mfpc: Optional[bool] = None,
                       mfpr: Optional[bool] = None, akms_type: Optional[str] = None) -> None:
        self._append(dict(
            timestamp=ts, source="mgmt_frame", frame_subtype=subtype,
            bssid=bssid, sa=sa, ta=ta, ra=ra, da=da, ssid=ssid,
            rssi=rssi, channel=channel, freq=freq, datarate=datarate,
            mcs_index=mcs_index, retry=retry, pwrmgt=pwrmgt, protected_frame=protected_frame,
            duration_us=duration_us, seq_num=seq_num, beacon_interval=beacon_interval,
            reason_code=reason_code, status_code=status_code, auth_alg=auth_alg,
            mfpc=mfpc, mfpr=mfpr, akms_type=akms_type,
        ))

    def log_data_frame(self, ts: float, ta: str, ra: str, bssid: str,
                       rssi: Optional[int], freq: Optional[int], datarate: Optional[float],
                       mcs_index: Optional[int], frame_len: Optional[int]) -> None:
        self._append(dict(
            timestamp=ts, source="data_frame",
            ta=ta, ra=ra, bssid=bssid,
            rssi=rssi, freq=freq, datarate=datarate,
            mcs_index=mcs_index, frame_len=frame_len,
        ))

    def log_eapol_frame(self, ts: float, sa: str, da: str, key_type: int) -> None:
        self._append(dict(timestamp=ts, source="eapol_frame", sa=sa, da=da, eapol_key_type=key_type))

    def log_alert(self, ts: float, severity: str, category: str, message: str,
                  bssid: str = "", mac: str = "") -> None:
        self._append(dict(timestamp=ts, source="alert", severity=severity,
                          category=category, message=message, bssid=bssid, sa=mac))

    def log_event(self, ts: float, kind: str, mac: str, detail: str) -> None:
        self._append(dict(timestamp=ts, source="event", kind=kind, sa=mac, detail=detail))

    def log_connected_client(self, ts: float, ip: str, mac: str, vendor: str) -> None:
        self._append(dict(timestamp=ts, source="connected_client", ip=ip, sa=mac, vendor=vendor))

LOG: Optional[AlertLog] = None
ML: Optional[MLLogger] = None

# ---------- UI helpers ----------
def time_ago(dt: datetime) -> str:
    secs = int((datetime.now() - dt).total_seconds())
    if secs < 5:    return "just now"
    if secs < 60:   return f"{secs}s ago"
    if secs < 3600: return f"{secs // 60}m ago"
    return f"{secs // 3600}h ago"

def rssi_bar(rssi: int) -> Text:
    if rssi == -999:
        return Text("─────  ?dBm", style="grey66")
    pct = max(0.0, min(1.0, (rssi + 95) / 65))
    filled = int(pct * 5)
    bar = "█" * filled + "░" * (5 - filled)
    style = "bright_green" if rssi >= -60 else ("yellow" if rssi >= -75 else "red")
    t = Text()
    t.append(bar, style=style)
    t.append(f" {rssi:>4}dBm", style="grey66")
    return t

def rep_text(rep: int) -> Text:
    if rep >= 80:   style, icon = "bright_green", "●"
    elif rep >= 50: style, icon = "yellow",       "●"
    else:           style, icon = "bold red",      "●"
    return Text(f"{icon} {rep:>3}", style=style)

def mini_bar(count: int, max_count: int, width: int = 8) -> str:
    if max_count == 0:
        return "░" * width
    filled = int((count / max_count) * width)
    return "█" * filled + "░" * (width - filled)

# ---------- Frame parsing (tshark) ----------
# Management frame tshark fields (tab-separated, 24 fields)
_MGMT_TSHARK_FIELDS = [
    "frame.time_epoch",            # 0
    "wlan.fc.subtype",             # 1
    "wlan.ta",                     # 2
    "wlan.ra",                     # 3
    "wlan.sa",                     # 4
    "wlan.da",                     # 5
    "wlan.bssid",                  # 6
    "wlan.ssid",                   # 7
    "radiotap.dbm_antsignal",      # 8  RSSI dBm
    "radiotap.channel.freq",       # 9  MHz
    "radiotap.datarate",           # 10 Mbps
    "radiotap.mcs.index",          # 11 MCS index
    "wlan.fc.retry",               # 12 retry bit
    "wlan.fc.pwrmgt",              # 13 power-save bit
    "wlan.fc.protected",           # 14 protected frame bit
    "wlan.duration",               # 15 duration µs
    "wlan.seq",                    # 16 sequence number
    "wlan.fixed.beacon",           # 17 beacon interval (TUs)
    "wlan.fixed.reason_code",      # 18 deauth/disassoc reason
    "wlan.fixed.status_code",      # 19 auth/assoc status
    "wlan.fixed.auth.alg",         # 20 auth algorithm (0=Open,3=SAE)
    "wlan.rsn.capabilities.mfpc", # 21 PMF capable
    "wlan.rsn.capabilities.mfpr", # 22 PMF required
    "wlan.rsn.akms.type",          # 23 AKM suite type
]

# Data frame tshark fields (tab-separated, 9 fields)
_DATA_TSHARK_FIELDS = [
    "frame.time_epoch",        # 0
    "wlan.ta",                 # 1
    "wlan.ra",                 # 2
    "wlan.bssid",              # 3
    "radiotap.dbm_antsignal",  # 4
    "radiotap.datarate",       # 5
    "radiotap.channel.freq",   # 6
    "radiotap.mcs.index",      # 7
    "frame.len",               # 8
]

def _int_s(v: str) -> Optional[int]:
    v = v.strip()
    if not v:
        return None
    try:
        return int(v)
    except Exception:
        try:
            return int(v, 16)
        except Exception:
            return None

def _float_s(v: str) -> Optional[float]:
    try:
        return float(v.strip())
    except Exception:
        return None

def _decode_tshark_ssid(raw: str) -> str:
    """tshark outputs wlan.ssid as raw hex bytes (FT_BYTES), e.g. '537765657420486f6d65'.
    Decode to UTF-8; fall back to the raw value if it isn't valid hex."""
    raw = raw.strip()
    if not raw:
        return ""
    hex_str = raw.replace(":", "")  # handle colon-separated form too
    if len(hex_str) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in hex_str):
        try:
            return bytes.fromhex(hex_str).decode("utf-8", errors="replace")
        except Exception:
            pass
    return raw

def parse_mgmt_tshark(line: str) -> Optional[dict]:
    parts = line.rstrip("\n").split("\t")
    if len(parts) < len(_MGMT_TSHARK_FIELDS):
        return None
    ts = _float_s(parts[0])
    subtype = _int_s(parts[1])
    if ts is None or subtype is None:
        return None

    ta    = parts[2].strip().upper() or None
    ra    = parts[3].strip().upper() or None
    sa    = parts[4].strip().upper() or None
    da    = parts[5].strip().upper() or None
    bssid = parts[6].strip().upper() or None
    ssid  = _decode_tshark_ssid(parts[7])

    rssi     = _int_s(parts[8])
    freq     = _int_s(parts[9])
    datarate = _float_s(parts[10])
    mcs      = _int_s(parts[11])
    retry    = parts[12].strip() == "1"
    pwrmgt   = parts[13].strip() == "1"
    protected = parts[14].strip() == "1"
    duration = _int_s(parts[15])
    seq      = _int_s(parts[16])
    beacon_int  = _int_s(parts[17])
    reason_code = _int_s(parts[18])
    status_code = _int_s(parts[19])
    auth_alg    = _int_s(parts[20])
    _r21 = parts[21].strip().lower(); mfpc = (_r21 in ("1", "true")) if _r21 else None
    _r22 = parts[22].strip().lower(); mfpr = (_r22 in ("1", "true")) if _r22 else None

    akms_raw = parts[23].strip() if len(parts) > 23 else ""
    akms_type: Optional[int] = None
    if akms_raw:
        # tshark may render as "0x00000002" or "2" or "00-0f-ac:8"
        m = re.search(r':(\d+)\s*$', akms_raw)
        if m:
            akms_type = _int_s(m.group(1))
        else:
            akms_type = _int_s(akms_raw.split(",")[0].strip())

    channel = freq_to_chan(freq) if freq else None

    return {
        "ts": ts, "subtype": subtype,
        "ta": ta, "ra": ra, "sa": sa, "da": da, "bssid": bssid, "ssid": ssid,
        "rssi": rssi, "freq": freq, "channel": channel, "datarate": datarate, "mcs": mcs,
        "retry": retry, "pwrmgt": pwrmgt, "protected": protected,
        "duration": duration, "seq": seq, "beacon_int": beacon_int,
        "reason_code": reason_code, "status_code": status_code,
        "auth_alg": auth_alg, "mfpc": mfpc, "mfpr": mfpr, "akms_type": akms_type,
    }

def parse_data_tshark(line: str) -> Optional[dict]:
    parts = line.rstrip("\n").split("\t")
    if len(parts) < len(_DATA_TSHARK_FIELDS):
        return None
    ts = _float_s(parts[0])
    if ts is None:
        return None
    return {
        "ts": ts,
        "ta":       parts[1].strip().upper() or None,
        "ra":       parts[2].strip().upper() or None,
        "bssid":    parts[3].strip().upper() or None,
        "rssi":     _int_s(parts[4]),
        "datarate": _float_s(parts[5]),
        "freq":     _int_s(parts[6]),
        "mcs":      _int_s(parts[7]),
        "frame_len": _int_s(parts[8]),
    }

# ---------- Detection ----------
def detect_beacon(f: dict) -> None:
    bssid = f.get("bssid") or ""
    if not bssid:
        return
    ssid = f.get("ssid", "").strip()
    rssi = f.get("rssi"); freq = f.get("freq", 0) or 0; channel = f.get("channel", 0) or 0
    datarate = f.get("datarate"); mcs = f.get("mcs"); beacon_int = f.get("beacon_int")
    mfpc = f.get("mfpc"); mfpr = f.get("mfpr"); akms_type = f.get("akms_type")
    STATE.frame_type_counts["beacon"] += 1
    with STATE.lock:
        ap = STATE.get_or_create_ap(bssid)
        ap.last_seen = datetime.now(); ap.frame_count += 1
        if ssid:
            ap.ssid = ssid; ap.hidden = False
        elif not ap.ssid:
            ap.hidden = True
        if rssi is not None and rssi != -999:
            ap.rssi_prev = ap.rssi; ap.rssi = rssi
        if freq:
            ap.freq = freq; ap.band = freq_to_band(freq)
        if channel:
            ap.channel = channel
        elif freq:
            ap.channel = freq_to_chan(freq)
        if datarate:
            ap.datarate = datarate
        if mcs is not None and mcs >= 0:
            ap.mcs_index = mcs
        if beacon_int:
            ap.beacon_interval = beacon_int
        if mfpc:
            ap.mfpc = True
        if mfpr:
            ap.mfpr = True
        if akms_type is not None:
            ap.akms_type = AKM_TYPES.get(akms_type, str(akms_type))
        if ap.channel:
            STATE.channel_ap_map[ap.channel].add(bssid)
    if ML:
        ML.log_mgmt_frame(
            f["ts"], 8, bssid, f.get("sa") or "", f.get("da") or "", ssid, rssi or -999,
            channel=channel, ta=f.get("ta"), ra=f.get("ra"), freq=freq,
            datarate=datarate, mcs_index=mcs, retry=f.get("retry"), pwrmgt=f.get("pwrmgt"),
            protected_frame=f.get("protected"), duration_us=f.get("duration"),
            seq_num=f.get("seq"), beacon_interval=beacon_int,
            mfpc=mfpc, mfpr=mfpr,
            akms_type=AKM_TYPES.get(akms_type, str(akms_type)) if akms_type is not None else None,
        )

def detect_deauth(f: dict) -> None:
    bssid = f.get("bssid") or ""; sa = f.get("sa") or f.get("ta") or ""
    da = f.get("da") or f.get("ra") or ""; reason = f.get("reason_code"); now = time.time()
    if not bssid:
        return
    STATE.frame_type_counts["deauth"] += 1
    reason_str = f" reason={REASON_CODES.get(reason, reason)}" if reason is not None else ""
    STATE.add_event("deauth", sa, f"to {da}  via {bssid}{reason_str}")
    STATE.add_conn("deauth", sa, bssid)
    with STATE.lock:
        if reason is not None:
            STATE.reason_code_counts[reason] += 1
        lst = STATE.deauth_times[bssid]; lst.append(now)
        STATE.deauth_times[bssid] = STATE.prune(lst)
        if len(lst) == CFG["deauth_threshold"]:
            STATE.add_alert("CRITICAL", "DEAUTH_FLOOD",
                f"Deauth flood: {len(lst)}/{CFG['window_sec']}s BSSID={bssid} SA={sa}{reason_str}",
                bssid=bssid, mac=sa)
            if bssid in STATE.aps:
                STATE.aps[bssid].reputation = max(0, STATE.aps[bssid].reputation - 35)
    if ML:
        ML.log_mgmt_frame(f["ts"], 12, bssid, sa, da, "", -999,
            channel=f.get("channel"), ta=f.get("ta"), ra=f.get("ra"), freq=f.get("freq"),
            datarate=f.get("datarate"), retry=f.get("retry"),
            reason_code=reason, seq_num=f.get("seq"))

def detect_disassoc(f: dict) -> None:
    bssid = f.get("bssid") or ""; sa = f.get("sa") or f.get("ta") or ""
    reason = f.get("reason_code"); now = time.time()
    if not bssid:
        return
    STATE.frame_type_counts["disassoc"] += 1
    reason_str = f" reason={REASON_CODES.get(reason, reason)}" if reason is not None else ""
    STATE.add_event("disassoc", sa, f"from {bssid}{reason_str}")
    STATE.add_conn("disassoc", sa, bssid)
    with STATE.lock:
        if reason is not None:
            STATE.reason_code_counts[reason] += 1
        lst = STATE.disassoc_times[bssid]; lst.append(now)
        STATE.disassoc_times[bssid] = STATE.prune(lst)
        if len(lst) == CFG["deauth_threshold"]:
            STATE.add_alert("ALERT", "DISASSOC_FLOOD",
                f"Disassoc flood: {len(lst)}/{CFG['window_sec']}s BSSID={bssid}",
                bssid=bssid, mac=sa)
    if ML:
        ML.log_mgmt_frame(f["ts"], 10, bssid, sa, f.get("da") or "", "", -999,
            channel=f.get("channel"), ta=f.get("ta"), ra=f.get("ra"), freq=f.get("freq"),
            reason_code=reason, seq_num=f.get("seq"))

def detect_probe_req(f: dict) -> None:
    mac = f.get("sa") or f.get("ta") or ""; ssid = f.get("ssid", "").strip(); now = time.time()
    if not mac:
        return
    STATE.frame_type_counts["probe"] += 1
    with STATE.lock:
        c = STATE.get_or_create_client(mac)
        c.last_seen = datetime.now(); c.frame_count += 1
        if f.get("rssi") and f["rssi"] != -999: c.last_rssi = f["rssi"]
        if f.get("freq"): c.last_freq = f["freq"]
        if f.get("datarate"): c.last_datarate = f["datarate"]
        if f.get("retry"): c.retry_frames += 1
        if ssid:
            c.probed_ssids.add(ssid)
        STATE.add_event("probe", mac,
            f"-> '{ssid or '<wildcard>'}'{' [RAND]' if c.randomized else ''} [{c.vendor}]")
        lst = STATE.probe_times[mac]
        if ssid:
            lst.append((now, ssid))
        lst = [(t, s) for t, s in lst if t >= now - CFG["window_sec"]]
        STATE.probe_times[mac] = lst
        unique_ssids = {s for _, s in lst}
        if len(unique_ssids) == CFG["probe_threshold"]:
            STATE.add_alert("WARN", "PROBE_STORM",
                f"Probe storm: {mac} hit {len(unique_ssids)} SSIDs in {CFG['window_sec']}s", mac=mac)
    if ML:
        ML.log_mgmt_frame(f["ts"], 4, "", mac, "", ssid, f.get("rssi") or -999,
            channel=f.get("channel"), ta=f.get("ta"), ra=f.get("ra"), freq=f.get("freq"),
            datarate=f.get("datarate"), mcs_index=f.get("mcs"),
            retry=f.get("retry"), pwrmgt=f.get("pwrmgt"), seq_num=f.get("seq"))

def detect_auth(f: dict) -> None:
    bssid = f.get("bssid") or ""; sa = f.get("sa") or f.get("ta") or ""
    auth_alg = f.get("auth_alg"); status = f.get("status_code")
    if not sa:
        return
    STATE.frame_type_counts["auth"] += 1
    alg_str = AUTH_ALGS.get(auth_alg, str(auth_alg)) if auth_alg is not None else "?"
    with STATE.lock:
        if auth_alg is not None:
            STATE.auth_alg_counts[auth_alg] += 1
            if bssid and bssid in STATE.aps:
                STATE.aps[bssid].auth_algs_seen.add(auth_alg)
    if status and status != 0:
        STATE.add_event("auth_fail", sa, f"-> {bssid} alg={alg_str} status={status}")
        with STATE.lock:
            if sa in STATE.clients:
                STATE.clients[sa].auth_failures += 1
    else:
        STATE.add_event("auth_ok", sa, f"-> {bssid} alg={alg_str}")
    if ML:
        ML.log_mgmt_frame(f["ts"], 11, bssid, sa, f.get("da") or "", "", f.get("rssi") or -999,
            channel=f.get("channel"), ta=f.get("ta"), ra=f.get("ra"), freq=f.get("freq"),
            auth_alg=auth_alg, status_code=status, seq_num=f.get("seq"))

def detect_assoc(f: dict) -> None:
    bssid = f.get("bssid") or ""; sa = f.get("sa") or f.get("ta") or ""
    subtype = f.get("subtype", 0); status = f.get("status_code")
    if not sa:
        return
    STATE.frame_type_counts["assoc"] += 1
    with STATE.lock:
        if sa in STATE.aps:
            return
        c = STATE.get_or_create_client(sa)
        c.last_seen = datetime.now(); c.frame_count += 1
        if bssid:
            c.associated_bssid = bssid
            STATE.add_event("assoc", sa,
                f"-> {bssid}" + (f" status={status}" if status else ""))
            STATE.add_conn("assoc", sa, bssid)
    if ML:
        ML.log_mgmt_frame(f["ts"], subtype, bssid, sa, f.get("da") or "", "", f.get("rssi") or -999,
            channel=f.get("channel"), ta=f.get("ta"), ra=f.get("ra"), freq=f.get("freq"),
            status_code=status, seq_num=f.get("seq"))

def detect_data_frame(f: dict) -> None:
    ta = f.get("ta") or ""; bssid = f.get("bssid") or ""
    rssi = f.get("rssi"); freq = f.get("freq"); datarate = f.get("datarate")
    frame_len = f.get("frame_len") or 0
    if ta in ("FF:FF:FF:FF:FF:FF", "", None):
        return
    with STATE.lock:
        STATE.data_frame_count += 1
        if frame_len:
            STATE.total_data_bytes += frame_len
        if ta not in STATE.aps:
            c = STATE.get_or_create_client(ta)
            c.data_frames += 1; c.last_seen = datetime.now()
            if rssi and rssi != -999: c.last_rssi = rssi
            if freq: c.last_freq = freq
            if datarate: c.last_datarate = datarate
        if bssid and bssid in STATE.aps:
            ap = STATE.aps[bssid]
            if rssi and rssi != -999: ap.rssi = rssi
            if freq and not ap.freq: ap.freq = freq
            if datarate: ap.datarate = datarate
    if ML:
        ML.log_data_frame(f["ts"], ta, f.get("ra") or "", bssid,
                          rssi, freq, datarate, f.get("mcs"), frame_len or None)

# ---------- EAPOL handshake tracking ----------
def detect_eapol(f: dict) -> None:
    sa = f.get("sa", ""); da = f.get("da", "")
    key_type_str = f.get("eapol_key_type", ""); ts_str = f.get("time_epoch", "")
    STATE.frame_type_counts["eapol"] += 1
    STATE.tick()
    STATE.add_event("eapol", sa, f"-> {da}" + (f"  key_type={key_type_str}" if key_type_str else ""))
    try:
        ts = float(ts_str) if ts_str else time.time()
    except ValueError:
        ts = time.time()
    with STATE.lock:
        if sa in STATE.aps:
            return
        c = STATE.get_or_create_client(sa)
        c.eapol_count += 1; c.last_seen = datetime.now()
        if c.eapol_count == 1:
            STATE.add_alert("INFO", "EAPOL",
                f"WPA handshake: {sa} seen first time this session", mac=sa)
        elif c.eapol_count == 8:
            STATE.add_alert("WARN", "EAPOL_STORM",
                f"Repeated handshakes from {sa} ({c.eapol_count} frames)", mac=sa)
    try:
        key_type = int(key_type_str) if key_type_str else None
    except ValueError:
        key_type = None
    if key_type not in (2, 3, 4, 5):
        if ML:
            ML.log_eapol_frame(ts, sa, da, key_type if key_type is not None else -1)
        return
    msg_map = {2: "M1", 3: "M2", 4: "M3", 5: "M4"}
    msg_type = msg_map[key_type]
    bssid = None
    if sa in STATE.aps:
        bssid = sa; sta_mac = da
    elif da in STATE.aps:
        bssid = da; sta_mac = sa
    else:
        if ML:
            ML.log_eapol_frame(ts, sa, da, key_type)
        return
    if not sta_mac:
        return
    with STATE.lock:
        hs_key = (bssid, sta_mac)
        state = STATE.hs_states.get(hs_key)
        if msg_type == "M1":
            STATE.hs_states[hs_key] = {"last_msg": "M1", "last_time": ts, "start_time": ts}
        elif state is None:
            STATE.add_alert("WARN", "EAPOL_ANOMALY",
                f"Stray {msg_type} from {sa} to {da} without M1 (bssid={bssid})",
                bssid=bssid, mac=sta_mac)
        else:
            expected = {"M1": "M2", "M2": "M3", "M3": "M4"}.get(state["last_msg"])
            if msg_type != expected:
                STATE.add_alert("WARN", "EAPOL_SEQUENCE",
                    f"Unexpected {msg_type} after {state['last_msg']} STA {sta_mac} bssid={bssid}",
                    bssid=bssid, mac=sta_mac)
                del STATE.hs_states[hs_key]
            elif msg_type == "M4":
                duration = ts - state.get("start_time", ts)
                if duration > CFG["handshake_timeout_sec"]:
                    STATE.add_alert("WARN", "EAPOL_TIMEOUT",
                        f"Handshake for {sta_mac} took {duration:.1f}s > {CFG['handshake_timeout_sec']}s",
                        bssid=bssid, mac=sta_mac)
                del STATE.hs_states[hs_key]
            else:
                state["last_msg"] = msg_type; state["last_time"] = ts
    if ML:
        ML.log_eapol_frame(ts, sa, da, key_type)

# ---------- LAN threat detection ----------
LAN_CATEGORIES = {"ARP_SCAN", "ARP_POISON", "PORT_SCAN", "DHCP_STARVE",
                  "LAN_READER_ERR", "LAN_RESTART", "LAN_SKIP"}

def parse_lan_line(line: str) -> dict | None:
    line = line.strip()
    if not line:
        return None
    r: dict = {}
    if "ARP" in line:
        if "who-has" in line:
            r["type"] = "arp_request"
            m = re.search(r'who-has (\d+\.\d+\.\d+\.\d+) tell (\d+\.\d+\.\d+\.\d+)', line)
            if m:
                r["target_ip"] = m.group(1); r["sender_ip"] = m.group(2)
            m2 = re.search(r'^[\d:.]+\s+([0-9a-f:]{17})\s+>', line)
            if m2:
                r["sender_mac"] = m2.group(1).upper()
        elif "is-at" in line:
            r["type"] = "arp_reply"
            m = re.search(r'(\d+\.\d+\.\d+\.\d+) is-at ([0-9a-f:]{17})', line)
            if m:
                r["ip"] = m.group(1); r["mac"] = m.group(2).upper()
        else:
            return None
    elif "Flags [S]" in line and "Flags [S.]" not in line:
        r["type"] = "tcp_syn"
        m = re.search(r'IP (\d+\.\d+\.\d+\.\d+)\.(\d+) > (\d+\.\d+\.\d+\.\d+)\.(\d+)', line)
        if not m:
            return None
        r["src_ip"] = m.group(1); r["src_port"] = int(m.group(2))
        r["dst_ip"] = m.group(3); r["dst_port"] = int(m.group(4))
    elif "BOOTP/DHCP" in line and "Request" in line:
        r["type"] = "dhcp_discover"
        m = re.search(r'Request from ([0-9a-f:]{17})', line)
        if m:
            r["client_mac"] = m.group(1).upper()
        else:
            m2 = re.search(r'^[\d:.]+\s+([0-9a-f:]{17})\s+>', line)
            if m2:
                r["client_mac"] = m2.group(1).upper()
    else:
        return None
    return r if r.get("type") else None

def detect_arp_scan(r: dict) -> None:
    sender_ip = r.get("sender_ip", "")
    if not sender_ip or sender_ip in STATE.own_ips:
        return
    now = time.time()
    with STATE.lock:
        lst = STATE.arp_request_times[sender_ip]; lst.append(now)
        cutoff = now - CFG["arp_scan_window"]
        lst = [t for t in lst if t >= cutoff]
        STATE.arp_request_times[sender_ip] = lst
        if len(lst) == CFG["arp_scan_threshold"]:
            STATE.add_alert("WARN", "ARP_SCAN",
                f"{sender_ip} sent {len(lst)} ARP requests in {CFG['arp_scan_window']}s — possible recon",
                mac=r.get("sender_mac", ""))

def detect_arp_poison(r: dict) -> None:
    ip = r.get("ip", ""); mac = r.get("mac", "")
    if not ip or not mac:
        return
    with STATE.lock:
        known = STATE.ip_mac_table.get(ip)
        if known is None:
            STATE.ip_mac_table[ip] = mac
        elif known != mac:
            STATE.add_alert("CRITICAL", "ARP_POISON",
                f"MITM? {ip} was {known}, now claims {mac}")
            STATE.ip_mac_table[ip] = mac

def detect_port_scan(r: dict) -> None:
    src_ip = r.get("src_ip", ""); dst_port = r.get("dst_port")
    if not src_ip or dst_port is None or src_ip in STATE.own_ips:
        return
    now = time.time()
    with STATE.lock:
        lst = STATE.port_scan_times[src_ip]; lst.append((now, dst_port))
        cutoff = now - CFG["port_scan_window"]
        lst = [(t, p) for t, p in lst if t >= cutoff]
        STATE.port_scan_times[src_ip] = lst
        unique = {p for _, p in lst}
        if len(unique) == CFG["port_scan_threshold"]:
            STATE.add_alert("ALERT", "PORT_SCAN",
                f"{src_ip} hit {len(unique)} unique ports in {CFG['port_scan_window']}s")

def detect_dhcp_starve(r: dict) -> None:
    mac = r.get("client_mac", "")
    if not mac:
        return
    now = time.time(); cutoff = now - CFG["dhcp_starve_window"]
    with STATE.lock:
        STATE.dhcp_discover_times[mac].append(now)
        active = {m for m, times in STATE.dhcp_discover_times.items()
                  if any(t >= cutoff for t in times)}
        if len(active) == CFG["dhcp_starve_threshold"]:
            STATE.add_alert("CRITICAL", "DHCP_STARVE",
                f"{len(active)} unique MACs DHCP DISCOVER in {CFG['dhcp_starve_window']}s — starvation?")

# ---------- Capture threads ----------
_PROCESSES: List[Tuple[subprocess.Popen, str]] = []
_PROCS_LOCK = threading.Lock()

def mgmt_reader_thread() -> None:
    log_dir = CFG["base_log_dir"].parent
    cmd = (["tshark", "-i", CFG["monitor_iface"], "-l", "-n", "-T", "fields"]
           + [arg for f in _MGMT_TSHARK_FIELDS for arg in ("-e", f)]
           + ["-Y", "wlan.fc.type == 0", "-E", "separator=\t"])
    while STATE.running:
        fh = open(log_dir / "tshark_mgmt.log", "a")
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=fh, text=True)
        with _PROCS_LOCK:
            _PROCESSES.append((proc, "mgmt"))
        try:
            for line in proc.stdout:
                if not STATE.running:
                    break
                f = parse_mgmt_tshark(line)
                if f is None:
                    continue
                STATE.tick()
                st = f["subtype"]
                # Count retries globally
                if f.get("retry"):
                    b = f.get("bssid") or ""
                    with STATE.lock:
                        if b and b in STATE.aps:
                            STATE.aps[b].retry_frames += 1
                if st == 8:
                    detect_beacon(f)
                elif st == 12:
                    detect_deauth(f)
                elif st == 10:
                    detect_disassoc(f)
                elif st == 4:
                    detect_probe_req(f)
                elif st == 11:
                    detect_auth(f)
                elif st in (0, 1, 2, 3):
                    detect_assoc(f)
                elif ML:
                    # Probe responses (5), action frames (13), etc. — log to parquet
                    ML.log_mgmt_frame(
                        f["ts"], st, f.get("bssid") or "", f.get("sa") or "",
                        f.get("da") or "", f.get("ssid", ""), f.get("rssi") or -999,
                        channel=f.get("channel"), ta=f.get("ta"), ra=f.get("ra"),
                        freq=f.get("freq"), datarate=f.get("datarate"),
                        mcs_index=f.get("mcs"), retry=f.get("retry"), seq_num=f.get("seq"),
                    )
        except Exception as e:
            STATE.add_alert("ALERT", "MGMT_READER_ERR", str(e))
        finally:
            fh.close(); proc.terminate(); time.sleep(5)

def data_reader_thread() -> None:
    log_dir = CFG["base_log_dir"].parent
    cmd = (["tshark", "-i", CFG["monitor_iface"], "-l", "-n", "-T", "fields"]
           + [arg for f in _DATA_TSHARK_FIELDS for arg in ("-e", f)]
           + ["-Y", "wlan.fc.type == 2", "-E", "separator=\t"])
    while STATE.running:
        fh = open(log_dir / "tshark_data.log", "a")
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=fh, text=True)
        with _PROCS_LOCK:
            _PROCESSES.append((proc, "data"))
        try:
            for line in proc.stdout:
                if not STATE.running:
                    break
                f = parse_data_tshark(line)
                if f is None:
                    continue
                STATE.tick()
                detect_data_frame(f)
        except Exception as e:
            STATE.add_alert("ALERT", "DATA_READER_ERR", str(e))
        finally:
            fh.close(); proc.terminate(); time.sleep(5)

def eapol_reader_thread() -> None:
    log_dir = CFG["base_log_dir"].parent
    while STATE.running:
        fh = open(log_dir / "tshark_eapol.log", "a")
        proc = subprocess.Popen(
            ["tshark", "-i", CFG["monitor_iface"], "-l", "-n", "-T", "fields",
             "-e", "frame.time_epoch", "-e", "wlan.sa", "-e", "wlan.da",
             "-e", "eapol.keydes.type", "-Y", "eapol", "-E", "separator=\t"],
            stdout=subprocess.PIPE, stderr=fh, text=True)
        with _PROCS_LOCK:
            _PROCESSES.append((proc, "eapol"))
        try:
            for line in proc.stdout:
                if not STATE.running:
                    break
                parts = line.strip().split("\t")
                if len(parts) < 4:
                    continue
                detect_eapol({"time_epoch": parts[0].strip(),
                               "sa": parts[1].strip().upper(),
                               "da": parts[2].strip().upper(),
                               "eapol_key_type": parts[3].strip()})
        except Exception as e:
            fh.write(f"[EXCEPTION] {e}\n")
        finally:
            fh.close(); proc.terminate(); time.sleep(5)

def lan_monitor_thread() -> None:
    log_dir = CFG["base_log_dir"].parent
    while STATE.running:
        iface = CFG["scan_iface"]
        try:
            if "monitor" in subprocess.check_output(
                    ["iw", "dev", iface, "info"], text=True, stderr=subprocess.DEVNULL):
                STATE.add_alert("WARN", "LAN_SKIP", f"{iface} is in monitor mode — retry in 30s")
                time.sleep(30); continue
        except:
            time.sleep(10); continue
        fh = open(log_dir / "tcpdump_lan.log", "a")
        proc = subprocess.Popen(
            ["tcpdump", "-i", iface, "-n", "-e", "-l",
             "arp or (udp port 67) or (tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0)"],
            stdout=subprocess.PIPE, stderr=fh, text=True)
        with _PROCS_LOCK:
            _PROCESSES.append((proc, "lan"))
        try:
            for line in proc.stdout:
                if not STATE.running:
                    break
                r = parse_lan_line(line.strip())
                if not r:
                    continue
                t = r["type"]
                if t == "arp_request":     detect_arp_scan(r)
                elif t == "arp_reply":     detect_arp_poison(r)
                elif t == "tcp_syn":       detect_port_scan(r)
                elif t == "dhcp_discover": detect_dhcp_starve(r)
        except Exception as e:
            STATE.add_alert("ALERT", "LAN_READER_ERR", str(e))
        finally:
            fh.close(); proc.terminate()
            if STATE.running:
                STATE.add_alert("ALERT", "LAN_RESTART", "LAN monitor died – restarting in 5s")
                time.sleep(5)

# ---------- Scanner, inventory, watchdog, heartbeat, export ----------
def _nmcli_scan() -> Tuple[str, int]:
    try:
        out = subprocess.check_output(
            ["nmcli", "-t", "-f", "BSSID,CHAN,SSID", "dev", "wifi", "list",
             "ifname", CFG["scan_iface"]],
            stderr=subprocess.DEVNULL, text=True, timeout=20)
        for raw in out.splitlines():
            esc = raw.replace("\\:", "\x00"); parts = esc.split(":", 2)
            if len(parts) < 3:
                continue
            bssid = parts[0].replace("\x00", ":").upper()
            try:
                chan = int(parts[1])
            except:
                continue
            ssid = parts[2].replace("\x00", ":")
            if ssid == CFG["home_ssid"]:
                return bssid, chan
    except:
        pass
    return "", 0

def scanner_thread() -> None:
    prev_bssid, prev_channel = "", 0
    while STATE.running:
        bssid, chan = _nmcli_scan()
        if bssid and chan:
            with STATE.lock:
                if prev_bssid and bssid != prev_bssid:
                    STATE.add_alert("WARN", "HOME_BSSID_CHANGE",
                        f"Home BSSID changed: {prev_bssid}->{bssid}", bssid=bssid)
                if prev_channel and chan != prev_channel:
                    STATE.add_alert("WARN", "CHANNEL_CHANGE",
                        f"Home AP moved: ch {prev_channel}->{chan}", bssid=bssid)
                    subprocess.run(["iw", "dev", CFG["monitor_iface"], "set", "channel", str(chan)],
                                   capture_output=True)
                STATE.home_bssid, STATE.home_channel = bssid, chan
                ap = STATE.get_or_create_ap(bssid)
                ap.is_home = True; ap.channel = chan
                if not ap.ssid:
                    ap.ssid = CFG["home_ssid"]
            if not prev_bssid:
                subprocess.run(["iw", "dev", CFG["monitor_iface"], "set", "channel", str(chan)],
                               capture_output=True)
                STATE.add_alert("INFO", "INIT",
                    f"Home AP '{CFG['home_ssid']}': BSSID={bssid} ch={chan}")
            prev_bssid, prev_channel = bssid, chan
        else:
            if prev_bssid:
                STATE.add_alert("ALERT", "AP_LOST", "Home AP no longer visible")
        time.sleep(CFG["channel_check_interval"])

def _run_client_inventory() -> None:
    iface = CFG["scan_iface"]
    try:
        out = subprocess.check_output(["arp-scan", "-I", iface, "-l", "-q"],
                                      stderr=subprocess.DEVNULL, text=True, timeout=15)
    except Exception:
        return
    ts = time.time()
    clients = []
    for line in out.splitlines():
        if not line or any(s in line for s in
                           ("Starting arp-scan", "packets received", "Interface:")):
            continue
        parts = line.split()
        if len(parts) >= 2:
            ip = parts[0]; mac = parts[1].upper(); vendor = oui_lookup(mac)
            clients.append((ip, mac, vendor))
            if ML:
                ML.log_connected_client(ts, ip, mac, vendor)
    with STATE.lock:
        STATE.connected_clients_cache = clients
        STATE.connected_clients_ts = ts

def client_inventory_thread() -> None:
    time.sleep(3)  # let the interface come up first
    _run_client_inventory()
    while STATE.running:
        time.sleep(CFG["client_inventory_interval"])
        if not STATE.running:
            break
        _run_client_inventory()

def watchdog_thread() -> None:
    time.sleep(15)
    while STATE.running:
        time.sleep(30)
        with _PROCS_LOCK:
            _PROCESSES[:] = [(p, n) for p, n in _PROCESSES if p.poll() is None]
        if (STATE.total_frames > 0
                and STATE.frame_type_counts.get("beacon", 0) == 0
                and STATE.frame_type_counts.get("probe", 0) == 0
                and STATE.frame_type_counts.get("deauth", 0) == 0):
            STATE.add_alert("CRITICAL", "CAPTURE_FAILURE",
                "0 management frames seen — check debug logs")

def heartbeat_thread() -> None:
    while STATE.running:
        time.sleep(CFG["heartbeat_interval"])
        STATE.add_event("heartbeat", "—",
            f"ch={STATE.home_channel or '?'}  APs={len(STATE.aps)}  "
            f"clients={len(STATE.clients)}  {round(STATE.fps(), 1)} fr/s  "
            f"data={STATE.data_frame_count}  total={STATE.total_frames}")

def export_snapshot(reason: str = "scheduled") -> None:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    def _s(v):
        if isinstance(v, datetime): return str(v)
        if isinstance(v, set):     return list(v)
        return v
    with STATE.lock:
        aps = list(STATE.aps.values())
        clis = list(STATE.clients.values())
        alerts = list(STATE.alerts)
    data = {
        "exported_at": str(datetime.now()), "reason": reason,
        "home_bssid": STATE.home_bssid, "home_channel": STATE.home_channel,
        "total_frames": STATE.total_frames, "data_frames": STATE.data_frame_count,
        "aps":    [{k: _s(v) for k, v in ap.__dict__.items()} for ap in aps],
        "clients":[{k: _s(v) for k, v in c.__dict__.items()}  for c in clis],
        "alerts": [{"ts": str(a.ts), "severity": a.severity, "category": a.category,
                    "message": a.message, "bssid": a.bssid, "mac": a.mac} for a in alerts],
    }
    out_path = SESSION_DIR / f"snapshot_{ts}.json"
    with open(out_path, "w") as fh:
        json.dump(data, fh, indent=2)
    STATE.add_alert("INFO", "EXPORT", f"[{reason}] -> {out_path.name}")
    STATE.last_export = time.time()

def export_scheduler_thread() -> None:
    while STATE.running:
        time.sleep(CFG["export_interval_min"] * 60)
        export_snapshot("scheduled")

def update_all_aps_from_nmcli() -> None:
    time.sleep(5)
    while STATE.running:
        try:
            out = subprocess.check_output(
                ["nmcli", "--terse", "--fields", "BSSID,SSID,CHAN,SECURITY,SIGNAL",
                 "dev", "wifi", "list", "ifname", CFG["scan_iface"]],
                stderr=subprocess.DEVNULL, text=True, timeout=15)
            for line in out.splitlines():
                if not line:
                    continue
                esc = line.replace("\\:", "\x00"); parts = esc.split(":")
                if len(parts) < 5:
                    continue
                bssid  = parts[0].replace("\x00", ":").strip().upper()
                ssid   = parts[1].replace("\x00", ":").strip()
                chan   = parts[2].strip()
                sec    = parts[3].strip()
                signal = parts[4].strip()
                if not bssid or bssid == "--":
                    continue
                with STATE.lock:
                    ap = STATE.get_or_create_ap(bssid)
                    if ssid and ssid != "--":
                        ap.ssid = ssid; ap.hidden = False
                    if chan and chan != "--":
                        try:
                            ap.channel = int(chan)
                        except:
                            pass
                    if "WPA2" in sec and "WPA3" in sec:
                        ap.transition_mode = True; ap.security = "WPA2/WPA3"
                        ap.mfpc = True
                        if ap.is_home and bssid not in STATE.transition_alerted_bssids:
                            STATE.transition_alerted_bssids.add(bssid)
                            STATE.add_alert("WARN", "WPA3_DOWNGRADE_RISK",
                                f"Home AP {bssid} ({ssid}) in WPA3 transition — downgrade possible!",
                                bssid=bssid)
                    elif "WPA3" in sec: ap.security = "WPA3-SAE"; ap.mfpc = True; ap.mfpr = True
                    elif "WPA2" in sec: ap.security = "WPA2-PSK"
                    elif "WEP"  in sec: ap.security = "WEP"
                    elif sec == "":    ap.security = "Open"
                    if signal and signal != "--":
                        try:
                            if ap.rssi == -999:
                                ap.rssi = (int(signal) // 2) - 100
                        except:
                            pass
        except Exception as e:
            STATE.add_alert("WARN", "NMCLI_ERR", str(e))
        time.sleep(60)

# ---------- TUI ----------
SEV_STYLE  = {"INFO": "cyan", "WARN": "yellow", "ALERT": "bold red", "CRITICAL": "bold white on red"}
SEV_ICON   = {"INFO": "ℹ", "WARN": "⚠", "ALERT": "✖", "CRITICAL": "☠"}
KIND_STYLE = {
    "beacon": "grey62", "probe": "bright_cyan", "deauth": "bold red", "disassoc": "red",
    "assoc": "bright_green", "assoc_fail": "yellow", "auth_ok": "green", "auth_fail": "yellow",
    "eapol": "magenta", "new_device": "bold bright_yellow", "heartbeat": "steel_blue1",
}
KIND_ICON = {
    "beacon": "📡", "probe": "🔍", "deauth": "💀", "disassoc": "⚡", "assoc": "🔗",
    "assoc_fail": "✖", "auth_ok": "✓", "auth_fail": "✖", "eapol": "🔑",
    "new_device": "👾", "heartbeat": "♥",
}
FRAME_ICONS = {"beacon": "📡", "probe": "🔍", "auth": "🔐", "assoc": "🔗",
               "eapol": "🔑", "deauth": "💀", "disassoc": "⚡"}

def _status_bar() -> Panel:
    fps = round(STATE.fps(), 1)
    n_alr = sum(STATE.alert_counts.values())
    pulse_style = "bright_green bold" if STATE._pulse_active else "dim green"
    STATE._pulse_active = False
    t = Text(overflow="fold")
    t.append(f" {STATE._pulse_char} WIDS  ", style=pulse_style)
    t.append("│ ", style="grey66")
    t.append("iface ", style="grey66");  t.append(CFG["monitor_iface"], style="bold cyan")
    t.append("  ch ",  style="grey66");  t.append(str(STATE.home_channel or "?"), style="bold yellow")
    t.append("  home ", style="grey66"); t.append(STATE.home_bssid or "scanning…", style="bold bright_green")
    t.append("  APs ", style="grey66");  t.append(str(len(STATE.aps)), style="bold")
    t.append("  clients ", style="grey66"); t.append(str(len(STATE.clients)), style="bold")
    t.append("  data ", style="grey66"); t.append(str(STATE.data_frame_count), style="bold bright_blue")
    t.append("  alerts ", style="grey66")
    t.append(str(n_alr), style="bold red" if n_alr else "bold bright_green")
    t.append("  up ", style="grey66");    t.append(STATE.uptime_str(), style="bold magenta")
    t.append("  fr/s ", style="grey66");  t.append(str(fps), style="bold bright_cyan")
    t.append("  total ", style="grey66"); t.append(str(STATE.total_frames), style="bold")
    return Panel(t, style="on grey11", box=box.HORIZONTALS, padding=(0, 0))

def _ap_table() -> Panel:
    with STATE.lock:
        aps = sorted(STATE.aps.values(), key=lambda a: a.rssi, reverse=True)
        home_bssid = STATE.home_bssid
    tbl = Table(box=box.SIMPLE_HEAD, expand=True, header_style="bold cyan",
                show_footer=False, padding=(0, 0))
    tbl.add_column(" ",        no_wrap=True, width=1)
    tbl.add_column("BSSID",    no_wrap=True, width=17, max_width=17)
    tbl.add_column("SSID",     no_wrap=True, max_width=12)
    tbl.add_column("Ch/Band",  no_wrap=True, width=7)
    tbl.add_column("Signal",   no_wrap=True, width=12)
    tbl.add_column("Security", no_wrap=True, max_width=9)
    tbl.add_column("PMF",      no_wrap=True, width=3)
    tbl.add_column("Rate",     no_wrap=True, width=6)
    tbl.add_column("Rep",      no_wrap=True, width=5)
    max_rows = max(5, console.height - 20)
    for ap in aps[:max_rows]:
        is_home = (ap.bssid == home_bssid)
        star_t  = Text("★" if is_home else " ", style="bold bright_green" if is_home else "")
        bssid_t = Text(ap.bssid, style="bold bright_green" if is_home else "white")
        ssid_t  = Text(ap.ssid) if ap.ssid else Text("<hidden>", style="italic grey58")
        if ap.ibss:
            ssid_t.append(" IBSS", style="bold red")
        pmf_t   = Text("✓" if ap.mfpc else "✗", style="bright_green" if ap.mfpc else "red")
        sec_display = ap.security if not ap.transition_mode else "WPA2/3 ↔"
        ch_band = f"{ap.channel}/{ap.band}" if ap.channel else "?/?"
        rate_str = (f"{ap.datarate:.0f}M" if ap.datarate
                    else (f"MCS{ap.mcs_index}" if ap.mcs_index >= 0 else "—"))
        tbl.add_row(star_t, bssid_t, ssid_t, ch_band,
                    rssi_bar(ap.rssi), sec_display, pmf_t, rate_str, rep_text(ap.reputation))
    return Panel(tbl,
                 title="[bold cyan]◉ RF Radar — Access Points[/]  "
                       "[grey66]★=home  PMF=802.11w  Rep=trust  ↔=transition[/]",
                 border_style="cyan", box=box.ROUNDED)

def _alert_panel() -> Panel:
    with STATE.lock:
        alerts = list(STATE.alerts)
    wids_alerts = [a for a in alerts if a.category not in LAN_CATEGORIES][:11]
    lan_alerts  = [a for a in alerts if a.category in LAN_CATEGORIES][:9]
    txt = Text(overflow="fold")
    txt.append("  RF / WIDS\n", style="bold cyan")
    if not wids_alerts:
        txt.append("  All quiet — watching the ether …\n", style="grey58 italic")
    for a in wids_alerts:
        icon = SEV_ICON.get(a.severity, "·"); sty = SEV_STYLE.get(a.severity, "white")
        txt.append(f"  {a.ts.strftime('%H:%M:%S')} ", style="grey66")
        txt.append(f"{icon} ", style=sty)
        txt.append(f"{a.category:<16}", style="bold")
        txt.append(f" {a.message[:60]}\n", style="white")
    txt.append("  " + "─" * 58 + "\n", style="grey35")
    txt.append("  LAN Threats\n", style="bold yellow")
    if not lan_alerts:
        txt.append("  No LAN threats detected …\n", style="grey58 italic")
    for a in lan_alerts:
        icon = SEV_ICON.get(a.severity, "·"); sty = SEV_STYLE.get(a.severity, "white")
        txt.append(f"  {a.ts.strftime('%H:%M:%S')} ", style="grey66")
        txt.append(f"{icon} ", style=sty)
        txt.append(f"{a.category:<16}", style="bold")
        txt.append(f" {a.message[:60]}\n", style="white")
    return Panel(txt,
                 title="[bold red]⚠ Alert Feed[/]  [grey66]☠=CRITICAL  ✖=ALERT  ⚠=WARN  ℹ=INFO[/]",
                 border_style="red", box=box.ROUNDED)

def _stats_panel() -> Panel:
    with STATE.lock:
        fcounts  = dict(STATE.frame_type_counts)
        acounts  = dict(STATE.alert_counts)
        n_new    = len(STATE.new_bssids_boot)
        n_rand   = sum(1 for c in STATE.clients.values() if c.randomized)
        n_ibss   = sum(1 for ap in STATE.aps.values() if ap.ibss)
        n_hid    = sum(1 for ap in STATE.aps.values() if ap.hidden)
        n_trans  = sum(1 for ap in STATE.aps.values() if ap.transition_mode)
        ch_map   = {ch: len(bssids) for ch, bssids in STATE.channel_ap_map.items()}
        alg_cnt  = dict(STATE.auth_alg_counts)
        rc_cnt   = dict(STATE.reason_code_counts)
        dfcount  = STATE.data_frame_count
        dbytes   = STATE.total_data_bytes
    txt = Text(overflow="fold")

    # Frame histogram
    txt.append("Frame histogram\n", style="bold white")
    max_f = max(fcounts.values(), default=1)
    for kind in ("beacon", "probe", "assoc", "auth", "eapol", "deauth", "disassoc"):
        cnt = fcounts.get(kind, 0)
        txt.append(f"  {FRAME_ICONS.get(kind, '·')} {kind:<9} ", style="grey74")
        txt.append(mini_bar(cnt, max_f, 7), style="cyan")
        txt.append(f" {cnt}\n", style="bold")
    data_mb = dbytes / (1024 * 1024) if dbytes else 0
    txt.append(f"  💾 data      ", style="grey74")
    txt.append(f"{dfcount}", style="bold bright_blue")
    txt.append(f" ({data_mb:.1f}MB)\n", style="grey66")

    # Alert breakdown
    txt.append("\nAlert breakdown\n", style="bold white")
    if acounts:
        for cat, cnt in sorted(acounts.items(), key=lambda x: -x[1])[:6]:
            txt.append(f"  {cat:<18} ", style="grey74")
            txt.append(f"{cnt}\n", style="bold yellow")
    else:
        txt.append("  (none yet)\n", style="grey58 italic")

    # Network counters
    txt.append("\nCounters\n", style="bold white")
    for label, val, sty in [
        ("New BSSIDs",   n_new,  "bold cyan"),
        ("Rand MACs",    n_rand, "bold yellow"),
        ("IBSS/ad-hoc",  n_ibss, "bold red" if n_ibss else "bold"),
        ("Hidden SSIDs", n_hid,  "bold"),
        ("Trans. mode",  n_trans, "bold red" if n_trans else "bold"),
        ("Total frames", STATE.total_frames, "bold"),
    ]:
        txt.append(f"  {label:<16} ", style="grey74")
        txt.append(f"{val}\n", style=sty)

    # Channel occupancy
    if ch_map:
        txt.append("\nChannel occupancy\n", style="bold white")
        home_ch = STATE.home_channel
        for ch in sorted(ch_map.keys())[:8]:
            cnt = ch_map[ch]
            marker = "★" if ch == home_ch else " "
            band = freq_to_band(2412 + (ch - 1) * 5 if 1 <= ch <= 13
                                else 5180 + (ch - 36) * 5 if 36 <= ch <= 165
                                else 5955)
            txt.append(f"  {marker}ch{ch:<4}", style="bold bright_green" if ch == home_ch else "grey74")
            txt.append(mini_bar(cnt, max(ch_map.values()), 5), style="yellow")
            txt.append(f" {cnt} AP  {band}\n", style="grey66")

    # Auth algorithm distribution
    if alg_cnt:
        txt.append("\nAuth methods\n", style="bold white")
        for alg, cnt in sorted(alg_cnt.items(), key=lambda x: -x[1])[:4]:
            label = AUTH_ALGS.get(alg, f"alg{alg}")
            sty = "bright_green" if alg == 3 else ("yellow" if alg == 0 else "white")
            txt.append(f"  {label:<12} ", style=sty)
            txt.append(f"{cnt}\n", style="bold")

    # Top disconnect reason codes
    if rc_cnt:
        txt.append("\nDisconnect reasons\n", style="bold white")
        for rc, cnt in sorted(rc_cnt.items(), key=lambda x: -x[1])[:4]:
            label = REASON_CODES.get(rc, f"rc{rc}")[:16]
            sty = "bold red" if rc in (13, 14, 15, 22) else "grey74"
            txt.append(f"  {label:<16} ", style=sty)
            txt.append(f"{cnt}\n", style="bold")

    return Panel(txt, title="[bold yellow]📊 Network Stats[/]", border_style="yellow", box=box.ROUNDED)

def _client_table() -> Panel:
    with STATE.lock:
        ap_macs = set(STATE.aps.keys())
        clients = sorted([c for c in STATE.clients.values() if c.mac not in ap_macs],
                         key=lambda c: c.last_seen, reverse=True)
    tbl = Table(box=box.SIMPLE_HEAD, expand=True, header_style="bold magenta", padding=(0, 0))
    tbl.add_column("MAC",    no_wrap=True, width=17, max_width=17)
    tbl.add_column("Vendor", no_wrap=True, width=10, max_width=10)
    tbl.add_column("Rand",   no_wrap=True, width=4)
    tbl.add_column("Probes", no_wrap=True, width=5)
    tbl.add_column("EAPOL",  no_wrap=True, width=5)
    tbl.add_column("Data",   no_wrap=True, width=5)
    tbl.add_column("Retry",  no_wrap=True, width=5)
    tbl.add_column("RSSI",   no_wrap=True, width=5)
    tbl.add_column("Last",   no_wrap=True, width=8)
    tbl.add_column("",       no_wrap=True, width=3)
    max_rows = max(5, console.height - 20)
    for c in clients[:max_rows]:
        rnd_t  = Text("🎲" if c.randomized else " ", style="yellow" if c.randomized else "grey58")
        new_t  = Text("NEW", style="bold bright_yellow") if c.is_new else Text("")
        rssi_t = Text(str(c.last_rssi) if c.last_rssi != -999 else "—",
                      style="bright_green" if c.last_rssi != -999 and c.last_rssi >= -70
                      else ("yellow" if c.last_rssi != -999 else "grey58"))
        tbl.add_row(c.mac, c.vendor[:11], rnd_t,
                    str(len(c.probed_ssids)),
                    str(c.eapol_count) if c.eapol_count else "—",
                    str(c.data_frames) if c.data_frames else "—",
                    str(c.retry_frames) if c.retry_frames else "—",
                    rssi_t,
                    time_ago(c.last_seen), new_t)
        c.is_new = False
    return Panel(tbl,
                 title="[bold magenta]👾 Device Registry[/]  "
                       "[grey66]Rand=randomised  Data/Retry=frame counts  RSSI=last seen[/]",
                 border_style="magenta", box=box.ROUNDED)

def _timeline_panel() -> Panel:
    with STATE.lock:
        events = list(STATE.events)[:28]
    txt = Text(overflow="fold")
    for e in events:
        sty  = KIND_STYLE.get(e.kind, "white")
        icon = KIND_ICON.get(e.kind, "·")
        txt.append(f"  {e.ts.strftime('%H:%M:%S')} ", style="grey66")
        txt.append(f"{icon} ", style=sty)
        txt.append(f"{e.kind:<11}", style=sty)
        txt.append(f" {e.mac:<17}  ", style="grey66")
        txt.append(f"{e.detail[:52]}\n", style="white")
    return Panel(txt,
                 title="[bold blue]📻 Live Event Stream[/]  [grey66]♥=heartbeat  detach: Ctrl-B D[/]",
                 border_style="blue", box=box.ROUNDED)

def _connected_clients_panel() -> Panel:
    with STATE.lock:
        clients = list(STATE.connected_clients_cache)
        ts = STATE.connected_clients_ts
    age = int(time.time() - ts) if ts else -1
    age_str = f"  [grey66]{age}s ago[/]" if age >= 0 else "  [grey66]pending scan…[/]"
    if not clients:
        msg = "[italic]No clients yet[/]\n[dim]Waiting for arp-scan inventory…[/]"
        return Panel(msg,
                     title=f"[bold green]🔗 Connected Clients[/]{age_str}",
                     border_style="green", box=box.ROUNDED)
    tbl = Table(box=box.SIMPLE_HEAD, expand=True, header_style="bold green", padding=(0, 0))
    tbl.add_column("IP Address", no_wrap=True, width=15)
    tbl.add_column("MAC",        no_wrap=True, width=17, max_width=17)
    tbl.add_column("Vendor",     no_wrap=True, width=14, max_width=14)
    for ip, mac, vendor in clients[:20]:
        tbl.add_row(ip, mac, vendor)
    return Panel(tbl,
                 title=f"[bold green]🔗 Connected Clients[/]{age_str}",
                 border_style="green", box=box.ROUNDED)

def build_layout() -> Layout:
    layout = Layout()
    layout.split_column(
        Layout(name="status", size=3),
        Layout(name="top",    ratio=5),
        Layout(name="bottom", ratio=4),
    )
    layout["top"].split_row(
        Layout(name="aps",    ratio=3),
        Layout(name="alerts", ratio=3),
        Layout(name="stats",  ratio=2),
    )
    layout["bottom"].split_row(
        Layout(name="clients",   ratio=3),
        Layout(name="timeline",  ratio=3),
        Layout(name="connected", ratio=2),
    )
    return layout

def render_dashboard(layout: Layout) -> None:
    layout["status"].update(_status_bar())
    layout["aps"].update(_ap_table())
    layout["alerts"].update(_alert_panel())
    layout["stats"].update(_stats_panel())
    layout["clients"].update(_client_table())
    layout["timeline"].update(_timeline_panel())
    layout["connected"].update(_connected_clients_panel())

# ---------- Setup & main ----------
def setup_monitor_mode() -> bool:
    iface = CFG["monitor_iface"]
    console.print(f"[cyan]Setting {iface} -> monitor mode …[/]")
    try:
        subprocess.run(["nmcli", "device", "set", iface, "managed", "no"],
                       check=False, capture_output=True)
        subprocess.run(["ip", "link", "set", iface, "down"],           check=True, capture_output=True)
        subprocess.run(["iw", "dev", iface, "set", "type", "monitor"], check=True, capture_output=True)
        subprocess.run(["ip", "link", "set", iface, "up"],             check=True, capture_output=True)
        console.print(f"[bright_green]✓ {iface} in monitor mode[/]")
        return True
    except subprocess.CalledProcessError as e:
        console.print(f"[bold red]✗ {e}[/]"); return False

def check_deps() -> bool:
    ok = True
    for tool in ("tshark", "tcpdump", "iw", "nmcli"):
        if subprocess.run(["which", tool], capture_output=True).returncode != 0:
            console.print(f"[red]Missing: {tool}[/]"); ok = False
    return ok

def ensure_wlan0_connected() -> bool:
    iface = CFG["scan_iface"]; ssid = CFG["home_ssid"]; pwd = CFG["home_password"]
    try:
        if ssid in subprocess.check_output(
                ["iw", "dev", iface, "link"], text=True, stderr=subprocess.DEVNULL):
            console.print(f"[green]✓ {iface} already connected to '{ssid}'[/]")
            return True
    except:
        pass
    console.print(f"[yellow]⚠ {iface} not connected to '{ssid}'. Attempting to connect...[/]")
    try:
        subprocess.run(["nmcli", "device", "set", iface, "managed", "yes"], capture_output=True)
        subprocess.run(["nmcli", "device", "wifi", "connect", ssid, "password", pwd, "ifname", iface],
                       check=True, capture_output=True, timeout=30)
        console.print(f"[bright_green]✓ {iface} connected to '{ssid}'[/]")
        return True
    except subprocess.CalledProcessError as e:
        console.print(f"[bold red]✗ Failed to connect {iface} to '{ssid}': {e}[/]")
        return False

def rename_tmux_window() -> None:
    if os.environ.get("TMUX"):
        subprocess.run(["tmux", "rename-window", "WIDS"], capture_output=True)

def shutdown(sig=None, frame=None) -> None:
    STATE.running = False
    if ML:
        ML.stop()
    with _PROCS_LOCK:
        for p, _ in _PROCESSES:
            try:
                p.terminate()
            except:
                pass
    console.print("\n[yellow]Shutting down …[/]")
    try:
        export_snapshot("shutdown")
    except:
        pass
    sys.exit(0)

def main() -> None:
    global LOG, ML, SESSION_DIR

    _load_system_oui()
    if os.geteuid() != 0:
        sys.exit("Run as root: sudo python3 wids.py")
    if not check_deps():
        sys.exit(1)

    session_ts = datetime.now().strftime("%Y-%m-%dT%H-%M-%S")
    SESSION_DIR = CFG["base_log_dir"] / f"session_{session_ts}"
    SESSION_DIR.mkdir(parents=True, exist_ok=True)
    CFG["base_log_dir"].parent.mkdir(parents=True, exist_ok=True)

    LOG = AlertLog(SESSION_DIR / "alerts.log")
    ML  = MLLogger(SESSION_DIR, CFG["ml_flush_sec"], CFG["ml_max_file_mb"])

    signal.signal(signal.SIGINT,  shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    console.print(Rule("[bold cyan]WIDS v3 — Wi-Fi Intrusion Detection[/]"))
    console.print(f"[dim]Session:[/] [bold]{SESSION_DIR}[/]")
    console.print(f"[dim]monitor:[/] [bold]{CFG['monitor_iface']}[/]  "
                  f"[dim]scan:[/] [bold]{CFG['scan_iface']}[/]  "
                  f"[dim]SSID:[/] [bold]{CFG['home_ssid']}[/]")

    rename_tmux_window()
    if not setup_monitor_mode():
        shutdown()
    if not ensure_wlan0_connected():
        console.print("[yellow]Warning: wlan0 not connected – client list will be empty[/]")

    for target, name in [
        (mgmt_reader_thread,       "mgmt"),
        (data_reader_thread,       "data"),
        (eapol_reader_thread,      "eapol"),
        (scanner_thread,           "scan"),
        (heartbeat_thread,         "beat"),
        (watchdog_thread,          "watchdog"),
        (export_scheduler_thread,  "export"),
        (update_all_aps_from_nmcli,"nmcli"),
        (lan_monitor_thread,       "lan"),
        (client_inventory_thread,  "client_inv"),
    ]:
        threading.Thread(target=target, daemon=True, name=name).start()

    time.sleep(2)
    layout = build_layout()
    with Live(layout, console=console, refresh_per_second=1, screen=True):
        while STATE.running:
            try:
                render_dashboard(layout)
            except:
                pass
            time.sleep(CFG["dashboard_refresh"])

if __name__ == "__main__":
    if "TMUX" not in os.environ:
        subprocess.run(["tmux", "kill-session", "-t", "wids"], capture_output=True)
        subprocess.run(["tmux", "new-session", "-d", "-s", "wids", sys.executable, __file__],
                       check=True)
        os.execvp("tmux", ["tmux", "attach-session", "-t", "wids"])
    else:
        main()
