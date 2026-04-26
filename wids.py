#!/usr/bin/env python3
"""
WIDS — Wi-Fi Intrusion Detection System for Raspberry Pi
Uses tcpdump for management frames and iw station dump for connected clients.
"""
from __future__ import annotations

import csv
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
from typing import Dict, List, Set, Tuple

# rich imports
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
    subprocess.run([sys.executable, "-m", "pip", "install", "rich", "--break-system-packages"], check=False)
    from rich import box
    from rich.console import Console
    from rich.layout import Layout
    from rich.live import Live
    from rich.panel import Panel
    from rich.rule import Rule
    from rich.table import Table
    from rich.text import Text

console = Console()

# ============================
#  CONFIG
# ============================
CFG: dict = {
    "monitor_iface": os.environ.get("WIDS_MONITOR_IFACE", "wlan1"),  # use the wifi interface that support monitor mode
    "scan_iface": os.environ.get("WIDS_SCAN_IFACE", "wlan0"),  # can be any wifi interface, even the RPi's stock iface is ok
    "home_ssid": os.environ.get("WIDS_HOME_SSID", "Hell's WiFi"),
    "home_password": os.environ.get("WIDS_HOME_PASSWORD", "rectum_obliterator_666"),
    "log_dir": Path("/var/log/wids"),
    "log_file": Path("/var/log/wids/wids.log"),
    "deauth_threshold": 5,
    "probe_threshold": 20,
    "auth_fail_threshold": 5,
    "window_sec": 10,
    "rssi_jump_db": 12,
    "beacon_int_delta": 5,
    "channel_check_interval": 300,
    "dashboard_refresh": 1.0,
    "heartbeat_interval": 30,
    "export_interval_min": 30,
    "max_alerts": 400,
    "max_events": 600,
    "fps_window_sec": 10,
    "arp_scan_threshold": 20,
    "arp_scan_window": 5,
    "port_scan_threshold": 15,
    "port_scan_window": 10,
    "dhcp_starve_threshold": 8,
    "dhcp_starve_window": 10,
    # NEW: handshake timeout threshold (seconds)
    "handshake_timeout_sec": 5,
}

# ============================
#  OUI LOOKUP
# ============================
_OUI: Dict[str, str] = {
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
    "AC:87:A3": "Apple", "F8:FF:C2": "Apple", "3C:15:C2": "Apple",
    "00:1C:BF": "Intel", "10:02:B5": "Intel", "34:DE:1A": "Intel",
    "60:F6:77": "Qualcomm", "00:17:C9": "Qualcomm",
    "00:26:82": "TP-Link", "50:C7:BF": "TP-Link", "E8:65:D4": "TP-Link",
    "00:18:4D": "Netgear", "A0:21:B7": "Netgear", "28:C6:8E": "Netgear",
    "DC:9F:DB": "Ubiquiti", "24:A4:3C": "Ubiquiti", "FC:EC:DA": "Ubiquiti",
    "4C:1F:CC": "Huawei", "28:6E:D4": "Huawei",
    "28:D2:44": "ASUS", "04:D4:C4": "ASUS",
    "00:1C:C0": "D-Link", "1C:BD:B9": "D-Link",
    "50:32:37": "Samsung", "FC:00:12": "Samsung",
    "54:60:09": "Google", "F4:F5:D8": "Google",
    "00:50:F2": "Microsoft", "00:15:5D": "MS/HyperV",
    "00:0C:E7": "Cisco", "00:23:69": "Cisco",
}

def _load_system_oui() -> None:
    paths = [
        "/usr/share/ieee-data/oui.txt",
        "/usr/share/wireshark/manuf",
        "/usr/share/arp-scan/ieee-oui.txt",
    ]
    for path in paths:
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
                            if "-" in oui:
                                oui = oui.replace("-", ":")
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

# ============================
#  DATA CLASSES
# ============================
@dataclass
class AlertRecord:
    ts: datetime; severity: str; category: str; message: str; bssid: str = ""; mac: str = ""

@dataclass
class EventRecord:
    ts: datetime; kind: str; mac: str; detail: str

@dataclass
class APRecord:
    bssid: str; ssid: str = ""; channel: int = 0; rssi: int = -999; rssi_prev: int = -999
    beacon_interval: int = 0; security: str = "?"; security_prev: str = "?"; mfpc: bool = False
    mfpr: bool = False; ibss: bool = False; hidden: bool = False; vendor: str = ""
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    frame_count: int = 0; reputation: int = 100; is_home: bool = False
    # NEW: flag for WPA3 transition mode (advertises both WPA2 and WPA3)
    transition_mode: bool = False

@dataclass
class ClientRecord:
    mac: str; vendor: str = ""; randomized: bool = False
    probed_ssids: Set[str] = field(default_factory=set)
    associated_bssid: str = ""
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    auth_failures: int = 0; frame_count: int = 0; eapol_count: int = 0; is_new: bool = True

# ============================
#  SHARED STATE
# ============================
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
        self._pulse_iter = itertools.cycle("◐◓◑◒")
        self._pulse_char = "◐"
        self._pulse_active = False
        self.last_export = time.time()
        self.running = True
        # LAN threat detection state
        self.arp_request_times: Dict[str, List[float]] = defaultdict(list)
        self.ip_mac_table: Dict[str, str] = {}
        self.port_scan_times: Dict[str, List[Tuple[float, int]]] = defaultdict(list)
        self.dhcp_discover_times: Dict[str, List[float]] = defaultdict(list)
        # Cache own IPs to avoid self-alerting
        try:
            self.own_ips: set = set(subprocess.check_output(
                ["hostname", "-I"], text=True, stderr=subprocess.DEVNULL).split())
        except Exception:
            self.own_ips = set()
        # NEW: handshake state tracking (bssid, sta_mac) -> {last_msg, last_time, start_time}
        self.hs_states: Dict[Tuple[str, str], dict] = {}
        # NEW: prevent duplicate transition‐mode alerts per BSSID
        self.transition_alerted_bssids: Set[str] = set()

    def tick(self) -> None:
        now = time.time()
        self.total_frames += 1
        self.fps_ts.append(now)
        self._pulse_char = next(self._pulse_iter)
        self._pulse_active = True

    def fps(self) -> float:
        cutoff = time.time() - CFG["fps_window_sec"]
        return sum(1 for t in self.fps_ts if t >= cutoff) / CFG["fps_window_sec"]

    def add_alert(self, severity: str, category: str, message: str, bssid: str = "", mac: str = "") -> None:
        a = AlertRecord(ts=datetime.now(), severity=severity, category=category,
                        message=message, bssid=bssid, mac=mac)
        with self.lock:
            self.alerts.appendleft(a)
            self.alert_counts[category] += 1
        self._write_log(a)

    def add_event(self, kind: str, mac: str, detail: str) -> None:
        with self.lock:
            self.events.appendleft(EventRecord(ts=datetime.now(), kind=kind, mac=mac, detail=detail))

    def add_conn(self, kind: str, mac: str, bssid: str) -> None:
        with self.lock:
            self.conn_log.appendleft((datetime.now(), kind, mac, bssid))

    def _write_log(self, a: AlertRecord) -> None:
        try:
            CFG["log_dir"].mkdir(parents=True, exist_ok=True)
            with open(CFG["log_file"], "a") as fh:
                fh.write(f'{a.ts.strftime("%Y-%m-%d %H:%M:%S")} [{a.severity}] [{a.category}] {a.message}\n')
        except:
            pass

    def get_or_create_ap(self, bssid: str) -> APRecord:
        with self.lock:
            if bssid not in self.aps:
                ap = APRecord(bssid=bssid, vendor=oui_lookup(bssid))
                self.aps[bssid] = ap
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

# ============================
#  UI HELPERS
# ============================
def time_ago(dt: datetime) -> str:
    secs = int((datetime.now() - dt).total_seconds())
    if secs < 5: return "just now"
    if secs < 60: return f"{secs}s ago"
    if secs < 3600: return f"{secs // 60}m ago"
    return f"{secs // 3600}h ago"

def rssi_bar(rssi: int) -> Text:
    if rssi == -999: return Text("─────  ?dBm", style="grey66")
    pct = max(0.0, min(1.0, (rssi + 95) / 65))
    filled = int(pct * 5)
    bar = "█" * filled + "░" * (5 - filled)
    if rssi >= -60: style = "bright_green"
    elif rssi >= -75: style = "yellow"
    else: style = "red"
    t = Text()
    t.append(bar, style=style)
    t.append(f" {rssi:>4}dBm", style="grey66")
    return t

def rep_text(rep: int) -> Text:
    if rep >= 80: style, icon = "bright_green", "●"
    elif rep >= 50: style, icon = "yellow", "●"
    else: style, icon = "bold red", "●"
    return Text(f"{icon} {rep:>3}", style=style)

def mini_bar(count: int, max_count: int, width: int = 8) -> str:
    if max_count == 0: return "░" * width
    return "█" * int((count / max_count) * width) + "░" * (width - int((count / max_count) * width))

# ============================
#  MANAGEMENT FRAME PARSER
# ============================
def parse_tcpdump_line(line: str) -> dict | None:
    line = line.strip()
    if not line: return None
    bssid = ""; sa = ""; da = ""; ssid = ""
    bssid_match = re.search(r'BSSID:([0-9A-Fa-f:]{17})', line)
    sa_match    = re.search(r'SA:([0-9A-Fa-f:]{17})', line)
    da_match    = re.search(r'DA:([0-9A-Fa-f:]{17})', line)
    if bssid_match: bssid = bssid_match.group(1).upper()
    if sa_match:    sa    = sa_match.group(1).upper()
    if da_match:    da    = da_match.group(1).upper()
    ssid_match = re.search(r'SSID:"([^"]*)"', line)
    if ssid_match: ssid = ssid_match.group(1)
    subtype = None
    if "Beacon" in line:                subtype = 8
    elif "Probe Request" in line:       subtype = 4
    elif "Deauthentication" in line:    subtype = 12
    elif "Disassociation" in line:      subtype = 10
    elif "Authentication" in line:      subtype = 11
    elif "Association Request" in line: subtype = 0
    elif "Association Response" in line:subtype = 1
    elif "Reassociation Request" in line:  subtype = 2
    elif "Reassociation Response" in line: subtype = 3
    else: return None
    rssi_match = re.search(r'signal ([-0-9]+)dBm', line)
    rssi = int(rssi_match.group(1)) if rssi_match else -999
    return {"subtype": subtype, "bssid": bssid, "sa": sa, "da": da,
            "ssid": ssid, "rssi": rssi, "channel": 0}

def detect_beacon(f: dict) -> None:
    bssid = f.get("bssid", ""); ssid = f.get("ssid", "").strip(); rssi = f.get("rssi", -999)
    if not bssid: return
    STATE.frame_type_counts["beacon"] += 1
    with STATE.lock:
        ap = STATE.get_or_create_ap(bssid)
        ap.last_seen = datetime.now()
        ap.frame_count += 1
        if ssid:
            ap.ssid = ssid
            ap.hidden = False
        elif not ap.ssid:
            ap.ssid = ""
            ap.hidden = True
        if rssi != -999:
            ap.rssi = rssi

def detect_deauth(f: dict) -> None:
    bssid = f.get("bssid", ""); sa = f.get("sa", ""); da = f.get("da", ""); now = time.time()
    if not bssid: return
    STATE.frame_type_counts["deauth"] += 1
    STATE.add_event("deauth", sa, f"to {da}  via {bssid}")
    STATE.add_conn("deauth", sa, bssid)
    with STATE.lock:
        lst = STATE.deauth_times[bssid]
        lst.append(now); lst = STATE.prune(lst); STATE.deauth_times[bssid] = lst
        if len(lst) == CFG["deauth_threshold"]:
            STATE.add_alert("CRITICAL", "DEAUTH_FLOOD",
                f"Deauth flood: {len(lst)} frames/{CFG['window_sec']}s BSSID={bssid} SA={sa} DA={da}",
                bssid=bssid, mac=sa)
            if bssid in STATE.aps:
                STATE.aps[bssid].reputation = max(0, STATE.aps[bssid].reputation - 35)

def detect_disassoc(f: dict) -> None:
    bssid = f.get("bssid", ""); sa = f.get("sa", ""); now = time.time()
    if not bssid: return
    STATE.frame_type_counts["disassoc"] += 1
    STATE.add_event("disassoc", sa, f"from {bssid}")
    STATE.add_conn("disassoc", sa, bssid)
    with STATE.lock:
        lst = STATE.disassoc_times[bssid]
        lst.append(now); lst = STATE.prune(lst); STATE.disassoc_times[bssid] = lst
        if len(lst) == CFG["deauth_threshold"]:
            STATE.add_alert("ALERT", "DISASSOC_FLOOD",
                f"Disassoc flood: {len(lst)}/{CFG['window_sec']}s BSSID={bssid}",
                bssid=bssid, mac=sa)

def detect_probe_req(f: dict) -> None:
    mac = f.get("sa", ""); ssid = f.get("ssid", "").strip(); now = time.time()
    if not mac: return
    STATE.frame_type_counts["probe"] += 1
    with STATE.lock:
        client = STATE.get_or_create_client(mac)
        client.last_seen = datetime.now(); client.frame_count += 1
        if ssid: client.probed_ssids.add(ssid)
        rand_tag = " [RAND]" if client.randomized else ""
        STATE.add_event("probe", mac, f"-> '{ssid or '<wildcard>'}'{rand_tag} [{client.vendor}]")
        lst = STATE.probe_times[mac]
        if ssid: lst.append((now, ssid))
        cutoff = now - CFG["window_sec"]
        lst = [(t, s) for t, s in lst if t >= cutoff]
        STATE.probe_times[mac] = lst
        unique = {s for _, s in lst}
        if len(unique) == CFG["probe_threshold"]:
            STATE.add_alert("WARN", "PROBE_STORM",
                f"Probe storm: {mac} hit {len(unique)} SSIDs in {CFG['window_sec']}s", mac=mac)

def detect_auth(f: dict) -> None:
    bssid = f.get("bssid", ""); sa = f.get("sa", "")
    if not sa: return
    STATE.frame_type_counts["auth"] += 1
    STATE.add_event("auth_ok", sa, f"-> {bssid}")

def detect_assoc(f: dict) -> None:
    bssid = f.get("bssid", ""); sa = f.get("sa", "")
    if not sa: return
    STATE.frame_type_counts["assoc"] += 1
    with STATE.lock:
        if sa in STATE.aps: return
        c = STATE.get_or_create_client(sa)
        c.last_seen = datetime.now(); c.frame_count += 1
        if bssid:
            c.associated_bssid = bssid
            STATE.add_event("assoc", sa, f"-> {bssid}")
            STATE.add_conn("assoc", sa, bssid)

# ============================
#  EAPOL / HANDSHAKE DETECTION (ENRICHED)
# ============================
def detect_eapol(f: dict) -> None:
    """
    Receives a dict with keys:
        sa, da, eapol_key_type (string), time_epoch (string)
    """
    sa = f.get("sa", ""); da = f.get("da", ""); key_type_str = f.get("eapol_key_type", "")
    ts_str = f.get("time_epoch", "")

    # Legacy event for display
    STATE.frame_type_counts["eapol"] += 1
    STATE.tick()
    detail = f"-> {da}" + (f"  key_type={key_type_str}" if key_type_str else "")
    STATE.add_event("eapol", sa, detail)

    with STATE.lock:
        if sa in STATE.aps: return          # don't track AP->AP or AP self
        c = STATE.get_or_create_client(sa)
        c.eapol_count += 1
        c.last_seen = datetime.now()

        # Original alert on repeated handshakes (EAPOL storm)
        if c.eapol_count == 1:
            STATE.add_alert("INFO", "EAPOL",
                f"WPA handshake: {sa} seen first time this session", mac=sa)
        elif c.eapol_count == 8:
            STATE.add_alert("WARN", "EAPOL_STORM",
                f"Repeated handshakes from {sa} ({c.eapol_count} frames) — possible deauth-reconnect loop",
                mac=sa)

    # ----------------- NEW: handshake message tracking -----------------
    try:
        key_type = int(key_type_str) if key_type_str else None
    except ValueError:
        key_type = None

    # Only process 4‑way handshake messages (EAPOL‑Key)
    if key_type not in (2, 3, 4, 5):
        return

    msg_map = {2: "M1", 3: "M2", 4: "M3", 5: "M4"}
    msg_type = msg_map.get(key_type, "?")

    # Determine AP BSSID: sa or da must be a known AP
    bssid = None
    if sa in STATE.aps:
        bssid = sa
        sta_mac = da
    elif da in STATE.aps:
        bssid = da
        sta_mac = sa
    else:
        return              # neither endpoint is a known AP

    if not sta_mac:
        return

    try:
        ts = float(ts_str)
    except (ValueError, TypeError):
        ts = time.time()

    with STATE.lock:
        hs_key = (bssid, sta_mac)
        state = STATE.hs_states.get(hs_key)

        if msg_type == "M1":
            # Start of new handshake – reset previous state silently
            STATE.hs_states[hs_key] = {
                "last_msg": "M1",
                "last_time": ts,
                "start_time": ts,
            }

        elif state is None:
            # Stray message without a preceding M1
            if msg_type != "M1":  # just in case
                STATE.add_alert("WARN", "EAPOL_ANOMALY",
                    f"Stray {msg_type} from {sa} to {da} without M1 (bssid={bssid})",
                    bssid=bssid, mac=sta_mac)

        else:
            expected = {"M1": "M2", "M2": "M3", "M3": "M4"}.get(state["last_msg"])
            if msg_type != expected:
                STATE.add_alert("WARN", "EAPOL_SEQUENCE",
                    f"Unexpected {msg_type} after {state['last_msg']} for STA {sta_mac} (bssid={bssid})",
                    bssid=bssid, mac=sta_mac)
                # reset state on sequence error
                del STATE.hs_states[hs_key]
                return

            # Check timeout only on completion (M4)
            if msg_type == "M4" and state is not None:
                duration = ts - state.get("start_time", ts)
                if duration > CFG["handshake_timeout_sec"]:
                    STATE.add_alert("WARN", "EAPOL_TIMEOUT",
                        f"Handshake for {sta_mac} took {duration:.1f}s > {CFG['handshake_timeout_sec']}s",
                        bssid=bssid, mac=sta_mac)
                # Cleanup after completion
                del STATE.hs_states[hs_key]
            else:
                # Update state for next expected message
                state["last_msg"] = msg_type
                state["last_time"] = ts

    # Transition mode awareness (alert only if home AP is in transition mode)
    if bssid and bssid in STATE.aps:
        ap = STATE.aps[bssid]
        if ap.transition_mode and ap.is_home:
            # We already raise a dedicated alert when transition mode is first detected,
            # so here we don't spam per handshake.
            pass

# ============================
#  LAN THREAT DETECTION
# ============================
LAN_CATEGORIES = {"ARP_SCAN", "ARP_POISON", "PORT_SCAN", "DHCP_STARVE",
                  "LAN_READER_ERR", "LAN_RESTART", "LAN_SKIP"}

def parse_lan_line(line: str) -> dict | None:
    line = line.strip()
    if not line: return None
    r: dict = {}
    if "ARP" in line:
        if "who-has" in line:
            r["type"] = "arp_request"
            m = re.search(r'who-has (\d+\.\d+\.\d+\.\d+) tell (\d+\.\d+\.\d+\.\d+)', line)
            if m: r["target_ip"] = m.group(1); r["sender_ip"] = m.group(2)
            m2 = re.search(r'^[\d:.]+\s+([0-9a-f:]{17})\s+>', line)
            if m2: r["sender_mac"] = m2.group(1).upper()
        elif "is-at" in line:
            r["type"] = "arp_reply"
            m = re.search(r'(\d+\.\d+\.\d+\.\d+) is-at ([0-9a-f:]{17})', line)
            if m: r["ip"] = m.group(1); r["mac"] = m.group(2).upper()
        else:
            return None
    elif "Flags [S]" in line and "Flags [S.]" not in line:
        r["type"] = "tcp_syn"
        m = re.search(r'IP (\d+\.\d+\.\d+\.\d+)\.(\d+) > (\d+\.\d+\.\d+\.\d+)\.(\d+)', line)
        if not m: return None
        r["src_ip"] = m.group(1); r["src_port"] = int(m.group(2))
        r["dst_ip"] = m.group(3); r["dst_port"] = int(m.group(4))
    elif "BOOTP/DHCP" in line and "Request" in line:
        r["type"] = "dhcp_discover"
        m = re.search(r'Request from ([0-9a-f:]{17})', line)
        if m:
            r["client_mac"] = m.group(1).upper()
        else:
            m2 = re.search(r'^[\d:.]+\s+([0-9a-f:]{17})\s+>', line)
            if m2: r["client_mac"] = m2.group(1).upper()
    else:
        return None
    return r if r.get("type") else None

def detect_arp_scan(r: dict) -> None:
    sender_ip = r.get("sender_ip", "")
    if not sender_ip: return
    if sender_ip in STATE.own_ips: return
    now = time.time()
    with STATE.lock:
        lst = STATE.arp_request_times[sender_ip]
        lst.append(now)
        cutoff = now - CFG["arp_scan_window"]
        lst = [t for t in lst if t >= cutoff]
        STATE.arp_request_times[sender_ip] = lst
        if len(lst) == CFG["arp_scan_threshold"]:
            STATE.add_alert("WARN", "ARP_SCAN",
                f"{sender_ip} sent {len(lst)} ARP requests in {CFG['arp_scan_window']}s — possible recon")

def detect_arp_poison(r: dict) -> None:
    ip = r.get("ip", ""); mac = r.get("mac", "")
    if not ip or not mac: return
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
    if not src_ip or dst_port is None: return
    if src_ip in STATE.own_ips: return
    now = time.time()
    with STATE.lock:
        lst = STATE.port_scan_times[src_ip]
        lst.append((now, dst_port))
        cutoff = now - CFG["port_scan_window"]
        lst = [(t, p) for t, p in lst if t >= cutoff]
        STATE.port_scan_times[src_ip] = lst
        unique = {p for _, p in lst}
        if len(unique) == CFG["port_scan_threshold"]:
            STATE.add_alert("ALERT", "PORT_SCAN",
                f"{src_ip} hit {len(unique)} unique ports in {CFG['port_scan_window']}s")

def detect_dhcp_starve(r: dict) -> None:
    mac = r.get("client_mac", "")
    if not mac: return
    now = time.time()
    cutoff = now - CFG["dhcp_starve_window"]
    with STATE.lock:
        STATE.dhcp_discover_times[mac].append(now)
        active = {m for m, times in STATE.dhcp_discover_times.items()
                  if any(t >= cutoff for t in times)}
        if len(active) == CFG["dhcp_starve_threshold"]:
            STATE.add_alert("CRITICAL", "DHCP_STARVE",
                f"{len(active)} unique MACs sending DHCP DISCOVER in {CFG['dhcp_starve_window']}s — starvation attack?")

# ============================
#  CAPTURE THREADS
# ============================
_PROCESSES: List[Tuple[subprocess.Popen, str]] = []
_PROCS_LOCK = threading.Lock()

def mgmt_reader_thread() -> None:
    while STATE.running:
        debug_log = open(CFG["log_dir"] / "tcpdump_mgmt.log", "a")
        cmd = ["tcpdump", "-i", CFG["monitor_iface"], "-e", "-n", "-l"]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=debug_log, text=True)
        with _PROCS_LOCK:
            _PROCESSES.append((proc, "mgmt"))
        try:
            for line in proc.stdout:
                if not STATE.running: break
                line = line.strip()
                if not line: continue
                parsed = parse_tcpdump_line(line)
                if not parsed: continue
                subtype = parsed.get("subtype")
                STATE.tick()
                if subtype == 8:          detect_beacon(parsed)
                elif subtype == 12:       detect_deauth(parsed)
                elif subtype == 10:       detect_disassoc(parsed)
                elif subtype == 4:        detect_probe_req(parsed)
                elif subtype == 11:       detect_auth(parsed)
                elif subtype in (0,1,2,3):detect_assoc(parsed)
        except Exception as e:
            STATE.add_alert("ALERT", "MGMT_READER_ERR", f"tcpdump reader exception: {e}")
        finally:
            debug_log.close()
            try: proc.terminate()
            except: pass
        if STATE.running:
            time.sleep(5)

def eapol_reader_thread() -> None:
    """Enhanced EAPOL reader: captures timestamp, SA, DA, keydes.type"""
    while STATE.running:
        debug_log = open(CFG["log_dir"] / "tshark_eapol.log", "a")
        cmd = ["tshark", "-i", CFG["monitor_iface"], "-l", "-n", "-T", "fields",
               "-e", "frame.time_epoch",
               "-e", "wlan.sa",
               "-e", "wlan.da",
               "-e", "eapol.keydes.type",
               "-Y", "eapol"]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=debug_log, text=True)
        with _PROCS_LOCK:
            _PROCESSES.append((proc, "eapol"))
        try:
            for line in proc.stdout:
                if not STATE.running: break
                line = line.strip()
                if not line: continue
                parts = line.split("|")
                if len(parts) < 4:
                    continue
                detect_eapol({
                    "time_epoch": parts[0].strip(),
                    "sa":           parts[1].strip(),
                    "da":           parts[2].strip(),
                    "eapol_key_type": parts[3].strip(),
                })
        except Exception as e:
            debug_log.write(f"[EXCEPTION] {e}\n")
        finally:
            debug_log.close()
            try: proc.terminate()
            except: pass
        if STATE.running:
            time.sleep(5)

def pmf_reader_thread() -> None:
    while STATE.running:
        debug_log = open(CFG["log_dir"] / "tshark_pmf.log", "a")
        cmd = ["tshark", "-i", CFG["monitor_iface"], "-l", "-n",
               "-T", "fields",
               "-e", "wlan.bssid",
               "-e", "wlan.rsn.capabilities.mfpc",
               "-e", "wlan.rsn.capabilities.mfpr",
               "-Y", "wlan.fc.type_subtype == 8"]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=debug_log, text=True)
        with _PROCS_LOCK:
            _PROCESSES.append((proc, "pmf"))
        try:
            for line in proc.stdout:
                if not STATE.running: break
                line = line.strip()
                if not line: continue
                parts = line.split("\t")
                if len(parts) < 2: continue
                bssid = parts[0].strip().upper()
                mfpc  = parts[1].strip() in ("1", "True")
                mfpr  = parts[2].strip() in ("1", "True") if len(parts) > 2 else False
                if not bssid: continue
                with STATE.lock:
                    ap = STATE.get_or_create_ap(bssid)
                    ap.mfpc = mfpc
                    ap.mfpr = mfpr
        except Exception as e:
            debug_log.write(f"[EXCEPTION] {e}\n")
        finally:
            debug_log.close()
            try: proc.terminate()
            except: pass
        if STATE.running:
            time.sleep(5)

def lan_monitor_thread() -> None:
    while STATE.running:
        iface = CFG["scan_iface"]
        try:
            out = subprocess.check_output(["iw", "dev", iface, "info"],
                                          text=True, stderr=subprocess.DEVNULL)
            if "monitor" in out:
                STATE.add_alert("WARN", "LAN_SKIP",
                    f"{iface} is in monitor mode — LAN monitor skipping, retry in 30s")
                time.sleep(30)
                continue
        except Exception:
            time.sleep(10)
            continue

        debug_log = open(CFG["log_dir"] / "tcpdump_lan.log", "a")
        cmd = ["tcpdump", "-i", iface, "-n", "-e", "-l",
               "arp or (udp port 67) or "
               "(tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0)"]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=debug_log, text=True)
        with _PROCS_LOCK:
            _PROCESSES.append((proc, "lan"))
        try:
            for line in proc.stdout:
                if not STATE.running: break
                line = line.strip()
                if not line: continue
                r = parse_lan_line(line)
                if not r: continue
                t = r.get("type")
                if t == "arp_request":    detect_arp_scan(r)
                elif t == "arp_reply":    detect_arp_poison(r)
                elif t == "tcp_syn":      detect_port_scan(r)
                elif t == "dhcp_discover":detect_dhcp_starve(r)
        except Exception as e:
            STATE.add_alert("ALERT", "LAN_READER_ERR", f"LAN monitor exception: {e}")
        finally:
            debug_log.close()
            try: proc.terminate()
            except: pass
        if STATE.running:
            STATE.add_alert("ALERT", "LAN_RESTART", "LAN monitor died – restarting in 5s")
            time.sleep(5)

# ============================
#  SCANNER, WATCHDOG, HEARTBEAT, EXPORT
# ============================
def _nmcli_scan() -> Tuple[str, int]:
    try:
        out = subprocess.check_output(
            ["nmcli", "-t", "-f", "BSSID,CHAN,SSID", "dev", "wifi", "list",
             "ifname", CFG["scan_iface"]],
            stderr=subprocess.DEVNULL, text=True, timeout=20)
        for raw in out.splitlines():
            esc = raw.replace("\\:", "\x00")
            parts = esc.split(":", 2)
            if len(parts) < 3: continue
            bssid = parts[0].replace("\x00", ":").upper()
            try: chan = int(parts[1])
            except: continue
            ssid = parts[2].replace("\x00", ":")
            if ssid == CFG["home_ssid"]: return bssid, chan
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
                if not ap.ssid: ap.ssid = CFG["home_ssid"]
            if not prev_bssid:
                subprocess.run(["iw", "dev", CFG["monitor_iface"], "set", "channel", str(chan)],
                               capture_output=True)
                STATE.add_alert("INFO", "INIT",
                    f"Home AP '{CFG['home_ssid']}': BSSID={bssid} ch={chan}")
            prev_bssid, prev_channel = bssid, chan
        else:
            if prev_bssid:
                STATE.add_alert("ALERT", "AP_LOST",
                    f"Home AP no longer visible on {CFG['scan_iface']}")
        time.sleep(CFG["channel_check_interval"])

def watchdog_thread() -> None:
    time.sleep(15)
    while STATE.running:
        time.sleep(30)
        with _PROCS_LOCK:
            _PROCESSES[:] = [(p, n) for p, n in _PROCESSES if p.poll() is None]

        n_mgmt = (STATE.frame_type_counts.get("beacon", 0) +
                  STATE.frame_type_counts.get("probe", 0) +
                  STATE.frame_type_counts.get("deauth", 0))
        if n_mgmt == 0 and STATE.total_frames > 0:
            STATE.add_alert("CRITICAL", "CAPTURE_FAILURE",
                "0 management frames seen — check /var/log/wids/tcpdump_mgmt.log")

def heartbeat_thread() -> None:
    while STATE.running:
        time.sleep(CFG["heartbeat_interval"])
        fps = round(STATE.fps(), 1)
        STATE.add_event("heartbeat", "—",
            f"ch={STATE.home_channel or '?'}  APs={len(STATE.aps)}  "
            f"clients={len(STATE.clients)}  {fps} fr/s  total={STATE.total_frames}")

def export_snapshot(reason: str = "scheduled") -> None:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = CFG["log_dir"] / f"wids_{ts}"
    CFG["log_dir"].mkdir(parents=True, exist_ok=True)
    def _s(v):
        if isinstance(v, datetime): return str(v)
        if isinstance(v, set): return list(v)
        return v
    with STATE.lock:
        aps = list(STATE.aps.values())
        clis = list(STATE.clients.values())
        alerts = list(STATE.alerts)
    data = {
        "exported_at": str(datetime.now()), "reason": reason,
        "home_bssid": STATE.home_bssid, "home_channel": STATE.home_channel,
        "total_frames": STATE.total_frames,
        "aps":     [{k: _s(v) for k, v in ap.__dict__.items()} for ap in aps],
        "clients": [{k: _s(v) for k, v in c.__dict__.items()}  for c in clis],
        "alerts":  [{"ts": str(a.ts), "severity": a.severity, "category": a.category,
                     "message": a.message, "bssid": a.bssid, "mac": a.mac} for a in alerts],
    }
    with open(f"{base}.json", "w") as fh:
        json.dump(data, fh, indent=2)
    with open(f"{base}_alerts.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["timestamp","severity","category","message","bssid","mac"])
        for a in alerts:
            w.writerow([a.ts, a.severity, a.category, a.message, a.bssid, a.mac])
    STATE.add_alert("INFO", "EXPORT", f"[{reason}] -> {base}.json + _alerts.csv")
    STATE.last_export = time.time()

def export_scheduler_thread() -> None:
    while STATE.running:
        time.sleep(CFG["export_interval_min"] * 60)
        export_snapshot("scheduled")

# ============================
#  TUI CONSTANTS
# ============================
SEV_STYLE  = {"INFO": "cyan", "WARN": "yellow", "ALERT": "bold red", "CRITICAL": "bold white on red"}
SEV_ICON   = {"INFO": "ℹ", "WARN": "⚠", "ALERT": "✖", "CRITICAL": "☠"}
KIND_STYLE = {
    "beacon": "grey62", "probe": "bright_cyan", "deauth": "bold red", "disassoc": "red",
    "assoc": "bright_green", "assoc_fail": "yellow", "auth_ok": "green", "auth_fail": "yellow",
    "eapol": "magenta", "new_device": "bold bright_yellow", "heartbeat": "steel_blue1",
}
KIND_ICON  = {
    "beacon": "📡", "probe": "🔍", "deauth": "💀", "disassoc": "⚡", "assoc": "🔗",
    "assoc_fail": "✖", "auth_ok": "✓", "auth_fail": "✖", "eapol": "🔑",
    "new_device": "👾", "heartbeat": "♥",
}
FRAME_ICONS = {"beacon": "📡", "probe": "🔍", "auth": "🔐", "assoc": "🔗",
               "eapol": "🔑", "deauth": "💀", "disassoc": "⚡"}

# ============================
#  TUI PANELS
# ============================
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
    t.append("  alerts ", style="grey66")
    t.append(str(n_alr), style="bold red" if n_alr else "bold bright_green")
    t.append("  up ", style="grey66");     t.append(STATE.uptime_str(), style="bold magenta")
    t.append("  fr/s ", style="grey66");   t.append(str(fps), style="bold bright_cyan")
    t.append("  total ", style="grey66");  t.append(str(STATE.total_frames), style="bold")
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
    tbl.add_column("Ch",       no_wrap=True, width=3)
    tbl.add_column("Signal",   no_wrap=True, width=12)
    tbl.add_column("Security", no_wrap=True, max_width=9)
    tbl.add_column("PMF",      no_wrap=True, width=3)
    tbl.add_column("Rep",      no_wrap=True, width=5)
    max_rows = max(5, console.height - 20)
    for ap in aps[:max_rows]:
        is_home = (ap.bssid == home_bssid)
        star_t  = Text("★" if is_home else " ", style="bold bright_green" if is_home else "")
        bssid_t = Text(ap.bssid, style="bold bright_green" if is_home else "white")
        ssid_t  = Text(ap.ssid) if ap.ssid else Text("<hidden>", style="italic grey58")
        if ap.ibss: ssid_t.append(" IBSS", style="bold red")
        pmf_t   = Text("✓" if ap.mfpc else "✗", style="bright_green" if ap.mfpc else "red")
        # Security field may now show transition info
        sec_display = ap.security if not ap.transition_mode else "WPA2/3 ↔"
        tbl.add_row(star_t, bssid_t, ssid_t,
                    str(ap.channel) if ap.channel else "?",
                    rssi_bar(ap.rssi),
                    sec_display,
                    pmf_t, rep_text(ap.reputation))
    return Panel(tbl,
                 title="[bold cyan]◉ RF Radar — Access Points[/]  "
                       "[grey66]★=home  PMF=802.11w  Rep=trust score  ↔=transition mode[/]",
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
                 title="[bold red]⚠ Alert Feed[/]  "
                       "[grey66]☠=CRITICAL  ✖=ALERT  ⚠=WARN  ℹ=INFO[/]",
                 border_style="red", box=box.ROUNDED)

def _stats_panel() -> Panel:
    with STATE.lock:
        fcounts = dict(STATE.frame_type_counts)
        acounts = dict(STATE.alert_counts)
        n_new  = len(STATE.new_bssids_boot)
        n_rand = sum(1 for c in STATE.clients.values() if c.randomized)
        n_ibss = sum(1 for ap in STATE.aps.values() if ap.ibss)
        n_hid  = sum(1 for ap in STATE.aps.values() if ap.hidden)
        n_trans = sum(1 for ap in STATE.aps.values() if ap.transition_mode)  # NEW
    txt = Text(overflow="fold")
    txt.append("Frame histogram\n", style="bold white")
    max_f = max(fcounts.values(), default=1)
    for kind in ("beacon","probe","assoc","auth","eapol","deauth","disassoc"):
        cnt = fcounts.get(kind, 0)
        bar = mini_bar(cnt, max_f, 7)
        icon = FRAME_ICONS.get(kind, "·")
        txt.append(f"  {icon} {kind:<9} ", style="grey74")
        txt.append(bar, style="cyan")
        txt.append(f" {cnt}\n", style="bold")
    txt.append("\nAlert breakdown\n", style="bold white")
    if acounts:
        for cat, cnt in sorted(acounts.items(), key=lambda x: -x[1])[:7]:
            txt.append(f"  {cat:<18} ", style="grey74")
            txt.append(f"{cnt}\n", style="bold yellow")
    else:
        txt.append("  (none yet)\n", style="grey58 italic")
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
    return Panel(txt, title="[bold yellow]📊 Network Stats[/]",
                 border_style="yellow", box=box.ROUNDED)

def _client_table() -> Panel:
    with STATE.lock:
        ap_macs = set(STATE.aps.keys())
        clients = sorted([c for c in STATE.clients.values() if c.mac not in ap_macs],
                         key=lambda c: c.last_seen, reverse=True)
    tbl = Table(box=box.SIMPLE_HEAD, expand=True, header_style="bold magenta", padding=(0, 0))
    tbl.add_column("MAC",    no_wrap=True, width=17, max_width=17)
    tbl.add_column("Vendor", no_wrap=True, width=10, max_width=18)
    tbl.add_column("Rand",   no_wrap=True, width=5)
    tbl.add_column("Probes", no_wrap=True, width=5)
    tbl.add_column("EAPOL",  no_wrap=True, width=5)
    tbl.add_column("Fails",  no_wrap=True, width=5)
    tbl.add_column("Last",   no_wrap=True, width=8)
    tbl.add_column("",       no_wrap=True, width=3)
    max_rows = max(5, console.height - 20)
    for c in clients[:max_rows]:
        rnd_t  = Text("🎲 yes" if c.randomized else "  no",
                      style="yellow" if c.randomized else "grey58")
        new_t  = Text("NEW", style="bold bright_yellow") if c.is_new else Text("")
        fail_t = Text(str(c.auth_failures) if c.auth_failures else "—",
                      style="red" if c.auth_failures else "grey58")
        tbl.add_row(c.mac, c.vendor[:11], rnd_t,
                    str(len(c.probed_ssids)),
                    str(c.eapol_count) if c.eapol_count else "—",
                    fail_t, time_ago(c.last_seen), new_t)
        c.is_new = False
    return Panel(tbl,
                 title="[bold magenta]👾 Device Registry[/]  "
                       "[grey66]Rand=MAC randomisation  Fails=auth errors[/]",
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
                 title="[bold blue]📻 Live Event Stream[/]  "
                       "[grey66]♥=heartbeat  detach: Ctrl-B D[/]",
                 border_style="blue", box=box.ROUNDED)

def _connected_clients_panel() -> Panel:
    iface = CFG["scan_iface"]
    try:
        cmd = ["arp-scan", "-I", iface, "-l", "-q"]
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True, timeout=10)
    except subprocess.CalledProcessError as e:
        return Panel(f"[red]arp-scan failed (code {e.returncode})[/]",
                     title="[bold green]🔗 Connected Clients[/]",
                     border_style="green", box=box.ROUNDED)
    except FileNotFoundError:
        return Panel("[red]arp-scan not installed[/]\n[dim]sudo apt install arp-scan[/]",
                     title="[bold green]🔗 Connected Clients[/]",
                     border_style="green", box=box.ROUNDED)

    clients = []
    for line in out.splitlines():
        line = line.strip()
        if not line or "Starting arp-scan" in line or "packets received" in line or "Interface:" in line:
            continue
        parts = line.split()
        if len(parts) >= 2:
            ip = parts[0]; mac = parts[1].upper(); vendor = oui_lookup(mac)
            clients.append((ip, mac, vendor))

    if not clients:
        return Panel("[italic]No clients found[/]\n"
                     "[dim]Check that wlan0 has an IP and is on the same subnet as the AP[/]",
                     title="[bold green]🔗 Connected Clients[/]",
                     border_style="green", box=box.ROUNDED)

    tbl = Table(box=box.SIMPLE_HEAD, expand=True, header_style="bold green", padding=(0, 0))
    tbl.add_column("IP Address", no_wrap=True, width=15)
    tbl.add_column("MAC",        no_wrap=True, width=17, max_width=17)
    tbl.add_column("Vendor",     no_wrap=True, width=18, max_width=18)
    for ip, mac, vendor in clients[:20]:
        tbl.add_row(ip, mac, vendor)
    return Panel(tbl,
                 title="[bold green]🔗 Connected Clients[/]  [grey66]via arp-scan[/]",
                 border_style="green", box=box.ROUNDED)

# ============================
#  LAYOUT
# ============================
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

# ============================
#  SETUP + MAIN
# ============================
def setup_monitor_mode() -> bool:
    iface = CFG["monitor_iface"]
    console.print(f"[cyan]Setting {iface} -> monitor mode …[/]")
    try:
        subprocess.run(["nmcli", "device", "set", iface, "managed", "no"],
                       check=False, capture_output=True)
        subprocess.run(["ip", "link", "set", iface, "down"],       check=True, capture_output=True)
        subprocess.run(["iw", "dev", iface, "set", "type", "monitor"], check=True, capture_output=True)
        subprocess.run(["ip", "link", "set", iface, "up"],         check=True, capture_output=True)
        console.print(f"[bright_green]✓ {iface} in monitor mode[/]")
        return True
    except subprocess.CalledProcessError as e:
        console.print(f"[bold red]✗ {e}[/]")
        return False

def check_deps() -> bool:
    ok = True
    for tool in ("tcpdump", "tshark", "iw", "nmcli"):
        if subprocess.run(["which", tool], capture_output=True).returncode != 0:
            console.print(f"[red]Missing: {tool}[/]"); ok = False
    return ok

def rename_tmux_window() -> None:
    if os.environ.get("TMUX"):
        subprocess.run(["tmux", "rename-window", "WIDS"], capture_output=True)

def shutdown(sig=None, frame=None) -> None:
    STATE.running = False
    with _PROCS_LOCK:
        for p, _ in _PROCESSES:
            try: p.terminate()
            except: pass
    console.print("\n[yellow]Shutting down — saving snapshot …[/]")
    try: export_snapshot("shutdown")
    except: pass
    sys.exit(0)

def ensure_wlan0_connected() -> bool:
    iface = CFG["scan_iface"]; ssid = CFG["home_ssid"]; pwd = CFG["home_password"]
    try:
        out = subprocess.check_output(["iw", "dev", iface, "link"],
                                      text=True, stderr=subprocess.DEVNULL)
        if ssid in out:
            console.print(f"[green]✓ {iface} already connected to '{ssid}'[/]")
            return True
    except subprocess.CalledProcessError:
        pass
    console.print(f"[yellow]⚠ {iface} not connected to '{ssid}'. Attempting to connect...[/]")
    try:
        subprocess.run(["nmcli", "device", "set", iface, "managed", "yes"],
                       check=False, capture_output=True)
        subprocess.run(["nmcli", "device", "wifi", "connect", ssid,
                        "password", pwd, "ifname", iface],
                       check=True, capture_output=True, timeout=30)
        console.print(f"[bright_green]✓ {iface} connected to '{ssid}'[/]")
        return True
    except subprocess.CalledProcessError as e:
        console.print(f"[bold red]✗ Failed to connect {iface} to '{ssid}': {e}[/]")
        return False

def update_all_aps_from_nmcli() -> None:
    time.sleep(5)
    while STATE.running:
        try:
            cmd = ["nmcli", "--terse", "--fields", "BSSID,SSID,CHAN,SECURITY,SIGNAL",
                   "dev", "wifi", "list", "ifname", CFG["scan_iface"]]
            out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True, timeout=15)
            for line in out.splitlines():
                line = line.strip()
                if not line:
                    continue
                esc = line.replace("\\:", "\x00")
                parts = esc.split(":")
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
                        ap.ssid = ssid
                        ap.hidden = False
                    if chan and chan != "--":
                        try:
                            ap.channel = int(chan)
                        except ValueError:
                            pass
                    # NEW: detect WPA3 transition mode (advertises both WPA2 and WPA3)
                    if sec and "WPA2" in sec and "WPA3" in sec:
                        ap.transition_mode = True
                        ap.security = "WPA2/WPA3"
                        if ap.is_home and bssid not in STATE.transition_alerted_bssids:
                            STATE.transition_alerted_bssids.add(bssid)
                            STATE.add_alert("WARN", "WPA3_DOWNGRADE_RISK",
                                f"Home AP {bssid} ({ssid}) is in WPA3 transition mode — downgrade attacks possible!",
                                bssid=bssid)
                    elif "WPA3" in sec:
                        ap.security = "WPA3-SAE"
                    elif "WPA2" in sec:
                        ap.security = "WPA2-PSK"
                    elif "WEP" in sec:
                        ap.security = "WEP"
                    else:
                        ap.security = "Open"
                    # else: leave security as previous value
                    if signal and signal != "--":
                        try:
                            pct = int(signal)
                            if ap.rssi == -999:
                                ap.rssi = (pct // 2) - 100
                        except ValueError:
                            pass
        except Exception as e:
            STATE.add_alert("WARN", "NMCLI_ERR", f"AP update failed: {e}")
        time.sleep(60)

def main() -> None:
    _load_system_oui()
    if os.geteuid() != 0:
        console.print("[bold red]Must run as root:  sudo python3 wids.py[/]")
        sys.exit(1)
    if not check_deps(): sys.exit(1)
    signal.signal(signal.SIGINT,  shutdown)
    signal.signal(signal.SIGTERM, shutdown)
    CFG["log_dir"].mkdir(parents=True, exist_ok=True)
    rename_tmux_window()
    console.print(Rule("[bold cyan]WIDS v2 — Wi-Fi Intrusion Detection[/]"))
    console.print(f"[dim]monitor:[/] [bold]{CFG['monitor_iface']}[/]  "
                  f"[dim]scan:[/] [bold]{CFG['scan_iface']}[/]  "
                  f"[dim]SSID:[/] [bold]{CFG['home_ssid']}[/]")
    if not setup_monitor_mode(): sys.exit(1)
    if not ensure_wlan0_connected():
        console.print("[yellow]Warning: wlan0 not connected – client list will be empty[/]")
    for target, name in [
        (mgmt_reader_thread,       "mgmt"),
        (eapol_reader_thread,      "eapol"),
        (scanner_thread,           "scan"),
        (heartbeat_thread,         "beat"),
        (watchdog_thread,          "watchdog"),
        (export_scheduler_thread,  "export"),
        (update_all_aps_from_nmcli,"nmcli_full"),
        (lan_monitor_thread,       "lan"),
        (pmf_reader_thread,        "pmf"),
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
    main()