# WIDS — Wi-Fi Intrusion Detection System

A real-time Wi-Fi and LAN threat CLI monitor for Raspberry Pi. Displays a live terminal dashboard (uses TMUX) showing all activity: deauth attacks, probe floods, nearby access points, connected devices, management frame activity, and active LAN threat detection (ARP scanning, ARP poisoning/MITM, port scanning, DHCP starvation).

---

## Screenshots

### Main Dashboard

<img alt="dashboard" src=.media/Dashboard.png />

### Alert Feed

<img alt="Alert Feed" src=.media/Alert_Feed.png />

### RF Radar

<img alt="RF Radar" src=.media/RF_Radar.png />

### Network Stats

<img alt="Network Stats" src=.media/Network_Stats.png />

<!-- ### Device Registry

<img alt="Device Registry" src=.media/Device_Registry.png /> -->


## Table of Contents

1. [How It Works](#how-it-works)
2. [Hardware Requirements](#hardware-requirements)
3. [Recommended Wi-Fi Dongles](#recommended-wi-fi-dongles)
4. [Raspberry Pi OS Setup](#raspberry-pi-os-setup)
5. [SSH Setup](#ssh-setup)
6. [System Dependencies](#system-dependencies)
7. [Python Dependencies](#python-dependencies)
8. [Configuration](#configuration)
9. [Running Manually](#running-manually)
10. [Running as a systemd Service](#running-as-a-systemd-service)
11. [tmux Setup and Attaching](#tmux-setup-and-attaching)
12. [Dashboard Reference](#dashboard-reference)
13. [Log Files](#log-files)
14. [Security Notes Before Pushing to Git](#security-notes-before-pushing-to-git)
15. [Troubleshooting](#troubleshooting)

---

## How It Works

WIDS uses **two separate Wi-Fi interfaces** simultaneously:

| Interface | Role | Mode |
|-----------|------|------|
| `wlan0` | Built-in RPi Wi-Fi | Managed — stays connected to your home AP for LAN monitoring and nmcli scanning |
| `wlan1` | USB Wi-Fi dongle | Monitor mode — passively captures all 802.11 management frames in the air |

**Why two interfaces?**

A Wi-Fi adapter in monitor mode cannot simultaneously be associated with an access point. It just listens to raw 802.11 frames. If you put your only adapter into monitor mode, you lose your network connection and can no longer scan for IPs, run arp-scan, or get security metadata from NetworkManager. You need one adapter locked to your home network (wlan0) and a second one free to sniff the air (wlan1).

**Data sources:**

- `tcpdump` on `wlan1` — captures beacon, probe, deauth, disassoc, auth, assoc, and reassoc frames. Provides RSSI (signal strength) for APs on the same channel.
- `tshark` on `wlan1` — captures EAPOL (WPA handshake) frames.
- `nmcli` on `wlan0` — periodic full scan providing SSID, channel, security type, and signal percentage for all visible APs (including those on other channels).
- `tcpdump` on `wlan0` — watches live IP traffic for ARP scans, ARP poisoning, TCP SYN port scans, and DHCP starvation.
- `arp-scan` on `wlan0` — periodic sweep to list active IP/MAC pairs on your LAN.

---

## Hardware Requirements

- **Raspberry Pi** — any model with USB ports. Tested on RPi 4 and RPi 3B+. RPi Zero W will work but is slow.
- **MicroSD card** — 8 GB minimum, 16 GB recommended (logs grow over time).
- **Power supply** — official RPi power supply recommended. Underpowered supplies cause USB instability which will crash your monitor-mode dongle.
- **USB Wi-Fi adapter** that supports **monitor mode** (see next section).
- **Internet connection** during setup (Ethernet cable or using wlan0 temporarily).

---

## Recommended Wi-Fi Dongles

Not all Wi-Fi adapters support monitor mode. Many cheap adapters advertise it but the Linux driver does not implement it. The following chipsets are well-tested on Raspberry Pi OS:

### Best options (2024)

| Adapter | Chipset | Monitor Mode | Packet Injection | Notes |
|---------|---------|-------------|-----------------|-------|
| Alfa AWUS036ACM | MediaTek MT7612U | ✓ | ✓ | Best overall. Dual-band. Works out of box. |
| Alfa AWUS036ACHM | MediaTek MT7610U | ✓ | ✓ | Good 2.4/5 GHz support. |
| Alfa AWUS036NHA | Atheros AR9271 | ✓ | ✓ | 2.4 GHz only. Very reliable. Classic choice. |
| TP-Link TL-WN722N v1 | Atheros AR9271 | ✓ | ✓ | **v1 only** — v2/v3 use Realtek and do NOT support monitor mode. Check the version. |
| Panda PAU09 | Ralink RT5572 | ✓ | ✓ | Dual-band, good RPi compatibility. |

### Chipsets to avoid

- **Realtek RTL8188** / RTL8192 / RTL8811 series — monitor mode support is unreliable or broken on many kernel versions.
- Any adapter that does not explicitly list the chipset — almost certainly a Realtek.

### Verifying your dongle supports monitor mode

Plug in the dongle and run:

```bash
iw list | grep -A 10 "Supported interface modes"
```

You should see `monitor` in the list. If it is not there, the driver does not support it and the dongle will not work for WIDS.

---

## Raspberry Pi OS Setup

### 1. Flash the OS

Download **Raspberry Pi OS Lite (64-bit)** from https://www.raspberrypi.com/software/

Use **Raspberry Pi Imager** (https://www.raspberrypi.com/software/) to flash to your SD card.

In Imager, before flashing, click the gear icon (⚙) or press `Ctrl+Shift+X` to open advanced options:

- **Enable SSH** — check this box
- **Set username and password** — choose a username (e.g. `sud`) and a strong password
- **Configure Wi-Fi** — enter your home SSID and password so the Pi connects on first boot
- **Set locale/timezone** — set your country and timezone

Flash, insert the SD card into the Pi, and power on.

### 2. Find the Pi's IP address

From your router's admin page, or run this from another machine on the same network:

```bash
nmap -sn 192.168.1.0/24 | grep -i raspberry
```

Or use the hostname (if mDNS works on your network):

```bash
ping raspberrypi.local
```

---

## SSH Setup

### Connect for the first time

```bash
ssh sud@192.168.1.X
```

Replace `192.168.1.X` with your Pi's actual IP. Accept the host key fingerprint when prompted.

### Set up SSH key authentication (recommended)

On your **local machine**:

```bash
# Generate a key pair if you don't have one
ssh-keygen -t ed25519 -C "wids-rpi"

# Copy your public key to the Pi
ssh-copy-id sud@192.168.1.X
```

Now you can SSH without a password. You should then disable password authentication on the Pi for security:

```bash
sudo nano /etc/ssh/sshd_config
```

Find and set:
```
PasswordAuthentication no
PubkeyAuthentication yes
```

```bash
sudo systemctl restart ssh
```

### Keep the session alive

Add to your local `~/.ssh/config`:

```
Host rpi
    HostName 192.168.1.X
    User sud
    ServerAliveInterval 60
    ServerAliveCountMax 3
```

Now you can connect with just `ssh rpi`.

---

## System Dependencies

Update the system first:

```bash
sudo apt update && sudo apt upgrade -y
```

Install all required tools:

```bash
sudo apt install -y \
    tcpdump \
    tshark \
    iw \
    wireless-tools \
    network-manager \
    arp-scan \
    tmux \
    python3 \
    python3-pip \
    git
```

During `tshark` installation you will be asked whether non-root users should be able to capture packets. Select **Yes** (but WIDS runs as root anyway).

### Verify everything installed

```bash
which tcpdump tshark iw nmcli arp-scan tmux python3
```

All should return a path. If any are missing, install them individually.

### Ensure NetworkManager manages wlan0

NetworkManager must be in control of `wlan0` for nmcli scanning to work:

```bash
nmcli device status
```

You should see `wlan0` listed with state `connected`. If it shows `unmanaged`, run:

```bash
sudo nmcli device set wlan0 managed yes
```

---

## Python Dependencies

WIDS requires only one Python library beyond the standard library:

```bash
pip3 install rich --break-system-packages
```

The `--break-system-packages` flag is required on Raspberry Pi OS Bookworm (Debian 12) and later, which use externally managed Python environments.

Verify:

```bash
python3 -c "from rich import box; print('rich OK')"
```

---

## Configuration

### Clone the repository

```bash
cd ~
git clone https://github.com/YOURUSERNAME/wids.git
cd wids
```

### Create a local config file

**Do not put your Wi-Fi password in `wids.py` directly.** Instead, create a local config file that is excluded from git:

```bash
nano ~/wids/wids_local.conf
```

Add:

```ini
HOME_SSID=Hell`s WiFi
HOME_PASSWORD=rectum_obliterator_666
MONITOR_IFACE=wlan1  # use the wifi interface that support monitor mode
SCAN_IFACE=wlan0 # can be any wifi interface, even the RPi's stock iface is ok
```

### Identify your interfaces

Plug in your USB Wi-Fi dongle, then:

```bash
ip link show
```

You will see something like:

```
2: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP> ...
3: wlan1: <BROADCAST,MULTICAST> ...
```

`wlan0` is typically the built-in RPi Wi-Fi. `wlan1` is the USB dongle. Confirm which is which:

```bash
iw dev
```

This shows each interface with its PHY (physical radio), MAC address, and current mode.

If your interfaces are named differently (e.g. `wlx00c0ca...`), update `monitor_iface` and `scan_iface` in the config accordingly.

### Verify the dongle supports monitor mode

```bash
sudo iw dev wlan1 set type monitor
sudo ip link set wlan1 up
iw dev wlan1 info | grep type
```

If you see `type monitor`, the dongle works. Reset it after testing:

```bash
sudo ip link set wlan1 down
sudo iw dev wlan1 set type managed
sudo ip link set wlan1 up
```

WIDS sets monitor mode automatically at startup — this is just a pre-flight check.

---

## Running Manually

WIDS must run as root because it uses raw packet capture:

```bash
sudo python3 ~/wids/wids.py
```

You should see startup output:

```
──────────── WIDS v2 — Wi-Fi Intrusion Detection ────────────
monitor: wlan1  scan: wlan0  SSID: YourNetwork
Setting wlan1 -> monitor mode …
✓ wlan1 in monitor mode
✓ wlan0 already connected to 'YourNetwork'
```

After about 5–10 seconds the full dashboard will appear. Press `Ctrl+C` to stop.

---

## Running as a systemd Service

Running WIDS as a service means it starts automatically on boot and restarts if it crashes.

### 1. Install tmux wrapper script

WIDS runs inside a tmux session so you can attach and detach from the dashboard. Create the service wrapper:

```bash
sudo nano /usr/local/bin/wids-attach
```

Paste:

```bash
#!/bin/bash
SESSION="wids"

if tmux has-session -t "$SESSION" 2>/dev/null; then
    tmux attach-session -t "$SESSION"
else
    STATUS=$(systemctl is-active wids 2>/dev/null)
    echo ""
    echo "[wids] Session not running."
    echo "       Status: $STATUS"
    echo "       Start:  sudo systemctl start wids"
    echo ""
fi
```

```bash
sudo chmod +x /usr/local/bin/wids-attach
```

Now you can type `wids-attach` from anywhere to open the dashboard.

### 2. Create the systemd unit

```bash
sudo nano /etc/systemd/system/wids.service
```

Paste (adjust paths and environment variables to match your setup):

```ini
[Unit]
Description=WIDS — Wi-Fi Intrusion Detection System
After=network-online.target NetworkManager.service
Wants=network-online.target

[Service]
Type=forking
User=root
WorkingDirectory=/opt/wids

# Load local config as environment variables
EnvironmentFile=-/opt/wids/wids_local.conf

ExecStart=/usr/bin/tmux new-session -d -s wids -x 220 -y 55 \
    /usr/bin/python3 /opt/wids/wids.py

ExecStop=/usr/bin/tmux kill-session -t wids

Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

### 3. Deploy the script

```bash
sudo mkdir -p /opt/wids
sudo cp ~/wids/wids.py /opt/wids/wids.py
sudo cp ~/wids/wids_local.conf /opt/wids/wids_local.conf
sudo chmod 600 /opt/wids/wids_local.conf  # protect the password
```

### 4. Enable and start the service

```bash
sudo systemctl daemon-reload
sudo systemctl enable wids
sudo systemctl start wids
```

### 5. Check it started

```bash
sudo systemctl status wids
```

You should see `Active: active (running)`. Then attach to the dashboard:

```bash
wids-attach
```

### Useful service commands

```bash
sudo systemctl start wids      # start
sudo systemctl stop wids       # stop
sudo systemctl restart wids    # restart
sudo systemctl status wids     # check status
sudo journalctl -u wids -f     # follow service logs
```

---

## tmux Setup and Attaching

WIDS runs inside a **tmux** session. tmux is a terminal multiplexer — it keeps the dashboard running in the background even when you disconnect your SSH session.

### Key tmux commands inside a WIDS session

| Action | Keys |
|--------|------|
| Detach (leave dashboard running) | `Ctrl+B` then `D` |
| Scroll up in panel | `Ctrl+B` then `[` then arrow keys, `Q` to exit |
| Kill session | `Ctrl+B` then `:kill-session` |

### Re-attach after detaching or reconnecting via SSH

```bash
wids-attach
# or directly:
sudo tmux attach -t wids
```

### tmux configuration (optional but recommended)

Create `~/.tmux.conf`:

```
set -g mouse on
set -g history-limit 5000
set -g default-terminal "screen-256color"
```

This enables mouse scrolling inside the dashboard.

---

## Dashboard Reference

The dashboard is divided into six panels:

```
┌─────────────────────────────────────────────────────────────┐
│  Status Bar — pulse, interfaces, channel, AP count, uptime  │
├──────────────────────┬──────────────────┬───────────────────┤
│  RF Radar            │  Alert Feed      │  Network Stats    │
│  Access Points table │  RF/WIDS alerts  │  Frame histogram  │
│  BSSID/SSID/Ch/      │  ── divider ──   │  Alert breakdown  │
│  Signal/Security/    │  LAN Threats     │  Counters         │
│  PMF/Rep             │                  │                   │
├──────────────────────┬──────────────────┬───────────────────┤
│  Device Registry     │  Live Event      │  Connected        │
│  Probing clients,    │  Stream          │  Clients          │
│  MAC/vendor/rand/    │  Real-time frame │  IP/MAC/vendor    │
│  EAPOL/failures      │  log             │  via arp-scan     │
└──────────────────────┴──────────────────┴───────────────────┘
```

### RF Radar — Access Points

| Column | Meaning |
|--------|---------|
| ★ | Home AP marker |
| BSSID | MAC address of the access point |
| SSID | Network name. `<hidden>` means the AP does not broadcast its SSID |
| Ch | Wi-Fi channel |
| Signal | RSSI in dBm. Green ≥ -60, yellow ≥ -75, red below |
| Security | WPA2-PSK / WPA3-SAE / WEP / Open / ? (not yet scanned) |
| PMF | 802.11w Protected Management Frames. ✓ = enabled, ✗ = not |
| Rep | Trust score 0–100. Decreases on suspicious activity |

APs are sorted strongest signal first. APs on the same channel as your home AP get live RSSI from beacons. APs on other channels get estimated RSSI from nmcli (updated every 60 seconds).

### Alert Feed

Split into two sections:

**RF / WIDS** — 802.11 layer threats:

| Alert | Meaning |
|-------|---------|
| DEAUTH_FLOOD | Someone is sending rapid deauthentication frames — classic Wi-Fi jamming/kickoff attack |
| DISASSOC_FLOOD | Similar to deauth flood |
| PROBE_STORM | A device is probing for many different SSIDs rapidly — possible scanner |
| EAPOL_STORM | Repeated WPA handshakes from one device — possible deauth+reconnect loop |

**LAN Threats** — IP layer threats:

| Alert | Meaning |
|-------|---------|
| ARP_SCAN | A device sent many ARP requests in a short window — possible network reconnaissance (e.g. nmap -sn, arp-scan) |
| ARP_POISON | An IP address is claiming a different MAC than previously seen — possible MITM/ARP spoofing attack |
| PORT_SCAN | A device hit many different destination ports in a short window — possible port scan |
| DHCP_STARVE | Many different MACs sending DHCP DISCOVER simultaneously — possible DHCP starvation attack |

### Severity levels

| Icon | Level | Meaning |
|------|-------|---------|
| ℹ | INFO | Informational, no action needed |
| ⚠ | WARN | Suspicious, worth investigating |
| ✖ | ALERT | Likely malicious activity |
| ☠ | CRITICAL | Active attack or system failure |

### Device Registry

All Wi-Fi clients seen probing or associating. Columns:

| Column | Meaning |
|--------|---------|
| Rand | Whether the MAC address is randomised (locally administered bit set) |
| Probes | Number of unique SSIDs this device has probed for |
| EAPOL | WPA handshake frame count |
| Fails | Authentication failure count |
| NEW | Badge shown on first appearance this session |

### Connected Clients

Devices actively on your LAN right now, discovered via `arp-scan`. Shows IP address, MAC, and vendor. Refreshes every dashboard cycle (~1 second) but `arp-scan` itself takes a few seconds so there is slight lag.

---

## Log Files

All logs are written to `/var/log/wids/`:

| File | Contents |
|------|----------|
| `wids.log` | All alerts with timestamp and severity |
| `tcpdump_mgmt.log` | Raw tcpdump stderr from the management frame capture on wlan1 |
| `tcpdump_lan.log` | Raw tcpdump stderr from the LAN monitor on wlan0 |
| `tshark_eapol.log` | tshark stderr from the EAPOL capture |
| `wids_YYYYMMDD_HHMMSS.json` | Full snapshot export every 30 minutes and on shutdown |
| `wids_YYYYMMDD_HHMMSS_alerts.csv` | CSV of all alerts at time of export |

Log rotation is not built in. To prevent disk fill on long-running deployments, set up logrotate:

```bash
sudo nano /etc/logrotate.d/wids
```

```
/var/log/wids/*.log {
    daily
    rotate 7
    compress
    missingok
    notifempty
}
```

---

## Security Notes Before Pushing to Git

### What must NOT be in your repository

1. **Your Wi-Fi password** — move it to an environment variable or external config file (see Configuration section above)
2. **Log files** — contain your home BSSID, all neighbour BSSIDs, and MAC addresses of every device on your network
3. **Export snapshots** — `.json` and `.csv` files contain the same sensitive data

### Minimum `.gitignore`

```gitignore
# Local config with secrets
wids_local.conf
*.conf

# Log and export files
*.log
*.json
*.csv

# Python cache
__pycache__/
*.pyc
*.pyo
```

### What is safe to commit

- `wids.py` — after removing hardcoded password and SSID (replace with `os.environ.get(...)`)
- `wids.service` — contains no secrets if you use `EnvironmentFile`
- `README.md`
- `.gitignore`

### Check before pushing

```bash
git diff --staged | grep -iE "password|ssid|secret|key|token"
```

Run this before every commit. If it returns anything, do not push.

---

## Troubleshooting

### "wlan1 not found" or monitor mode fails

The USB dongle may not be recognised. Check:

```bash
lsusb
dmesg | tail -30
```

Look for the dongle's USB vendor/product ID in `lsusb` and any kernel messages about loading firmware. If the dongle is listed but monitor mode fails, the driver may not support it — see [Recommended Wi-Fi Dongles](#recommended-wi-fi-dongles).

### Dashboard not appearing / service stuck in "activating"

Run directly to see the error:

```bash
sudo python3 /opt/wids/wids.py
```

Common causes:
- `tcpdump` or `tshark` not installed
- wlan1 does not support monitor mode
- Running without root (`sudo`)

### All APs show `<hidden>` SSID and `?` security

The nmcli scan thread has not run yet (it waits 5 seconds on startup) or wlan0 is not connected. Check:

```bash
nmcli device status
nmcli dev wifi list ifname wlan0
```

If `nmcli dev wifi list` returns nothing, wlan0 is not scanning. Ensure NetworkManager is managing it:

```bash
sudo nmcli device set wlan0 managed yes
sudo nmcli device wifi rescan ifname wlan0
```

### Signal column shows `?dBm` for all APs except home

Expected behaviour for APs on channels other than your home AP's channel. wlan1 in monitor mode is locked to a single channel — it only receives beacons from APs on that channel. APs on other channels get estimated signal from nmcli (shown after the first 60-second scan cycle). This is a hardware limitation, not a bug.

### CAPTURE_DIED alerts appearing

A critical capture process (management frame reader or EAPOL reader) has exited. Check the logs:

```bash
sudo tail -50 /var/log/wids/tcpdump_mgmt.log
sudo tail -50 /var/log/wids/tshark_eapol.log
```

Common cause: wlan1 was disconnected, NetworkManager grabbed it back out of monitor mode, or another process bound to the interface. The reader will auto-restart every 5 seconds.

### False ARP_SCAN alerts

WIDS ignores ARP traffic originating from the Pi itself, but if your home IP changed (e.g. after DHCP renewal) the cached `own_ips` set will be stale. Restart the service:

```bash
sudo systemctl restart wids
```

The IP cache is rebuilt at startup.

### LAN monitor shows no threats but dies repeatedly

Check:

```bash
sudo tail -20 /var/log/wids/tcpdump_lan.log
iw dev wlan0 info | grep type
```

If `wlan0` shows `type monitor`, something has flipped it into monitor mode (unlikely but possible). WIDS will detect this and skip the LAN monitor with a `LAN_SKIP` alert until it is resolved.

### High CPU usage

On a RPi 3B+ with a busy network, CPU can reach 30–40% during peak probe activity. This is normal. If it consistently exceeds 80%, reduce the dashboard refresh rate in CFG:

```python
"dashboard_refresh": 2.0,  # was 1.0
```

### tmux session not found after reboot

The service may still be starting. Wait 15–20 seconds after boot then try `wids-attach` again. If it consistently fails, check:

```bash
sudo systemctl status wids
sudo journalctl -u wids -n 30
```
