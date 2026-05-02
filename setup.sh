#!/usr/bin/env bash
# setup.sh — install wids as a systemd service
set -euo pipefail

SERVICE="wids"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WIDS_PY="$SCRIPT_DIR/wids.py"
ENV_FILE="$SCRIPT_DIR/.env"

# ── require root ──────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo "Run with sudo:  sudo bash setup.sh"
    exit 1
fi

# ── env file ──────────────────────────────────────────────────
if [[ ! -f "$ENV_FILE" ]]; then
    if [[ -f "$SCRIPT_DIR/.env.example" ]]; then
        cp "$SCRIPT_DIR/.env.example" "$ENV_FILE"
        echo "[!] Created $ENV_FILE from .env.example — edit it before continuing."
        echo "    Then re-run:  sudo bash setup.sh"
        exit 0
    fi
fi

# ── log directory ─────────────────────────────────────────────
mkdir -p /var/log/wids/sessions
chmod 755 /var/log/wids

# ── systemd unit ──────────────────────────────────────────────
cat > /etc/systemd/system/wids.service <<EOF
[Unit]
Description=Wi-Fi Intrusion Detection System (WIDS)
After=network.target

[Service]
Type=forking
ExecStartPre=-/usr/bin/tmux kill-session -t wids
ExecStart=/usr/bin/tmux new-session -d -s wids /usr/bin/python3 $WIDS_PY
ExecStop=/usr/bin/tmux kill-session -t wids
Restart=on-failure
RestartSec=10
EnvironmentFile=-$ENV_FILE
StandardOutput=append:/var/log/wids/wids.log
StandardError=append:/var/log/wids/wids.log

[Install]
WantedBy=multi-user.target
EOF

# ── wids-attach helper ────────────────────────────────────────
cat > /usr/local/bin/wids-attach <<'EOF'
#!/usr/bin/env bash
SESSION="wids"

if ! sudo tmux has-session -t "$SESSION" 2>/dev/null; then
    echo "[wids] Session not running."
    echo "       Status: $(systemctl is-active wids 2>/dev/null || echo unknown)"
    echo "       Start:  sudo systemctl start wids"
    exit 1
fi

echo "[wids] Attaching to TUI — detach with  Ctrl-B then D"
exec sudo tmux attach-session -t "$SESSION"
EOF

chmod +x /usr/local/bin/wids-attach

# ── reload & enable ───────────────────────────────────────────
systemctl daemon-reload
systemctl enable "$SERVICE"

# ── start now ─────────────────────────────────────────────────
echo ""
echo "Starting service …"
systemctl start "$SERVICE"
sleep 2

STATUS=$(systemctl is-active "$SERVICE" 2>/dev/null || echo "unknown")
if [[ "$STATUS" == "active" ]]; then
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo " ✓  WIDS is running"
    echo ""
    echo "  Attach to the live TUI (from this or any SSH session):"
    echo "      wids-attach"
    echo ""
    echo "  Detach from TUI without stopping WIDS:"
    echo "      Ctrl-B  then  D"
    echo ""
    echo "  Service control:"
    echo "      sudo systemctl status wids"
    echo "      sudo systemctl restart wids"
    echo "      sudo systemctl stop wids"
    echo ""
    echo "  Logs (append-only, readable any time):"
    echo "      tail -f /var/log/wids/wids.log"
    echo "      ls /var/log/wids/          # JSON + CSV exports here too"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
else
    echo ""
    echo "[!] Service started but status is: $STATUS"
    echo "    Check:  journalctl -u wids -n 30"
fi
