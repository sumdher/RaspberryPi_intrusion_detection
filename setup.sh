# Attach to the live WIDS TUI from any SSH session.
# Usage:  wids-attach  (no sudo needed if your user can sudo tmux)

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

# ── start now ────────────────────────────────────────────────
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
