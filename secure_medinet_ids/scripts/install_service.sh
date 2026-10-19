#!/usr/bin/env bash
# Runs the Edge IDS live replay at boot as a systemd service.
# Run on the Pi, from your normal user:
#
#   sudo bash ~/NIDS/scripts/install_service.sh
#
# Safe to run again: it never overwrites /etc/secure-medinet-ids.env.
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "Run with sudo."; exit 1; }

IDS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_USER="${IDS_USER:-${SUDO_USER:-}}"
[[ -n "$RUN_USER" && "$RUN_USER" != "root" ]] \
    || { echo "Run with sudo from your normal user (or set IDS_USER)."; exit 1; }
RUN_GROUP="$(id -gn "$RUN_USER")"
PYTHON="${PYTHON:-/usr/bin/python3}"
ENV_FILE="/etc/secure-medinet-ids.env"
UNIT="/etc/systemd/system/secure-medinet-ids.service"

# Check what the service user's Python sees: NumPy and PyTorch must agree.
if ! sudo -u "$RUN_USER" "$PYTHON" -c \
    "import numpy, pandas, sklearn, torch; torch.zeros(1).numpy()" 2>/dev/null; then
    echo "$PYTHON as $RUN_USER cannot import numpy/pandas/sklearn/torch together."
    echo "Check: sudo -u $RUN_USER $PYTHON -c 'import numpy, torch; torch.zeros(1).numpy()'"
    exit 1
fi
[[ -f "$IDS_DIR/saved_models/isolation_forest.joblib" ]] \
    || { echo "No trained models in $IDS_DIR/saved_models. Run: python3 train.py"; exit 1; }

sed -e "s#@USER@#$RUN_USER#g" -e "s#@IDS_DIR@#$IDS_DIR#g" -e "s#@PYTHON@#$PYTHON#g" \
    "$IDS_DIR/systemd/secure-medinet-ids.service" > "$UNIT"

if [[ ! -f "$ENV_FILE" ]]; then
    cat > "$ENV_FILE" <<'EOF'
# Settings for the Secure MediNet Edge IDS service.
#
# Maps IDS device IDs to the MAC addresses the SDN gateway enforces on.
# WARNING: the service replays attacks forever. A device listed here WILL be
# quarantined or throttled again every time the replay reaches an attack, so
# map only devices you are happy to lose, never your real sensors.
# Unmapped detections still appear on the dashboard as "not enforced".
#
# SDN_DEVICE_MACS='{"iomt_device_1":"aa:bb:cc:dd:ee:01"}'
#
# Seconds between replayed windows (default 1.0):
# IDS_LIVE_DELAY_SEC=1.0
EOF
    echo "Created $ENV_FILE (no devices mapped)."
fi

# The logs grow for as long as the replay runs; keep them from filling the SD card.
cat > /etc/logrotate.d/secure-medinet-ids <<EOF
$IDS_DIR/logs/ids_events.jsonl $IDS_DIR/logs/ids_runs.jsonl {
    size 20M
    rotate 3
    compress
    missingok
    notifempty
    su $RUN_USER $RUN_GROUP
}
EOF

systemctl daemon-reload
systemctl enable secure-medinet-ids
systemctl restart secure-medinet-ids

echo "IDS service running as $RUN_USER from $IDS_DIR"
echo "  status: systemctl status secure-medinet-ids"
echo "  logs:   journalctl -u secure-medinet-ids -f"
echo "  map devices (optional): sudo nano $ENV_FILE && sudo systemctl restart secure-medinet-ids"
