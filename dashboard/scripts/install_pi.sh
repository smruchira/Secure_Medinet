#!/usr/bin/env bash
# Installs the Secure MediNet dashboard on Raspberry Pi OS Lite (64-bit).
# Run from the repository root after SDN/scripts/setup_pi.sh:
#
#   sudo DASHBOARD_PASSWORD='choose-a-strong-one' bash dashboard/scripts/install_pi.sh
set -euo pipefail

APP_DIR="/opt/secure-medinet-dashboard"
ENV_FILE="/etc/secure-medinet-dashboard.env"
PORT="8501"
SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"

[[ $EUID -eq 0 ]] || { echo "Run with sudo."; exit 1; }
[[ -n "${DASHBOARD_PASSWORD:-}" ]] || { echo "Set DASHBOARD_PASSWORD."; exit 1; }
# Streamlit needs pyarrow, which has prebuilt wheels for 64-bit ARM only.
[[ "$(uname -m)" == "aarch64" ]] || { echo "Needs 64-bit Raspberry Pi OS (aarch64)."; exit 1; }

apt-get install -y -qq python3-venv

id dashboard &>/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin dashboard

mkdir -p "$APP_DIR"
cp -r "$SRC_DIR"/{Home.py,settings.py,ui.py,sources,pages,.streamlit,requirements.txt} "$APP_DIR"/
python3 -m venv "$APP_DIR/venv"
# The wheels are large (pyarrow, pandas); tolerate a slow or flaky uplink.
"$APP_DIR/venv/bin/pip" install --timeout 120 --retries 10 --prefer-binary \
    -r "$APP_DIR/requirements.txt"
chown -R root:root "$APP_DIR"

umask 077
printf 'DASHBOARD_PASSWORD=%s\n' "$DASHBOARD_PASSWORD" > "$ENV_FILE"
umask 022

# IoT devices on the hotspot must never reach the dashboard.
for iface in br-sdn wlan0; do
    iptables -C INPUT -i "$iface" -p tcp --dport "$PORT" -j DROP 2>/dev/null \
        || iptables -I INPUT -i "$iface" -p tcp --dport "$PORT" -j DROP
done
netfilter-persistent save >/dev/null 2>&1 || true

cp "$SRC_DIR/systemd/secure-medinet-dashboard.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now secure-medinet-dashboard

echo "Dashboard running: http://$(hostname -I | awk '{print $1}'):${PORT}"
