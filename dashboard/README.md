# Secure MediNet Dashboard

Streamlit dashboard for the Secure MediNet modules. It is fully separate from
the modules: it never imports their code, and talks to them only through their
APIs and output files (one adapter per module in `sources/`).

Currently connected: **SDN Gateway**. Other modules show as "Not connected yet".

## Views

- **Home** (`Home.py`): device counts and devices under enforcement, plus a
  card per module.
- **SDN Gateway** (`pages/1_SDN_Gateway.py`): all devices with status filter
  and search, and manual restore / rate-limit / quarantine.

Both refresh every 5 seconds. If the SDN API is unreachable, the dashboard shows
the last saved `device_registry.json` read-only and disables actions.

## Run locally (development)

```bash
cd dashboard
pip install -r requirements.txt
SDN_API_URL=http://<pi-ip>:5000 streamlit run Home.py
```

## Deploy on the Raspberry Pi 4 (Raspberry Pi OS Lite, 64-bit)

After `SDN/scripts/setup_pi.sh`, from the repository root:

```bash
sudo DASHBOARD_PASSWORD='choose-a-strong-one' bash dashboard/scripts/install_pi.sh
```

This installs to `/opt/secure-medinet-dashboard` in a venv, runs it as the
unprivileged `dashboard` user under systemd (`secure-medinet-dashboard.service`),
and blocks port 8501 on the hotspot interfaces so IoT devices cannot reach it.
Open `http://<pi-eth0-ip>:8501` from a computer on the hospital LAN.

## Settings (environment variables)

| Variable | Default |
|---|---|
| `SDN_API_URL` | `http://127.0.0.1:5000` |
| `SDN_REGISTRY_PATH` | `../SDN/config/device_registry.json` |
| `DASHBOARD_REFRESH_SEC` | `5` |
| `DASHBOARD_PASSWORD` | unset (no login; development only) |

## Adding a module

1. Add `sources/<module>.py` that reads the module's API or output files.
2. Add `pages/<n>_<Module>.py` for the detail view.
3. Replace the module's "Not connected yet" card in `Home.py` with a summary.
