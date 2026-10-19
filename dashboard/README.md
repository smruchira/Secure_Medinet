# Secure MediNet Dashboard

Streamlit dashboard for the Secure MediNet modules. It is fully separate from
the modules: it never imports their code, and talks to them only through their
APIs and output files (one adapter per module in `sources/`). That separation
is why the dashboard needs neither PyTorch nor the trained models.

Connected: **SDN Gateway** (live REST API), **Edge IDS ensemble**, **ECG
HIDS** and **behavioural token binding** (log and state files).

## Views

- **Home** (`Home.py`) — device counts and IDS detections side by side, devices
  under enforcement annotated with the threat that implicated them, and the
  latest detections.
- **SDN Gateway** (`pages/1_SDN_Gateway.py`) — all devices with status filter
  and search, plus manual restore / rate-limit / quarantine.
- **Edge IDS** (`pages/2_Edge_IDS.py`) — confirmed threats, how many the
  gateway actually enforced, per-tier confidence, gating and latency, and the
  current model card.
- **ECG HIDS** (`pages/3_ECG_HIDS.py`) — heart rate with the readings the
  cloud model flagged, attacks by type, watchdog alerts, cloud-model
  availability, and each reading's SDN request beside the device's live status.
- **Token binding** (`pages/4_Token_Binding.py`) — trusted / learning /
  revoked devices, learned token rhythm, rejection reasons, recent decisions,
  and a restore action. It reads `behavior_profile.json`,
  `revoked_devices.json`, and `token_decisions.jsonl` from `/home/*/` or the
  `TOKEN_PROFILES`, `TOKEN_REVOKED`, and `TOKEN_DECISIONS` paths.

## Token bridge and dashboard access

Run the updated `behavioural_token_binding/security_mqtt_bridge.py` to record
new decisions. It writes one JSONL row for every accepted, rejected, or failed
verification; rows contain a device ID and reason, but no token, HMAC, or
secret. Existing decisions from before this change cannot be reconstructed.
Verification now runs in the bridge process so repeated sequence numbers are
recognized as replay attempts while the bridge remains running.

On the Pi, the dashboard service runs as `dashboard`. Give that account read
access to the profile and decision files, and write access to the revocation
file to enable Restore. A dedicated shared directory
avoids granting access to `token_secret.txt` or the client's TLS key. For
example, set `TOKEN_PROFILES`, `TOKEN_REVOKED`, and `TOKEN_DECISIONS` to files
in a directory owned by the bridge user with group `dashboard` and mode
`2770`; give the revocation file group write permission. Set the same three
variables for the dashboard service. If the revocation path is not writable,
Restore shows an error and leaves the file unchanged. Restoring a token device
does not clear a separate SDN quarantine.

## ECG HIDS data and patient privacy

The dashboard reads the HIDS's own files and never changes the HIDS. It finds
`full_log.jsonl`, `detection_results.jsonl` and `watchdog_alerts.jsonl`
anywhere up to three folders deep under `/home/*/HIDS` (or the repo's
`edge/`), using the newest copy of each. Set `HIDS_DIR` to search elsewhere.

`full_log.jsonl` also holds patient identity. The dashboard reads it through
an allow-list (`FULL_LOG_FIELDS` in `sources/hids.py`): name, patient ID, age,
sex, location, device IP and the raw ECG value are dropped as each line is
parsed, so they never reach the dashboard or a browser.

The live views refresh every 5 seconds. If the SDN API is unreachable the
dashboard shows the last saved `device_registry.json` read-only and disables
actions; if the IDS has not run, its page says so rather than erroring.

## Feeding it IDS data

The IDS is a script, not a service, so the dashboard reads the JSONL logs it
writes (`ids_events.jsonl`, `ids_runs.jsonl`, `ids_model_report.json`):

```bash
cd secure_medinet_ids
python3 train.py                 # writes the model card
python3 inference.py --live      # streams detections while you present
python3 inference.py             # or the one-off latency comparison
```

Set `SDN_DEVICE_MACS` before running so detections map to real MACs and the
gateway can act on them — otherwise the dashboard will (correctly) report them
as "not enforced".

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
unprivileged `dashboard` user under systemd, and blocks port 8501 on the
hotspot interfaces so IoT devices cannot reach it. Open
`http://<pi-eth0-ip>:8501` from a computer on the hospital LAN.

The service reads the IDS logs from `/home/chega/NIDS/logs` (set by
`IDS_LOG_DIR` in `systemd/secure-medinet-dashboard.service`). The `dashboard`
user must be able to enter the home directory: `chmod o+x /home/chega`. That
allows passing through without exposing a listing of its contents. If the IDS
lives elsewhere, change `IDS_LOG_DIR` there.

## Settings (environment variables)

| Variable | Default |
|---|---|
| `SDN_API_URL` | `http://127.0.0.1:5000` |
| `SDN_REGISTRY_PATH` | `../SDN/config/device_registry.json` |
| `IDS_LOG_DIR` | `../secure_medinet_ids/logs` |
| `IDS_MAX_EVENTS` | `500` (how much of the event log is read) |
| `HIDS_DIR` | `/home/*/HIDS` and the repo's HIDS `edge/` |
| `HIDS_MAX_READINGS` | `600` (newest readings read per refresh) |
| `HIDS_STALE_SEC` | `120` (older newest-reading = "not streaming") |
| `TOKEN_PROFILES` | newest `behavior_profile.json` under `/home/*/` or the repo |
| `TOKEN_REVOKED` | newest `revoked_devices.json` under `/home/*/` or the repo |
| `TOKEN_DECISIONS` | newest `token_decisions.jsonl` under `/home/*/` or the repo |
| `TOKEN_MAX_DECISIONS` | `500` (newest decisions read per refresh) |
| `DASHBOARD_REFRESH_SEC` | `5` |
| `DASHBOARD_PASSWORD` | unset (no login; development only) |

## Layout

```
Home.py                 overview across modules
pages/                  one detail view per module
sources/                one adapter per module -- the only code that
                        knows how a module exposes its data
theme.py                palette (dark, validated for the chart surface)
charts.py               Altair chart builders
ui.py                   shared widgets: tiles, tables, password gate
```

## Adding a module

1. Add `sources/<module>.py` that reads the module's API or output files.
2. Add `pages/<n>_<Module>.py` for the detail view.
3. Replace the module's "not connected yet" card in `Home.py` with a summary.
