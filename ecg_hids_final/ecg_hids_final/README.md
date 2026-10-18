# ECG Host-Based Intrusion Detection System (HIDS) — Privacy-Preserving Module

Research module: detects host-based attacks on an ECG sensor device
(spoofing, tampering, replay, masquerading), preserves patient privacy
by stripping identifying data before anything leaves the edge device,
and enforces network-level response via integration with a teammate's
SDN Gateway module.

## Architecture

```
ESP32 (ECG sensor)
   |  raw values, WiFi
   v
RPi4 [edge/]
   - esp32_listener.py   receives raw data
   - feature_extractor   raw -> 6 ML features
   - logger              writes full private log (local only)
   - watchdog            fast rule-based checks (timeout, plausibility)
   - privacy_strip       strips to cloud-safe features
   |
   |  6 numbers only, HTTPS -- no patient data
   v
Render [cloud/]
   - FastAPI service, stateless
   - Loads trained Random Forest model
   - POST /predict -> {prediction, confidence}
   |
   |  prediction result
   v
RPi4 [edge/orchestrator.py]
   - decides: ignore / rate_limit / drop
   |
   |  POST /alert {mac, action, score, type}
   v
SDN Gateway (teammate's module, local network)
   - enforces quarantine / rate-limit on the device's MAC
```

## Folder structure

- **`edge/`** — everything that runs on the RPi4. This is where private
  patient data lives and where privacy-stripping happens.
- **`cloud/`** — the FastAPI service to deploy on Render. Stateless,
  never sees patient data, only the 6 anonymized features.
- **`training/`** — offline, one-time scripts to generate the synthetic
  dataset and train the model. Not needed at runtime.

## Setup

### 1. Deploy the cloud ML API (Render)

1. Push the `cloud/` folder to a GitHub repo (or connect Render directly).
2. On [render.com](https://render.com), create a new Web Service from
   that repo. Render will detect `render.yaml` automatically, or set:
   - Build command: `pip install -r requirements.txt`
   - Start command: `uvicorn main:app --host 0.0.0.0 --port $PORT`
3. Once deployed, copy your service URL (e.g. `https://ecg-attack-detection-api.onrender.com`).

### 2. Set up the RPi4 (edge)

```bash
cd edge
pip install -r requirements.txt --break-system-packages

# Point at your deployed Render service:
export RENDER_API_URL="https://your-app.onrender.com"

# Point at the teammate's SDN gateway (adjust to actual IP):
export SDN_GATEWAY_URL="http://10.0.0.1:5000"
```

### 3. Run it

Three processes, each in its own terminal:

```bash
# Terminal 1: receive real ESP32 data over WiFi
python3 esp32_listener.py

# (or, if testing without real hardware yet:)
python3 demo_stream.py

# Terminal 2: the detection pipeline itself
python3 orchestrator.py
```

`orchestrator.py` watches for new entries, runs the watchdog, calls
the Render API, and enforces via the SDN gateway when an attack is
detected with sufficient confidence.

## Configuration

All settings are environment variables (see `edge/config.py` for the
full list and defaults), so nothing needs to be hardcoded or edited
in the code:

| Variable | Purpose | Default |
|---|---|---|
| `RENDER_API_URL` | Where the cloud ML service lives | `https://cloud-ml-api.onrender.com` |
| `SDN_GATEWAY_URL` | Where the SDN gateway lives | `http://10.0.0.1:5000` |
| `DROP_CONFIDENCE_THRESHOLD` | Confidence above which to quarantine | `0.8` |
| `RATE_LIMIT_CONFIDENCE_THRESHOLD` | Confidence above which to rate-limit | `0.5` |
| `WATCHDOG_TIMEOUT_SEC` | Seconds of silence before a timeout alert | `15` |

## Retraining the model

If you collect more data (synthetic or real) later:

```bash
cd training
python3 generate_dataset.py   # regenerate/expand the dataset
python3 train_model.py        # retrain, saves ecg_attack_model.joblib
```

Then copy the new `ecg_attack_model.joblib` into `cloud/` and redeploy
to Render.

## Privacy design note

The core research claim of this module: **private patient data never
leaves the RPi4.** Only 6 numeric, non-identifying features
(`hr_bpm`, `rr_interval`, `signal_entropy`, `qrs_amplitude`,
`sampling_gap_ms`, `is_duplicate_window`) are sent to the cloud. Name,
patient ID, age, sex, location, device MAC, device IP, and raw ECG
values all stay local, in `full_log.jsonl`, and are never transmitted.
