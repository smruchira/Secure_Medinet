"""
temp_config.py
---------------
All configurable settings for the temperature sensor HIDS, mirroring
edge/config.py's pattern. Every value can be overridden by an
environment variable of the same name.

This is a separate module from edge/config.py on purpose (separate
ESP32 device, separate ML model, separate SDN-facing identity) so the
ECG pipeline needs zero changes to run this alongside it.
"""

import os
from pathlib import Path

TEMP_DIR = Path(__file__).resolve().parent


def _path_setting(name, default_name):
    value = os.environ.get(name)
    if value:
        return value
    return str(TEMP_DIR / default_name)


# --- Render ML API (same Render service as ECG; separate endpoint) ---
RENDER_API_URL = os.environ.get(
    "RENDER_API_URL",
    "https://cloud-ml-api.onrender.com",
)
RENDER_API_TIMEOUT_SEC = float(os.environ.get("RENDER_API_TIMEOUT_SEC", "30"))

# --- SDN Gateway (same gateway, same per-team contract as ECG) ---
SDN_GATEWAY_URL = os.environ.get("SDN_GATEWAY_URL", "http://10.0.0.1:5000")
SDN_GATEWAY_TIMEOUT_SEC = float(os.environ.get("SDN_GATEWAY_TIMEOUT_SEC", "3"))

# --- Threat response thresholds (decide drop vs rate_limit vs ignore) ---
TEMP_DROP_CONFIDENCE_THRESHOLD = float(os.environ.get("TEMP_DROP_CONFIDENCE_THRESHOLD", "0.8"))
TEMP_RATE_LIMIT_CONFIDENCE_THRESHOLD = float(os.environ.get("TEMP_RATE_LIMIT_CONFIDENCE_THRESHOLD", "0.5"))

# --- Watchdog settings ---
TEMP_WATCHDOG_TIMEOUT_SEC = float(os.environ.get("TEMP_WATCHDOG_TIMEOUT_SEC", "30"))
# Plausible range for a DS18B20 strapped to a patient (skin/body contact).
# Widen if you're using it for ambient/room monitoring instead.
MIN_PLAUSIBLE_TEMP_C = float(os.environ.get("MIN_PLAUSIBLE_TEMP_C", "25"))
MAX_PLAUSIBLE_TEMP_C = float(os.environ.get("MAX_PLAUSIBLE_TEMP_C", "42"))
# Fastest a real patient's skin temp can plausibly move between samples.
MAX_PLAUSIBLE_RATE_C = float(os.environ.get("MAX_PLAUSIBLE_RATE_C", "2.0"))

# --- File paths (local to RPi4) ---
FULL_LOG_PATH = _path_setting("TEMP_FULL_LOG_PATH", "full_log_temp.jsonl")
WATCHDOG_ALERTS_PATH = _path_setting("TEMP_WATCHDOG_ALERTS_PATH", "watchdog_alerts_temp.jsonl")
DETECTION_RESULTS_PATH = _path_setting("TEMP_DETECTION_RESULTS_PATH", "detection_results_temp.jsonl")

PROCESS_EXISTING_ENTRIES = os.environ.get("TEMP_PROCESS_EXISTING_ENTRIES", "1").lower() not in {
    "0", "false", "no"
}
