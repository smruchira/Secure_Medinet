"""
config.py
----------
All configurable settings in one place. Every value can be overridden
by setting an environment variable of the same name, so you never have
to edit code to change a URL or threshold -- just set env vars.

Example (Linux/Mac):
    export RENDER_API_URL="https://cloud-ml-api.onrender.com"

Example (Windows PowerShell):
    $env:RENDER_API_URL="https://cloud-ml-api.onrender.com"
"""

import os
from pathlib import Path


# Resolve runtime files relative to this edge package, not the caller's
# current working directory. This keeps demo_stream.py and orchestrator.py
# connected even when launched from different directories.
EDGE_DIR = Path(__file__).resolve().parent


def _path_setting(name, default_name):
    value = os.environ.get(name)
    if value:
        return value
    return str(EDGE_DIR / default_name)

# --- Render ML API (the cloud detection service) ---
RENDER_API_URL = os.environ.get(
    "RENDER_API_URL",
    "https://cloud-ml-api.onrender.com",
)
RENDER_API_TIMEOUT_SEC = float(os.environ.get("RENDER_API_TIMEOUT_SEC", "30"))

# --- SDN Gateway (network enforcement service, per team contract) ---
SDN_GATEWAY_URL = os.environ.get("SDN_GATEWAY_URL", "http://10.0.0.1:5000")
SDN_GATEWAY_TIMEOUT_SEC = float(os.environ.get("SDN_GATEWAY_TIMEOUT_SEC", "3"))

# --- Threat response thresholds (decide drop vs rate_limit vs ignore) ---
DROP_CONFIDENCE_THRESHOLD = float(os.environ.get("DROP_CONFIDENCE_THRESHOLD", "0.8"))
RATE_LIMIT_CONFIDENCE_THRESHOLD = float(os.environ.get("RATE_LIMIT_CONFIDENCE_THRESHOLD", "0.5"))

# --- Watchdog settings ---
WATCHDOG_TIMEOUT_SEC = float(os.environ.get("WATCHDOG_TIMEOUT_SEC", "15"))
MIN_PLAUSIBLE_HR = float(os.environ.get("MIN_PLAUSIBLE_HR", "30"))
MAX_PLAUSIBLE_HR = float(os.environ.get("MAX_PLAUSIBLE_HR", "220"))

# --- File paths (local to RPi4) ---
FULL_LOG_PATH = _path_setting("FULL_LOG_PATH", "full_log.jsonl")
WATCHDOG_ALERTS_PATH = _path_setting("WATCHDOG_ALERTS_PATH", "watchdog_alerts.jsonl")
DETECTION_RESULTS_PATH = _path_setting("DETECTION_RESULTS_PATH", "detection_results.jsonl")

# Process records already present when the orchestrator starts. This makes
# the local demo immediately visible while remaining configurable for a
# production deployment that should only consume new records.
PROCESS_EXISTING_ENTRIES = os.environ.get("PROCESS_EXISTING_ENTRIES", "1").lower() not in {
    "0", "false", "no"
}
