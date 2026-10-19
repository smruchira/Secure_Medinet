"""
temp_config.py
---------------
Training-side config for the temperature module, mirrors training/config.py's
pattern (paths relative to cwd, not package-relative -- run these scripts
from inside training/temp/).
"""

import os

RENDER_API_URL = os.environ.get(
    "RENDER_API_URL",
    "https://cloud-ml-api.onrender.com",
)
RENDER_API_TIMEOUT_SEC = float(os.environ.get("RENDER_API_TIMEOUT_SEC", "5"))

SDN_GATEWAY_URL = os.environ.get("SDN_GATEWAY_URL", "http://10.0.0.1:5000")
SDN_GATEWAY_TIMEOUT_SEC = float(os.environ.get("SDN_GATEWAY_TIMEOUT_SEC", "3"))

TEMP_DROP_CONFIDENCE_THRESHOLD = float(os.environ.get("TEMP_DROP_CONFIDENCE_THRESHOLD", "0.8"))
TEMP_RATE_LIMIT_CONFIDENCE_THRESHOLD = float(os.environ.get("TEMP_RATE_LIMIT_CONFIDENCE_THRESHOLD", "0.5"))

TEMP_WATCHDOG_TIMEOUT_SEC = float(os.environ.get("TEMP_WATCHDOG_TIMEOUT_SEC", "30"))
MIN_PLAUSIBLE_TEMP_C = float(os.environ.get("MIN_PLAUSIBLE_TEMP_C", "25"))
MAX_PLAUSIBLE_TEMP_C = float(os.environ.get("MAX_PLAUSIBLE_TEMP_C", "42"))
MAX_PLAUSIBLE_RATE_C = float(os.environ.get("MAX_PLAUSIBLE_RATE_C", "2.0"))

FULL_LOG_PATH = os.environ.get("TEMP_FULL_LOG_PATH", "full_log_temp.jsonl")
WATCHDOG_ALERTS_PATH = os.environ.get("TEMP_WATCHDOG_ALERTS_PATH", "watchdog_alerts_temp.jsonl")
DETECTION_RESULTS_PATH = os.environ.get("TEMP_DETECTION_RESULTS_PATH", "detection_results_temp.jsonl")
