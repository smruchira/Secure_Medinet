"""
settings.py
-----------
Dashboard settings. Every value can be overridden with an environment
variable of the same name, so nothing needs editing for deployment.
"""

import os
from pathlib import Path

REPO_DIR = Path(__file__).resolve().parent.parent

# --- SDN Gateway (SDN/sdn/alert_api.py) ---
# The dashboard runs on the same Raspberry Pi as the SDN API.
SDN_API_URL = os.environ.get("SDN_API_URL", "http://127.0.0.1:5000")
SDN_TIMEOUT_SEC = float(os.environ.get("SDN_TIMEOUT_SEC", "2"))
# Read-only fallback when the API is unreachable (e.g. developing off the Pi).
SDN_REGISTRY_PATH = os.environ.get(
    "SDN_REGISTRY_PATH", str(REPO_DIR / "SDN" / "config" / "device_registry.json")
)

# --- UI ---
REFRESH_SEC = int(os.environ.get("DASHBOARD_REFRESH_SEC", "5"))
# Shared password for the dashboard. Leave unset only for local development:
# the dashboard can change live network policy.
PASSWORD = os.environ.get("DASHBOARD_PASSWORD", "")
