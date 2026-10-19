"""
settings.py
-----------
Dashboard settings. Every value can be overridden with an environment
variable of the same name, so nothing needs editing for deployment.
"""

import os
import time
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

# --- Edge IDS ensemble (secure_medinet_ids/utils/event_log.py) ---
# Files only: the IDS is a script, not a service. Point these at the Pi's
# copy of the module (IDS_LOG_DIR there) if it lives outside this repo.
def _default_ids_log_dir():
    """First candidate folder that already holds IDS logs, so the dashboard
    finds the IDS wherever it was installed. IDS_LOG_DIR always wins."""
    candidates = [
        REPO_DIR / "secure_medinet_ids" / "logs",      # running from the repo
        Path("/opt/secure-medinet-ids/logs"),
        *sorted(Path("/home").glob("*/NIDS/logs")),    # e.g. /home/chega/NIDS/logs
    ]
    for folder in candidates:
        try:
            if any(name.startswith("ids_") for name in os.listdir(folder)):
                return str(folder)
        except OSError:
            continue
    return str(candidates[0])


IDS_LOG_DIR = os.environ.get("IDS_LOG_DIR") or _default_ids_log_dir()
IDS_EVENTS_PATH = os.environ.get(
    "IDS_EVENTS_LOG", str(Path(IDS_LOG_DIR) / "ids_events.jsonl")
)
IDS_RUNS_PATH = os.environ.get(
    "IDS_RUNS_LOG", str(Path(IDS_LOG_DIR) / "ids_runs.jsonl")
)
IDS_MODEL_REPORT_PATH = os.environ.get(
    "IDS_MODEL_REPORT", str(Path(IDS_LOG_DIR) / "ids_model_report.json")
)
# Cap how much of the event log is read into memory on the Pi.
IDS_MAX_EVENTS = int(os.environ.get("IDS_MAX_EVENTS", "500"))

# --- ECG HIDS (ecg_hids_final/.../edge) ---
# The HIDS writes three JSONL files. Installs differ (the Pi keeps full_log at
# ~/HIDS while results may sit in a subfolder), so each file is found on its
# own: HIDS_<KIND> env var if set, else the newest copy under the search roots.
HIDS_FILES = {
    "full_log": "full_log.jsonl",          # readings (identity fields dropped on read)
    "results": "detection_results.jsonl",  # watchdog + ML + SDN decision per reading
    "watchdog": "watchdog_alerts.jsonl",   # rule-based alerts only
}
HIDS_SEARCH_ROOTS = [
    Path(p) for p in os.environ.get("HIDS_DIR", "").split(os.pathsep) if p
] or [
    REPO_DIR / "ecg_hids_final" / "ecg_hids_final" / "edge",
    *sorted(Path("/home").glob("*/HIDS")),         # e.g. /home/chega/HIDS
]
HIDS_SEARCH_DEPTH = 3
HIDS_MAX_READINGS = int(os.environ.get("HIDS_MAX_READINGS", "600"))
# A reading older than this means the HIDS is not streaming right now.
HIDS_STALE_SEC = int(os.environ.get("HIDS_STALE_SEC", "120"))

_SKIP_DIRS = {"venv", ".venv", "__pycache__", "site-packages", ".git", "node_modules"}
_hids_cache = {"at": 0.0, "paths": {}}


def hids_path(kind):
    """Path of the HIDS file `kind` ('full_log' | 'results' | 'watchdog'),
    or None if it cannot be found. Searched at most once a minute, so a HIDS
    started after the dashboard is still picked up."""
    override = os.environ.get(f"HIDS_{kind.upper()}")
    if override:
        return override
    now = time.monotonic()
    if now - _hids_cache["at"] > 60 or kind not in _hids_cache["paths"]:
        _hids_cache["paths"] = _find_hids_files()
        _hids_cache["at"] = now
    return _hids_cache["paths"].get(kind)


def _find_hids_files():
    wanted = {name: kind for kind, name in HIDS_FILES.items()}
    found = {}
    for root in HIDS_SEARCH_ROOTS:
        base_depth = str(root).rstrip(os.sep).count(os.sep)
        for folder, dirs, files in os.walk(root, onerror=lambda _err: None):
            if folder.count(os.sep) - base_depth >= HIDS_SEARCH_DEPTH:
                dirs[:] = []
            dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
            for name in files:
                kind = wanted.get(name)
                if not kind:
                    continue
                path = os.path.join(folder, name)
                try:
                    mtime = os.path.getmtime(path)
                except OSError:
                    continue
                # Several copies (an old run, a backup): use the newest.
                if kind not in found or mtime > found[kind][0]:
                    found[kind] = (mtime, path)
    return {kind: path for kind, (_, path) in found.items()}


# --- Behavioural token binding (behavioural_token_binding/) ---
# The bridge keeps two JSON state files in its user's home directory. Each is
# found on its own: TOKEN_<KIND> env var if set, else the newest copy.
TOKEN_FILES = {
    "profiles": "behavior_profile.json",   # learned timing per device
    "revoked": "revoked_devices.json",     # revoked devices and why
    "decisions": "token_decisions.jsonl",  # accept/reject outcomes, without token material
}
TOKEN_MAX_DECISIONS = int(os.environ.get("TOKEN_MAX_DECISIONS", "500"))
# Mirrors behavior_profiler.check_behavior: an interval is accepted when it is
# within max(1 s, 50% of the learned mean) of that mean.
TOKEN_TOLERANCE_MIN_SEC = 1.0
TOKEN_TOLERANCE_FRACTION = 0.5


def token_path(kind):
    """Path of the token-binding file `kind` ('profiles' | 'revoked'), or
    None if not found."""
    override = os.environ.get(f"TOKEN_{kind.upper()}")
    if override:
        return override
    name = TOKEN_FILES[kind]
    candidates = [*Path("/home").glob(f"*/{name}"),
                  REPO_DIR / "behavioural_token_binding" / name]
    existing = []
    for path in candidates:
        try:
            existing.append((path.stat().st_mtime, str(path)))
        except OSError:
            continue
    return max(existing)[1] if existing else None


# --- UI ---
REFRESH_SEC = int(os.environ.get("DASHBOARD_REFRESH_SEC", "5"))
# Shared password for the dashboard. Leave unset only for local development:
# the dashboard can change live network policy.
PASSWORD = os.environ.get("DASHBOARD_PASSWORD", "")
