"""
watchdog.py
------------
Fast, rule-based checks that run locally on RPi4, independent of the
ML model. Two checks:

  1. TIMEOUT: has data stopped arriving recently?
  2. PLAUSIBILITY: is hr_bpm within a realistic human range?

Exposes check_entry() for use by orchestrator.py (real-time, per-entry
checking) and can also run standalone as a background watcher.
"""

import json
import time
import logging

import config

logger = logging.getLogger("watchdog")

_last_entry_epoch = None  # tracks time of previous entry, for timeout check


def check_entry(entry):
    """
    Runs both watchdog checks on a single log entry.
    Returns a list of alert strings (empty list = all clear).
    Updates internal state so the next call can detect timing gaps.
    """
    global _last_entry_epoch
    alerts = []
    now = time.time()

    # --- Plausibility check ---
    hr = entry.get("hr_bpm")
    if hr is not None and (hr < config.MIN_PLAUSIBLE_HR or hr > config.MAX_PLAUSIBLE_HR):
        alert = f"implausible_hr_bpm({hr})"
        alerts.append(alert)
        logger.warning(f"Watchdog alert: {alert}")

    # --- Timeout check (gap since previous entry) ---
    if _last_entry_epoch is not None:
        gap = now - _last_entry_epoch
        if gap > config.WATCHDOG_TIMEOUT_SEC:
            alert = f"large_gap_since_last_entry({gap:.1f}s)"
            alerts.append(alert)
            logger.warning(f"Watchdog alert: {alert}")

    _last_entry_epoch = now

    if alerts:
        _write_alerts(entry, alerts)

    return alerts


def _write_alerts(entry, alerts):
    record = {
        "timestamp": entry.get("timestamp"),
        "alerts": alerts,
    }
    with open(config.WATCHDOG_ALERTS_PATH, "a") as f:
        f.write(json.dumps(record) + "\n")
