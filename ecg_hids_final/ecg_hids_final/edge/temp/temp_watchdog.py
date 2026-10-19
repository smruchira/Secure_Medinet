"""
temp_watchdog.py
------------------
Fast, rule-based checks that run locally on RPi4, independent of the
ML model. Mirrors watchdog.py's two checks, adapted for temperature:

  1. TIMEOUT: has data stopped arriving recently?
  2. PLAUSIBILITY: is mean_temp_c within a realistic human range, and
     is max_rate_of_change within a realistic per-sample jump?
"""

import json
import time
import logging

import temp_config as config

logger = logging.getLogger("temp_watchdog")

_last_entry_epoch = None


def check_entry(entry):
    """
    Runs both watchdog checks on a single temperature log entry.
    Returns a list of alert strings (empty list = all clear).
    """
    global _last_entry_epoch
    alerts = []
    now = time.time()

    # --- Plausibility: temperature range ---
    temp = entry.get("mean_temp_c")
    if temp is not None and (temp < config.MIN_PLAUSIBLE_TEMP_C or temp > config.MAX_PLAUSIBLE_TEMP_C):
        alert = f"implausible_temp_c({temp})"
        alerts.append(alert)
        logger.warning(f"Watchdog alert: {alert}")

    # --- Plausibility: rate of change ---
    rate = entry.get("max_rate_of_change")
    if rate is not None and rate > config.MAX_PLAUSIBLE_RATE_C:
        alert = f"implausible_rate_of_change({rate})"
        alerts.append(alert)
        logger.warning(f"Watchdog alert: {alert}")

    # --- Timeout check (gap since previous entry) ---
    if _last_entry_epoch is not None:
        gap = now - _last_entry_epoch
        if gap > config.TEMP_WATCHDOG_TIMEOUT_SEC:
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
