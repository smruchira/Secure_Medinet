"""
sources/hids.py
---------------
Reads the ECG HIDS edge logs (ecg_hids_final/.../edge): the readings log
full_log.jsonl, the per-reading decisions detection_results.jsonl, and
watchdog_alerts.jsonl. Files only; the HIDS is never imported or modified.

PRIVACY: full_log.jsonl also holds patient identity (patient_id, name, age,
sex, location), the device IP and the raw ECG value. The HIDS's own design is
that these never leave the edge, so the dashboard honours it: FULL_LOG_FIELDS
is an allow-list applied as each line is parsed, so identity never enters the
dashboard's memory or reaches a browser.
"""

from datetime import datetime, timezone

import pandas as pd

import settings
from sources._jsonl import read_tail

FULL_LOG_FIELDS = (
    "timestamp", "device_mac", "hr_bpm", "rr_interval", "signal_entropy",
    "qrs_amplitude", "sampling_gap_ms", "is_duplicate_window", "source",
)
RESULT_FIELDS = (
    "timestamp", "watchdog_alerts", "ml_prediction", "ml_confidence", "sdn_action",
)
# Predictions that are not an attack: a normal reading, or no verdict because
# the cloud model could not be reached.
NOT_ATTACK = {"normal", "ml_unavailable", None}

READING_COLUMNS = ["timestamp", *FULL_LOG_FIELDS[1:], "ml_prediction",
                   "ml_confidence", "sdn_action", "watchdog_alerts", "is_attack"]


def status():
    """Which HIDS files were found: {kind: path or None}."""
    return {kind: settings.hids_path(kind) for kind in settings.HIDS_FILES}


def get_readings(limit=None):
    """Recent readings joined to their detection result, newest first.

    detection_results.jsonl has no device MAC, but each result carries the
    timestamp of the reading it judged, so the join is on that timestamp.
    Always returns every column in READING_COLUMNS, even when empty.
    """
    limit = limit or settings.HIDS_MAX_READINGS
    readings = read_tail(settings.hids_path("full_log") or "", limit, FULL_LOG_FIELDS)
    results = read_tail(settings.hids_path("results") or "", limit, RESULT_FIELDS)

    if not readings and not results:
        empty = pd.DataFrame(columns=READING_COLUMNS)
        empty["timestamp"] = pd.to_datetime(empty["timestamp"], utc=True)
        empty["is_attack"] = empty["is_attack"].astype(bool)
        return empty

    left = pd.DataFrame(readings or [{"timestamp": None}])
    right = pd.DataFrame(results or [{"timestamp": None}])
    left = left.dropna(subset=["timestamp"]).drop_duplicates("timestamp", keep="last")
    right = right.dropna(subset=["timestamp"]).drop_duplicates("timestamp", keep="last")
    df = left.merge(right, on="timestamp", how="outer")

    for column in READING_COLUMNS:
        if column not in df.columns:
            df[column] = None
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    df["device_mac"] = df["device_mac"].map(
        lambda mac: str(mac).strip().lower() if isinstance(mac, str) else None)
    df["is_attack"] = ~df["ml_prediction"].map(
        lambda p: p if isinstance(p, str) else None).isin(NOT_ATTACK)
    df["watchdog_alerts"] = df["watchdog_alerts"].map(
        lambda alerts: list(alerts) if isinstance(alerts, list) else [])
    return (df[READING_COLUMNS]
            .sort_values("timestamp", ascending=False, na_position="last")
            .reset_index(drop=True))


def attacks(readings):
    """Readings the cloud model judged to be an attack, shaped like IDS
    detections (timestamp, threat_type) so the shared charts accept them."""
    # astype(bool): on an empty frame the column has object dtype, and pandas
    # would read a non-boolean Series as a list of columns to select.
    flagged = readings[readings["is_attack"].astype(bool)].copy()
    flagged["threat_type"] = flagged["ml_prediction"]
    return flagged


def get_watchdog_alerts(limit=50):
    """Rule-based watchdog alerts, newest first, one row per alert."""
    rows = []
    for record in read_tail(settings.hids_path("watchdog") or "", limit):
        for alert in record.get("alerts") or []:
            rows.append({"timestamp": record.get("timestamp"), "alert": str(alert)})
    df = pd.DataFrame(rows, columns=["timestamp", "alert"])
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    return df.sort_values("timestamp", ascending=False, na_position="last")


def summarize(readings):
    """Headline numbers for the KPI row."""
    judged = readings[readings["ml_prediction"].notna()]
    unavailable = int((judged["ml_prediction"] == "ml_unavailable").sum())
    last = readings["timestamp"].max() if not readings.empty else None
    age = None
    if last is not None and pd.notna(last):
        age = (datetime.now(timezone.utc) - last.to_pydatetime()).total_seconds()
    return {
        "readings": len(readings),
        "attacks": int(readings["is_attack"].sum()),
        "drop": int((readings["sdn_action"] == "drop").sum()),
        "rate_limit": int((readings["sdn_action"] == "rate_limit").sum()),
        "watchdog": int(readings["watchdog_alerts"].map(len).sum()),
        "ml_unavailable": unavailable,
        "ml_judged": len(judged),
        "devices": readings["device_mac"].dropna().nunique(),
        "last_seen": last,
        "streaming": age is not None and age <= settings.HIDS_STALE_SEC,
        "age_sec": age,
    }


def describe_age(seconds):
    if seconds is None:
        return "no readings"
    if seconds < 90:
        return f"{seconds:.0f}s ago"
    if seconds < 5400:
        return f"{seconds / 60:.0f} min ago"
    if seconds < 172800:
        return f"{seconds / 3600:.0f} h ago"
    return f"{seconds / 86400:.0f} days ago"
