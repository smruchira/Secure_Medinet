"""
sources/ids.py
--------------
Reads the Edge IDS ensemble's runtime logs (written by
secure_medinet_ids/utils/event_log.py). Files only -- the IDS runs as a
script, not a service, and the dashboard never imports its code, so the
dashboard needs neither PyTorch nor the trained models.
"""

import json
import os
from pathlib import Path

import pandas as pd

import settings
from sources._jsonl import read_tail


def log_status():
    """Why the IDS page might be empty. Returns (state, folder) where state is
    'ok' (IDS logs found), 'empty' (folder readable, no IDS logs yet),
    'missing' (folder does not exist) or 'unreadable' (no permission --
    typically the dashboard's service user cannot enter the IDS owner's home
    directory)."""
    folder = Path(settings.IDS_LOG_DIR)
    try:
        names = os.listdir(folder)
    except FileNotFoundError:
        return "missing", folder
    except PermissionError:
        return "unreadable", folder
    except OSError:
        return "missing", folder
    return ("ok" if any(n.startswith("ids_") for n in names) else "empty"), folder


def _read_jsonl(path, limit):
    """The newest `limit` records, oldest first (see sources/_jsonl.py)."""
    return read_tail(path, limit)


DETECTION_COLUMNS = [
    "timestamp", "window_index", "device_id", "device_mac", "threat_type",
    "fused_confidence", "isolation_forest", "autoencoder", "lstm",
    "enforced", "sdn_action", "sdn_status", "sdn_detail",
]


def get_detections(limit=None):
    """Confirmed threats as a DataFrame, newest first. Tier scores are
    flattened into one column per tier. When there are none (the IDS has not
    run, or its first passes confirmed nothing) the frame is empty but still
    has every column, so callers never fail on a missing one."""
    rows = _read_jsonl(settings.IDS_EVENTS_PATH, limit=limit or settings.IDS_MAX_EVENTS)
    if not rows:
        empty = pd.DataFrame(columns=DETECTION_COLUMNS)
        empty["timestamp"] = pd.to_datetime(empty["timestamp"], utc=True)
        return empty

    for row in rows:
        for tier, score in (row.pop("tier_scores", None) or {}).items():
            row[tier] = score
        # Long transport errors are useless in a table; keep the first clause.
        detail = row.get("sdn_detail")
        if detail:
            row["sdn_detail"] = str(detail).split(" (Caused by")[0][:120]

    df = pd.DataFrame(rows)
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    return df.sort_values("timestamp", ascending=False, na_position="last")


def get_runs(limit=25):
    """Recent inference runs (latency + gating), newest first."""
    rows = _read_jsonl(settings.IDS_RUNS_PATH, limit=limit)
    if not rows:
        return pd.DataFrame()
    df = pd.DataFrame(rows)
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    return df.sort_values("timestamp", ascending=False, na_position="last")


def get_model_report():
    """The last training run's evaluation, or None if train.py has not run."""
    try:
        return json.loads(Path(settings.IDS_MODEL_REPORT_PATH).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def device_mac(row):
    """The MAC a detection belongs to, for lining it up against the SDN
    gateway's device list. Falls back to the device_id for older log lines
    written before the MAC was recorded, and for IDs that are already MACs."""
    mac = row.get("device_mac")
    if mac and str(mac) != "nan":
        return str(mac).strip().lower()
    candidate = str(row.get("device_id", "")).strip().lower().replace("-", ":")
    return candidate


def summarize(detections):
    """Headline counts for the KPI row."""
    if detections.empty:
        return {"detections": 0, "devices": 0, "enforced": 0, "unenforced": 0,
                "last_seen": None}
    enforced = int(detections["enforced"].sum()) if "enforced" in detections else 0
    return {
        "detections": len(detections),
        "devices": detections["device_id"].nunique(),
        "enforced": enforced,
        "unenforced": len(detections) - enforced,
        "last_seen": detections["timestamp"].max(),
    }


def latest_latency(runs):
    """Per-stage latency from the most recent run as a tidy DataFrame."""
    if runs.empty:
        return pd.DataFrame(), None
    latest = runs.iloc[0]
    stages = latest.get("latency_ms") or {}
    if not isinstance(stages, dict) or not stages:
        return pd.DataFrame(), latest
    rows = [
        {"stage": _stage_label(name), "mean_ms": vals.get("mean"),
         "p95_ms": vals.get("p95"), "windows": vals.get("n")}
        for name, vals in stages.items()
    ]
    return pd.DataFrame(rows), latest


def _stage_label(name):
    return {
        "tier1_isolation_forest": "Tier 1 · Isolation Forest",
        "tier2a_autoencoder": "Tier 2a · AutoEncoder",
        "tier2b_lstm": "Tier 2b · LSTM",
        "fusion": "Fusion",
    }.get(name, name.replace("_", " ").title())
