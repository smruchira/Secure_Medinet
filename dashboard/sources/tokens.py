"""
sources/tokens.py
-----------------
Reads the bridge's timing profiles, revocation list and decision log.
Only explicitly allowed decision fields reach the dashboard.
"""

import json
import re
from datetime import datetime, timezone

import pandas as pd

import settings
from sources._jsonl import read_tail

DEVICE_COLUMNS = ["device_id", "state", "mean_interval", "std_interval",
                  "tolerance", "sample_count", "last_seen", "reason", "samples",
                  "rejected_interval"]

# The bridge never adds the token that got a device revoked to its history,
# but the revocation reason records it: "...(interval=25s expected=3.034s)".
_REJECTED = re.compile(r"interval=([0-9.]+)s")
DECISION_COLUMNS = ["timestamp", "device_id", "decision", "stage", "reason",
                    "revoked", "sdn_status"]


def _rejected_interval(reason):
    match = _REJECTED.search(reason or "")
    return float(match.group(1)) if match else None


def _load(kind):
    path = settings.token_path(kind)
    if not path:
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):   # unreadable, or mid-write by the bridge
        return {}
    return data if isinstance(data, dict) else {}


def status():
    return {kind: settings.token_path(kind) for kind in settings.TOKEN_FILES}


def get_decisions():
    """Newest first; tolerate an absent or partially written log."""
    path = settings.token_path("decisions")
    records = read_tail(path, settings.TOKEN_MAX_DECISIONS, DECISION_COLUMNS) if path else []
    df = pd.DataFrame(records, columns=DECISION_COLUMNS)
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    return df.dropna(subset=["timestamp"]).sort_values("timestamp", ascending=False)


def rejection_counts(decisions):
    rejected = decisions[decisions["decision"] == "rejected"]
    if rejected.empty:
        return pd.DataFrame(columns=["reason", "count"])
    labels = rejected["reason"].fillna("UNKNOWN").astype(str).str.replace(
        r"^ABNORMAL TIMING.*", "ABNORMAL TIMING", regex=True)
    counts = labels.value_counts()
    return pd.DataFrame({"reason": counts.index, "count": counts.values})


def restore_device(device_id):
    """Remove one revocation from the configured file, if writable."""
    path = settings.token_path("revoked")
    if not path:
        return False, "Revocation file not found."
    try:
        with open(path, "r", encoding="utf-8") as source:
            revoked = json.load(source)
        if not isinstance(revoked, dict) or device_id not in revoked:
            return False, "Device is no longer revoked."
        del revoked[device_id]
        # Match revocation_manager.save_revoked_devices: keep file ownership
        # with the bridge user, which must continue writing future revocations.
        with open(path, "w", encoding="utf-8") as output:
            json.dump(revoked, output, indent=2)
    except (OSError, ValueError) as exc:
        return False, f"Could not restore device: {exc}"
    return True, f"Restored {device_id} in token binding. Restore its SDN policy separately if needed."


def get_devices():
    """One row per device seen in either file, revoked devices first."""
    profiles = _load("profiles")
    revoked = _load("revoked")
    rows = []
    for device_id in sorted(set(profiles) | set(revoked)):
        profile = profiles.get(device_id) or {}
        mean = profile.get("mean_interval")
        last = profile.get("last_timestamp")
        if device_id in revoked:
            state = "revoked"
        elif mean is None:
            state = "learning"
        else:
            state = "trusted"
        reason = (revoked.get(device_id) or {}).get("reason", "")
        rows.append({
            "device_id": device_id,
            "state": state,
            "mean_interval": mean,
            "std_interval": profile.get("std_interval"),
            "tolerance": None if mean is None else max(
                settings.TOKEN_TOLERANCE_MIN_SEC,
                mean * settings.TOKEN_TOLERANCE_FRACTION),
            "sample_count": profile.get("sample_count", 0),
            "last_seen": (datetime.fromtimestamp(last, tz=timezone.utc)
                          if isinstance(last, (int, float)) else None),
            "reason": reason,
            "samples": list(profile.get("samples") or []),
            "rejected_interval": _rejected_interval(reason),
        })
    df = pd.DataFrame(rows, columns=DEVICE_COLUMNS)
    df["last_seen"] = pd.to_datetime(df["last_seen"], utc=True)
    order = {"revoked": 0, "learning": 1, "trusted": 2}
    return df.sort_values("state", key=lambda s: s.map(order)).reset_index(drop=True)


def summarize(devices):
    last = devices["last_seen"].max() if not devices.empty else None
    return {
        "devices": len(devices),
        "trusted": int((devices["state"] == "trusted").sum()),
        "learning": int((devices["state"] == "learning").sum()),
        "revoked": int((devices["state"] == "revoked").sum()),
        "last_seen": last if last is not None and pd.notna(last) else None,
    }
