"""
logger.py
---------
Writes the FULL log file (private data + features + label + source).
This is the "local, private" log that stays on the RPi4 and never
leaves the device.

ESP32 sends raw fields (patient_id, patient_name, age, sex, location,
device_mac, device_ip, raw_ecg_value). RPi4 adds the computed feature
fields via feature_extractor.py before logging.
"""

import json
import hashlib
import numpy as np
from datetime import datetime, timezone

import config

# Tracks fingerprints of raw windows already logged, so repeated
# (replayed) windows can be flagged automatically. This is a simple
# host-side "duplicate detection" watchdog check -- feeds the
# is_duplicate_window feature that the ML model uses to catch replay
# attacks.
_seen_window_hashes = set()


def _window_hash(raw_window):
    rounded = np.round(np.array(raw_window, dtype=float), 3)
    return hashlib.sha256(rounded.tobytes()).hexdigest()


def _is_duplicate_window(raw_window):
    h = _window_hash(raw_window)
    is_dup = 1 if h in _seen_window_hashes else 0
    _seen_window_hashes.add(h)
    return is_dup


def make_log_entry(patient_info, raw_window, features, source="synthetic", label="normal"):
    """
    Builds one full log entry (dict) combining:
      - private patient/device info (stays local, never sent to cloud)
      - raw ecg value (last sample of window, representative)
      - computed features (the only part that gets sent to the cloud)
      - source (synthetic/real) and label (attack type or normal, used
        for training/demo -- real deployments would leave label unset
        until the ML model determines it)
    """
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),

        # PRIVATE fields (never sent to cloud)
        "patient_id": patient_info["patient_id"],
        "patient_name": patient_info["patient_name"],
        "age": patient_info["age"],
        "sex": patient_info["sex"],
        "location": patient_info["location"],
        "device_mac": patient_info["device_mac"],
        "device_ip": patient_info["device_ip"],
        "raw_ecg_value": float(raw_window[-1]) if len(raw_window) else None,

        # FEATURE fields (safe to send to cloud) -- cast to native float
        # to avoid JSON serialization errors from numpy types
        "hr_bpm": float(features["hr_bpm"]),
        "rr_interval": float(features["rr_interval"]),
        "signal_entropy": float(features["signal_entropy"]),
        "qrs_amplitude": float(features["qrs_amplitude"]),
        "sampling_gap_ms": float(features["sampling_gap_ms"]),
        "is_duplicate_window": _is_duplicate_window(raw_window),

        # META
        "source": source,   # "synthetic" or "real"
        "label": label,     # "normal", "sensor_spoofing", "firmware_tampering",
                             # "replay_attack", "data_tampering", "device_masquerading"
    }
    return entry


def write_log_entry(entry, path=None):
    """Appends one JSON line to the full log file."""
    path = path or config.FULL_LOG_PATH
    with open(path, "a") as f:
        f.write(json.dumps(entry) + "\n")
