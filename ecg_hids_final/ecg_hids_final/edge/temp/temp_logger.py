"""
temp_logger.py
---------------
Writes the FULL temperature log file (private data + features + label
+ source). Stays on the RPi4, never leaves the device. Mirrors
logger.py exactly.

ESP32 (temp) sends raw fields (patient_id, patient_name, age, sex,
location, device_mac, device_ip, raw_temp_value). The RPi4 adds
computed feature fields via temp_feature_extractor.py before logging.
"""

import json
import hashlib
import numpy as np
from datetime import datetime, timezone

import temp_config as config

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
      - raw temp value (last sample of window, representative)
      - computed features (the only part that gets sent to the cloud)
      - source (synthetic/real) and label
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
        "raw_temp_value": float(raw_window[-1]) if len(raw_window) else None,

        # FEATURE fields (safe to send to cloud)
        "mean_temp_c": float(features["mean_temp_c"]),
        "temp_std_c": float(features["temp_std_c"]),
        "max_rate_of_change": float(features["max_rate_of_change"]),
        "signal_entropy": float(features["signal_entropy"]),
        "sampling_gap_ms": float(features["sampling_gap_ms"]),
        "is_duplicate_window": _is_duplicate_window(raw_window),

        # META
        "source": source,   # "synthetic" or "real"
        "label": label,     # "normal", "sensor_spoofing", "firmware_tampering",
                             # "replay_attack", "data_tampering", "device_masquerading"
    }
    return entry


def write_log_entry(entry, path=None):
    """Appends one JSON line to the full temperature log file."""
    path = path or config.FULL_LOG_PATH
    with open(path, "a") as f:
        f.write(json.dumps(entry) + "\n")
