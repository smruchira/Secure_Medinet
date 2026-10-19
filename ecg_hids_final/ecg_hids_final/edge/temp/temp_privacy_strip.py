"""
temp_privacy_strip.py
-----------------------
Strips a full temperature log entry down to ONLY the fields safe to
send to the Render ML API: features + timestamp. No patient name, ID,
location, MAC, IP, or raw temperature value ever leaves the RPi4.
Mirrors privacy_strip.py exactly.
"""

CLOUD_SAFE_FIELDS = [
    "timestamp",
    "mean_temp_c",
    "temp_std_c",
    "max_rate_of_change",
    "signal_entropy",
    "sampling_gap_ms",
    "is_duplicate_window",
]

FEATURE_KEYS = [
    "mean_temp_c", "temp_std_c", "max_rate_of_change",
    "signal_entropy", "sampling_gap_ms", "is_duplicate_window",
]


def strip_entry(full_entry):
    """Takes one full log entry dict, returns only the cloud-safe fields."""
    return {k: full_entry[k] for k in CLOUD_SAFE_FIELDS if k in full_entry}


def strip_to_features(full_entry):
    """
    Returns just the 6 ML feature values (no timestamp), in the exact
    format the Render ML API's /predict_temp endpoint expects.
    """
    return {k: full_entry[k] for k in FEATURE_KEYS}
