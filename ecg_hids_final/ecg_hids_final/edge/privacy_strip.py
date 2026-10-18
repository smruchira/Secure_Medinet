"""
privacy_strip.py
-----------------
Strips a full log entry down to ONLY the fields safe to send to the
Render ML API: features + label + source + timestamp. No patient
name, ID, location, MAC, IP, or raw ECG value ever leaves the RPi4.

This is the core privacy-preserving step of the research project.
"""

CLOUD_SAFE_FIELDS = [
    "timestamp",
    "hr_bpm",
    "rr_interval",
    "signal_entropy",
    "qrs_amplitude",
    "sampling_gap_ms",
    "is_duplicate_window",
]


def strip_entry(full_entry):
    """Takes one full log entry dict, returns only the cloud-safe fields."""
    return {k: full_entry[k] for k in CLOUD_SAFE_FIELDS if k in full_entry}


def strip_to_features(full_entry):
    """
    Returns just the 6 ML feature values (no timestamp), in the exact
    format the Render ML API's /predict endpoint expects.
    """
    feature_keys = [
        "hr_bpm", "rr_interval", "signal_entropy",
        "qrs_amplitude", "sampling_gap_ms", "is_duplicate_window",
    ]
    return {k: full_entry[k] for k in feature_keys}
