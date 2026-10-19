"""
temp_feature_extractor.py
---------------------------
Converts a window of raw DS18B20 temperature readings into ML-ready
features. Mirrors feature_extractor.py's role for ECG, but with
temperature-appropriate features (no neurokit2 needed -- a temperature
trace has no QRS complex / heartbeat structure to detect).

6 features, matching the ECG module's feature count:
  mean_temp_c        -- average temperature in the window
  temp_std_c          -- variability (flatline spoofing -> ~0, noise -> high)
  max_rate_of_change   -- biggest jump between consecutive samples (C/sample)
  signal_entropy       -- histogram-based entropy of the readings
  sampling_gap_ms      -- consistency of real-world arrival timing
  is_duplicate_window   -- set by logger.py (replay detection)
"""

import numpy as np


def _histogram_entropy(readings, bins=10):
    """Simple, dependency-free entropy estimate: bins the readings and
    computes Shannon entropy of the bin distribution. A flat/fake signal
    (all one value) -> ~0 entropy. A noisy/spoofed signal -> high entropy.
    A real, slowly-drifting temperature sits in between."""
    if len(readings) < 2:
        return 0.0
    counts, _ = np.histogram(readings, bins=bins)
    probs = counts / counts.sum()
    probs = probs[probs > 0]
    return float(-np.sum(probs * np.log2(probs)))


def extract_temp_features(raw_window):
    """
    Takes a window (list/array) of raw temperature readings (Celsius)
    and returns a dict of features suitable for ML training.

    Falls back to safe defaults instead of crashing on short/corrupted
    windows -- attacks may deliberately break the normal shape.
    """
    raw_window = np.array(raw_window, dtype=float)

    features = {
        "mean_temp_c": 0.0,
        "temp_std_c": 0.0,
        "max_rate_of_change": 0.0,
        "signal_entropy": 0.0,
        "sampling_gap_ms": 0.0,
    }

    try:
        if len(raw_window) >= 1:
            features["mean_temp_c"] = float(np.mean(raw_window))
            features["temp_std_c"] = float(np.std(raw_window))

        if len(raw_window) >= 2:
            diffs = np.abs(np.diff(raw_window))
            features["max_rate_of_change"] = float(np.max(diffs))

        features["signal_entropy"] = _histogram_entropy(raw_window)

    except Exception:
        # Still return the default dict -- the failure itself can be a
        # useful signal that something is wrong with the data.
        pass

    # sampling_gap_ms is set by the caller (based on real arrival
    # timestamps), default 0 here, same convention as feature_extractor.py
    return features


if __name__ == "__main__":
    from synthetic_temp import generate_synthetic_temp

    readings, interval = generate_synthetic_temp(duration_sec=30)
    feats = extract_temp_features(readings)
    print("Extracted features:")
    for k, v in feats.items():
        print(f"  {k}: {v}")
