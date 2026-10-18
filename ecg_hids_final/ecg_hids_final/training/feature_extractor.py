"""
feature_extractor.py
---------------------
Converts a window of raw ECG values into ML-ready features.
Works the same whether the raw values came from synthetic_ecg.py
or a real ESP32 device later -- input is just a list/array of numbers.
"""

import neurokit2 as nk
import numpy as np


def extract_features(raw_window, sampling_rate=250):
    """
    Takes a window (list/array) of raw ECG values and returns
    a dict of features suitable for ML training.

    If the window is too short/corrupted (e.g. due to an attack),
    it falls back to safe default values instead of crashing --
    important because attacks may deliberately break normal signal shape.
    """
    raw_window = np.array(raw_window, dtype=float)

    features = {
        "hr_bpm": 0,
        "rr_interval": 0.0,
        "signal_entropy": 0.0,
        "qrs_amplitude": 0.0,
        "sampling_gap_ms": 0.0,
    }

    try:
        # Clean the signal (removes baseline wander/noise)
        cleaned = nk.ecg_clean(raw_window, sampling_rate=sampling_rate)

        # Detect R-peaks (heartbeats)
        peaks, info = nk.ecg_peaks(cleaned, sampling_rate=sampling_rate)
        r_peaks = info["ECG_R_Peaks"]

        if len(r_peaks) >= 2:
            # Heart rate (bpm)
            rr_samples = np.diff(r_peaks)
            rr_sec = rr_samples / sampling_rate
            features["rr_interval"] = float(np.mean(rr_sec))
            features["hr_bpm"] = float(60.0 / np.mean(rr_sec))

            # QRS amplitude (peak height -- proxy for signal strength)
            features["qrs_amplitude"] = float(np.mean(cleaned[r_peaks]))

        # Signal entropy (measures randomness/irregularity -- useful for
        # detecting spoofed or flat/fake signals, which look "too clean")
        features["signal_entropy"] = float(
            nk.entropy_sample(cleaned)[0] if len(cleaned) > 10 else 0.0
        )

    except Exception:
        # If feature extraction fails completely (e.g. garbage data from
        # an attack), we still return the default dict -- this itself
        # can be a useful signal that something is wrong.
        pass

    # Sampling gap: how consistent are the sample timings (ms between samples)
    # This is set by the caller (based on real arrival timestamps), default 0 here
    return features


if __name__ == "__main__":
    from synthetic_ecg import generate_synthetic_ecg

    signal, fs = generate_synthetic_ecg(duration_sec=10, heart_rate=75)
    feats = extract_features(signal, sampling_rate=fs)
    print("Extracted features:")
    for k, v in feats.items():
        print(f"  {k}: {v}")
