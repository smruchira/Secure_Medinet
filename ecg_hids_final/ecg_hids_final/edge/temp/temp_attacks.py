"""
temp_attacks.py
----------------
Simulates the same 5 host-based attack categories as the ECG module,
adapted for a DS18B20 temperature stream. Mirrors attacks.py exactly
in structure, so generate_temp_dataset.py can call these uniformly.
"""

import numpy as np
import copy


# ---------------------------------------------------------------------
# 1. SENSOR VALUE SPOOFING
# Raw readings replaced with a fabricated window -- flatline, random
# noise, or an implausible spike (e.g. fire/fault-like reading).
# ---------------------------------------------------------------------
def sensor_spoofing(raw_window, sample_interval_sec=1.0):
    n = len(raw_window)
    choice = np.random.choice(["flatline", "random_noise", "fake_spike"])

    if choice == "flatline":
        fake = np.full(n, np.random.choice([0.0, -10.0, 99.9]))
    elif choice == "random_noise":
        fake = np.random.uniform(10, 60, n)
    else:  # fake_spike
        fake = np.random.normal(36.8, 0.1, n)
        spike_positions = np.random.choice(n, size=max(1, n // 10), replace=False)
        fake[spike_positions] = np.random.uniform(70, 95, len(spike_positions))

    return fake, "sensor_spoofing"


# ---------------------------------------------------------------------
# 2. FIRMWARE TAMPERING
# Systematic distortion of an otherwise-real reading stream -- wrong
# calibration/gain, fixed offset, or clipped range.
# ---------------------------------------------------------------------
def firmware_tampering(raw_window, sample_interval_sec=1.0):
    raw_window = np.array(raw_window, dtype=float)
    fault = np.random.choice(["wrong_gain", "dc_offset", "clipping"])

    if fault == "wrong_gain":
        gain = np.random.choice([0.5, 0.6, 1.5, 2.0])
        tampered = raw_window * gain
    elif fault == "dc_offset":
        offset = np.random.uniform(5.0, 12.0) * np.random.choice([-1, 1])
        tampered = raw_window + offset
    else:  # clipping
        center = np.mean(raw_window)
        limit = np.random.uniform(0.05, 0.15)
        tampered = np.clip(raw_window, center - limit, center + limit)

    return tampered, "firmware_tampering"


# ---------------------------------------------------------------------
# 3. REPLAY ATTACK
# An old, previously captured "normal" window is resent as if live.
# ---------------------------------------------------------------------
def replay_attack(old_window_pool):
    replayed = old_window_pool[np.random.randint(0, len(old_window_pool))]
    return np.array(replayed, dtype=float), "replay_attack"


# ---------------------------------------------------------------------
# 4. DATA TAMPERING (feature-level corruption)
# Forces implausible feature combinations that wouldn't occur from a
# real DS18B20 stream, mimicking a hand-edited log entry.
# ---------------------------------------------------------------------
def data_tampering(features):
    tampered = copy.deepcopy(features)
    fault = np.random.choice(["impossible_temp", "negative_std", "zeroed_entropy"])

    if fault == "impossible_temp":
        tampered["mean_temp_c"] = float(np.random.choice([-40.0, 0.0, 150.0]))
    elif fault == "negative_std":
        tampered["temp_std_c"] = -abs(tampered["temp_std_c"]) - 0.1
    else:  # zeroed_entropy
        tampered["signal_entropy"] = 0.0
        tampered["max_rate_of_change"] = 0.0

    return tampered, "data_tampering"


# ---------------------------------------------------------------------
# 5. DEVICE MASQUERADING
# A rogue process writes plausible-looking but structurally inconsistent
# data -- normal-ish mean_temp_c but irregular sampling_gap_ms / entropy.
# ---------------------------------------------------------------------
def device_masquerading(features):
    tampered = copy.deepcopy(features)
    tampered["sampling_gap_ms"] = float(np.random.uniform(300, 1500))  # real device: near 0-50ms
    tampered["mean_temp_c"] = float(np.random.uniform(36.0, 37.5))  # looks "normal" on the surface
    tampered["signal_entropy"] = float(np.random.uniform(2.5, 4.0))  # unnatural entropy for real temp
    return tampered, "device_masquerading"
