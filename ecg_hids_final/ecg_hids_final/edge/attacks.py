"""
attacks.py
----------
Simulates all 5 host-based attacks by corrupting either the raw ECG
window (before feature extraction) or the log entry itself (after).

Each function returns (raw_window, label) or modifies an entry dict,
so generate_dataset.py can call them uniformly.
"""

import numpy as np
import copy


# ---------------------------------------------------------------------
# 1. SENSOR VALUE SPOOFING
# The raw signal is replaced with a fabricated fake waveform (not from
# a real heartbeat) -- e.g. a flat line, random noise, or an exaggerated
# fake spike pattern, instead of the real generated ECG.
# ---------------------------------------------------------------------
def sensor_spoofing(raw_window, sampling_rate=250):
    n = len(raw_window)
    choice = np.random.choice(["flatline", "random_noise", "fake_spike"])

    if choice == "flatline":
        fake = np.full(n, np.random.uniform(-0.05, 0.05))
    elif choice == "random_noise":
        fake = np.random.uniform(-2, 2, n)
    else:  # fake_spike
        fake = np.random.normal(0, 0.05, n)
        spike_positions = np.random.choice(n, size=max(1, n // 50), replace=False)
        fake[spike_positions] = np.random.uniform(3, 6, len(spike_positions))

    return fake, "sensor_spoofing"


# ---------------------------------------------------------------------
# 2. FIRMWARE TAMPERING
# Simulated as a systematic distortion applied to an otherwise real
# signal -- e.g. wrong calibration/gain, or a fixed offset -- mimicking
# what would happen if the firmware's reading/scaling logic was changed.
# ---------------------------------------------------------------------
def firmware_tampering(raw_window, sampling_rate=250):
    raw_window = np.array(raw_window, dtype=float)
    fault = np.random.choice(["wrong_gain", "dc_offset", "clipping"])

    if fault == "wrong_gain":
        gain = np.random.choice([0.2, 0.3, 3.0, 4.0])  # way off from normal
        tampered = raw_window * gain
    elif fault == "dc_offset":
        offset = np.random.uniform(1.5, 3.0) * np.random.choice([-1, 1])
        tampered = raw_window + offset
    else:  # clipping
        limit = np.random.uniform(0.2, 0.4)
        tampered = np.clip(raw_window, -limit, limit)

    return tampered, "firmware_tampering"


# ---------------------------------------------------------------------
# 3. REPLAY ATTACK
# An old, previously captured "normal" window gets reused/resent as if
# it were a brand new live reading. Implemented at the log level:
# the entry's raw_window is a stored old window, but is written with a
# current/live timestamp.
# ---------------------------------------------------------------------
def replay_attack(old_window_pool):
    """
    old_window_pool: list of previously seen 'normal' raw windows.
    Picks one at random and returns it, unchanged, to simulate replay.
    """
    replayed = old_window_pool[np.random.randint(0, len(old_window_pool))]
    return np.array(replayed, dtype=float), "replay_attack"


# ---------------------------------------------------------------------
# 4. DATA TAMPERING (log insertion / deletion at feature level)
# Simulated by corrupting the FEATURES directly after extraction --
# e.g. forcing implausible feature combinations that wouldn't occur
# from a real signal (mimicking a log entry that was hand-edited).
# ---------------------------------------------------------------------
def data_tampering(features):
    tampered = copy.deepcopy(features)
    fault = np.random.choice(["impossible_hr", "negative_rr", "zeroed_entropy"])

    if fault == "impossible_hr":
        tampered["hr_bpm"] = float(np.random.choice([0, 300, 400]))
    elif fault == "negative_rr":
        tampered["rr_interval"] = -abs(tampered["rr_interval"]) - 0.1
    else:  # zeroed_entropy
        tampered["signal_entropy"] = 0.0
        tampered["qrs_amplitude"] = 0.0

    return tampered, "data_tampering"


# ---------------------------------------------------------------------
# 5. DEVICE MASQUERADING (process/service impersonation)
# Simulated as an entry that looks structurally different from the
# legitimate logger's output -- e.g. missing normal feature correlation,
# unusual sampling_gap_ms (irregular timing) as if a rogue process is
# writing to the log instead of the real sensor-reading service.
# ---------------------------------------------------------------------
def device_masquerading(features):
    tampered = copy.deepcopy(features)
    # Rogue process writes plausible-looking but inconsistent data:
    # normal-ish hr_bpm but irregular/unnatural sampling gap
    tampered["sampling_gap_ms"] = float(np.random.uniform(200, 800))  # real device: near 0-10ms
    tampered["hr_bpm"] = float(np.random.uniform(60, 100))  # looks "normal" on the surface
    tampered["signal_entropy"] = float(np.random.uniform(0.8, 1.5))  # unnatural entropy for real ECG
    return tampered, "device_masquerading"
