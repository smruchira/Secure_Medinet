"""
generate_dataset.py
--------------------
Generates the full labeled dataset (~1000 entries) covering:
  - normal
  - sensor_spoofing
  - firmware_tampering
  - replay_attack
  - data_tampering
  - device_masquerading

Writes to full_log.jsonl (private, local) then run privacy_strip.py
to produce cloud_log.jsonl (features + label only, safe for cloud training).
"""

import numpy as np
import json
from datetime import datetime, timezone, timedelta

from synthetic_ecg import generate_synthetic_ecg
from feature_extractor import extract_features
from logger import make_log_entry, write_log_entry, FULL_LOG_PATH
import attacks

# NOTE: duplicate-window detection (for replay attacks) is now handled
# automatically inside logger.make_log_entry() via _is_duplicate_window().

N_PER_CLASS = 166   # ~166 x 6 classes ~= 1000 total
SAMPLING_RATE = 250
WINDOW_SEC = 10

PATIENT_INFO = {
    "patient_id": "P001",
    "patient_name": "John Silva",
    "age": 45,
    "sex": "M",
    "location": "Colombo, Home",
    "device_mac": "AA:BB:CC:DD:EE:FF",
    "device_ip": "192.168.1.50",
}


def fresh_normal_window():
    hr = np.random.randint(60, 95)  # natural variation in normal heart rate
    signal, fs = generate_synthetic_ecg(duration_sec=WINDOW_SEC, sampling_rate=SAMPLING_RATE, heart_rate=hr)
    return signal


def generate_dataset():
    # clear old full log so we start fresh
    open(FULL_LOG_PATH, "w").close()

    normal_window_pool = []  # used later for replay_attack
    entries_written = 0

    # ---- 1. NORMAL entries (also builds the pool used for replay attack) ----
    print("Generating normal entries...")
    for i in range(N_PER_CLASS):
        window = fresh_normal_window()
        normal_window_pool.append(window)
        features = extract_features(window, sampling_rate=SAMPLING_RATE)
        entry = make_log_entry(PATIENT_INFO, window, features, source="synthetic", label="normal")
        write_log_entry(entry)
        entries_written += 1

    # ---- 2. SENSOR SPOOFING ----
    print("Generating sensor_spoofing entries...")
    for i in range(N_PER_CLASS):
        fake_window, label = attacks.sensor_spoofing(fresh_normal_window(), SAMPLING_RATE)
        features = extract_features(fake_window, sampling_rate=SAMPLING_RATE)
        entry = make_log_entry(PATIENT_INFO, fake_window, features, source="synthetic", label=label)
        write_log_entry(entry)
        entries_written += 1

    # ---- 3. FIRMWARE TAMPERING ----
    print("Generating firmware_tampering entries...")
    for i in range(N_PER_CLASS):
        tampered_window, label = attacks.firmware_tampering(fresh_normal_window(), SAMPLING_RATE)
        features = extract_features(tampered_window, sampling_rate=SAMPLING_RATE)
        entry = make_log_entry(PATIENT_INFO, tampered_window, features, source="synthetic", label=label)
        write_log_entry(entry)
        entries_written += 1

    # ---- 4. REPLAY ATTACK (reuses old normal windows) ----
    print("Generating replay_attack entries...")
    for i in range(N_PER_CLASS):
        replayed_window, label = attacks.replay_attack(normal_window_pool)
        features = extract_features(replayed_window, sampling_rate=SAMPLING_RATE)
        entry = make_log_entry(PATIENT_INFO, replayed_window, features, source="synthetic", label=label)
        write_log_entry(entry)
        entries_written += 1

    # ---- 5. DATA TAMPERING (corrupts features directly) ----
    print("Generating data_tampering entries...")
    for i in range(N_PER_CLASS):
        window = fresh_normal_window()
        features = extract_features(window, sampling_rate=SAMPLING_RATE)
        tampered_features, label = attacks.data_tampering(features)
        entry = make_log_entry(PATIENT_INFO, window, tampered_features, source="synthetic", label=label)
        write_log_entry(entry)
        entries_written += 1

    # ---- 6. DEVICE MASQUERADING (corrupts features directly) ----
    print("Generating device_masquerading entries...")
    for i in range(N_PER_CLASS):
        window = fresh_normal_window()
        features = extract_features(window, sampling_rate=SAMPLING_RATE)
        tampered_features, label = attacks.device_masquerading(features)
        entry = make_log_entry(PATIENT_INFO, window, tampered_features, source="synthetic", label=label)
        write_log_entry(entry)
        entries_written += 1

    print(f"\nDone. Total entries written: {entries_written} -> {FULL_LOG_PATH}")


if __name__ == "__main__":
    generate_dataset()
