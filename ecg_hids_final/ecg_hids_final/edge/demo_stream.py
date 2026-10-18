"""
demo_stream.py
----------------
Simulates a REAL-TIME ECG feed for demo purposes. Instead of generating
all 996 entries at once (like generate_dataset.py), this writes ONE new
entry every few seconds, continuously -- like a live patient monitor.

Randomly mixes in normal readings and attacks, so you can watch the
detection system react to things live during your demo.

Run this in its own terminal window. Leave it running while you show
monitor_bridge.py picking up and reacting to each new entry.
"""

import time
import random
import numpy as np

from synthetic_ecg import generate_synthetic_ecg
from feature_extractor import extract_features
from logger import make_log_entry, write_log_entry
from config import FULL_LOG_PATH
import attacks

SAMPLING_RATE = 250
WINDOW_SEC = 10
SECONDS_BETWEEN_ENTRIES = 5   # how often a new entry appears (demo pace)

PATIENT_INFO = {
    "patient_id": "P001",
    "patient_name": "John Silva",
    "age": 45,
    "sex": "M",
    "location": "Colombo, Home",
    "device_mac": "AA:BB:CC:DD:EE:FF",
    "device_ip": "192.168.1.50",
}

# Probability of each outcome per new entry (must sum to 1.0)
OUTCOME_WEIGHTS = {
    "normal": 0.55,
    "sensor_spoofing": 0.09,
    "firmware_tampering": 0.09,
    "replay_attack": 0.09,
    "data_tampering": 0.09,
    "device_masquerading": 0.09,
}

normal_window_pool = []  # built up over time, used for replay_attack


def fresh_normal_window():
    hr = np.random.randint(60, 95)
    signal, fs = generate_synthetic_ecg(duration_sec=WINDOW_SEC, sampling_rate=SAMPLING_RATE, heart_rate=hr)
    return signal


def generate_one_entry():
    outcome = random.choices(
        list(OUTCOME_WEIGHTS.keys()),
        weights=list(OUTCOME_WEIGHTS.values()),
        k=1
    )[0]

    if outcome == "normal":
        window = fresh_normal_window()
        normal_window_pool.append(window)
        if len(normal_window_pool) > 20:
            normal_window_pool.pop(0)  # keep pool from growing forever
        features = extract_features(window, sampling_rate=SAMPLING_RATE)
        label = "normal"

    elif outcome == "sensor_spoofing":
        window, label = attacks.sensor_spoofing(fresh_normal_window(), SAMPLING_RATE)
        features = extract_features(window, sampling_rate=SAMPLING_RATE)

    elif outcome == "firmware_tampering":
        window, label = attacks.firmware_tampering(fresh_normal_window(), SAMPLING_RATE)
        features = extract_features(window, sampling_rate=SAMPLING_RATE)

    elif outcome == "replay_attack":
        if len(normal_window_pool) == 0:
            # not enough history yet, fall back to normal
            window = fresh_normal_window()
            normal_window_pool.append(window)
            features = extract_features(window, sampling_rate=SAMPLING_RATE)
            label = "normal"
        else:
            window, label = attacks.replay_attack(normal_window_pool)
            features = extract_features(window, sampling_rate=SAMPLING_RATE)

    elif outcome == "data_tampering":
        window = fresh_normal_window()
        base_features = extract_features(window, sampling_rate=SAMPLING_RATE)
        features, label = attacks.data_tampering(base_features)

    else:  # device_masquerading
        window = fresh_normal_window()
        base_features = extract_features(window, sampling_rate=SAMPLING_RATE)
        features, label = attacks.device_masquerading(base_features)

    entry = make_log_entry(PATIENT_INFO, window, features, source="synthetic", label=label)
    write_log_entry(entry)
    return entry


def run_stream():
    print(f"Starting live demo stream -- new entry every {SECONDS_BETWEEN_ENTRIES}s")
    print(f"Writing to: {FULL_LOG_PATH}")
    print("Press Ctrl+C to stop.\n")

    count = 0
    while True:
        entry = generate_one_entry()
        count += 1
        print(f"[{count}] {entry['timestamp']} | label={entry['label']:<20} "
              f"hr_bpm={entry['hr_bpm']:.1f}")
        time.sleep(SECONDS_BETWEEN_ENTRIES)


if __name__ == "__main__":
    run_stream()
