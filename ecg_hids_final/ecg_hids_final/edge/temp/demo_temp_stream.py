"""
demo_temp_stream.py
----------------------
Simulates a REAL-TIME temperature feed for demo/testing purposes, same
role as demo_stream.py. Writes one new windowed entry every so often,
mixing in normal readings and attacks, so you can test temp_orchestrator.py
without wiring up the real DS18B20 ESP32 yet.

Run this in its own terminal, in place of esp32_temp_listener.py, while
temp_orchestrator.py runs in another.
"""

import time
import random
import numpy as np

from synthetic_temp import generate_synthetic_temp
from temp_feature_extractor import extract_temp_features
from temp_logger import make_log_entry, write_log_entry
from temp_config import FULL_LOG_PATH
import temp_attacks as attacks

WINDOW_SEC = 30
SECONDS_BETWEEN_ENTRIES = 8   # demo pace

PATIENT_INFO = {
    "patient_id": "P001",
    "patient_name": "John Silva",
    "age": 45,
    "sex": "M",
    "location": "Colombo, Home",
    "device_mac": "11:22:33:44:55:66",   # separate device from the ECG ESP32
    "device_ip": "192.168.1.51",
}

OUTCOME_WEIGHTS = {
    "normal": 0.55,
    "sensor_spoofing": 0.09,
    "firmware_tampering": 0.09,
    "replay_attack": 0.09,
    "data_tampering": 0.09,
    "device_masquerading": 0.09,
}

normal_window_pool = []


def fresh_normal_window():
    readings, _ = generate_synthetic_temp(duration_sec=WINDOW_SEC)
    return readings


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
            normal_window_pool.pop(0)
        features = extract_temp_features(window)
        label = "normal"

    elif outcome == "sensor_spoofing":
        window, label = attacks.sensor_spoofing(fresh_normal_window())
        features = extract_temp_features(window)

    elif outcome == "firmware_tampering":
        window, label = attacks.firmware_tampering(fresh_normal_window())
        features = extract_temp_features(window)

    elif outcome == "replay_attack":
        if len(normal_window_pool) == 0:
            window = fresh_normal_window()
            normal_window_pool.append(window)
            features = extract_temp_features(window)
            label = "normal"
        else:
            window, label = attacks.replay_attack(normal_window_pool)
            features = extract_temp_features(window)

    elif outcome == "data_tampering":
        window = fresh_normal_window()
        base_features = extract_temp_features(window)
        features, label = attacks.data_tampering(base_features)

    else:  # device_masquerading
        window = fresh_normal_window()
        base_features = extract_temp_features(window)
        features, label = attacks.device_masquerading(base_features)

    entry = make_log_entry(PATIENT_INFO, window, features, source="synthetic", label=label)
    write_log_entry(entry)
    return entry


def run_stream():
    print(f"Starting live temp demo stream -- new entry every {SECONDS_BETWEEN_ENTRIES}s")
    print(f"Writing to: {FULL_LOG_PATH}")
    print("Press Ctrl+C to stop.\n")

    count = 0
    while True:
        entry = generate_one_entry()
        count += 1
        print(f"[{count}] {entry['timestamp']} | label={entry['label']:<20} "
              f"mean_temp_c={entry['mean_temp_c']:.2f}")
        time.sleep(SECONDS_BETWEEN_ENTRIES)


if __name__ == "__main__":
    run_stream()
