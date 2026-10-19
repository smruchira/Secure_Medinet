"""
generate_temp_dataset.py
---------------------------
Generates the full labeled temperature dataset (~1000 entries) covering:
  - normal
  - sensor_spoofing
  - firmware_tampering
  - replay_attack
  - data_tampering
  - device_masquerading

Writes full_log_temp.jsonl (private, local) and cloud_log_temp.jsonl
(features + label only, safe for cloud training). Mirrors
generate_dataset.py exactly.
"""

import json

from synthetic_temp import generate_synthetic_temp
from temp_feature_extractor import extract_temp_features
from temp_logger import make_log_entry, write_log_entry
from temp_config import FULL_LOG_PATH
import temp_attacks as attacks

N_PER_CLASS = 166   # ~166 x 6 classes ~= 1000 total
WINDOW_SEC = 30
CLOUD_LOG_PATH = "cloud_log_temp.jsonl"

# Fields safe for cloud/training use: features + label + source + timestamp.
# No patient name, ID, location, MAC, IP, or raw temp value.
CLOUD_SAFE_FIELDS = [
    "timestamp", "mean_temp_c", "temp_std_c", "max_rate_of_change",
    "signal_entropy", "sampling_gap_ms", "is_duplicate_window",
    "label", "source",
]


def strip_entry_for_training(entry):
    return {k: entry[k] for k in CLOUD_SAFE_FIELDS if k in entry}

PATIENT_INFO = {
    "patient_id": "P001",
    "patient_name": "John Silva",
    "age": 45,
    "sex": "M",
    "location": "Colombo, Home",
    "device_mac": "11:22:33:44:55:66",
    "device_ip": "192.168.1.51",
}


def fresh_normal_window():
    readings, _ = generate_synthetic_temp(duration_sec=WINDOW_SEC)
    return readings


def generate_dataset():
    open(FULL_LOG_PATH, "w").close()
    open(CLOUD_LOG_PATH, "w").close()

    normal_window_pool = []
    entries_written = 0

    def _write_both(entry):
        write_log_entry(entry)
        with open(CLOUD_LOG_PATH, "a") as f:
            f.write(json.dumps(strip_entry_for_training(entry)) + "\n")

    print("Generating normal entries...")
    for i in range(N_PER_CLASS):
        window = fresh_normal_window()
        normal_window_pool.append(window)
        features = extract_temp_features(window)
        entry = make_log_entry(PATIENT_INFO, window, features, source="synthetic", label="normal")
        _write_both(entry)
        entries_written += 1

    print("Generating sensor_spoofing entries...")
    for i in range(N_PER_CLASS):
        fake_window, label = attacks.sensor_spoofing(fresh_normal_window())
        features = extract_temp_features(fake_window)
        entry = make_log_entry(PATIENT_INFO, fake_window, features, source="synthetic", label=label)
        _write_both(entry)
        entries_written += 1

    print("Generating firmware_tampering entries...")
    for i in range(N_PER_CLASS):
        tampered_window, label = attacks.firmware_tampering(fresh_normal_window())
        features = extract_temp_features(tampered_window)
        entry = make_log_entry(PATIENT_INFO, tampered_window, features, source="synthetic", label=label)
        _write_both(entry)
        entries_written += 1

    print("Generating replay_attack entries...")
    for i in range(N_PER_CLASS):
        replayed_window, label = attacks.replay_attack(normal_window_pool)
        features = extract_temp_features(replayed_window)
        entry = make_log_entry(PATIENT_INFO, replayed_window, features, source="synthetic", label=label)
        _write_both(entry)
        entries_written += 1

    print("Generating data_tampering entries...")
    for i in range(N_PER_CLASS):
        window = fresh_normal_window()
        features = extract_temp_features(window)
        tampered_features, label = attacks.data_tampering(features)
        entry = make_log_entry(PATIENT_INFO, window, tampered_features, source="synthetic", label=label)
        _write_both(entry)
        entries_written += 1

    print("Generating device_masquerading entries...")
    for i in range(N_PER_CLASS):
        window = fresh_normal_window()
        features = extract_temp_features(window)
        tampered_features, label = attacks.device_masquerading(features)
        entry = make_log_entry(PATIENT_INFO, window, tampered_features, source="synthetic", label=label)
        _write_both(entry)
        entries_written += 1

    print(f"\nDone. Total entries written: {entries_written} -> {FULL_LOG_PATH} / {CLOUD_LOG_PATH}")


if __name__ == "__main__":
    generate_dataset()
