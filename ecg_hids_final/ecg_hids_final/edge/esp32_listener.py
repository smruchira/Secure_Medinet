"""
esp32_listener.py
-------------------
Runs on the RPi4. Listens for raw ECG data sent over WiFi from the ESP32,
buffers it into time-windows, extracts features, and writes to the log --
using the EXACT SAME functions as the synthetic data path.

This is a simple Flask HTTP server. Your friend's ESP32 should send an
HTTP POST request to this RPi4's IP address, like:

    POST http://<rpi4-ip>:5000/ecg_data
    Content-Type: application/json

    {
      "patient_id": "P001",
      "patient_name": "John Silva",
      "age": 45,
      "sex": "M",
      "location": "Colombo, Home",
      "device_mac": "AA:BB:CC:DD:EE:FF",
      "device_ip": "192.168.1.50",
      "raw_ecg_value": 0.732,
      "timestamp": "2026-08-21T10:15:32Z"
    }

Each POST = ONE raw sample. This script buffers samples into a rolling
window (default 10 seconds worth) per patient, then runs feature
extraction + logging once the window is full -- same as the synthetic
data path.
"""

from flask import Flask, request, jsonify
from collections import defaultdict, deque
import numpy as np

from feature_extractor import extract_features
from logger import make_log_entry, write_log_entry

app = Flask(__name__)

SAMPLING_RATE = 250        # must match what feature_extractor expects
WINDOW_SIZE = SAMPLING_RATE * 10   # 10 seconds worth of samples

# One rolling buffer of raw values per patient_id, so multiple
# patients/devices could theoretically be handled at once.
buffers = defaultdict(lambda: deque(maxlen=WINDOW_SIZE))
# Keep the latest patient info (name/id/etc.) seen per patient_id
latest_patient_info = {}


@app.route("/ecg_data", methods=["POST"])
def receive_ecg_data():
    data = request.get_json(force=True)

    required = ["patient_id", "patient_name", "age", "sex", "location",
                "device_mac", "device_ip", "raw_ecg_value"]
    missing = [f for f in required if f not in data]
    if missing:
        return jsonify({"error": f"Missing fields: {missing}"}), 400

    patient_id = data["patient_id"]
    buffers[patient_id].append(float(data["raw_ecg_value"]))
    latest_patient_info[patient_id] = {
        "patient_id": data["patient_id"],
        "patient_name": data["patient_name"],
        "age": data["age"],
        "sex": data["sex"],
        "location": data["location"],
        "device_mac": data["device_mac"],
        "device_ip": data["device_ip"],
    }

    # Once we have a full window, extract features and log it
    if len(buffers[patient_id]) == WINDOW_SIZE:
        window = np.array(buffers[patient_id])
        features = extract_features(window, sampling_rate=SAMPLING_RATE)

        entry = make_log_entry(
            latest_patient_info[patient_id],
            window,
            features,
            source="real",       # <-- marks this as real device data
            label="normal"       # default; attack labels are only for
                                  # training data you generate yourself
        )
        write_log_entry(entry)

        # Clear buffer so next window starts fresh
        buffers[patient_id].clear()

        return jsonify({"status": "window_logged", "features": features}), 200

    return jsonify({
        "status": "buffering",
        "samples_collected": len(buffers[patient_id]),
        "samples_needed": WINDOW_SIZE
    }), 200


@app.route("/health", methods=["GET"])
def health_check():
    """Quick way to check the listener is running: visit /health in browser."""
    return jsonify({"status": "RPi4 listener is running"}), 200


if __name__ == "__main__":
    # host="0.0.0.0" makes it reachable from other devices on the WiFi
    # (like the ESP32), not just from the RPi4 itself.
    print("Starting ECG listener on RPi4...")
    print("ESP32 should POST to: http://<this-rpi4-ip>:5000/ecg_data")
    app.run(host="0.0.0.0", port=5000, debug=False)
