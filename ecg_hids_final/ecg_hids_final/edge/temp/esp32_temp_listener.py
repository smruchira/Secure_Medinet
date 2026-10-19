"""
esp32_temp_listener.py
------------------------
Runs on the RPi4. Listens for raw DS18B20 temperature data sent over
WiFi from the SEPARATE temperature ESP32 (its own device, own MAC/IP
-- not the ECG ESP32), buffers it into time-windows, extracts features,
and writes to the temperature log. Mirrors esp32_listener.py.

Runs on its own port (5002 by default) so it doesn't collide with the
ECG listener (port 5000) or the SDN gateway (default port 5000 on a
different host) -- all three can run at once on the RPi4.

The temperature ESP32 should send an HTTP POST to this RPi4's IP:

    POST http://<rpi4-ip>:5002/temp_data
    Content-Type: application/json

    {
      "patient_id": "P001",
      "patient_name": "John Silva",
      "age": 45,
      "sex": "M",
      "location": "Colombo, Home",
      "device_mac": "11:22:33:44:55:66",
      "device_ip": "192.168.1.51",
      "raw_temp_value": 36.8,
      "timestamp": "2026-10-19T10:15:32Z"
    }

Each POST = ONE raw DS18B20 reading. Because DS18B20 reads are slow
(~1/sec), the default window is 30 samples (~30 seconds) rather than
ECG's 2500 samples/10 seconds.
"""

from flask import Flask, request, jsonify
from collections import defaultdict, deque
import numpy as np

from temp_feature_extractor import extract_temp_features
from temp_logger import make_log_entry, write_log_entry

app = Flask(__name__)

WINDOW_SIZE = 30   # ~30 seconds of samples at ~1 reading/sec

buffers = defaultdict(lambda: deque(maxlen=WINDOW_SIZE))
latest_patient_info = {}


@app.route("/temp_data", methods=["POST"])
def receive_temp_data():
    data = request.get_json(force=True)

    required = ["patient_id", "patient_name", "age", "sex", "location",
                "device_mac", "device_ip", "raw_temp_value"]
    missing = [f for f in required if f not in data]
    if missing:
        return jsonify({"error": f"Missing fields: {missing}"}), 400

    patient_id = data["patient_id"]
    buffers[patient_id].append(float(data["raw_temp_value"]))
    latest_patient_info[patient_id] = {
        "patient_id": data["patient_id"],
        "patient_name": data["patient_name"],
        "age": data["age"],
        "sex": data["sex"],
        "location": data["location"],
        "device_mac": data["device_mac"],
        "device_ip": data["device_ip"],
    }

    if len(buffers[patient_id]) == WINDOW_SIZE:
        window = np.array(buffers[patient_id])
        features = extract_temp_features(window)

        entry = make_log_entry(
            latest_patient_info[patient_id],
            window,
            features,
            source="real",
            label="normal"
        )
        write_log_entry(entry)

        buffers[patient_id].clear()

        return jsonify({"status": "window_logged", "features": features}), 200

    return jsonify({
        "status": "buffering",
        "samples_collected": len(buffers[patient_id]),
        "samples_needed": WINDOW_SIZE
    }), 200


@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({"status": "RPi4 temperature listener is running"}), 200


if __name__ == "__main__":
    print("Starting temperature listener on RPi4...")
    print("Temp ESP32 should POST to: http://<this-rpi4-ip>:5002/temp_data")
    app.run(host="0.0.0.0", port=5002, debug=False)
