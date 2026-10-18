"""
synthetic_ecg.py
-----------------
Generates synthetic ECG signals to simulate what the ESP32 would send
over WiFi. Use this until the real ESP32 device is connected.

Later, when real data arrives, you just swap out the call to
generate_synthetic_ecg() with your ESP32 WiFi receiver function --
everything downstream (feature extraction, logging) stays the same.
"""

import neurokit2 as nk
import numpy as np


def generate_synthetic_ecg(duration_sec=10, sampling_rate=250, heart_rate=75, noise=0.02):
    """
    Generates a synthetic ECG signal.

    Returns:
        ecg_signal (np.array): raw ECG values (like what ESP32 ADC would send)
        sampling_rate (int): samples per second
    """
    ecg_signal = nk.ecg_simulate(
        duration=duration_sec,
        sampling_rate=sampling_rate,
        heart_rate=heart_rate,
        noise=noise,
        method="ecgsyn"
    )
    return ecg_signal, sampling_rate


def stream_raw_values(ecg_signal):
    """
    Simulates the ESP32 sending one raw_ecg_value at a time over WiFi.
    In real life, this would be replaced by reading incoming WiFi/socket packets.
    """
    for value in ecg_signal:
        yield float(value)


if __name__ == "__main__":
    # quick test
    signal, fs = generate_synthetic_ecg(duration_sec=5, heart_rate=80)
    print(f"Generated {len(signal)} samples at {fs} Hz")
    print("First 10 raw values:", signal[:10])
