"""
synthetic_temp.py
------------------
Generates a synthetic DS18B20 skin/body-temperature window, for testing
and dataset generation. A DS18B20 is slow (~1 reading/sec at 12-bit
resolution), so a "window" here is a short sequence of readings, not a
high-frequency waveform like ECG.
"""

import numpy as np


def generate_synthetic_temp(duration_sec=30, sample_interval_sec=1.0,
                             base_temp_c=36.8, drift=True):
    """
    Returns (readings, sample_interval_sec).

    readings: 1D numpy array of temperature values in Celsius, one per
    sample_interval_sec, with small realistic sensor noise and a slow
    random-walk drift (body/skin temp doesn't jump around -- it creeps).
    """
    n = max(2, int(duration_sec / sample_interval_sec))
    readings = np.empty(n, dtype=float)
    temp = base_temp_c + np.random.uniform(-0.3, 0.3)

    for i in range(n):
        if drift:
            temp += np.random.uniform(-0.03, 0.03)  # slow natural drift
        noise = np.random.normal(0, 0.05)  # DS18B20 sensor noise (~+-0.0625C res)
        readings[i] = temp + noise

    return readings, sample_interval_sec


if __name__ == "__main__":
    readings, interval = generate_synthetic_temp()
    print(f"{len(readings)} readings @ {interval}s interval")
    print(readings[:10])
