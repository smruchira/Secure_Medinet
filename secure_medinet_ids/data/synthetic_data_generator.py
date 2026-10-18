"""
synthetic_data_generator.py
============================
Generates a synthetic gateway-metadata CSV that mimics the structure expected
from the Mininet-WiFi IoMT simulation (Member 1/2's pipeline), WITH the
severe class imbalance you'll actually see between normal traffic and rare
attacks (MITM/replay/spoofing/DDoS).

This exists ONLY so the rest of the module (preprocessing -> models ->
fusion -> SDN trigger) is runnable and testable end-to-end before the real
dataset lands. Swap RAW_DATA_PATH in config.py to the real export and delete
this generator once real data is available -- do not train the final models
on synthetic data.
"""

import sys
import os
import numpy as np
import pandas as pd

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config


def _generate_normal(n, rng):
    return pd.DataFrame({
        "packet_size": rng.normal(500, 80, n).clip(40, 1500),
        "inter_arrival_time": rng.exponential(0.05, n),
        "flow_duration": rng.normal(2.0, 0.5, n).clip(0.01, None),
        "src_port": rng.integers(1024, 65535, n),
        "dst_port": rng.choice([1883, 8883, 443, 80], n),
        "tls_handshake_time": rng.normal(0.15, 0.03, n).clip(0.01, None),
        "mqtt_qos": rng.choice([0, 1, 2], n, p=[0.6, 0.3, 0.1]),
        "packet_count_window": rng.normal(30, 8, n).clip(1, None),
        "byte_rate": rng.normal(4000, 900, n).clip(1, None),
        "retransmission_count": rng.poisson(0.3, n),
        "protocol": rng.choice(["TCP", "UDP", "MQTT", "TLS"], n, p=[0.4, 0.1, 0.3, 0.2]),
        "tcp_flags": rng.choice(["SYN_ACK", "ACK", "FIN_ACK"], n),
        "direction": rng.choice(["inbound", "outbound"], n),
        "label": config.BENIGN_CLASS,
    })


def _generate_mitm(n, rng):
    df = _generate_normal(n, rng)
    df["tls_handshake_time"] = rng.normal(0.45, 0.08, n).clip(0.05, None)  # extra hop delay
    df["retransmission_count"] = rng.poisson(2.5, n)
    df["inter_arrival_time"] = rng.exponential(0.12, n)
    df["label"] = "mitm"
    return df


def _generate_replay(n, rng):
    df = _generate_normal(n, rng)
    df["inter_arrival_time"] = rng.exponential(0.05, n) * 0.2  # bursts of identical timing
    df["mqtt_qos"] = rng.choice([0, 1], n)
    df["packet_size"] = rng.choice([500, 512, 500, 512], n)  # near-identical payload sizes
    df["label"] = "replay"
    return df


def _generate_spoofing(n, rng):
    df = _generate_normal(n, rng)
    df["src_port"] = rng.integers(1, 1024, n)  # anomalous low ports
    df["tcp_flags"] = rng.choice(["SYN", "RST"], n)
    df["retransmission_count"] = rng.poisson(1.5, n)
    df["label"] = "spoofing"
    return df


def _generate_ddos(n, rng):
    df = _generate_normal(n, rng)
    df["packet_count_window"] = rng.normal(400, 60, n).clip(50, None)
    df["byte_rate"] = rng.normal(60000, 8000, n).clip(1000, None)
    df["inter_arrival_time"] = rng.exponential(0.002, n)
    df["tcp_flags"] = rng.choice(["SYN"], n)
    df["label"] = "ddos"
    return df


def generate(n_total=8000, n_bursts_per_attack=4, burst_length=30, seed=None):
    """
    Builds a CHRONOLOGICALLY ORDERED synthetic stream:
      - starts as n_total samples of benign traffic, in time order
      - each attack type is injected as several contiguous BURSTS
        (bursts of `burst_length` consecutive timesteps), not scattered
        randomly through the timeline.

    This matters: real MITM/replay/spoofing/DDoS events happen over a
    contiguous span of time, not as isolated packets randomly interspersed
    with normal traffic. Row order here IS the temporal order the LSTM
    windowing step (preprocessing/windowing.py) depends on -- do NOT
    shuffle rows after calling this, or you destroy the exact signal the
    LSTM tier is supposed to learn.
    """
    rng = np.random.default_rng(seed or config.RANDOM_SEED)

    df = _generate_normal(n_total, rng)
    df["label"] = config.BENIGN_CLASS

    attack_generators = {
        "mitm": _generate_mitm,
        "replay": _generate_replay,
        "spoofing": _generate_spoofing,
        "ddos": _generate_ddos,
    }

    used_ranges = []
    # Reserve the same tail fraction train.py uses for its chronological
    # test split (test_frac=0.2) and guarantee at least one burst of every
    # attack type lands in each region, so a demo train/test split actually
    # exercises all four attack classes on both sides. Real deployment data
    # won't need this -- it will have its own natural time distribution.
    split_point = int(n_total * 0.8)

    def _non_overlapping_start(region_start, region_end):
        for _ in range(50):
            start = int(rng.integers(region_start, region_end - burst_length))
            end = start + burst_length
            if all(end <= s or start >= e for s, e in used_ranges):
                return start, end
        raise RuntimeError("Could not place non-overlapping burst; reduce n_bursts_per_attack.")

    for attack_name, gen_fn in attack_generators.items():
        # one guaranteed burst in the test region
        start, end = _non_overlapping_start(split_point, n_total)
        used_ranges.append((start, end))
        burst_df = gen_fn(burst_length, rng).reset_index(drop=True)
        for col in burst_df.columns:
            df.loc[start:end - 1, col] = burst_df[col].values

        # remaining bursts scattered through the train region
        for _ in range(n_bursts_per_attack - 1):
            start, end = _non_overlapping_start(0, split_point)
            used_ranges.append((start, end))
            burst_df = gen_fn(burst_length, rng).reset_index(drop=True)
            for col in burst_df.columns:
                df.loc[start:end - 1, col] = burst_df[col].values

    df[config.DEVICE_ID_COLUMN] = rng.choice(
        [f"iomt_device_{i}" for i in range(1, 9)], len(df)
    )
    base_ts = pd.Timestamp("2026-01-01")
    df[config.TIMESTAMP_COLUMN] = [
        base_ts + pd.Timedelta(seconds=i * 0.05) for i in range(len(df))
    ]
    # NOTE: no row shuffling -- chronological order is preserved by design.
    return df


if __name__ == "__main__":
    os.makedirs(config.DATA_DIR, exist_ok=True)
    df = generate()
    df.to_csv(config.RAW_DATA_PATH, index=False)
    print(f"Synthetic dataset written to {config.RAW_DATA_PATH}")
    print(df["label"].value_counts())
