"""
inference.py
============
Simulates the gateway's real-time operational workflow described in the
project brief:

    extract network metadata at the edge
        -> (in production: receive a pre-alert from the cloud detector)
        -> locally confirm the threat via the ensemble
        -> trigger the SDN controller to isolate the device if confirmed

This script replays a CSV stream window-by-window (as if packets were
arriving live) and demonstrates:
  1. The GATED pipeline (config.GATED_PIPELINE): Tier 1 runs on every
     window; Tier 2 (AutoEncoder + LSTM) only runs when Tier 1 flags it.
  2. Per-stage latency measurement, to produce the latency/accuracy
     tradeoff evidence for the edge-deployment claim.
  3. Calling sdn_integration.sdn_trigger.trigger_quarantine() the moment
     the decision engine confirms a threat.

Run:
    python3 inference.py            # gated vs ungated latency comparison
    python3 inference.py --live     # continuous replay for a live demo
"""

import os
import sys
import time
import numpy as np

import config
from preprocessing.feature_extraction import load_raw, FeatureExtractor
from preprocessing.windowing import build_windows
from models.isolation_forest_model import IsolationForestTier
from models.autoencoder_model import AutoEncoderTier
from models.lstm_model import LSTMTier
from fusion.align import aggregate_to_windows
from fusion.decision_engine import DecisionEngine
from fusion.threat_classifier import ThreatTypeClassifier
from sdn_integration.sdn_trigger import trigger_quarantine, resolve_mac
from utils.metrics import LatencyTimer, summarize_latency
from utils import event_log


def load_pipeline():
    fx = FeatureExtractor.load()
    tier1 = IsolationForestTier.load()
    tier2a = AutoEncoderTier.load()
    tier2b = LSTMTier.load()
    engine = DecisionEngine.load()
    try:
        threat_clf = ThreatTypeClassifier.load()
    except FileNotFoundError:
        threat_clf = None  # falls back to "unclassified_threat" in the SDN payload
    return fx, tier1, tier2a, tier2b, engine, threat_clf


def run_stream(csv_path=None, gated=None, max_windows=None,
               delay_sec=0.0, mode="batch", start_window=0):
    gated = config.GATED_PIPELINE if gated is None else gated
    fx, tier1, tier2a, tier2b, engine, threat_clf = load_pipeline()

    df = load_raw(csv_path)
    X = fx.transform(df)
    y = fx.label_encoder.transform(df[config.LABEL_COLUMN].astype(str)) \
        if config.LABEL_COLUMN in df.columns else None
    device_ids = df[config.DEVICE_ID_COLUMN].values if config.DEVICE_ID_COLUMN in df.columns else None

    Xw, yw = build_windows(X, y)
    starts = list(range(0, len(X) - config.WINDOW_SIZE + 1, config.WINDOW_STRIDE))
    if start_window:
        # Successive live passes walk forward through the stream and wrap
        # around when they reach the end.
        offset = start_window % len(Xw)
        Xw, starts = Xw[offset:], starts[offset:]
        if yw is not None:
            yw = yw[offset:]

    if max_windows:
        Xw, starts = Xw[:max_windows], starts[:max_windows]
        if yw is not None:
            yw = yw[:max_windows]

    latency = {}
    confirmed_events = []
    gate_open_count = 0

    for i, (window, start) in enumerate(zip(Xw, starts)):
        if delay_sec:
            time.sleep(delay_sec)
        window_flat = window  # (window_size, F)
        last_packet = window_flat[-1:]  # gate decision made on the most recent packet

        # --- Tier 1: always runs (cheap, per-window) --------------------
        with LatencyTimer("tier1_isolation_forest", latency):
            if_conf = tier1.confidence(window_flat).max()  # p90/max over window
            gate_open = if_conf >= config.IFOREST_GATE_THRESHOLD
        gate_open_count += int(bool(gate_open))

        ae_conf, lstm_conf = None, None
        if (not gated) or gate_open:
            # --- Tier 2a: AutoEncoder --------------------------------------
            with LatencyTimer("tier2a_autoencoder", latency):
                ae_conf = tier2a.confidence(window_flat).max()
            # --- Tier 2b: LSTM ----------------------------------------------
            with LatencyTimer("tier2b_lstm", latency):
                lstm_conf = float(tier2b.confidence(window_flat[np.newaxis, ...])[0])

        with LatencyTimer("fusion", latency):
            fused, confirmed = engine.fuse(
                np.array([if_conf]),
                None if ae_conf is None else np.array([ae_conf]),
                None if lstm_conf is None else np.array([lstm_conf]),
            )

        if confirmed[0]:
            device_id = device_ids[start] if device_ids is not None else "unknown_device"

            # threat_type is produced ENTIRELY from the ensemble's own
            # outputs (tier scores + this window's features) -- never from
            # ground truth, since none is available at real inference time.
            if threat_clf is not None and ae_conf is not None and lstm_conf is not None:
                threat_type = threat_clf.predict(window_flat, if_conf, ae_conf, lstm_conf)
            else:
                threat_type = "unclassified_threat"

            confirmed_events.append((i, device_id, threat_type, float(fused[0])))
            sdn_ok, sdn_detail = trigger_quarantine(
                device_id=device_id,
                threat_type=threat_type,
                confidence=float(fused[0]),
            )
            event_log.log_detection(
                window_index=i,
                device_id=device_id,
                device_mac=resolve_mac(device_id),
                threat_type=threat_type,
                fused_confidence=float(fused[0]),
                tier_scores={
                    "isolation_forest": if_conf,
                    "autoencoder": ae_conf,
                    "lstm": lstm_conf,
                },
                sdn_ok=sdn_ok,
                sdn_detail=sdn_detail,
            )

            # Ground truth is ONLY used here, for the demo printout, to show
            # how the predicted type compares -- it never reaches the SDN
            # payload or influences the decision above.
            if yw is not None:
                true_label = fx.inverse_label([yw[i]])[0]
                match = "OK" if true_label == threat_type else "mismatch"
                print(f"    (demo eval only: predicted='{threat_type}' "
                      f"ground_truth='{true_label}' [{match}])")

    print(f"\nProcessed {len(Xw)} windows | gated={gated} | "
          f"confirmed threats: {len(confirmed_events)}")
    latency_summary = summarize_latency(latency)
    event_log.log_run(
        windows_processed=len(Xw),
        gated=gated,
        confirmed_count=len(confirmed_events),
        gate_open_count=gate_open_count,
        latency_summary=latency_summary,
        mode=mode,
    )
    return confirmed_events, latency


def compare_gated_vs_ungated(csv_path=None, max_windows=200):
    print("\n=== Latency comparison: gated vs ungated pipeline ===")
    print("\n--- Gated (Tier 2 only runs when Tier 1 flags) ---")
    _, lat_gated = run_stream(csv_path, gated=True, max_windows=max_windows)
    print("\n--- Ungated (Tier 2 always runs) ---")
    _, lat_ungated = run_stream(csv_path, gated=False, max_windows=max_windows)

    def total_ms(latency):
        return sum(sum(v) for v in latency.values())

    g, u = total_ms(lat_gated), total_ms(lat_ungated)
    if u > 0:
        print(f"\nTotal inference time -- gated: {g:.1f} ms | ungated: {u:.1f} ms "
              f"| gating saved {100*(1 - g/u):.1f}% compute time over this run")


def run_live(csv_path=None):
    """
    Continuous replay for a live demo: streams the CSV one window at a time
    (config.LIVE_WINDOW_DELAY_SEC apart) so detections appear in the
    dashboard as they are confirmed, and loops when the data runs out.
    """
    print(f"Live replay: one window every {config.LIVE_WINDOW_DELAY_SEC}s "
          f"| loop={config.LIVE_LOOP} | Ctrl+C to stop")
    cursor = 0
    while True:
        # Short passes so the latency/gating summary is refreshed while the
        # demo is running, instead of only when the whole stream ends.
        run_stream(
            csv_path,
            max_windows=config.LIVE_PASS_WINDOWS,
            delay_sec=config.LIVE_WINDOW_DELAY_SEC,
            mode="live",
            start_window=cursor,
        )
        if not config.LIVE_LOOP:
            break
        cursor += config.LIVE_PASS_WINDOWS


if __name__ == "__main__":
    if "--live" in sys.argv:
        try:
            run_live()
        except KeyboardInterrupt:
            print("\nLive replay stopped.")
    else:
        compare_gated_vs_ungated()
