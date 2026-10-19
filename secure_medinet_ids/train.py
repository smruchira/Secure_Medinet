"""
train.py
========
End-to-end training pipeline for the Secure-MediNet edge IDS ensemble.

    raw CSV -> FeatureExtractor -> Isolation Forest (Tier 1)
                                -> AutoEncoder      (Tier 2a)
                                -> sliding windows  -> LSTM (Tier 2b)
                                -> per-packet scores aggregated to windows
                                -> DecisionEngine meta-learner (fusion)

Uses a CHRONOLOGICAL train/test split (not random shuffling) because the
LSTM windows depend on real temporal order -- shuffling first would leak
future context into training windows and invalidate the replay-detection
evaluation.

Run:
    python3 train.py                 # uses config.RAW_DATA_PATH
    python3 data/synthetic_data_generator.py   # (re)generate demo data first
"""

import os
import sys
import numpy as np
from sklearn.model_selection import train_test_split

import config
from preprocessing.feature_extraction import load_raw, FeatureExtractor
from preprocessing.windowing import build_windows
from models.isolation_forest_model import IsolationForestTier
from models.autoencoder_model import AutoEncoderTier
from models.lstm_model import LSTMTier
from fusion.align import aggregate_to_windows
from fusion.decision_engine import DecisionEngine
from fusion.threat_classifier import ThreatTypeClassifier
from utils.metrics import per_class_report, print_confusion_matrix
from utils import event_log


def chronological_split(X, y, test_frac=0.2):
    n = len(X)
    split_idx = int(n * (1 - test_frac))
    return X[:split_idx], X[split_idx:], y[:split_idx], y[split_idx:]


def main():
    print("=" * 70)
    print("Secure-MediNet Edge IDS -- Training Pipeline")
    print("=" * 70)

    # 1. Load + featurize -----------------------------------------------
    df = load_raw()
    fx = FeatureExtractor()
    X, y = fx.fit_transform(df)
    benign_idx = fx.label_index(config.BENIGN_CLASS)
    class_names = list(fx.label_encoder.classes_)
    print(f"\nLoaded {len(df)} rows | classes: {class_names}")

    X_train, X_test, y_train, y_test = chronological_split(X, y, test_frac=0.2)
    print(f"Chronological split -> train: {len(X_train)}, test: {len(X_test)}")

    # 2. Tier 1: Isolation Forest ----------------------------------------
    print("\n--- Training Tier 1: Isolation Forest ---")
    tier1 = IsolationForestTier().fit(X_train)

    # 3. Tier 2a: AutoEncoder (normal-only) -------------------------------
    print("\n--- Training Tier 2a: AutoEncoder ---")
    X_normal_train_all = X_train[y_train == benign_idx]
    X_ae_train, X_ae_val = train_test_split(
        X_normal_train_all, test_size=0.2, random_state=config.RANDOM_SEED
    )
    tier2a = AutoEncoderTier().fit(X_ae_train, X_ae_val)

    # 4. Tier 2b: LSTM on sliding windows ---------------------------------
    print("\n--- Training Tier 2b: LSTM ---")
    Xw_train, yw_train = build_windows(X_train, y_train)
    Xw_test, yw_test = build_windows(X_test, y_test)
    y_train_binary = (yw_train != benign_idx).astype(int)
    y_test_binary = (yw_test != benign_idx).astype(int)
    print(f"Train windows: {len(yw_train)} ({y_train_binary.mean()*100:.1f}% attack) | "
          f"Test windows: {len(yw_test)} ({y_test_binary.mean()*100:.1f}% attack)")

    tier2b = LSTMTier().fit(Xw_train, y_train_binary)

    # 5. Align Tier 1 / Tier 2a per-packet scores to window granularity --
    print("\n--- Fitting Decision Engine (fusion) ---")
    if_scores_train = tier1.confidence(X_train)
    ae_scores_train = tier2a.confidence(X_train)
    if_win_train = aggregate_to_windows(if_scores_train)
    ae_win_train = aggregate_to_windows(ae_scores_train)
    lstm_win_train = tier2b.confidence(Xw_train)

    engine = DecisionEngine()
    if config.USE_STACKED_META_LEARNER:
        engine.fit_meta_learner(if_win_train, ae_win_train, lstm_win_train, y_train_binary)
        print("Fusion mode: stacked logistic-regression meta-learner")
    else:
        print("Fusion mode: fixed weighted voting", config.FUSION_WEIGHTS)

    # 5b. Threat-type classifier (post-confirmation labeling only) --------
    # Trained ONLY on windows that are actually attacks, using tier scores
    # + raw feature summaries -- never using the binary confirm/deny output
    # itself, and never used by the Decision Engine's own decision.
    attack_mask_train = y_train_binary == 1
    threat_clf = None
    if attack_mask_train.sum() >= len(config.ATTACK_CLASSES) * 2:
        train_attack_labels = fx.inverse_label(yw_train[attack_mask_train])
        threat_clf = ThreatTypeClassifier().fit(
            Xw_train[attack_mask_train],
            if_win_train[attack_mask_train],
            ae_win_train[attack_mask_train],
            lstm_win_train[attack_mask_train],
            train_attack_labels,
        )
        threat_clf.save()
        print(f"Threat-type classifier trained on {attack_mask_train.sum()} attack windows "
              f"-> classes: {list(threat_clf.classes_)}")
    else:
        print("Not enough attack windows to train a threat-type classifier yet "
              "(SDN payload will report 'unclassified_threat' until more data is available).")

    # 6. Evaluate on held-out (chronologically later) test data ----------
    print("\n--- Evaluation on held-out test set ---")
    if_scores_test = tier1.confidence(X_test)
    ae_scores_test = tier2a.confidence(X_test)
    if_win_test = aggregate_to_windows(if_scores_test)
    ae_win_test = aggregate_to_windows(ae_scores_test)
    lstm_win_test = tier2b.confidence(Xw_test)

    fused_conf, confirmed = engine.fuse(if_win_test, ae_win_test, lstm_win_test)

    print("\nBinary (attack vs normal) window-level report:")
    binary_report = per_class_report(
        y_test_binary, confirmed.astype(int), ["normal_window", "attack_window"]
    )
    confusion = print_confusion_matrix(
        y_test_binary, confirmed.astype(int), ["normal_window", "attack_window"]
    )

    # per-attack-type recall -- the number that matters most for this
    # project's rare-attack-detection claim
    print("\nPer-attack-type recall (of windows truly containing that attack, "
          "how many did the fused decision confirm):")
    true_multiclass_labels = fx.inverse_label(yw_test)
    per_attack_recall = {}
    for attack in config.ATTACK_CLASSES:
        mask = true_multiclass_labels == attack
        if mask.sum() == 0:
            print(f"  {attack:10s}: no test windows for this class")
            continue
        recall = confirmed[mask].mean()
        per_attack_recall[attack] = {
            "recall": round(float(recall), 4),
            "windows": int(mask.sum()),
        }
        print(f"  {attack:10s}: recall={recall:.2f}  (n={int(mask.sum())} windows)")

    if threat_clf is not None:
        print("\nThreat-type classifier accuracy on CONFIRMED test detections "
              "(evaluation only -- ground truth is never used at inference time):")
        confirmed_idx = np.where(confirmed)[0]
        if len(confirmed_idx) > 0:
            correct = 0
            for i in confirmed_idx:
                pred_type = threat_clf.predict(
                    Xw_test[i], if_win_test[i], ae_win_test[i], lstm_win_test[i]
                )
                true_type = true_multiclass_labels[i]
                correct += int(pred_type == true_type)
                print(f"  window {i}: predicted={pred_type:20s} true={true_type}")
            print(f"  -> {correct}/{len(confirmed_idx)} correct "
                  f"({100*correct/len(confirmed_idx):.0f}%)")

    # 6b. Persist the evaluation so the dashboard can show the model card --
    event_log.write_model_report({
        "rows": int(len(df)),
        "classes": class_names,
        "train_windows": int(len(yw_train)),
        "test_windows": int(len(yw_test)),
        "test_attack_fraction": round(float(y_test_binary.mean()), 4),
        "fusion_mode": engine.mode,
        "binary_report": binary_report,
        "confusion_matrix": confusion.tolist(),
        "confusion_labels": ["normal_window", "attack_window"],
        "per_attack_recall": per_attack_recall,
        "threat_classifier_classes": (
            None if threat_clf is None else list(threat_clf.classes_)
        ),
        "thresholds": {
            "iforest_gate": config.IFOREST_GATE_THRESHOLD,
            "fusion_confirm": config.FUSION_CONFIRM_THRESHOLD,
            "window_size": config.WINDOW_SIZE,
            "window_stride": config.WINDOW_STRIDE,
            "gated_pipeline": config.GATED_PIPELINE,
        },
    })

    # 7. Persist everything ------------------------------------------------
    print("\n--- Saving models ---")
    fx.save()
    tier1.save()
    tier2a.save()
    tier2b.save()
    engine.save()
    print(f"All artifacts saved to {config.MODEL_DIR}/")
    print("\nDone. Run inference.py to simulate the real-time gateway loop.")


if __name__ == "__main__":
    main()
