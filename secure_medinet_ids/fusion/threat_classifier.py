"""
threat_classifier.py
=====================
IMPORTANT DESIGN NOTE (read before wiring this into inference.py further):

The Decision Engine (fusion/decision_engine.py) only answers a BINARY
question: "is this window a confirmed threat, yes/no?". None of Tier 1
(Isolation Forest), Tier 2a (AutoEncoder), or Tier 2b (LSTM, trained as a
binary attack/normal classifier) know WHICH attack type they're looking at.

At inference time there is no ground-truth label available -- so the
SDN payload's `threat_type` field CANNOT be filled in from y_true (doing
so is label leakage and will silently make the "system" look perfect in
a demo while being non-functional in real deployment).

This module adds a small, separate multiclass classifier trained ONLY on
confirmed-positive windows (using tier confidences + a compact summary of
the window's own raw features) to give a best-effort attack-type label for
logging / SDN policy differentiation. It never influences the confirm/deny
decision itself -- that stays the Decision Engine's job.

With very few labeled attack windows in the current synthetic demo dataset
(~13-15 per class), this classifier WILL overfit somewhat. Retrain once the
real Mininet-WiFi dataset is available; if per-class attack samples remain
scarce, consider reporting "unclassified_threat" instead of a specific type
below some confidence threshold, rather than guessing.
"""

import os
import sys
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config


def window_summary_features(window: np.ndarray) -> np.ndarray:
    """Compact per-window feature summary: mean across timesteps of every
    raw feature. Cheap, and gives the classifier the same raw signal shape
    (byte rate, retransmissions, etc.) that made each attack distinct."""
    return window.mean(axis=0)


class ThreatTypeClassifier:
    def __init__(self):
        self.model = RandomForestClassifier(
            n_estimators=150, class_weight="balanced", random_state=config.RANDOM_SEED
        )
        self.classes_ = None
        self.min_confidence = 0.35  # below this, report "unclassified_threat"

    def build_features(self, windows: np.ndarray, if_conf, ae_conf, lstm_conf) -> np.ndarray:
        summaries = np.stack([window_summary_features(w) for w in windows])
        tier_scores = np.column_stack([
            np.atleast_1d(if_conf), np.atleast_1d(ae_conf), np.atleast_1d(lstm_conf)
        ])
        return np.concatenate([tier_scores, summaries], axis=1)

    def fit(self, windows, if_conf, ae_conf, lstm_conf, attack_type_labels):
        """attack_type_labels: string labels, e.g. 'mitm'/'replay'/'spoofing'/'ddos'
        -- ONLY pass confirmed-attack windows here, never 'normal'."""
        X = self.build_features(windows, if_conf, ae_conf, lstm_conf)
        self.model.fit(X, attack_type_labels)
        self.classes_ = self.model.classes_
        return self

    def predict(self, window, if_conf, ae_conf, lstm_conf) -> str:
        """Call ONLY when the Decision Engine has already confirmed a threat
        for this window. Returns a class name or 'unclassified_threat' if
        the classifier isn't confident enough to commit to a specific type."""
        X = self.build_features(window[np.newaxis, ...], if_conf, ae_conf, lstm_conf)
        proba = self.model.predict_proba(X)[0]
        best_idx = int(np.argmax(proba))
        if proba[best_idx] < self.min_confidence:
            return "unclassified_threat"
        return str(self.classes_[best_idx])

    def save(self, path=None):
        path = path or os.path.join(config.MODEL_DIR, "threat_classifier.joblib")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        joblib.dump(self, path)
        return path

    @staticmethod
    def load(path=None):
        path = path or os.path.join(config.MODEL_DIR, "threat_classifier.joblib")
        return joblib.load(path)
