"""
isolation_forest_model.py
==========================
Tier 1: fast, low-overhead statistical triage. Runs on every flow. Its job
is NOT to be highly accurate -- it's to cheaply decide "is this worth
Tier 2's more expensive scrutiny?" (see config.GATED_PIPELINE).
"""

import os
import sys
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config


class IsolationForestTier:
    def __init__(self):
        self.model = IsolationForest(**config.IFOREST_PARAMS)
        self._score_min = None
        self._score_max = None

    def fit(self, X: np.ndarray):
        self.model.fit(X)
        # calibrate raw decision_function scores into a stable [0, 1] range
        # using the TRAINING distribution, so confidence is comparable
        # across runs/datasets.
        raw = -self.model.decision_function(X)  # higher = more anomalous
        self._score_min, self._score_max = float(raw.min()), float(raw.max())
        return self

    def confidence(self, X: np.ndarray) -> np.ndarray:
        """Returns anomaly confidence in [0, 1], higher = more anomalous."""
        raw = -self.model.decision_function(X)
        span = max(self._score_max - self._score_min, 1e-9)
        conf = (raw - self._score_min) / span
        return np.clip(conf, 0.0, 1.0)

    def gate(self, X: np.ndarray) -> np.ndarray:
        """Boolean mask: True where Tier 2 should be triggered."""
        return self.confidence(X) >= config.IFOREST_GATE_THRESHOLD

    def save(self, path=None):
        path = path or os.path.join(config.MODEL_DIR, "isolation_forest.joblib")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        joblib.dump(self, path)
        return path

    @staticmethod
    def load(path=None):
        path = path or os.path.join(config.MODEL_DIR, "isolation_forest.joblib")
        return joblib.load(path)


if __name__ == "__main__":
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from preprocessing.feature_extraction import load_raw, FeatureExtractor

    df = load_raw()
    fx = FeatureExtractor()
    X, y = fx.fit_transform(df)

    tier1 = IsolationForestTier().fit(X)
    conf = tier1.confidence(X)
    gated = tier1.gate(X)
    print(f"Mean confidence: {conf.mean():.3f} | Flagged for Tier 2: {gated.sum()}/{len(X)} "
          f"({gated.mean()*100:.1f}%)")
    tier1.save()
