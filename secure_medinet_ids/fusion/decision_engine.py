"""
decision_engine.py
===================
Combines Tier 1 (Isolation Forest) + Tier 2 (AutoEncoder, LSTM) confidence
scores into one final "is this a confirmed threat" decision.

Two fusion modes, both implemented (config.USE_STACKED_META_LEARNER selects):

  1. Weighted voting (config.FUSION_WEIGHTS) -- simple, interpretable,
     always available as a fallback (e.g., before enough labeled data
     exists to fit a meta-learner).

  2. Stacked meta-learner -- a small logistic regression trained on
     [if_conf, ae_conf, lstm_conf] -> is_attack. This lets the fusion layer
     learn, from data, how much to trust each tier (rather than hand-tuned
     weights), which is the more defensible design when asked "how did you
     pick the weights?".

Either way, the output is a single fused confidence in [0, 1] plus a
boolean "confirmed" decision against config.FUSION_CONFIRM_THRESHOLD.
"""

import os
import sys
import joblib
import numpy as np
from sklearn.linear_model import LogisticRegression

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config


class DecisionEngine:
    def __init__(self):
        self.meta_learner = None
        self.mode = "stacked" if config.USE_STACKED_META_LEARNER else "weighted"

    def fit_meta_learner(self, if_conf, ae_conf, lstm_conf, y_binary):
        """Fits the stacking classifier on aligned per-window tier scores.
        Caller is responsible for aligning IF/AE (per-packet) scores to the
        LSTM's per-window granularity (see fusion/align.py-style logic in
        train.py) before calling this."""
        Xstack = np.column_stack([if_conf, ae_conf, lstm_conf])
        self.meta_learner = LogisticRegression(class_weight="balanced", max_iter=1000)
        self.meta_learner.fit(Xstack, y_binary)
        self.mode = "stacked"
        return self

    def fuse(self, if_conf, ae_conf=None, lstm_conf=None):
        """
        Fuses tier confidences into a final decision.

        If Tier 2 was gated off (config.GATED_PIPELINE and Tier 1 did not
        flag the sample), ae_conf/lstm_conf will be None -- in that case we
        trust Tier 1's low score directly (Tier 2 was skipped because Tier 1
        was already confident nothing is happening).
        """
        if_conf = np.atleast_1d(if_conf).astype(float)

        if ae_conf is None or lstm_conf is None:
            fused = if_conf.copy()
        elif self.mode == "stacked" and self.meta_learner is not None:
            Xstack = np.column_stack([
                if_conf,
                np.atleast_1d(ae_conf).astype(float),
                np.atleast_1d(lstm_conf).astype(float),
            ])
            fused = self.meta_learner.predict_proba(Xstack)[:, 1]
        else:
            w = config.FUSION_WEIGHTS
            fused = (
                w["isolation_forest"] * if_conf
                + w["autoencoder"] * np.atleast_1d(ae_conf).astype(float)
                + w["lstm"] * np.atleast_1d(lstm_conf).astype(float)
            )

        confirmed = fused >= config.FUSION_CONFIRM_THRESHOLD
        return fused, confirmed

    def save(self, path=None):
        path = path or os.path.join(config.MODEL_DIR, "decision_engine.joblib")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        joblib.dump(self, path)
        return path

    @staticmethod
    def load(path=None):
        path = path or os.path.join(config.MODEL_DIR, "decision_engine.joblib")
        return joblib.load(path)


if __name__ == "__main__":
    # smoke test with synthetic tier outputs
    rng = np.random.default_rng(0)
    n = 500
    y = (rng.random(n) < 0.1).astype(int)
    if_conf = np.clip(y * 0.6 + rng.normal(0.2, 0.15, n), 0, 1)
    ae_conf = np.clip(y * 0.7 + rng.normal(0.15, 0.15, n), 0, 1)
    lstm_conf = np.clip(y * 0.8 + rng.normal(0.1, 0.15, n), 0, 1)

    engine = DecisionEngine().fit_meta_learner(if_conf, ae_conf, lstm_conf, y)
    fused, confirmed = engine.fuse(if_conf, ae_conf, lstm_conf)

    tp = int(((confirmed == 1) & (y == 1)).sum())
    fn = int(((confirmed == 0) & (y == 1)).sum())
    fp = int(((confirmed == 1) & (y == 0)).sum())
    recall = tp / max(tp + fn, 1)
    precision = tp / max(tp + fp, 1)
    print(f"Stacked fusion -- recall: {recall:.2f}, precision: {precision:.2f}")
