"""
autoencoder_model.py
=====================
Tier 2: learns a compressed representation of NORMAL traffic only. Attacks
(including zero-day patterns never seen in training) tend to reconstruct
poorly, so reconstruction error is used as the anomaly signal.

Threshold is calibrated from the validation-set NORMAL reconstruction-error
distribution (AE_THRESHOLD_PERCENTILE), not hand-picked -- this is part of
the project's rare-attack / imbalance-aware design.
"""

import os
import sys
import joblib
import numpy as np
import torch
import torch.nn as nn

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

torch.manual_seed(config.RANDOM_SEED)


class _AENet(nn.Module):
    def __init__(self, input_dim, hidden_dims):
        super().__init__()
        layers = []
        dims = [input_dim] + hidden_dims
        for i in range(len(dims) - 1):
            layers.append(nn.Linear(dims[i], dims[i + 1]))
            # no activation after the bottleneck-to-output final layer so the
            # network can reconstruct unbounded standardized features
            if i < len(dims) - 2:
                layers.append(nn.ReLU())
        layers.append(nn.Linear(dims[-1], input_dim))
        self.net = nn.Sequential(*layers)

    def forward(self, x):
        return self.net(x)


class AutoEncoderTier:
    def __init__(self, input_dim=None):
        self.input_dim = input_dim
        self.model = None
        self.threshold_ = None
        self._err_min = None
        self._err_max = None

    def _build(self, input_dim):
        self.input_dim = input_dim
        self.model = _AENet(input_dim, config.AE_HIDDEN_DIMS)

    def fit(self, X_normal_train: np.ndarray, X_normal_val: np.ndarray):
        """Trains ONLY on normal traffic -- attacks must never appear here,
        otherwise the model learns to reconstruct them too and loses signal."""
        if self.model is None:
            self._build(X_normal_train.shape[1])

        X_t = torch.tensor(X_normal_train, dtype=torch.float32)
        opt = torch.optim.Adam(self.model.parameters(), lr=config.AE_LEARNING_RATE)
        loss_fn = nn.MSELoss()

        self.model.train()
        n = X_t.shape[0]
        batch_size = min(config.AE_BATCH_SIZE, n)
        for epoch in range(config.AE_EPOCHS):
            perm = torch.randperm(n)
            epoch_loss = 0.0
            for i in range(0, n, batch_size):
                idx = perm[i:i + batch_size]
                batch = X_t[idx]
                opt.zero_grad()
                recon = self.model(batch)
                loss = loss_fn(recon, batch)
                loss.backward()
                opt.step()
                epoch_loss += loss.item() * len(idx)
            if (epoch + 1) % 10 == 0 or epoch == 0:
                print(f"  [AutoEncoder] epoch {epoch+1}/{config.AE_EPOCHS} "
                      f"loss={epoch_loss/n:.5f}")

        # calibrate threshold + normalization range from held-out NORMAL data
        val_errors = self._reconstruction_error(X_normal_val)
        self.threshold_ = float(np.percentile(val_errors, config.AE_THRESHOLD_PERCENTILE))
        self._err_min = float(val_errors.min())
        self._err_max = float(max(val_errors.max(), self.threshold_ * 2))
        return self

    def _reconstruction_error(self, X: np.ndarray) -> np.ndarray:
        self.model.eval()
        with torch.no_grad():
            X_t = torch.tensor(X, dtype=torch.float32)
            recon = self.model(X_t)
            err = torch.mean((recon - X_t) ** 2, dim=1).numpy()
        return err

    def confidence(self, X: np.ndarray) -> np.ndarray:
        """Anomaly confidence in [0, 1], higher = more anomalous, calibrated
        against the fitted threshold."""
        err = self._reconstruction_error(X)
        span = max(self._err_max - self._err_min, 1e-9)
        conf = (err - self._err_min) / span
        return np.clip(conf, 0.0, 1.0)

    def is_anomalous(self, X: np.ndarray) -> np.ndarray:
        err = self._reconstruction_error(X)
        return err >= self.threshold_

    def save(self, path=None):
        path = path or os.path.join(config.MODEL_DIR, "autoencoder.joblib")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        state = {
            "input_dim": self.input_dim,
            "state_dict": self.model.state_dict(),
            "threshold_": self.threshold_,
            "_err_min": self._err_min,
            "_err_max": self._err_max,
        }
        joblib.dump(state, path)
        return path

    @staticmethod
    def load(path=None):
        path = path or os.path.join(config.MODEL_DIR, "autoencoder.joblib")
        state = joblib.load(path)
        tier = AutoEncoderTier(input_dim=state["input_dim"])
        tier._build(state["input_dim"])
        tier.model.load_state_dict(state["state_dict"])
        tier.model.eval()
        tier.threshold_ = state["threshold_"]
        tier._err_min = state["_err_min"]
        tier._err_max = state["_err_max"]
        return tier


if __name__ == "__main__":
    from sklearn.model_selection import train_test_split
    from preprocessing.feature_extraction import load_raw, FeatureExtractor

    df = load_raw()
    fx = FeatureExtractor()
    X, y = fx.fit_transform(df)
    benign_idx = fx.label_index(config.BENIGN_CLASS)

    X_normal = X[y == benign_idx]
    X_train, X_val = train_test_split(X_normal, test_size=0.2, random_state=config.RANDOM_SEED)

    ae = AutoEncoderTier().fit(X_train, X_val)

    # sanity check: attacks should score higher than normal on average
    X_attack = X[y != benign_idx]
    normal_conf = ae.confidence(X_val)
    attack_conf = ae.confidence(X_attack)
    print(f"Mean AE confidence -- normal(val): {normal_conf.mean():.3f} | "
          f"attacks: {attack_conf.mean():.3f}")
    print(f"Attack detection rate at calibrated threshold: "
          f"{ae.is_anomalous(X_attack).mean()*100:.1f}%")
    ae.save()
