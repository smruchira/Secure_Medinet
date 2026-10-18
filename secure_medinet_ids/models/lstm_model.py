"""
lstm_model.py
=============
Tier 2: evaluates sliding windows of MQTT/TLS communication metadata for
temporal patterns -- this is what catches replay attacks (near-identical
packets recurring in a short burst) and other sequential anomalies that a
per-packet model (Isolation Forest, AutoEncoder) cannot see.

Trained as a binary attack-vs-normal sequence classifier with inverse-
frequency class weighting (config.LSTM_CLASS_WEIGHTING) since attack windows
are rare by construction.
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


class _LSTMNet(nn.Module):
    def __init__(self, input_dim, hidden_size, num_layers, dropout):
        super().__init__()
        self.lstm = nn.LSTM(
            input_size=input_dim,
            hidden_size=hidden_size,
            num_layers=num_layers,
            batch_first=True,
            dropout=dropout if num_layers > 1 else 0.0,
        )
        self.head = nn.Sequential(
            nn.Linear(hidden_size, hidden_size // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_size // 2, 1),  # binary logit: attack vs normal
        )

    def forward(self, x):
        out, (h_n, _) = self.lstm(x)
        last_hidden = h_n[-1]  # (batch, hidden_size) -- final layer's last timestep
        return self.head(last_hidden).squeeze(-1)  # (batch,) logits


class LSTMTier:
    def __init__(self, input_dim=None):
        self.input_dim = input_dim
        self.model = None

    def _build(self, input_dim):
        self.input_dim = input_dim
        self.model = _LSTMNet(
            input_dim, config.LSTM_HIDDEN_SIZE, config.LSTM_NUM_LAYERS, config.LSTM_DROPOUT
        )

    def fit(self, X_windows: np.ndarray, y_binary: np.ndarray):
        """
        X_windows: (num_windows, window_size, F)
        y_binary:  (num_windows,) 1 = attack window, 0 = normal window
        """
        if self.model is None:
            self._build(X_windows.shape[2])

        X_t = torch.tensor(X_windows, dtype=torch.float32)
        y_t = torch.tensor(y_binary, dtype=torch.float32)

        if config.LSTM_CLASS_WEIGHTING:
            n_pos = max(y_binary.sum(), 1)
            n_neg = max(len(y_binary) - n_pos, 1)
            pos_weight = torch.tensor(n_neg / n_pos, dtype=torch.float32)
        else:
            pos_weight = torch.tensor(1.0)

        loss_fn = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
        opt = torch.optim.Adam(self.model.parameters(), lr=config.LSTM_LEARNING_RATE)

        n = X_t.shape[0]
        batch_size = min(config.LSTM_BATCH_SIZE, n)
        self.model.train()
        for epoch in range(config.LSTM_EPOCHS):
            perm = torch.randperm(n)
            epoch_loss = 0.0
            for i in range(0, n, batch_size):
                idx = perm[i:i + batch_size]
                opt.zero_grad()
                logits = self.model(X_t[idx])
                loss = loss_fn(logits, y_t[idx])
                loss.backward()
                opt.step()
                epoch_loss += loss.item() * len(idx)
            if (epoch + 1) % 5 == 0 or epoch == 0:
                print(f"  [LSTM] epoch {epoch+1}/{config.LSTM_EPOCHS} "
                      f"loss={epoch_loss/n:.5f} (pos_weight={pos_weight.item():.1f})")
        return self

    def confidence(self, X_windows: np.ndarray) -> np.ndarray:
        """Returns attack confidence in [0, 1] per window (sigmoid of logit)."""
        self.model.eval()
        with torch.no_grad():
            X_t = torch.tensor(X_windows, dtype=torch.float32)
            logits = self.model(X_t)
            probs = torch.sigmoid(logits).numpy()
        return probs

    def save(self, path=None):
        path = path or os.path.join(config.MODEL_DIR, "lstm.joblib")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        joblib.dump({"input_dim": self.input_dim, "state_dict": self.model.state_dict()}, path)
        return path

    @staticmethod
    def load(path=None):
        path = path or os.path.join(config.MODEL_DIR, "lstm.joblib")
        state = joblib.load(path)
        tier = LSTMTier(input_dim=state["input_dim"])
        tier._build(state["input_dim"])
        tier.model.load_state_dict(state["state_dict"])
        tier.model.eval()
        return tier


if __name__ == "__main__":
    from preprocessing.feature_extraction import load_raw, FeatureExtractor
    from preprocessing.windowing import build_windows

    df = load_raw()
    fx = FeatureExtractor()
    X, y = fx.fit_transform(df)
    benign_idx = fx.label_index(config.BENIGN_CLASS)

    Xw, yw = build_windows(X, y)
    y_binary = (yw != benign_idx).astype(int)
    print(f"Windows: {len(yw)} total, {y_binary.sum()} attack windows "
          f"({y_binary.mean()*100:.1f}%)")

    lstm = LSTMTier().fit(Xw, y_binary)
    conf = lstm.confidence(Xw)
    print(f"Mean confidence -- normal windows: {conf[y_binary==0].mean():.3f} | "
          f"attack windows: {conf[y_binary==1].mean():.3f}")
    lstm.save()
