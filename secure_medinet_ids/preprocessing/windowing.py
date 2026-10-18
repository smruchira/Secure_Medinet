"""
windowing.py
============
Converts the flat (N, F) feature matrix into overlapping sliding windows of
shape (num_windows, WINDOW_SIZE, F) for the LSTM tier, which needs temporal
context to catch sequential threats (replay in particular).

Window labeling rule is config-driven (config.WINDOW_LABEL_RULE):
  "any"      -> window is attack-X if ANY timestep in it is attack-X
                 (maximizes recall on rare attacks; some label noise)
  "majority" -> window is attack-X if > 50% of timesteps are attack-X
                 (cleaner labels; may under-count short attack bursts)
Given this project's explicit goal (rare attack recall), "any" is the
recommended default -- documented here so the choice is traceable.
"""

import os
import sys
import numpy as np
from collections import Counter

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config


def window_starts(n_samples: int, window_size: int, stride: int):
    """Shared start-index logic so every module that windows the same
    stream (features, labels, per-packet tier scores) stays aligned."""
    return list(range(0, n_samples - window_size + 1, stride))


def build_windows(X: np.ndarray, y: np.ndarray = None,
                   window_size: int = None, stride: int = None,
                   label_rule: str = None):
    """
    X: (N, F) feature matrix, already time-ordered.
    y: (N,) integer-encoded labels, or None for inference-time streaming data.

    Returns:
        X_windows: (num_windows, window_size, F)
        y_windows: (num_windows,) or None
    """
    window_size = window_size or config.WINDOW_SIZE
    stride = stride or config.WINDOW_STRIDE
    label_rule = label_rule or config.WINDOW_LABEL_RULE

    n_samples = X.shape[0]
    if n_samples < window_size:
        raise ValueError(
            f"Not enough samples ({n_samples}) to build a single window of "
            f"size {window_size}. Reduce WINDOW_SIZE or provide more data."
        )

    starts = window_starts(n_samples, window_size, stride)
    X_windows = np.stack([X[s:s + window_size] for s in starts])

    y_windows = None
    if y is not None:
        y_windows = []
        benign_idx = None  # resolved by caller if needed; here we just vote/any over raw ints
        for s in starts:
            segment = y[s:s + window_size]
            y_windows.append(_label_window(segment, label_rule))
        y_windows = np.array(y_windows)

    return X_windows, y_windows


def _label_window(segment, label_rule):
    counts = Counter(segment.tolist())
    most_common_label, most_common_count = counts.most_common(1)[0]

    if label_rule == "majority":
        return most_common_label

    if label_rule == "any":
        # Prefer any non-majority (rarer) label present in the window --
        # in practice this means: if more than one class appears, pick the
        # class that is NOT the single most frequent one across the whole
        # stream is not knowable locally, so heuristically we pick the
        # label with the smallest count within this window (rarer signal
        # inside the window wins), unless the window is pure.
        if len(counts) == 1:
            return most_common_label
        # pick the rarest label within the window (attack signal, if any, wins)
        rarest_label, _ = min(counts.items(), key=lambda kv: kv[1])
        return rarest_label

    raise ValueError(f"Unknown WINDOW_LABEL_RULE: {label_rule}")


if __name__ == "__main__":
    # quick smoke test with dummy data
    rng = np.random.default_rng(0)
    X = rng.normal(size=(500, 13))
    y = np.zeros(500, dtype=int)
    y[250:255] = 1  # a short rare-attack burst
    Xw, yw = build_windows(X, y, window_size=50, stride=10)
    print("Window tensor shape:", Xw.shape)
    print("Windows containing the rare burst label 1:", int((yw == 1).sum()), "/", len(yw))
