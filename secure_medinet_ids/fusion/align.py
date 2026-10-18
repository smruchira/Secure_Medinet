"""
align.py
========
Isolation Forest and AutoEncoder emit one confidence score PER PACKET.
LSTM emits one confidence score PER WINDOW (WINDOW_SIZE packets).
Before the decision engine can fuse all three, the per-packet scores need
to be reduced to per-window scores using the SAME window boundaries the
LSTM was built on (preprocessing.windowing.window_starts) -- otherwise the
three tiers are talking about different spans of traffic.

Aggregation defaults to the 90th percentile rather than a strict max.
Empirically (see README "Known limitations of the demo run"), taking the
raw max of a per-packet anomaly score over a 50-packet window is too
noise-sensitive: with enough packets, random per-packet score variance
alone produces a high max even inside genuinely normal windows, which
erodes Tier 1/2a's contribution once fused with the LSTM. A high
percentile keeps sensitivity to real bursts of anomalous packets while
being far less influenced by a single noisy outlier packet.
"""

import os
import sys
import numpy as np

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from preprocessing.windowing import window_starts


def aggregate_to_windows(per_sample_scores: np.ndarray, window_size: int = None,
                          stride: int = None, agg: str = "p90") -> np.ndarray:
    window_size = window_size or config.WINDOW_SIZE
    stride = stride or config.WINDOW_STRIDE
    starts = window_starts(len(per_sample_scores), window_size, stride)

    if agg == "max":
        agg_fn = lambda seg: np.max(seg)
    elif agg == "mean":
        agg_fn = lambda seg: np.mean(seg)
    elif agg.startswith("p"):
        pct = float(agg[1:])
        agg_fn = lambda seg: np.percentile(seg, pct)
    else:
        raise ValueError(f"Unknown aggregation method: {agg}")

    return np.array([agg_fn(per_sample_scores[s:s + window_size]) for s in starts])
