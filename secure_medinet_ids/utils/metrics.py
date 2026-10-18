"""
metrics.py
==========
Evaluation helpers. Deliberately reports PER-CLASS precision/recall/F1
rather than leaning on overall accuracy, which is close to meaningless
under the kind of class imbalance this project targets (a model predicting
"normal" for everything can score >90% accuracy while catching zero
attacks). This is the evidence you'll want in the write-up to support the
rare-attack-recall novelty claim.
"""

import time
import numpy as np
from sklearn.metrics import classification_report, confusion_matrix


def per_class_report(y_true, y_pred, class_names):
    print(classification_report(y_true, y_pred, target_names=class_names, zero_division=0))
    return classification_report(
        y_true, y_pred, target_names=class_names, zero_division=0, output_dict=True
    )


def print_confusion_matrix(y_true, y_pred, class_names):
    cm = confusion_matrix(y_true, y_pred, labels=range(len(class_names)))
    print("Confusion matrix (rows=true, cols=predicted):")
    header = "        " + " ".join(f"{c[:8]:>8}" for c in class_names)
    print(header)
    for i, row in enumerate(cm):
        print(f"{class_names[i][:8]:>8} " + " ".join(f"{v:>8}" for v in row))
    return cm


class LatencyTimer:
    """Context manager for measuring per-stage inference latency, used to
    produce the edge-deployment latency/accuracy tradeoff evidence."""

    def __init__(self, label, store: dict):
        self.label = label
        self.store = store

    def __enter__(self):
        self._t0 = time.perf_counter()
        return self

    def __exit__(self, *exc):
        elapsed_ms = (time.perf_counter() - self._t0) * 1000
        self.store.setdefault(self.label, []).append(elapsed_ms)


def summarize_latency(store: dict):
    print("\n--- Latency summary (ms) ---")
    for stage, samples in store.items():
        arr = np.array(samples)
        print(f"{stage:20s} mean={arr.mean():7.3f}  p95={np.percentile(arr, 95):7.3f}  "
              f"n={len(arr)}")
