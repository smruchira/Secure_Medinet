"""
train_model.py
----------------
Trains a Random Forest classifier to detect ECG host-based attacks
using the cloud-safe features (no private data involved at all).

Input:  cloud_log.jsonl  (features + label + source, no private fields)
Output: ecg_attack_model.joblib  (the trained model, ready to use for
        predictions -- this is what you'd deploy to Google Cloud later)

Run this locally first to prove it works, then the exact same script
(or model) can be used inside Google Cloud (Vertex AI custom training).
"""

import json
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import joblib

CLOUD_LOG_PATH = "cloud_log.jsonl"
MODEL_OUTPUT_PATH = "ecg_attack_model.joblib"

# These are the actual ML input features -- everything else in the log
# (timestamp, source, label) is metadata, not something the model learns from.
FEATURE_COLUMNS = [
    "hr_bpm",
    "rr_interval",
    "signal_entropy",
    "qrs_amplitude",
    "sampling_gap_ms",
    "is_duplicate_window",
]


def load_dataset(path=CLOUD_LOG_PATH):
    rows = []
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return pd.DataFrame(rows)


def train_and_evaluate():
    print("Loading dataset...")
    df = load_dataset()
    print(f"Loaded {len(df)} entries")
    print(f"Label distribution:\n{df['label'].value_counts()}\n")

    X = df[FEATURE_COLUMNS]
    y = df["label"]

    # 80% train, 20% test -- stratify keeps class balance equal in both splits
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print(f"Training on {len(X_train)} entries, testing on {len(X_test)} entries...\n")

    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        random_state=42,
        class_weight="balanced"  # protects against any class imbalance
    )
    model.fit(X_train, y_train)

    # Evaluate on held-out test data (data the model never saw during training)
    y_pred = model.predict(X_test)

    print("=" * 60)
    print(f"TEST ACCURACY: {accuracy_score(y_test, y_pred):.4f}")
    print("=" * 60)
    print("\nClassification Report (per attack type):\n")
    print(classification_report(y_test, y_pred))

    print("\nConfusion Matrix:")
    labels_sorted = sorted(y.unique())
    cm = confusion_matrix(y_test, y_pred, labels=labels_sorted)
    cm_df = pd.DataFrame(cm, index=labels_sorted, columns=labels_sorted)
    print(cm_df)

    # Feature importance -- shows which features mattered most for detection,
    # useful to explain/justify your feature choices in the report
    print("\nFeature Importance (which features mattered most):")
    importance = pd.Series(model.feature_importances_, index=FEATURE_COLUMNS)
    print(importance.sort_values(ascending=False).round(4))

    # Save the trained model to disk
    joblib.dump(model, MODEL_OUTPUT_PATH)
    print(f"\nModel saved to: {MODEL_OUTPUT_PATH}")

    return model


def predict_single(model, features_dict):
    """
    Example of how to use the trained model to predict on ONE new entry
    (this is what the cloud/dashboard would call for live predictions).
    """
    X_new = pd.DataFrame([features_dict])[FEATURE_COLUMNS]
    prediction = model.predict(X_new)[0]
    probabilities = model.predict_proba(X_new)[0]
    confidence = max(probabilities)
    return prediction, confidence


if __name__ == "__main__":
    model = train_and_evaluate()

    # Quick demo: predict on one normal-looking entry
    print("\n" + "=" * 60)
    print("DEMO PREDICTION:")
    example = {
        "hr_bpm": 75.0,
        "rr_interval": 0.8,
        "signal_entropy": 0.14,
        "qrs_amplitude": 0.87,
        "sampling_gap_ms": 0.0,
        "is_duplicate_window": 0,
    }
    pred, conf = predict_single(model, example)
    print(f"Input: {example}")
    print(f"Prediction: {pred} (confidence: {conf:.2%})")
