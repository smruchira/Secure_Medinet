"""
train_temp_model.py
----------------------
Trains a Random Forest classifier to detect temperature-sensor
host-based attacks using cloud-safe features only. Mirrors
train_model.py exactly.

Input:  cloud_log_temp.jsonl
Output: temp_attack_model.joblib  (copy this into cloud/ and redeploy)
"""

import json
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import joblib

CLOUD_LOG_PATH = "cloud_log_temp.jsonl"
MODEL_OUTPUT_PATH = "temp_attack_model.joblib"

FEATURE_COLUMNS = [
    "mean_temp_c",
    "temp_std_c",
    "max_rate_of_change",
    "signal_entropy",
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

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print(f"Training on {len(X_train)} entries, testing on {len(X_test)} entries...\n")

    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        random_state=42,
        class_weight="balanced"
    )
    model.fit(X_train, y_train)

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

    print("\nFeature Importance (which features mattered most):")
    importance = pd.Series(model.feature_importances_, index=FEATURE_COLUMNS)
    print(importance.sort_values(ascending=False).round(4))

    joblib.dump(model, MODEL_OUTPUT_PATH)
    print(f"\nModel saved to: {MODEL_OUTPUT_PATH}")

    return model


def predict_single(model, features_dict):
    X_new = pd.DataFrame([features_dict])[FEATURE_COLUMNS]
    prediction = model.predict(X_new)[0]
    probabilities = model.predict_proba(X_new)[0]
    confidence = max(probabilities)
    return prediction, confidence


if __name__ == "__main__":
    model = train_and_evaluate()

    print("\n" + "=" * 60)
    print("DEMO PREDICTION:")
    example = {
        "mean_temp_c": 36.8,
        "temp_std_c": 0.1,
        "max_rate_of_change": 0.15,
        "signal_entropy": 2.8,
        "sampling_gap_ms": 0.0,
        "is_duplicate_window": 0,
    }
    pred, conf = predict_single(model, example)
    print(f"Input: {example}")
    print(f"Prediction: {pred} (confidence: {conf:.2%})")
