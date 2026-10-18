"""
feature_extraction.py
======================
Loads raw gateway metadata, encodes categorical fields, scales numeric
fields, and returns clean feature matrices + labels ready for the
Isolation Forest / AutoEncoder tiers and for windowing (LSTM tier).
"""

import os
import sys
import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler, LabelEncoder

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config


class FeatureExtractor:
    """Fits/loads scalers + encoders and transforms raw metadata into
    a numeric feature matrix. Persisted with joblib so inference uses the
    exact same transform that training used (no train/serve skew)."""

    def __init__(self):
        self.scaler = StandardScaler()
        self.encoders = {col: LabelEncoder() for col in config.CATEGORICAL_FEATURES}
        self.label_encoder = LabelEncoder()
        self._fitted = False

    def fit_transform(self, df: pd.DataFrame):
        df = df.copy()
        for col in config.CATEGORICAL_FEATURES:
            df[col] = self.encoders[col].fit_transform(df[col].astype(str))

        X_numeric = df[config.NUMERIC_FEATURES].astype(float).values
        X_categorical = df[config.CATEGORICAL_FEATURES].astype(float).values
        X = np.concatenate([X_numeric, X_categorical], axis=1)
        X = self.scaler.fit_transform(X)

        y = None
        if config.LABEL_COLUMN in df.columns:
            y = self.label_encoder.fit_transform(df[config.LABEL_COLUMN].astype(str))

        self._fitted = True
        return X, y

    def transform(self, df: pd.DataFrame):
        if not self._fitted:
            raise RuntimeError("FeatureExtractor must be fit before calling transform().")
        df = df.copy()
        for col in config.CATEGORICAL_FEATURES:
            known = set(self.encoders[col].classes_)
            df[col] = df[col].astype(str).apply(lambda v: v if v in known else self.encoders[col].classes_[0])
            df[col] = self.encoders[col].transform(df[col])

        X_numeric = df[config.NUMERIC_FEATURES].astype(float).values
        X_categorical = df[config.CATEGORICAL_FEATURES].astype(float).values
        X = np.concatenate([X_numeric, X_categorical], axis=1)
        return self.scaler.transform(X)

    def inverse_label(self, encoded_labels):
        return self.label_encoder.inverse_transform(encoded_labels)

    def label_index(self, class_name):
        return list(self.label_encoder.classes_).index(class_name)

    def save(self, path=None):
        path = path or os.path.join(config.MODEL_DIR, "feature_extractor.joblib")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        joblib.dump(self, path)
        return path

    @staticmethod
    def load(path=None):
        path = path or os.path.join(config.MODEL_DIR, "feature_extractor.joblib")
        return joblib.load(path)


def load_raw(path=None) -> pd.DataFrame:
    path = path or config.RAW_DATA_PATH
    df = pd.read_csv(path)
    df = df.sort_values(config.TIMESTAMP_COLUMN).reset_index(drop=True)
    return df


if __name__ == "__main__":
    df = load_raw()
    fx = FeatureExtractor()
    X, y = fx.fit_transform(df)
    print("Feature matrix shape:", X.shape)
    print("Classes:", list(fx.label_encoder.classes_))
    fx.save()
    print("Saved fitted FeatureExtractor to", os.path.join(config.MODEL_DIR, "feature_extractor.joblib"))
