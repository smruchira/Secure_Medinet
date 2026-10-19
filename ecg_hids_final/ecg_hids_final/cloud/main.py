"""
main.py
--------
FastAPI service that hosts the trained attack-detection models.
Deployed on Render. Stateless -- no database, no storage. Receives
privacy-safe features, returns a prediction. That's the entire job.

Two independent models are served from this one app (one Render
service, two endpoints) -- the ECG model and the temperature-sensor
model, added for the DS18B20/ESP32 temperature device:

Endpoints:
  GET  /health         -- simple check that the service and both models are up
  POST /predict         -- ECG features in, ECG prediction out
  POST /predict_temp    -- temperature features in, temperature prediction out

Run locally for testing:
  uvicorn main:app --host 0.0.0.0 --port 6000

On Render, the start command is the same, using the $PORT Render provides:
  uvicorn main:app --host 0.0.0.0 --port $PORT
"""

import logging
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import joblib
import pandas as pd

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ml_api")

app = FastAPI(title="Secure Medinet Attack Detection API", version="1.1")

# --- ECG model ---
ECG_MODEL_PATH = "ecg_attack_model.joblib"
ECG_FEATURE_COLUMNS = [
    "hr_bpm",
    "rr_interval",
    "signal_entropy",
    "qrs_amplitude",
    "sampling_gap_ms",
    "is_duplicate_window",
]

# --- Temperature model ---
TEMP_MODEL_PATH = "temp_attack_model.joblib"
TEMP_FEATURE_COLUMNS = [
    "mean_temp_c",
    "temp_std_c",
    "max_rate_of_change",
    "signal_entropy",
    "sampling_gap_ms",
    "is_duplicate_window",
]

logger.info("Loading trained ECG model...")
ecg_model = joblib.load(ECG_MODEL_PATH)
logger.info("Loading trained temperature model...")
temp_model = joblib.load(TEMP_MODEL_PATH)
logger.info("Models loaded and ready.")


class ECGFeatures(BaseModel):
    hr_bpm: float
    rr_interval: float
    signal_entropy: float
    qrs_amplitude: float
    sampling_gap_ms: float
    is_duplicate_window: int


class TempFeatures(BaseModel):
    mean_temp_c: float
    temp_std_c: float
    max_rate_of_change: float
    signal_entropy: float
    sampling_gap_ms: float
    is_duplicate_window: int


class PredictionResponse(BaseModel):
    prediction: str
    confidence: float


@app.get("/health")
def health_check():
    return {
        "status": "ML API is running",
        "models": {"ecg": ECG_MODEL_PATH, "temp": TEMP_MODEL_PATH},
    }


@app.post("/predict", response_model=PredictionResponse)
def predict(features: ECGFeatures):
    try:
        X_new = pd.DataFrame([features.model_dump()])[ECG_FEATURE_COLUMNS]
        prediction = ecg_model.predict(X_new)[0]
        probabilities = ecg_model.predict_proba(X_new)[0]
        confidence = float(max(probabilities))

        logger.info(f"ECG prediction: {prediction} (confidence={confidence:.2%})")
        return PredictionResponse(prediction=prediction, confidence=confidence)

    except Exception as e:
        logger.error(f"ECG prediction failed: {e}")
        raise HTTPException(status_code=500, detail="Prediction failed")


@app.post("/predict_temp", response_model=PredictionResponse)
def predict_temp(features: TempFeatures):
    try:
        X_new = pd.DataFrame([features.model_dump()])[TEMP_FEATURE_COLUMNS]
        prediction = temp_model.predict(X_new)[0]
        probabilities = temp_model.predict_proba(X_new)[0]
        confidence = float(max(probabilities))

        logger.info(f"Temp prediction: {prediction} (confidence={confidence:.2%})")
        return PredictionResponse(prediction=prediction, confidence=confidence)

    except Exception as e:
        logger.error(f"Temp prediction failed: {e}")
        raise HTTPException(status_code=500, detail="Prediction failed")
