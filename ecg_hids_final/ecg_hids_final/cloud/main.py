"""
main.py
--------
FastAPI service that hosts the trained ECG attack-detection model.
Deployed on Render. Stateless -- no database, no storage. Receives
6 privacy-safe features, returns a prediction. That's the entire job.

Endpoints:
  GET  /health   -- simple check that the service and model are up
  POST /predict  -- the real endpoint, takes features, returns prediction

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
logger = logging.getLogger("ecg_ml_api")

app = FastAPI(title="ECG Attack Detection API", version="1.0")

MODEL_PATH = "ecg_attack_model.joblib"
FEATURE_COLUMNS = [
    "hr_bpm",
    "rr_interval",
    "signal_entropy",
    "qrs_amplitude",
    "sampling_gap_ms",
    "is_duplicate_window",
]

logger.info("Loading trained model...")
model = joblib.load(MODEL_PATH)
logger.info("Model loaded and ready.")


class ECGFeatures(BaseModel):
    hr_bpm: float
    rr_interval: float
    signal_entropy: float
    qrs_amplitude: float
    sampling_gap_ms: float
    is_duplicate_window: int


class PredictionResponse(BaseModel):
    prediction: str
    confidence: float


@app.get("/health")
def health_check():
    return {"status": "ML API is running", "model": MODEL_PATH}


@app.post("/predict", response_model=PredictionResponse)
def predict(features: ECGFeatures):
    try:
        X_new = pd.DataFrame([features.model_dump()])[FEATURE_COLUMNS]
        prediction = model.predict(X_new)[0]
        probabilities = model.predict_proba(X_new)[0]
        confidence = float(max(probabilities))

        logger.info(f"Prediction: {prediction} (confidence={confidence:.2%})")
        return PredictionResponse(prediction=prediction, confidence=confidence)

    except Exception as e:
        logger.error(f"Prediction failed: {e}")
        raise HTTPException(status_code=500, detail="Prediction failed")
