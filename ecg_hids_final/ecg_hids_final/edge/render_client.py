"""
render_client.py
------------------
Sends privacy-stripped ECG features to the Render-hosted ML API and
gets back a prediction. This is the only thing that ever leaves the
RPi4 to the internet -- 6 numbers, no patient data.

Handles connection errors/timeouts gracefully -- if Render is down or
slow, this never crashes the rest of the system, it just reports
"ml_unavailable" so the orchestrator can decide what to do (e.g. rely
on the watchdog alone for that entry).
"""

import logging
import requests

import config

logger = logging.getLogger("render_client")


def get_prediction(features):
    """
    features: dict with keys hr_bpm, rr_interval, signal_entropy,
              qrs_amplitude, sampling_gap_ms, is_duplicate_window

    Returns: dict with "prediction" (str) and "confidence" (float),
             or {"prediction": "ml_unavailable", "confidence": 0.0}
             if the Render API could not be reached.
    """
    url = f"{config.RENDER_API_URL}/predict"

    try:
        resp = requests.post(url, json=features, timeout=config.RENDER_API_TIMEOUT_SEC)
        resp.raise_for_status()
        result = resp.json()

        if "prediction" not in result or "confidence" not in result:
            logger.error(f"Unexpected response shape from Render API: {result}")
            return {"prediction": "ml_unavailable", "confidence": 0.0}

        logger.info(f"Render prediction: {result['prediction']} "
                    f"(confidence={result['confidence']:.2%})")
        return result

    except requests.exceptions.Timeout:
        logger.error(f"Render API timed out after {config.RENDER_API_TIMEOUT_SEC}s")
    except requests.exceptions.ConnectionError:
        logger.error(f"Could not connect to Render API at {url}")
    except requests.exceptions.HTTPError as e:
        logger.error(f"Render API returned an error: {e}")
    except (ValueError, KeyError) as e:
        logger.error(f"Invalid response from Render API: {e}")
    except requests.exceptions.RequestException as e:
        logger.error(f"Render API request failed: {e}")

    return {"prediction": "ml_unavailable", "confidence": 0.0}
