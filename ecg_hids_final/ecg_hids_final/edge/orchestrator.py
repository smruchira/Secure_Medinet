"""
orchestrator.py
------------------
The main real-time process, runs on RPi4. For every new log entry
written by esp32_listener.py (or demo_stream.py):

  1. Runs watchdog checks (fast, local, no internet needed).
  2. Strips the entry down to privacy-safe features.
  3. Sends those features to the Render ML API for a prediction.
  4. If the prediction indicates an attack, decides between
     quarantine (drop) or rate_limit based on confidence, and calls
     the SDN Gateway to enforce it.
  5. Records the combined result locally.

This is the single script you run to bring the whole detection
pipeline to life. Start esp32_listener.py (or demo_stream.py) in one
terminal, and orchestrator.py in another.
"""

import json
import time
import os
import logging

import config
import watchdog
import render_client
import sdn_gateway_client
from privacy_strip import strip_to_features

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s"
)
logger = logging.getLogger("orchestrator")


def decide_and_enforce(entry, ml_result):
    """
    Given the ML prediction for this entry, decides whether to
    quarantine, rate-limit, or take no action -- then calls the SDN
    gateway accordingly. Returns the action taken (str) for logging.
    """
    prediction = ml_result.get("prediction")
    confidence = ml_result.get("confidence", 0.0)
    mac = entry.get("device_mac")

    if prediction in (None, "normal", "ml_unavailable"):
        return "none"

    if not mac:
        logger.warning("No device_mac on this entry -- cannot enforce via SDN gateway")
        return "none"

    if confidence >= config.DROP_CONFIDENCE_THRESHOLD:
        result = sdn_gateway_client.quarantineDevice(mac, score=confidence, threatType=prediction)
        action = "drop"
    elif confidence >= config.RATE_LIMIT_CONFIDENCE_THRESHOLD:
        result = sdn_gateway_client.rateLimitDevice(mac, score=confidence, threatType=prediction)
        action = "rate_limit"
    else:
        # Low confidence -- log it, but don't take network action
        return "none"

    if "error" in result:
        logger.error(f"SDN enforcement action '{action}' failed: {result['error']}")
    else:
        logger.info(f"SDN enforcement action '{action}' succeeded: {result}")

    return action


def write_result(entry, watchdog_alerts, ml_result, sdn_action):
    result = {
        "timestamp": entry.get("timestamp"),
        "true_label": entry.get("label"),  # only meaningful for demo/training data
        "watchdog_alerts": watchdog_alerts,
        "ml_prediction": ml_result.get("prediction"),
        "ml_confidence": ml_result.get("confidence"),
        "sdn_action": sdn_action,
    }
    with open(config.DETECTION_RESULTS_PATH, "a") as f:
        f.write(json.dumps(result) + "\n")
    return result


def process_entry(entry):
    """Runs the full pipeline on one log entry. Used by both the live
    tailing loop and can be called directly for testing."""
    watchdog_alerts = watchdog.check_entry(entry)

    features = strip_to_features(entry)
    ml_result = render_client.get_prediction(features)

    sdn_action = decide_and_enforce(entry, ml_result)

    result = write_result(entry, watchdog_alerts, ml_result, sdn_action)

    status = "OK" if not watchdog_alerts else "WATCHDOG ALERT"
    logger.info(
        f"true={result['true_label']} | ML={result['ml_prediction']} "
        f"(conf={result['ml_confidence']:.2%}) | watchdog={status} | "
        f"sdn_action={sdn_action}"
    )
    return result


def tail_log_file(path, start_at_end=False):
    """Yields existing and newly appended lines from a JSONL file."""
    with open(path, "r") as f:
        if start_at_end:
            f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue
            yield line.strip()


def run():
    logger.info("Starting orchestrator...")
    logger.info(f"Watching: {os.path.abspath(config.FULL_LOG_PATH)}")
    logger.info(f"Render ML API: {config.RENDER_API_URL}")
    logger.info(f"SDN Gateway: {config.SDN_GATEWAY_URL}")
    logger.info(
        "Processing existing entries: %s",
        config.PROCESS_EXISTING_ENTRIES,
    )

    if not os.path.exists(config.FULL_LOG_PATH):
        open(config.FULL_LOG_PATH, "a").close()

    for line in tail_log_file(
        config.FULL_LOG_PATH,
        start_at_end=not config.PROCESS_EXISTING_ENTRIES,
    ):
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            logger.warning("Skipping malformed log line")
            continue

        result = process_entry(entry)
        logger.info(
            "Processed entry: ML=%s confidence=%.2f%%",
            result.get("ml_prediction"),
            (result.get("ml_confidence") or 0.0) * 100,
        )


if __name__ == "__main__":
    run()
