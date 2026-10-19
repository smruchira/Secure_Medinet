"""
temp_orchestrator.py
----------------------
The real-time process for the temperature sensor pipeline, runs on
RPi4 alongside (not instead of) the existing ECG orchestrator.py.
Mirrors orchestrator.py's logic exactly, pointed at the temperature
log, the temperature ML endpoint, and the SAME SDN gateway.

For every new entry written by esp32_temp_listener.py (or
demo_temp_stream.py):

  1. Runs temp_watchdog checks (fast, local).
  2. Strips the entry to privacy-safe features.
  3. Sends those features to the Render ML API's /predict_temp.
  4. If the prediction indicates an attack, quarantines or rate-limits
     the temperature device's MAC via the SAME SDN gateway client used
     by the ECG pipeline.
  5. Records the combined result locally.

Run this in its own terminal, alongside (not replacing) the ECG
orchestrator. Start esp32_temp_listener.py (or demo_temp_stream.py) in
one terminal, and temp_orchestrator.py in another.
"""

import json
import time
import os
import logging

import temp_config as config
import temp_watchdog as watchdog
import temp_render_client as render_client
import sdn_gateway_client
from temp_privacy_strip import strip_to_features

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s"
)
logger = logging.getLogger("temp_orchestrator")


def decide_and_enforce(entry, ml_result):
    prediction = ml_result.get("prediction")
    confidence = ml_result.get("confidence", 0.0)
    mac = entry.get("device_mac")

    if prediction in (None, "normal", "ml_unavailable"):
        return "none"

    if not mac:
        logger.warning("No device_mac on this entry -- cannot enforce via SDN gateway")
        return "none"

    if confidence >= config.TEMP_DROP_CONFIDENCE_THRESHOLD:
        result = sdn_gateway_client.quarantineDevice(mac, score=confidence, threatType=prediction)
        action = "drop"
    elif confidence >= config.TEMP_RATE_LIMIT_CONFIDENCE_THRESHOLD:
        result = sdn_gateway_client.rateLimitDevice(mac, score=confidence, threatType=prediction)
        action = "rate_limit"
    else:
        return "none"

    if "error" in result:
        logger.error(f"SDN enforcement action '{action}' failed: {result['error']}")
    else:
        logger.info(f"SDN enforcement action '{action}' succeeded: {result}")

    return action


def write_result(entry, watchdog_alerts, ml_result, sdn_action):
    result = {
        "timestamp": entry.get("timestamp"),
        "true_label": entry.get("label"),
        "watchdog_alerts": watchdog_alerts,
        "ml_prediction": ml_result.get("prediction"),
        "ml_confidence": ml_result.get("confidence"),
        "sdn_action": sdn_action,
    }
    with open(config.DETECTION_RESULTS_PATH, "a") as f:
        f.write(json.dumps(result) + "\n")
    return result


def process_entry(entry):
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
    logger.info("Starting temperature orchestrator...")
    logger.info(f"Watching: {os.path.abspath(config.FULL_LOG_PATH)}")
    logger.info(f"Render ML API: {config.RENDER_API_URL}/predict_temp")
    logger.info(f"SDN Gateway: {config.SDN_GATEWAY_URL}")

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
