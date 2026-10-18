"""
sdn_trigger.py
==============
Sends a quarantine command to the SDN controller (smruchira/SDN) once the
decision engine confirms a threat.

Three transports are implemented since the team hasn't finalized which one
the SDN controller repo exposes:
  - REST webhook (POST)  <- recommended default: simplest to build/debug,
                             works with any standard SDN northbound API.
  - MQTT publish          <- fits naturally since MQTT is already in the
                             stack, but use a DEDICATED topic/broker (or at
                             least a clearly separated topic) so control-
                             plane quarantine commands never share a channel
                             with data-plane device traffic.
  - Raw TCP socket        <- lowest overhead, most work to build/secure;
                             only worth it if REST/MQTT latency is measured
                             and shown to be insufficient.

All three share the same payload contract so swapping transport later is a
one-line config change (config.SDN_TRANSPORT), not a rewrite.
"""

import os
import sys
import json
import socket
import time
import requests

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config


def build_payload(device_id, threat_type, confidence, timestamp=None):
    return {
        "action": "quarantine",
        "device_id": device_id,
        "threat_type": threat_type,
        "confidence": round(float(confidence), 4),
        "timestamp": timestamp or time.time(),
        "source": "secure-medinet-edge-ids",
    }


def _send_rest(payload):
    last_err = None
    for attempt in range(1, config.SDN_REST_MAX_RETRIES + 1):
        try:
            resp = requests.post(
                config.SDN_REST_ENDPOINT,
                json=payload,
                timeout=config.SDN_REST_TIMEOUT_SEC,
            )
            resp.raise_for_status()
            return True, resp.status_code
        except requests.RequestException as e:
            last_err = str(e)
            time.sleep(0.5 * attempt)  # simple backoff
    return False, last_err


def _send_mqtt(payload):
    try:
        import paho.mqtt.publish as mqtt_publish
    except ImportError:
        return False, (
            "paho-mqtt is not installed. Run: pip install paho-mqtt "
            "(add to requirements.txt if MQTT transport is selected)."
        )
    try:
        mqtt_publish.single(
            config.SDN_MQTT_TOPIC,
            payload=json.dumps(payload),
            hostname=config.SDN_MQTT_BROKER,
            port=config.SDN_MQTT_PORT,
            tls={} if config.SDN_MQTT_PORT == 8883 else None,
        )
        return True, "published"
    except Exception as e:
        return False, str(e)


def _send_socket(payload):
    try:
        with socket.create_connection(
            (config.SDN_SOCKET_HOST, config.SDN_SOCKET_PORT), timeout=config.SDN_REST_TIMEOUT_SEC
        ) as sock:
            message = (json.dumps(payload) + "\n").encode("utf-8")
            sock.sendall(message)
        return True, "sent"
    except OSError as e:
        return False, str(e)


def trigger_quarantine(device_id, threat_type, confidence, timestamp=None, transport=None):
    """
    Main entry point called by the decision engine / inference loop once a
    threat is confirmed. Returns (success: bool, detail: str).
    """
    transport = transport or config.SDN_TRANSPORT
    payload = build_payload(device_id, threat_type, confidence, timestamp)

    if transport == "rest":
        ok, detail = _send_rest(payload)
    elif transport == "mqtt":
        ok, detail = _send_mqtt(payload)
    elif transport == "socket":
        ok, detail = _send_socket(payload)
    else:
        raise ValueError(f"Unknown SDN_TRANSPORT: {transport}")

    status = "CONFIRMED" if ok else "FAILED"
    print(f"[SDN TRIGGER:{transport.upper()}] {status} -> device={device_id} "
          f"threat={threat_type} conf={confidence:.2f} detail={detail}")
    return ok, detail


if __name__ == "__main__":
    # dry-run against a placeholder endpoint -- expected to fail gracefully
    # since no real controller is reachable from this environment.
    ok, detail = trigger_quarantine(
        device_id="iomt_device_3",
        threat_type="replay",
        confidence=0.91,
    )
    print("Trigger result:", ok, detail)
