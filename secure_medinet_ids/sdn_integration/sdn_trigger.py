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

The payload follows the SDN Gateway's risk-alert contract (POST /alert in
SDN/sdn/alert_api.py): the SDN computes a risk score from confidence,
severity and device_criticality and selects the action itself, so a
confirmed threat may be rate-limited rather than quarantined.
"""

import os
import re
import sys
import json
import socket
import time
import requests

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

_MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


def resolve_mac(device_id):
    """Returns the MAC address for device_id, or None if it has no mapping."""
    candidate = config.SDN_DEVICE_MACS.get(device_id, device_id)
    candidate = str(candidate).strip().lower().replace("-", ":")
    return candidate if _MAC_RE.match(candidate) else None


def build_payload(device_mac, threat_type, confidence, device_id=None, timestamp=None):
    return {
        "device_mac": device_mac,
        "threat_type": threat_type,
        "confidence": round(float(confidence), 4),
        "severity": config.SDN_THREAT_SEVERITY.get(threat_type, config.SDN_DEFAULT_SEVERITY),
        "device_criticality": config.SDN_DEVICE_CRITICALITY,
        "device_id": device_id,
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
        except requests.RequestException as e:
            last_err = str(e)
            time.sleep(0.5 * attempt)  # simple backoff
            continue

        if resp.ok:
            body = resp.json()
            return True, (f"action={body.get('selected_action')} "
                          f"risk={body.get('risk_score')} status={body.get('status')}")
        last_err = f"HTTP {resp.status_code}: {resp.text.strip()}"
        if resp.status_code < 500:
            break  # the SDN rejected the payload; retrying will not help
        time.sleep(0.5 * attempt)
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
    device_mac = resolve_mac(device_id)
    if device_mac is None:
        detail = f"no MAC address mapped for device_id '{device_id}' (see config.SDN_DEVICE_MACS)"
        print(f"[SDN TRIGGER:{transport.upper()}] SKIPPED -> device={device_id} "
              f"threat={threat_type} conf={confidence:.2f} detail={detail}")
        return False, detail

    payload = build_payload(device_mac, threat_type, confidence, device_id, timestamp)

    if transport == "rest":
        ok, detail = _send_rest(payload)
    elif transport == "mqtt":
        ok, detail = _send_mqtt(payload)
    elif transport == "socket":
        ok, detail = _send_socket(payload)
    else:
        raise ValueError(f"Unknown SDN_TRANSPORT: {transport}")

    status = "CONFIRMED" if ok else "FAILED"
    print(f"[SDN TRIGGER:{transport.upper()}] {status} -> device={device_id} mac={device_mac} "
          f"threat={threat_type} conf={confidence:.2f} detail={detail}")
    return ok, detail


if __name__ == "__main__":
    # dry-run against config.SDN_REST_ENDPOINT -- fails gracefully if the
    # SDN Gateway is not reachable from this machine.
    ok, detail = trigger_quarantine(
        device_id="aa:bb:cc:dd:ee:03",
        threat_type="replay",
        confidence=0.91,
    )
    print("Trigger result:", ok, detail)
