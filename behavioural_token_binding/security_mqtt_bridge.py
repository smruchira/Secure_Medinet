"""Verify MQTT tokens, learn timing, and write privacy-safe dashboard decisions."""

import json
import os
from datetime import datetime, timezone
from pathlib import Path

import paho.mqtt.client as mqtt
import requests

import behavior_profiler
import revocation_manager
import token_verifier

BROKER = os.environ.get("TOKEN_MQTT_BROKER", "127.0.0.1")
PORT = int(os.environ.get("TOKEN_MQTT_PORT", "8883"))
TOPIC = os.environ.get("TOKEN_MQTT_TOPIC", "test/security")
CA_FILE = os.environ.get("TOKEN_CA_FILE", "/etc/mosquitto/certs/ca.crt")
CLIENT_CERT = os.environ.get("TOKEN_CLIENT_CERT", "/home/chega/esp32-client.crt")
CLIENT_KEY = os.environ.get("TOKEN_CLIENT_KEY", "/home/chega/esp32-client.key")
SDN_ALERT_URL = os.environ.get("TOKEN_SDN_ALERT_URL", "http://127.0.0.1:5000/alert")
SDN_DEVICE_MAC = os.environ.get("TOKEN_SDN_DEVICE_MAC", "e4:0d:36:df:11:f5")
DECISIONS_FILE = Path(os.environ.get("TOKEN_DECISIONS", "/home/chega/token_decisions.jsonl"))


def record_decision(device_id, decision, stage, reason, *, revoked=False, sdn_status=None):
    """Append only dashboard-safe fields. Never store token, signature or secret."""
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "device_id": device_id,
        "decision": decision,
        "stage": stage,
        "reason": reason,
        "revoked": revoked,
        "sdn_status": sdn_status,
    }
    try:
        DECISIONS_FILE.parent.mkdir(parents=True, exist_ok=True)
        with DECISIONS_FILE.open("a", encoding="utf-8") as output:
            output.write(json.dumps(event, separators=(",", ":")) + "\n")
    except OSError as exc:
        print(f"[DECISION LOG ERROR] {exc}")


def on_connect(client, userdata, flags, rc):
    print(f"[MQTT] Connected with rc={rc}")
    client.subscribe(TOPIC)


def on_message(client, userdata, msg):
    try:
        token = msg.payload.decode("utf-8").strip()
    except UnicodeDecodeError:
        record_decision(None, "rejected", "token", "INVALID ENCODING")
        return

    # Parse only the device identifier for reporting. Verification still owns
    # all format, age, HMAC and replay checks.
    parts = token.split("|")
    device_id = parts[0] if len(parts) == 4 and parts[0] else None
    try:
        allowed, reason = token_verifier.verify_token(token)
    except (OSError, RuntimeError) as exc:
        print(f"[VERIFIER ERROR] {exc}")
        record_decision(device_id, "error", "token", "VERIFIER UNAVAILABLE")
        return
    if not allowed:
        print(f"[SECURITY DECISION] REJECT / BLOCK: {reason}")
        record_decision(device_id, "rejected", "token", reason)
        return

    # A verified token always has four fields and an integer timestamp.
    timestamp = int(parts[2])
    if revocation_manager.is_revoked(device_id):
        record_decision(device_id, "rejected", "revocation", "DEVICE REVOKED", revoked=True)
        return

    try:
        allowed, reason = behavior_profiler.check_behavior(device_id, timestamp)
        if allowed:
            behavior_profiler.update_profile(device_id, timestamp)
            print(f"[BEHAVIOR DECISION] ACCEPT: {reason} ({device_id})")
            record_decision(device_id, "accepted", "behavior", reason)
            return
    except (OSError, ValueError, KeyError) as exc:
        print(f"[PROFILE ERROR] {exc}")
        record_decision(device_id, "error", "behavior", "PROFILE UNAVAILABLE")
        return

    print(f"[BEHAVIOR DECISION] REJECT / BLOCK: {reason} ({device_id})")
    sdn_status = None
    try:
        response = requests.post(SDN_ALERT_URL, json={
            "device_mac": SDN_DEVICE_MAC,
            "threat_type": "behavioral_anomaly",
            "confidence": 0.95,
            "severity": 0.9,
            "device_criticality": 0.8,
        }, timeout=3)
        sdn_status = response.status_code
        print(f"[SDN RESPONSE] {sdn_status}")
    except requests.RequestException as exc:
        print(f"[SDN ERROR] {exc}")

    try:
        revocation_manager.revoke_device(device_id, f"ABNORMAL BEHAVIOR: {reason}")
    except OSError as exc:
        print(f"[REVOCATION ERROR] {exc}")
        record_decision(device_id, "rejected", "behavior", reason, sdn_status=sdn_status)
        return
    record_decision(device_id, "rejected", "behavior", reason,
                    revoked=True, sdn_status=sdn_status)


def main():
    client = mqtt.Client()
    client.tls_set(ca_certs=CA_FILE, certfile=CLIENT_CERT, keyfile=CLIENT_KEY)
    # Retained for the existing prototype broker configuration.
    client.tls_insecure_set(True)
    client.on_connect = on_connect
    client.on_message = on_message
    print(f"[BRIDGE] Starting on {BROKER}:{PORT}, topic {TOPIC}")
    client.connect(BROKER, PORT, 60)
    client.loop_forever()


if __name__ == "__main__":
    main()
