import subprocess
import paho.mqtt.client as mqtt
import behavior_profiler
import revocation_manager
import requests

BROKER = "127.0.0.1"
PORT = 8883
TOPIC = "test/security"

CA_FILE = "/etc/mosquitto/certs/ca.crt"
CLIENT_CERT = "/home/chega/esp32-client.crt"
CLIENT_KEY = "/home/chega/esp32-client.key"

VERIFIER = "/home/chega/token_verifier.py"
SDN_ALERT_URL = "http://127.0.0.1:5000/alert"
SDN_DEVICE_MAC = "e4:0d:36:df:11:f5"


def on_connect(client, userdata, flags, rc):
    print(f"[MQTT] Connected with rc={rc}")
    client.subscribe(TOPIC)
    print(f"[MQTT] Subscribed to {TOPIC}")


def on_message(client, userdata, msg):
    token = msg.payload.decode().strip()

    print("\n========================================")
    print("[TOKEN RECEIVED]")
    print(token)

    # ----------------------------------------
    # STEP 1: Verify cryptographic token
    # ----------------------------------------
    try:
        result = subprocess.run(
            ["python3", VERIFIER, token],
            capture_output=True,
            text=True,
            timeout=5
        )

        verifier_output = result.stdout.strip()

        print("\n[VERIFIER OUTPUT]")
        print(verifier_output)

        if result.stderr:
            print("[VERIFIER ERROR]")
            print(result.stderr.strip())

    except Exception as e:
        print(f"[BRIDGE ERROR] {e}")
        return

    # ----------------------------------------
    # STEP 2: Stop if token verification fails
    # ----------------------------------------
    if "ACCEPT / ALLOW" not in verifier_output:
        print("[SECURITY DECISION] REJECT / BLOCK")
        print("[BEHAVIOR] Not checked because token verification failed")
        return

    # ----------------------------------------
    # STEP 3: Extract device ID and timestamp
    # Token format:
    # DEVICE_ID|SEQUENCE|TIMESTAMP|HMAC
    # ----------------------------------------
    try:
        parts = token.split("|")

        if len(parts) != 4:
            print("[BEHAVIOR ERROR] Invalid token format")
            return

        device_id = parts[0]
        timestamp = int(parts[2])

    except Exception as e:
        print(f"[BEHAVIOR ERROR] Could not parse token: {e}")
        return

    # ----------------------------------------
    # Check whether this device has already been revoked
    if revocation_manager.is_revoked(device_id):
        print("[REVOCATION] Device is revoked")
        print("[SECURITY DECISION] REJECT / BLOCK")
        return

    # STEP 4: Check behavioral timing
    # IMPORTANT: check BEFORE update_profile
    # ----------------------------------------
    allowed, reason = behavior_profiler.check_behavior(
        device_id,
        timestamp
    )

    print("\n[BEHAVIOR CHECK]")
    print(f"Device: {device_id}")
    print(f"Decision: {reason}")

    # ----------------------------------------
    # STEP 5: Update profile only for
    # cryptographically valid + normal/learning
    # traffic
    # ----------------------------------------
    if allowed:
        behavior_profiler.update_profile(
            device_id,
            timestamp
        )

        print("[BEHAVIOR DECISION] ACCEPT")
        print("[PROFILE] Updated")

    else:
        print("[BEHAVIOR DECISION] REJECT / BLOCK")
        print("[PROFILE] NOT updated")

        # Send abnormal behavior alert to Ruchira's SDN module
        try:
            alert = {
                "device_mac": SDN_DEVICE_MAC,
                "threat_type": "behavioral_anomaly",
                "confidence": 0.95,
                "severity": 0.9,
                "device_criticality": 0.8
            }

            response = requests.post(
                SDN_ALERT_URL,
                json=alert,
                timeout=3
            )

            print("[SDN ALERT] Sent to Ruchira's SDN")
            print(f"[SDN RESPONSE] {response.status_code} {response.text}")

        except Exception as e:
            print(f"[SDN ERROR] {e}")

        # Keep local revocation record
        revocation_manager.revoke_device(
            device_id,
            f"ABNORMAL BEHAVIOR: {reason}"
        )
        print("[REVOCATION] Device revoked")


client = mqtt.Client()

client.tls_set(
    ca_certs=CA_FILE,
    certfile=CLIENT_CERT,
    keyfile=CLIENT_KEY
)

# Temporary for the current local prototype.
# We will tighten server certificate verification later.
client.tls_insecure_set(True)

client.on_connect = on_connect
client.on_message = on_message

print("[BRIDGE] Starting...")
print(f"[BRIDGE] Broker: {BROKER}:{PORT}")
print(f"[BRIDGE] Topic: {TOPIC}")

client.connect(BROKER, PORT, 60)
client.loop_forever()
