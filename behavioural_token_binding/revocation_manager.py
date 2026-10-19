import json
import os
from pathlib import Path

REVOCATION_FILE = Path(os.environ.get("TOKEN_REVOKED", "/home/chega/revoked_devices.json"))


def load_revoked_devices():
    if not REVOCATION_FILE.exists():
        return {}

    try:
        with open(REVOCATION_FILE, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def save_revoked_devices(devices):
    with open(REVOCATION_FILE, "w") as f:
        json.dump(devices, f, indent=2)


def is_revoked(device_id):
    devices = load_revoked_devices()
    return device_id in devices


def revoke_device(device_id, reason):
    devices = load_revoked_devices()

    devices[device_id] = {
        "reason": reason
    }

    save_revoked_devices(devices)


def restore_device(device_id):
    devices = load_revoked_devices()

    if device_id in devices:
        del devices[device_id]
        save_revoked_devices(devices)


if __name__ == "__main__":
    print("Revocation manager OK")
