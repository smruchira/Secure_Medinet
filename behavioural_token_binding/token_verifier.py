#!/usr/bin/env python3

import hashlib
import hmac
import time
from pathlib import Path

SECRET_FILE = Path("/home/chega/token_secret.txt")
TOKEN_MAX_AGE = 30

_used_sequences = {}


def load_secret():
    secret = SECRET_FILE.read_bytes().strip()
    if not secret:
        raise RuntimeError("Token secret is empty")
    return secret


def make_hmac(device_id, sequence, timestamp):
    message = f"{device_id}|{sequence}|{timestamp}".encode()
    return hmac.new(
        load_secret(),
        message,
        hashlib.sha256
    ).hexdigest()


def create_token(device_id, sequence, timestamp=None):
    if timestamp is None:
        timestamp = int(time.time())

    signature = make_hmac(device_id, sequence, timestamp)
    return f"{device_id}|{sequence}|{timestamp}|{signature}"


def verify_token(token, expected_device_id=None, max_age=TOKEN_MAX_AGE):
    try:
        parts = token.strip().split("|")

        if len(parts) != 4:
            return False, "INVALID FORMAT"

        device_id, sequence_text, timestamp_text, received_hmac = parts

        if expected_device_id is not None and device_id != expected_device_id:
            return False, "WRONG DEVICE ID"

        sequence = int(sequence_text)
        timestamp = int(timestamp_text)

        if sequence < 0:
            return False, "INVALID SEQUENCE"

        now = int(time.time())

        if abs(now - timestamp) > max_age:
            return False, "EXPIRED TIMESTAMP"

        expected_hmac = make_hmac(device_id, sequence, timestamp)

        if not hmac.compare_digest(received_hmac, expected_hmac):
            return False, "INVALID HMAC"

        previous_sequence = _used_sequences.get(device_id, -1)

        if sequence <= previous_sequence:
            return False, "REPLAY ATTACK"

        _used_sequences[device_id] = sequence

        return True, "ACCEPT"

    except (ValueError, TypeError):
        return False, "INVALID TOKEN"


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python3 token_verifier.py '<token>'")
        sys.exit(1)

    token = sys.argv[1]
    allowed, reason = verify_token(token)

    if allowed:
        print(f"ACCEPT / ALLOW - {reason}")
        sys.exit(0)
    else:
        print(f"REJECT / BLOCK - {reason}")
        sys.exit(1)
