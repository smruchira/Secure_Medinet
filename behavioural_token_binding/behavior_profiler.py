#!/usr/bin/env python3

import json
import os
import time
from pathlib import Path
from statistics import mean, pstdev

PROFILE_FILE = Path(os.environ.get("TOKEN_PROFILES", "/home/chega/behavior_profile.json"))

MIN_SAMPLES = 5
MIN_INTERVAL = 0.5
MAX_INTERVAL = 30.0


def load_profiles():
    if not PROFILE_FILE.exists():
        return {}
    try:
        return json.loads(PROFILE_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def save_profiles(profiles):
    PROFILE_FILE.write_text(json.dumps(profiles, indent=2))


def update_profile(device_id, timestamp):
    profiles = load_profiles()

    profile = profiles.setdefault(device_id, {
        "samples": [],
        "mean_interval": None,
        "std_interval": None,
        "last_timestamp": None,
        "sample_count": 0
    })

    last_timestamp = profile["last_timestamp"]

    if last_timestamp is not None:
        interval = timestamp - last_timestamp

        if MIN_INTERVAL <= interval <= MAX_INTERVAL:
            profile["samples"].append(interval)
            profile["samples"] = profile["samples"][-50:]

            profile["mean_interval"] = round(
                mean(profile["samples"]), 3
            )

            profile["std_interval"] = round(
                pstdev(profile["samples"])
                if len(profile["samples"]) > 1 else 0.0,
                3
            )

            profile["sample_count"] = len(profile["samples"])

    profile["last_timestamp"] = timestamp

    save_profiles(profiles)
    return profile


def check_behavior(device_id, timestamp):
    profiles = load_profiles()
    profile = profiles.get(device_id)

    if not profile or profile["mean_interval"] is None:
        return True, "LEARNING"

    last_timestamp = profile.get("last_timestamp")

    if last_timestamp is None:
        return True, "LEARNING"

    interval = timestamp - last_timestamp
    expected = profile["mean_interval"]
    deviation = abs(interval - expected)

    tolerance = max(1.0, expected * 0.50)

    if deviation <= tolerance:
        return True, "NORMAL"

    return False, (
        f"ABNORMAL TIMING "
        f"(interval={interval}s expected={expected}s)"
    )


if __name__ == "__main__":
    print("Behavior profiler module loaded.")
    print(f"Profile file: {PROFILE_FILE}")
