"""
sources/sdn.py
--------------
Talks to the SDN Gateway REST API (see SDN/PROJECT.md -> REST API Reference).
When the API is unreachable, devices are read from device_registry.json as a
read-only snapshot and enforcement actions are unavailable.
"""

import json
import re
from pathlib import Path

import requests

import settings

STATUSES = ("quarantined", "rate_limited", "active")  # most to least severe
_MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


def _url(path):
    return settings.SDN_API_URL.rstrip("/") + path


def normalize_mac(mac):
    """Returns mac in aa:bb:cc:dd:ee:ff form, or None if it is not a MAC."""
    mac = mac.strip().lower().replace("-", ":")
    return mac if _MAC_RE.match(mac) else None


def get_devices():
    """Returns (devices, live). devices is {mac: {ip, hostname, status, ...}}."""
    try:
        resp = requests.get(_url("/devices"), timeout=settings.SDN_TIMEOUT_SEC)
        resp.raise_for_status()
        return resp.json()["devices"], True
    except (requests.RequestException, ValueError, KeyError):
        path = Path(settings.SDN_REGISTRY_PATH)
        try:
            return json.loads(path.read_text()).get("devices", {}), False
        except (OSError, ValueError):
            return {}, False


def status_counts(devices):
    counts = {"total": len(devices), **{s: 0 for s in STATUSES}}
    for info in devices.values():
        counts[info.get("status", "active")] = counts.get(info.get("status", "active"), 0) + 1
    return counts


def _call(method, path, **kwargs):
    """Returns (ok, message) for an enforcement call."""
    try:
        resp = requests.request(method, _url(path), timeout=settings.SDN_TIMEOUT_SEC, **kwargs)
    except requests.RequestException as exc:
        return False, f"SDN API unreachable: {exc}"
    body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
    if resp.ok:
        return True, f"{body.get('mac')} is now {body.get('status')}"
    return False, body.get("error", f"HTTP {resp.status_code}")


def quarantine(mac):
    return _call("POST", "/alert", json={"mac": mac, "action": "drop"})


def rate_limit(mac):
    return _call("POST", "/alert", json={"mac": mac, "action": "rate_limit"})


def restore(mac):
    return _call("DELETE", f"/alert/{mac}")
