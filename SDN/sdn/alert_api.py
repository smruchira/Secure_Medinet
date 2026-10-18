"""
sdn/alert_api.py — REST API for NIDS/HIDS to trigger SDN policies.

Endpoints:
  POST   /alert              Evaluate and apply a security alert
  DELETE /alert/<mac>        Restore a device to active (unquarantine)
  GET    /alert/status       Faucet datapath status summary
  GET    /devices            List all discovered devices + current status

All request/response bodies are JSON.
See PROJECT.md → REST API Reference for full field documentation.

Run standalone (dev):
  python3 -m sdn.alert_api

Run in production:
  Managed by systemd sdn-api.service (see systemd/ directory)
"""

import logging
import threading
import time
from datetime import datetime, timezone

from flask import Flask, jsonify, request
from flask_cors import CORS

from .config import API_HOST, API_PORT
from .device_discovery import DeviceDiscovery
from .faucet_manager import FaucetManager
from .risk_engine import (
    ACTION_ALLOW,
    ACTION_BLOCK,
    ACTION_QUARANTINE,
    ACTION_RATE_LIMIT,
    calculate_risk,
    select_action,
)

log = logging.getLogger(__name__)

# ── App and shared state ──────────────────────────────────────────────────
app     = Flask(__name__)
CORS(app)                   # Allow cross-origin requests from NIDS dashboards
manager = FaucetManager()   # Singleton shared with discovery daemon


# ── Routes ────────────────────────────────────────────────────────────────

@app.post("/alert")
def receive_alert():
    """
    Evaluate a threat and apply the selected policy to a device.

    Request body:
      { "device_mac": "aa:bb:cc:dd:ee:ff",
        "threat_type": "malware",
        "confidence": 0.85,
        "severity": 0.9,
        "device_criticality": 0.8
      }

    Response 200:
      { "status": "active" | "rate_limited" | "quarantined",
        "mac": "...", "risk_score": 0.82,
        "selected_action": "quarantine" }
    Response 400:
      { "error": "<reason>" }
    """
    started = time.perf_counter()
    body = request.get_json(silent=True)
    if not body:
        return _err("request body must be JSON", 400)

    raw_mac = body.get("device_mac", body.get("mac", ""))
    if not isinstance(raw_mac, str):
        return _err("device_mac/mac field must be a string", 400)
    mac = raw_mac.strip().lower()

    if not mac:
        return _err("device_mac/mac field is required", 400)

    risk_fields = ("confidence", "severity", "device_criticality")
    is_risk_alert = "device_mac" in body or any(
        field in body for field in risk_fields
    )

    if is_risk_alert:
        missing = [field for field in risk_fields if field not in body]
        if missing:
            return _err(
                "missing risk field(s): " + ", ".join(missing),
                400,
            )

        threat_type = body.get("threat_type", body.get("type"))
        if not isinstance(threat_type, str) or not threat_type.strip():
            return _err("threat_type/type field is required", 400)

        try:
            risk_score = calculate_risk(
                body["confidence"],
                body["severity"],
                body["device_criticality"],
            )
        except ValueError as exc:
            return _err(str(exc), 400)

        selected_action = select_action(risk_score)
        status = _apply_risk_action(mac, selected_action)
        response_time_ms = (time.perf_counter() - started) * 1000

        log.info(
            "RISK_DECISION | timestamp=%s device_mac=%s threat_type=%s "
            "risk_score=%.4f selected_action=%s response_time_ms=%.2f",
            datetime.now(timezone.utc).isoformat(),
            mac,
            threat_type.strip(),
            risk_score,
            selected_action,
            response_time_ms,
        )
        return jsonify({
            "status": status,
            "mac": mac,
            "risk_score": risk_score,
            "selected_action": selected_action,
        })

    action = body.get("action", "drop")
    if not isinstance(action, str):
        return _err("action field must be a string", 400)
    action = action.lower()

    log.warning("ALERT | mac=%s action=%s score=%s type=%s",
                mac, action, body.get("score"), body.get("type"))

    if action == "drop":
        _apply_risk_action(mac, ACTION_QUARANTINE)
        return jsonify({"status": "quarantined", "mac": mac})

    if action == "rate_limit":
        _apply_risk_action(mac, ACTION_RATE_LIMIT)
        return jsonify({"status": "rate_limited", "mac": mac})

    return _err(f"unknown action '{action}'. Use 'drop' or 'rate_limit'", 400)


def _apply_risk_action(mac: str, action: str) -> str:
    """Apply a risk-engine action through the existing policy API."""
    if action == ACTION_ALLOW:
        manager.unquarantine(mac)
        return "active"

    if action == ACTION_RATE_LIMIT:
        _ensure_device_registered(mac)
        manager.rate_limit(mac)
        return "rate_limited"

    if action in (ACTION_QUARANTINE, ACTION_BLOCK):
        # The existing Faucet layer exposes one drop-based enforcement method.
        _ensure_device_registered(mac)
        manager.quarantine(mac)
        return "quarantined"

    raise ValueError(f"unknown risk action '{action}'")


def _ensure_device_registered(mac: str) -> None:
    """Ensure a policy target exists before applying an enforcement action."""
    if mac not in manager.get_devices():
        manager.register(mac)


@app.delete("/alert/<path:mac>")
def unquarantine(mac: str):
    """
    Restore a quarantined/rate-limited device to normal active status.

    Response 200: { "status": "active", "mac": "..." }
    Response 404: { "error": "device not found" }
    """
    mac = mac.strip().lower()
    ok = manager.unquarantine(mac)
    if not ok:
        return _err("device not found", 404)
    log.info("UNQUARANTINE | mac=%s", mac)
    return jsonify({"status": "active", "mac": mac})


@app.get("/alert/status")
def get_status():
    """
    Quick health-check — returns a count of devices by status.

    Response 200:
      { "total": 5, "active": 3, "quarantined": 1, "rate_limited": 1 }
    """
    devices = manager.get_devices()
    counts = {"total": len(devices), "active": 0, "quarantined": 0, "rate_limited": 0}
    for info in devices.values():
        counts[info["status"]] = counts.get(info["status"], 0) + 1
    return jsonify(counts)


@app.get("/devices")
def list_devices():
    """
    List all discovered IoT devices and their current SDN status.

    Response 200:
      { "devices": { "<mac>": { "ip", "hostname", "status", "first_seen", "last_seen" } } }
    """
    return jsonify({"devices": manager.get_devices()})


# ── Helpers ───────────────────────────────────────────────────────────────

def _err(message: str, status: int):
    return jsonify({"error": message}), status


# ── Standalone entry-point ────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    # Start device discovery as a background daemon thread
    discovery = DeviceDiscovery(manager)
    t = threading.Thread(target=discovery.run, daemon=True, name="discovery")
    t.start()
    log.info("SDN Alert API starting on %s:%d", API_HOST, API_PORT)
    app.run(host=API_HOST, port=API_PORT)
