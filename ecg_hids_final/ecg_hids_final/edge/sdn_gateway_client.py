"""
sdn_gateway_client.py
------------------------
Integration module for the SDN Gateway REST API, per the team contract.
Implements the 5 required functions:

  quarantineDevice(mac, score, threatType)
  rateLimitDevice(mac, score, threatType)
  restoreDevice(mac)
  getGatewayStatus()
  getDevices()

Design notes (per contract requirements):
  - MAC addresses are normalized to lowercase before sending.
  - Short timeout (default 3s, configurable via config.py).
  - Connection errors, timeouts, non-2xx responses, and invalid JSON
    are all caught -- this module NEVER raises, so a down/unreachable
    SDN gateway never crashes the HIDS.
  - Base URL is configurable via SDN_GATEWAY_URL environment variable.
  - All actions and errors are logged.

All functions return a dict. On success, it's the gateway's JSON
response. On failure, it's {"error": "<description>"} so the caller
can check for the "error" key without needing try/except everywhere.
"""

import logging
import requests

import config

logger = logging.getLogger("sdn_gateway_client")


def _normalize_mac(mac):
    return mac.strip().lower()


def _request(method, path, json_body=None):
    """
    Shared request handler -- all 5 public functions route through
    this, so error handling only needs to be written once.
    """
    url = f"{config.SDN_GATEWAY_URL}{path}"

    try:
        resp = requests.request(
            method, url, json=json_body,
            timeout=config.SDN_GATEWAY_TIMEOUT_SEC
        )
        resp.raise_for_status()

        try:
            return resp.json()
        except ValueError:
            logger.error(f"SDN gateway returned invalid JSON from {method} {url}")
            return {"error": "invalid_json_response"}

    except requests.exceptions.Timeout:
        logger.error(f"SDN gateway timed out: {method} {url}")
        return {"error": "timeout"}
    except requests.exceptions.ConnectionError:
        logger.error(f"Could not connect to SDN gateway: {method} {url}")
        return {"error": "connection_failed"}
    except requests.exceptions.HTTPError as e:
        logger.error(f"SDN gateway returned an error status: {e}")
        return {"error": f"http_error: {e}"}
    except requests.exceptions.RequestException as e:
        logger.error(f"SDN gateway request failed: {e}")
        return {"error": f"request_failed: {e}"}


def quarantineDevice(mac, score=None, threatType=None):
    """POST /alert with action=drop. Fully quarantines the device."""
    mac = _normalize_mac(mac)
    body = {"mac": mac, "action": "drop"}
    if score is not None:
        body["score"] = score
    if threatType is not None:
        body["type"] = threatType

    logger.info(f"Requesting quarantine for {mac} (score={score}, type={threatType})")
    return _request("POST", "/alert", body)


def rateLimitDevice(mac, score=None, threatType=None):
    """POST /alert with action=rate_limit. Throttles the device instead
    of fully blocking it -- used for medium-confidence detections."""
    mac = _normalize_mac(mac)
    body = {"mac": mac, "action": "rate_limit"}
    if score is not None:
        body["score"] = score
    if threatType is not None:
        body["type"] = threatType

    logger.info(f"Requesting rate-limit for {mac} (score={score}, type={threatType})")
    return _request("POST", "/alert", body)


def restoreDevice(mac):
    """DELETE /alert/<mac>. Removes quarantine/rate-limit, restores
    normal network access."""
    mac = _normalize_mac(mac)
    logger.info(f"Requesting restore for {mac}")
    return _request("DELETE", f"/alert/{mac}")


def getGatewayStatus():
    """GET /alert/status. Returns counts of active/quarantined/rate_limited devices."""
    return _request("GET", "/alert/status")


def getDevices():
    """GET /devices. Returns the full list of discovered devices."""
    return _request("GET", "/devices")
