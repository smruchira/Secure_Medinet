"""
tests/test_sdn.py — Unit and integration tests for SDN Gateway module.

Runs on any platform (Windows, Linux, macOS) without needing a Raspberry Pi.
Tests:
  1. ACL rule generation (drop, rate-limit, segment, meter)
  2. FaucetManager state management & YAML generation
  3. REST API endpoints via Flask test client
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import yaml

from sdn.acl_rules import (
    allow_rule,
    drop_rule,
    meter_config,
    rate_limit_rule,
    segment_rule,
    _mac_to_meter_id,
)
from sdn.faucet_manager import (
    FaucetManager,
    STATUS_ACTIVE,
    STATUS_QUARANTINED,
    STATUS_RATE_LIMITED,
)
from sdn.alert_api import app
from sdn.risk_engine import calculate_risk, select_action


class TestRiskEngine(unittest.TestCase):
    """Test pure risk score and action selection behavior."""

    def test_calculate_risk(self):
        score = calculate_risk(0.85, 0.9, 0.8)
        self.assertAlmostEqual(score, 0.855)

    def test_action_thresholds(self):
        self.assertEqual(select_action(0.29), "allow")
        self.assertEqual(select_action(0.3), "rate_limit")
        self.assertEqual(select_action(0.7), "rate_limit")
        self.assertEqual(select_action(0.7001), "quarantine")
        self.assertEqual(select_action(0.9), "block")

    def test_invalid_factor(self):
        with self.assertRaises(ValueError):
            calculate_risk(1.1, 0.5, 0.5)


class TestACLRules(unittest.TestCase):
    """Test pure ACL builder functions in sdn/acl_rules.py."""

    def test_drop_rule(self):
        rule = drop_rule("aa:bb:cc:dd:ee:01")
        self.assertEqual(rule["rule"]["dl_src"], "aa:bb:cc:dd:ee:01")
        self.assertFalse(rule["rule"]["actions"]["allow"])

    def test_rate_limit_rule(self):
        rule = rate_limit_rule("aa:bb:cc:dd:ee:02", kbps=1024)
        self.assertEqual(rule["rule"]["dl_src"], "aa:bb:cc:dd:ee:02")
        self.assertTrue(rule["rule"]["actions"]["allow"])
        meter_name = rule["rule"]["actions"]["meter"]
        meters = meter_config("aa:bb:cc:dd:ee:02", kbps=1024)
        self.assertEqual(meters[meter_name]["entry"]["bands"][0]["rate"], 1024)

    def test_segment_rule(self):
        rule = segment_rule("aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02")
        self.assertEqual(rule["rule"]["dl_src"], "aa:bb:cc:dd:ee:01")
        self.assertEqual(rule["rule"]["dl_dst"], "aa:bb:cc:dd:ee:02")
        self.assertFalse(rule["rule"]["actions"]["allow"])

    def test_allow_rule(self):
        rule = allow_rule()
        self.assertTrue(rule["rule"]["actions"]["allow"])

    def test_meter_id_deterministic(self):
        id1 = _mac_to_meter_id("00:00:00:00:01:02")
        id2 = _mac_to_meter_id("00:00:00:00:01:02")
        self.assertEqual(id1, id2)
        self.assertEqual(id1, 1 * 256 + 2)


class TestFaucetManager(unittest.TestCase):
    """Test FaucetManager state handling and YAML configuration generation."""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.faucet_yaml = Path(self.tmp_dir.name) / "faucet.yaml"
        self.registry_json = Path(self.tmp_dir.name) / "device_registry.json"

        # Patch paths
        import sdn.faucet_manager as fm
        self.orig_faucet_yaml = fm.FAUCET_YAML
        self.orig_registry = fm.DEVICE_REGISTRY
        fm.FAUCET_YAML = self.faucet_yaml
        fm.DEVICE_REGISTRY = self.registry_json

        self.manager = FaucetManager()

    def tearDown(self):
        import sdn.faucet_manager as fm
        fm.FAUCET_YAML = self.orig_faucet_yaml
        fm.DEVICE_REGISTRY = self.orig_registry
        self.tmp_dir.cleanup()

    def test_register_device(self):
        is_new = self.manager.register("AA:BB:CC:DD:EE:01", ip="10.0.0.2", hostname="sensor-1")
        self.assertTrue(is_new)
        devices = self.manager.get_devices()
        self.assertIn("aa:bb:cc:dd:ee:01", devices)
        self.assertEqual(devices["aa:bb:cc:dd:ee:01"]["status"], STATUS_ACTIVE)
        self.assertEqual(devices["aa:bb:cc:dd:ee:01"]["ip"], "10.0.0.2")

        # Verify YAML generated
        self.assertTrue(self.faucet_yaml.exists())
        config = yaml.safe_load(self.faucet_yaml.read_text(encoding="utf-8"))
        self.assertIn("vlans", config)
        self.assertIn("dps", config)

    def test_quarantine_device(self):
        self.manager.register("aa:bb:cc:dd:ee:01")
        self.manager.quarantine("aa:bb:cc:dd:ee:01")
        devices = self.manager.get_devices()
        self.assertEqual(devices["aa:bb:cc:dd:ee:01"]["status"], STATUS_QUARANTINED)

        # Inspect generated ACL
        config = yaml.safe_load(self.faucet_yaml.read_text(encoding="utf-8"))
        rules = config["acls"]["iot_policy"]
        # First rule should be DROP for the quarantined mac
        self.assertEqual(rules[0]["rule"]["dl_src"], "aa:bb:cc:dd:ee:01")
        self.assertFalse(rules[0]["rule"]["actions"]["allow"])

    def test_rate_limit_device(self):
        self.manager.register("aa:bb:cc:dd:ee:02")
        self.manager.rate_limit("aa:bb:cc:dd:ee:02", kbps=256)
        devices = self.manager.get_devices()
        self.assertEqual(devices["aa:bb:cc:dd:ee:02"]["status"], STATUS_RATE_LIMITED)
        self.assertEqual(devices["aa:bb:cc:dd:ee:02"]["rate_kbps"], 256)

        config = yaml.safe_load(self.faucet_yaml.read_text(encoding="utf-8"))
        self.assertIn("meters", config)

    def test_unquarantine_device(self):
        self.manager.register("aa:bb:cc:dd:ee:01")
        self.manager.quarantine("aa:bb:cc:dd:ee:01")
        self.manager.unquarantine("aa:bb:cc:dd:ee:01")
        devices = self.manager.get_devices()
        self.assertEqual(devices["aa:bb:cc:dd:ee:01"]["status"], STATUS_ACTIVE)


class TestAlertAPI(unittest.TestCase):
    """Test Flask REST API routes."""

    def setUp(self):
        self.client = app.test_client()

    def test_alert_drop(self):
        res = self.client.post(
            "/alert",
            json={"mac": "11:22:33:44:55:66", "action": "drop", "score": 0.95, "type": "ddos"},
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "quarantined")
        self.assertEqual(data["mac"], "11:22:33:44:55:66")

    def test_alert_rate_limit(self):
        res = self.client.post(
            "/alert",
            json={"mac": "11:22:33:44:55:77", "action": "rate_limit"},
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "rate_limited")

    def test_risk_alert_low_risk_allows(self):
        res = self.client.post(
            "/alert",
            json={
                "device_mac": "11:22:33:44:55:80",
                "threat_type": "scan",
                "confidence": 0.1,
                "severity": 0.2,
                "device_criticality": 0.2,
            },
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertAlmostEqual(data["risk_score"], 0.15)
        self.assertEqual(data["selected_action"], "allow")
        self.assertEqual(data["status"], "active")

    def test_risk_alert_medium_risk_rate_limits(self):
        res = self.client.post(
            "/alert",
            json={
                "device_mac": "11:22:33:44:55:81",
                "threat_type": "anomaly",
                "confidence": 0.5,
                "severity": 0.5,
                "device_criticality": 0.5,
            },
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["selected_action"], "rate_limit")
        self.assertEqual(data["status"], "rate_limited")

    def test_risk_alert_high_risk_quarantines(self):
        res = self.client.post(
            "/alert",
            json={
                "device_mac": "11:22:33:44:55:82",
                "threat_type": "malware",
                "confidence": 0.9,
                "severity": 0.8,
                "device_criticality": 0.8,
            },
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertAlmostEqual(data["risk_score"], 0.85)
        self.assertEqual(data["selected_action"], "quarantine")
        self.assertEqual(data["status"], "quarantined")

    def test_risk_alert_critical_risk_blocks(self):
        res = self.client.post(
            "/alert",
            json={
                "device_mac": "11:22:33:44:55:83",
                "threat_type": "critical-malware",
                "confidence": 1.0,
                "severity": 1.0,
                "device_criticality": 1.0,
            },
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["risk_score"], 1.0)
        self.assertEqual(data["selected_action"], "block")
        self.assertEqual(data["status"], "quarantined")

    def test_incomplete_risk_alert(self):
        res = self.client.post(
            "/alert",
            json={
                "device_mac": "11:22:33:44:55:84",
                "threat_type": "malware",
                "confidence": 0.8,
            },
        )
        self.assertEqual(res.status_code, 400)
        self.assertIn("severity", res.get_json()["error"])

    def test_risk_alert_logs_research_fields(self):
        with self.assertLogs("sdn.alert_api", level="INFO") as captured:
            res = self.client.post(
                "/alert",
                json={
                    "device_mac": "11:22:33:44:55:85",
                    "threat_type": "malware",
                    "confidence": 0.9,
                    "severity": 0.8,
                    "device_criticality": 0.8,
                },
            )

        self.assertEqual(res.status_code, 200)
        message = "\n".join(captured.output)
        self.assertIn("RISK_DECISION", message)
        self.assertIn("threat_type=malware", message)
        self.assertIn("risk_score=0.8500", message)
        self.assertIn("selected_action=quarantine", message)
        self.assertIn("response_time_ms=", message)

    def test_get_devices(self):
        res = self.client.get("/devices")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("devices", data)

    def test_get_status(self):
        res = self.client.get("/alert/status")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("total", data)
        self.assertIn("active", data)

    def test_unquarantine_api(self):
        # First quarantine
        self.client.post("/alert", json={"mac": "aa:bb:cc:11:22:33", "action": "drop"})
        # Then delete
        res = self.client.delete("/alert/aa:bb:cc:11:22:33")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "active")

    def test_invalid_alert(self):
        res = self.client.post("/alert", json={"action": "drop"})
        self.assertEqual(res.status_code, 400)
        self.assertIn("mac field is required", res.get_json()["error"])


if __name__ == "__main__":
    unittest.main()
