"""Bridge-to-dashboard contract and restore behavior."""

import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "behavioural_token_binding"))
sys.path.insert(0, str(ROOT / "dashboard"))

import behavior_profiler
import revocation_manager
import security_mqtt_bridge as bridge
import token_verifier
from sources import tokens


class TokenDashboardTest(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        base = Path(self.folder.name)
        self.profile = base / "behavior_profile.json"
        self.revoked = base / "revoked_devices.json"
        self.events = base / "token_decisions.jsonl"
        self.secret = base / "token_secret.txt"
        self.secret.write_text("test-secret")
        patches = [
            patch.object(behavior_profiler, "PROFILE_FILE", self.profile),
            patch.object(revocation_manager, "REVOCATION_FILE", self.revoked),
            patch.object(token_verifier, "SECRET_FILE", self.secret),
            patch.object(bridge, "DECISIONS_FILE", self.events),
            patch.dict("os.environ", {"TOKEN_PROFILES": str(self.profile),
                                   "TOKEN_REVOKED": str(self.revoked),
                                   "TOKEN_DECISIONS": str(self.events)}),
        ]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)
        token_verifier._used_sequences.clear()

    def send(self, token):
        bridge.on_message(None, None, SimpleNamespace(payload=token.encode()))

    def test_accept_replay_and_bad_hmac_are_logged_without_secrets(self):
        signed = token_verifier.create_token("device-1", 1)
        self.send(signed)
        self.send(signed)
        self.send(signed[:-1] + ("0" if signed[-1] != "0" else "1"))
        events = tokens.get_decisions()
        self.assertEqual(events["decision"].tolist().count("accepted"), 1)
        self.assertEqual(set(events["reason"]),
                         {"LEARNING", "REPLAY ATTACK", "INVALID HMAC"})
        self.assertNotIn(signed, self.events.read_text())
        self.assertEqual(tokens.rejection_counts(events)["count"].sum(), 2)

    def test_behavioral_rejection_revocation_and_restore(self):
        now = int(time.time())
        self.profile.write_text(json.dumps({"device-2": {
            "samples": [1] * 5, "mean_interval": 1,
            "std_interval": 0, "last_timestamp": now - 20,
            "sample_count": 5,
        }}))
        with patch.object(bridge.requests, "post", return_value=SimpleNamespace(status_code=200)):
            self.send(token_verifier.create_token("device-2", 1, now))
        self.assertTrue(revocation_manager.is_revoked("device-2"))
        self.assertEqual(tokens.get_decisions().iloc[0]["stage"], "behavior")
        self.assertEqual(tokens.rejection_counts(tokens.get_decisions()).iloc[0]["reason"],
                         "ABNORMAL TIMING")
        ok, _ = tokens.restore_device("device-2")
        self.assertTrue(ok)
        self.assertFalse(revocation_manager.is_revoked("device-2"))


if __name__ == "__main__":
    unittest.main()
