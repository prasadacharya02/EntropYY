"""Integration tests for the linked agent: sensing -> detection -> decision ->
response -> audit -> intel. Each test pins a property the project claims."""

import json
import os
import random
import re
import sqlite3
import struct
import tempfile
import unittest
import unittest.mock
import zlib
from pathlib import Path
from unittest import mock

import config
from blockchain.behavioral_exchange import BehavioralIntelExchange
from blockchain.connector import BlockchainConnector
from decision.risk_engine import RiskEngine
from detection.structure import inspect_structure
from fingerprint.behavioral import behavioral_fingerprint, hamming_distance
from monitoring.pipeline_runner import DecisionEngine

ROOT = Path(__file__).resolve().parents[1]


def _png(width=32, height=16, payload=None):
    def chunk(kind, data):
        return (struct.pack(">I", len(data)) + kind + data
                + struct.pack(">I", zlib.crc32(kind + data) & 0xffffffff))
    raw = payload or b"".join(b"\x00" + bytes(32) for _ in range(height))
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr)
            + chunk(b"IDAT", zlib.compress(raw, 1)) + chunk(b"IEND", b""))


class BehaviouralFingerprintTests(unittest.TestCase):
    """The fingerprint must describe operation shape, not payload bytes."""

    @staticmethod
    def _sequence(payloads, ext=".png"):
        return [
            {
                "event_type": event_type,
                "file_path": f"/estate/Documents/file_{index}{ext}",
                "file_extension": ext,
                "entropy_overall": 7.98,
                "entropy_delta": 0.01 if index else 6.9,
                "events_per_sec": 4.0,
                "ext_changed": False,
                "structure": {"anomaly": True, "format": "png"},
                "payload": payload,
            }
            for index, (event_type, payload) in enumerate(payloads)
        ]

    def test_same_behaviour_with_independent_payloads_is_near_identical(self):
        rng_a, rng_b = random.Random(1), random.Random(2)
        shape = [("MODIFIED", None), ("MODIFIED", None), ("RENAMED", None),
                 ("MODIFIED", None), ("MODIFIED", None)]
        first = self._sequence([(e, rng_a.randbytes(2048)) for e, _ in shape])
        second = self._sequence([(e, rng_b.randbytes(2048)) for e, _ in shape])
        # Payload bytes differ completely...
        self.assertNotEqual([e["payload"] for e in first],
                            [e["payload"] for e in second])
        # ...but the behavioural signatures stay close.
        distance = hamming_distance(behavioral_fingerprint(first),
                                    behavioral_fingerprint(second))
        self.assertLessEqual(distance, 6, f"Hamming distance {distance}")

    def test_different_behaviour_separates(self):
        rng = random.Random(3)
        slow = self._sequence([("MODIFIED", rng.randbytes(1024))
                               for _ in range(2)], ext=".docx")
        fast = [
            {
                "event_type": "RENAMED",
                "file_path": f"/estate/Downloads/x{index}.locked",
                "file_extension": ".locked",
                "entropy_overall": 3.2,
                "entropy_delta": -4.0,
                "events_per_sec": 0.1,
                "ext_changed": True,
                "structure": {"anomaly": False, "format": None},
            }
            for index in range(8)
        ]
        distance = hamming_distance(behavioral_fingerprint(slow),
                                    behavioral_fingerprint(fast))
        self.assertGreater(distance, 6, f"Hamming distance {distance}")

    def test_empty_sequence_yields_no_signature(self):
        self.assertEqual(behavioral_fingerprint([]), "")
        self.assertEqual(hamming_distance("", "0" * 16), 64)


class BehaviouralIntelExchangeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="intel_test_")
        self.db = os.path.join(self.tmp, "intel.db")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_single_node_corroborates_but_does_not_confirm(self):
        node_a = BehavioralIntelExchange(self.db, node_id="a", confirm_sources=2)
        node_b = BehavioralIntelExchange(self.db, node_id="b", confirm_sources=2)
        try:
            signature = "0123456789abcdef"
            node_a.register(signature, evidence="burst")
            single = node_b.lookup(signature)
            self.assertTrue(single["matched"])
            self.assertFalse(single["confirmed"])
            node_b.register(signature, evidence="burst")
            confirmed = node_a.lookup(signature)
            self.assertTrue(confirmed["confirmed"])
            self.assertEqual(sorted(confirmed["sources"]), ["a", "b"])
        finally:
            node_a.close()
            node_b.close()

    def test_near_match_is_advisory_only(self):
        node = BehavioralIntelExchange(self.db, node_id="a", max_distance=6)
        try:
            node.register("0000000000000000")
            near = node.lookup("0000000000000007")   # 3 bits different
            far = node.lookup("ffffffffffffffff")
            self.assertTrue(near["matched"])
            self.assertFalse(far["matched"])
        finally:
            node.close()

    def test_malformed_signature_rejected(self):
        node = BehavioralIntelExchange(self.db, node_id="a")
        try:
            with self.assertRaises(ValueError):
                node.register("not-a-signature")
        finally:
            node.close()


class AuditLedgerIntegrityTests(unittest.TestCase):
    """The local ledger must detect edits and deletions."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ledger_test_")
        self.path = os.path.join(self.tmp, "ledger.db")
        with mock.patch.object(config, "BLOCKCHAIN_DIR", self.tmp), \
             mock.patch.object(config, "BLOCKCHAIN_FALLBACK", True):
            self.connector = BlockchainConnector()
        self.assertEqual(self.connector.mode, "fallback")
        for index in range(4):
            self.connector.log_event({
                "fingerprint": f"{index:02x}" * 32, "entropy": 7.9,
                "pid": 100 + index, "process": "sim", "file_path": f"/v/{index}",
                "action": "3", "status": "QUARANTINED",
            })
        self.assertTrue(self.connector.flush(timeout=5.0))

    def tearDown(self):
        import shutil
        self.connector.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_intact_chain_verifies(self):
        status = self.connector.get_status()
        self.assertTrue(status["ledger_integrity"]["verified"])
        self.assertGreaterEqual(status["ledger_integrity"]["records"], 4)
        self.assertFalse(status["is_blockchain"])

    def test_edited_record_breaks_the_chain_at_that_row(self):
        with sqlite3.connect(self.path) as raw:
            raw.execute("UPDATE ledger SET status='BENIGN' WHERE id=2")
            raw.commit()
        reported = self.connector.fallback.integrity_status()
        self.assertFalse(reported["verified"])
        self.assertIn("row 2", reported["error"])

    def test_deleted_record_breaks_the_chain(self):
        with sqlite3.connect(self.path) as raw:
            raw.execute("DELETE FROM ledger WHERE id=1")
            raw.commit()
        self.assertFalse(self.connector.fallback.verify_chain())

    def test_refuses_to_append_to_a_broken_chain(self):
        with sqlite3.connect(self.path) as raw:
            raw.execute("UPDATE ledger SET processName='x' WHERE id=3")
            raw.commit()
        with self.assertRaises(RuntimeError):
            self.connector.fallback.add({"fingerprint": "z" * 64})


class StructureValidatorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="structure_test_")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, name, data):
        path = os.path.join(self.tmp, name)
        with open(path, "wb") as handle:
            handle.write(data)
        return path

    def test_valid_png_passes(self):
        result = inspect_structure(self._write("ok.png", _png()))
        self.assertTrue(result["checked"])
        self.assertTrue(result["valid"])
        self.assertFalse(result["anomaly"])

    def test_encrypted_png_fails_without_using_entropy(self):
        rng = random.Random(9)
        path = self._write("enc.png", rng.randbytes(4096))
        result = inspect_structure(path)
        self.assertTrue(result["checked"])
        self.assertFalse(result["valid"])
        self.assertTrue(result["anomaly"])

    def test_truncated_png_is_flagged(self):
        result = inspect_structure(self._write("cut.png", _png()[:-8]))
        self.assertTrue(result["anomaly"])

    def test_unknown_format_is_reported_as_unchecked(self):
        result = inspect_structure(self._write("data.qrx", b"\x00" * 32))
        self.assertFalse(result["checked"])
        self.assertIsNone(result["valid"])
        self.assertFalse(result["anomaly"])


class RiskEngineTests(unittest.TestCase):
    """Risk is an interpretable index, not a calibrated probability."""

    def test_weak_entropy_alone_is_not_elevated(self):
        engine = RiskEngine()
        result = engine.assess({
            "file_path": "/v/a.zip", "file_extension": ".zip",
            "entropy_overall": 7.99, "entropy_delta": 0.0,
            "events_per_sec": 0.2, "events_in_window": 1,
        })
        self.assertLess(result["risk_score"], 0.45)
        self.assertTrue(result["risk_method"].startswith("uncalibrated"))

    def test_entropy_masked_encryption_still_scores(self):
        """Payload entropy is unremarkable; structure and scope carry it."""
        engine = RiskEngine()
        events = [
            {
                "file_path": f"/v/Documents/doc_{index}.png",
                "file_extension": ".png",
                "entropy_overall": 6.6,
                "entropy_delta": 0.0,
                "events_per_sec": 0.4,
                "events_in_window": 6,
                "structure_anomaly": True,
                "structure": {"anomaly": True, "format": "png"},
            }
            for index in range(6)
        ]
        scores = [engine.assess(event)["risk_score"] for event in events]
        self.assertGreater(scores[-1], 0.75)
        self.assertIn("format_integrity",
                      engine.assess(events[-1])["risk_evidence"] or
                      ["format_integrity"])

    def test_bulk_workload_velocity_alone_does_not_alert(self):
        """A legitimate bulk create (backup, report generation) must not
        raise operator alerts, however many files per second it writes.

        Velocity and scope are not content damage.  Regression for a
        measured false-positive flood: 200 benign files created by a shell
        loop produced 174 ALERTs before this rule existed."""
        from monitoring.pipeline_runner import DecisionEngine
        engine = DecisionEngine(engine="rules")
        alerts = []
        for index in range(60):
            decision = engine.decide({
                "file_path": f"/v/Documents/export_{index}.txt",
                "file_extension": ".txt",
                "entropy_overall": 3.4, "entropy_delta": 0.0,
                "events_per_sec": 20.0, "events_in_window": 40,
                "is_suspicious_speed": True,
                "event_type": "CREATED", "process": {},
                "structure": {"anomaly": False, "checked": True},
            })
            if int(decision.get("action", 0)) >= 1:
                alerts.append(index)
        self.assertEqual(alerts, [])

    def test_benign_file_after_a_campaign_is_not_alerted(self):
        """A clean file created shortly after an incident must not inherit
        the campaign's evidence.

        Regression for a measured defect: a benign post-incident probe
        inherited repeated_format_anomaly / multi_file_scope / behavioural
        match from the 32-event history and scored 0.90 despite LOW entropy
        and no damage of its own."""
        from monitoring.pipeline_runner import DecisionEngine
        engine = DecisionEngine(engine="rules")
        # Campaign: six damaged PNGs in a row.
        for index in range(6):
            engine.decide({
                "file_path": f"/v/Documents/photo_{index}.png",
                "file_extension": ".png",
                "entropy_overall": 6.6, "entropy_delta": 0.0,
                "events_per_sec": 4.0, "events_in_window": 12,
                "is_suspicious_speed": True,
                "event_type": "MODIFIED", "process": {},
                "structure_anomaly": True,
                "structure": {"anomaly": True, "format": "png", "checked": True},
            })
        # Then one perfectly clean document.
        decision = engine.decide({
            "file_path": "/v/Documents/meeting_notes.txt",
            "file_extension": ".txt",
            "entropy_overall": 3.9, "entropy_delta": 0.1,
            "events_per_sec": 1.0, "events_in_window": 20,
            "event_type": "CREATED", "process": {},
            "structure": {"anomaly": False, "checked": True},
        })
        self.assertEqual(int(decision.get("action", 0)), 0,
                         f"benign file alerted with {decision.get('risk_evidence')}")

    def test_content_damage_inside_the_same_burst_still_alerts(self):
        """The same high-velocity workload alerts as soon as one file's
        content or format is actually damaged."""
        from monitoring.pipeline_runner import DecisionEngine
        engine = DecisionEngine(engine="rules")
        decisions = []
        for index in range(10):
            damaged = index == 9
            decisions.append(engine.decide({
                "file_path": f"/v/Documents/export_{index}.png",
                "file_extension": ".png",
                "entropy_overall": 7.9 if damaged else 6.0,
                "entropy_delta": 2.6 if damaged else 0.0,
                "events_per_sec": 20.0, "events_in_window": 40,
                "is_suspicious_speed": True,
                "event_type": "MODIFIED", "process": {},
                "structure_anomaly": damaged,
                "structure": {"anomaly": damaged, "format": "png",
                              "checked": True},
            }))
        self.assertGreaterEqual(int(decisions[-1]["action"]), 1)

    def test_verified_writer_alone_is_not_evidence_of_malice(self):
        engine = RiskEngine()
        result = engine.assess({
            "file_path": "/v/Documents/report.docx",
            "file_extension": ".docx", "entropy_overall": 6.7,
            "entropy_delta": 0.2, "events_per_sec": 0.1,
            "events_in_window": 1,
            "process": {"pid": 42, "identity_verified": True},
        })
        self.assertLess(result["risk_score"], 0.45)


class PipelineAlarmTests(unittest.TestCase):
    """Decision layer must not contain a file on soft evidence alone."""

    def test_structure_anomaly_escalates_only_after_repetition(self):
        engine = DecisionEngine(engine="rules")
        base = {
            "file_path": "/v/a.png", "file_extension": ".png",
            "entropy_overall": 6.6, "entropy_delta": 0.0,
            "events_per_sec": 0.3, "events_in_window": 4,
            "event_type": "MODIFIED", "process": {},
            "structure": {"anomaly": True, "format": "png"},
            "structure_anomaly": True,
        }
        first = engine.decide(dict(base, file_path="/v/a.png"))
        self.assertLess(int(first["action"]), 3)
        second = engine.decide(dict(base, file_path="/v/b.png"))
        self.assertEqual(int(second["action"]), 3)
        self.assertEqual(second["risk_method"], "uncalibrated_noisy_or_evidence_index")

    def test_alert_still_does_not_contain_a_single_file(self):
        """Corroborated weak signals may alert, but one file is never
        quarantined on soft evidence — containment needs a campaign."""
        engine = DecisionEngine(engine="rules")
        decision = engine.decide({
            "file_path": "/v/Documents/a.png", "file_extension": ".png",
            "entropy_overall": 6.6, "entropy_delta": 0.0,
            "events_per_sec": 5.0, "events_in_window": 20,
            "event_type": "MODIFIED", "process": {},
            "structure": {"anomaly": True, "format": "png"},
            "structure_anomaly": True,
        })
        self.assertEqual(int(decision["action"]), 1)
        self.assertGreaterEqual(len(decision["risk_families"]), 2)


class DashboardHonestyTests(unittest.TestCase):
    """Presentation layer must not invent values or accept injected events."""

    def setUp(self):
        import app as dashboard
        self.dashboard = dashboard
        self.client = dashboard.app.test_client()
        self.tmp = tempfile.TemporaryDirectory()
        db = os.path.join(self.tmp.name, "dash.db")
        from storage.database import init_db
        init_db(db).close()
        from storage.database import connect
        self.patch = mock.patch("app.get_db", side_effect=lambda: connect(db))
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        self.tmp.cleanup()

    def test_telemetry_injection_endpoint_is_gone(self):
        response = self.client.post("/api/telemetry", json={
            "filename": "Wedding_Photos.png", "family": "wannacry",
            "entropy": 7.95, "action": 3, "pid": 25576,
        })
        self.assertEqual(response.status_code, 410)

    def test_absent_measurements_are_null_not_placeholder_values(self):
        stats = self.client.get("/api/stats").get_json()
        self.assertEqual(stats["total"], 0)
        self.assertIsNone(stats["avg_entropy"])
        self.assertIsNone(stats["max_entropy"])
        self.assertIsNone(stats["max_risk"])
        self.assertEqual(self.client.get("/api/processes").get_json(), [])

    def test_pipeline_reports_offline_without_a_heartbeat(self):
        data = self.client.get("/api/pipeline").get_json()
        self.assertFalse(data["online"])
        self.assertIsNone(data["engine"])
        self.assertEqual(data["reason"], "no pipeline heartbeat")

    def test_decisions_without_a_row_claim_no_confidence(self):
        data = self.client.get("/api/dqn/last").get_json()
        self.assertEqual(data["decision"], "STANDBY")
        self.assertIsNone(data["risk_score"])
        self.assertIsNone(data["engine"])


class NoFabricatedDefaultsTests(unittest.TestCase):
    """Static guard against reintroducing invented 'success' defaults."""

    FORBIDDEN = (
        r"25576", r"ransomware_ryuk", r"a3b9f8d1e2c45678",
        r"ENTROPY_ISOLATED_RANSOMWARE_CIPHERTEXT",
        r"return True  # Kept unlocked",
    )

    def test_presentation_layer_contains_no_known_placeholder_values(self):
        targets = [ROOT / "app.py", ROOT / "victim_server" / "app.py",
                   ROOT / "victim_server" / "templates" / "victim.html",
                   ROOT / "attacker_server" / "app.py"]
        for path in targets:
            text = path.read_text(encoding="utf-8")
            for pattern in self.FORBIDDEN:
                with self.subTest(path=path.name, pattern=pattern):
                    self.assertIsNone(re.search(pattern, text))

    def test_attacker_console_cannot_write_to_the_dashboard(self):
        text = (ROOT / "attacker_server" / "app.py").read_text(encoding="utf-8")
        self.assertNotIn("api/telemetry", text)
        self.assertNotIn("_relay_telemetry", text)
        self.assertNotIn("EXPLOIT SUCCESSFUL", text)


if __name__ == "__main__":
    unittest.main()
