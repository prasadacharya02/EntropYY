"""Multi-node federated exchange simulation invariants."""

import hashlib
import os
import shutil
import tempfile
import unittest
from unittest import mock

import config
import monitoring.pipeline_runner as runner
from benchmark.exchange_simulation import (PAYLOAD_SEED, NOTE_BYTES,
                                           run_simulation, payload_bytes)
from blockchain.behavioral_exchange import BehavioralIntelExchange
from blockchain.fingerprint_exchange import FingerprintExchange
from fingerprint.behavioral import hamming_distance


class ExchangeSimulationTests(unittest.TestCase):
    """The 'have we seen this before?' claim, end to end."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="exchange_sim_test_")
        # The simulation drives the real response path; keep the
        # canonical store out of it and keep forensic reports local.
        cls._patchers = [
            mock.patch.object(runner, "get_exchange",
                                       side_effect=AssertionError(
                                           "canonical store must not be "
                                           "used by the simulation")),
            mock.patch.object(config, "REPORTS_DIR",
                                       os.path.join(cls.tmp, "reports")),
        ]
        for p in cls._patchers:
            p.start()
        cls.report = run_simulation(base_dir=cls.tmp)

    @classmethod
    def tearDownClass(cls):
        for p in cls._patchers:
            p.stop()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _phase(self, name) -> dict:
        for phase in self.report["phases"]:
            if phase["phase"] == name:
                return phase
        raise AssertionError(f"phase {name} missing")

    def test_cold_start_is_alert_only(self):
        # Empty exchange: the locally ambiguous file is only an alert.
        result = self._phase("1_cold_start")["result"]
        self.assertEqual(result["action"], config.ACTION_ALERT)
        self.assertFalse(result["known_threat"])

    def test_single_sighting_stays_alert_only(self):
        # Poison-node defence: a lone node's sighting must never be enough
        # to quarantine a file. The probe is also a single file, which has
        # no behavioural shape to match on.
        result = self._phase("3_single_sighting")["result"]
        self.assertEqual(result["action"], config.ACTION_ALERT)
        self.assertFalse(result["known_threat_confirmed"])
        self.assertFalse(
            (result.get("behavioral_match") or {}).get("confirmed", False))

    def test_warm_start_quarantines_via_the_behavioural_channel(self):
        # A second host encrypting with its OWN ciphertext is contained.
        # The exact-content-hash channel is empty here; the behavioural
        # fingerprint plus the campaign layer carries the decision.
        result = self._phase("5_warm_start")["result"]
        self.assertEqual(result["action"],
                         config.ACTION_TERMINATE_QUARANTINE)
        match = result.get("behavioral_match") or {}
        self.assertTrue(match.get("matched"))
        self.assertTrue(match.get("confirmed"))
        self.assertGreaterEqual(len(match.get("sources") or []), 2)

    def test_seeding_hosts_contain_the_disguise_phase(self):
        # The encrypt-in-place step is deliberately conservative; the
        # rename that follows is what confirms the campaign. Asserting the
        # rename ops keeps that intent explicit instead of accidental.
        for name in ("2_seeding_alpha", "4_seeding_bravo"):
            renames = [rec for rec in self._phase(name)["ops"]
                       if rec["event_type"] == "RENAMED"]
            self.assertTrue(renames, f"{name}: no rename ops recorded")
            self.assertEqual(
                renames[-1]["action"], config.ACTION_TERMINATE_QUARANTINE,
                f"{name}: disguise rename should be contained",
            )

    def test_exchange_is_threat_only(self):
        # Legitimate work produces no quarantine and adds no records.
        phase = self._phase("6_workload_honesty")
        for rec in phase["ops"]:
            self.assertNotEqual(
                rec["action"], config.ACTION_TERMINATE_QUARANTINE,
                f"legitimate file quarantined: {rec['file']}",
            )
        self.assertEqual(phase["exchange_count_before"],
                         phase["exchange_count_after"])

    def test_randomised_ciphertext_never_matches_by_content_hash(self):
        """The measured negative result this project is built around.

        Each host encrypts with independently randomised bytes, so the
        ciphertext hashes differ. A content hash therefore cannot identify a
        shared strain across hosts. Only an identical artefact (the ransom
        note) matches."""
        store = FingerprintExchange(
            os.path.join(self.tmp, "exchange.db"), node_id="test"
        )
        try:
            alpha_payload = hashlib.sha256(
                payload_bytes(PAYLOAD_SEED)).hexdigest()
            bravo_payload = hashlib.sha256(
                payload_bytes(PAYLOAD_SEED + 1)).hexdigest()
            self.assertNotEqual(alpha_payload, bravo_payload)
            # Each host's ciphertext is registered by that host alone; no
            # second node ever corroborates it, which is exactly why the
            # content-hash channel cannot carry cross-host intelligence.
            alpha_rec = store.lookup(alpha_payload)
            bravo_rec = store.lookup(bravo_payload)
            if alpha_rec is not None:
                self.assertEqual(alpha_rec["sources"], ["tenant-alpha"])
            if bravo_rec is not None:
                self.assertEqual(bravo_rec["sources"], ["tenant-bravo"])
            self.assertEqual(
                self.report["recall_metrics"]
                ["exact_hash_cross_node_matches"], 0)
            # Positive control: the byte-identical note IS shared.
            note_rec = store.lookup(hashlib.sha256(NOTE_BYTES).hexdigest())
            self.assertIsNotNone(note_rec)
            self.assertEqual(len(note_rec["sources"]), 2)
        finally:
            store.close()

    def test_behavioural_fingerprint_correlates_across_randomised_hosts(self):
        """The measured positive result, verified against the artifact."""
        separation = (self.report["recall_metrics"]
                      .get("behavioral_separation") or {})
        same_strain = separation.get("strain_vs_other_host_same_strain")
        workload = separation.get("strain_vs_legitimate_backup_workload")
        self.assertIsNotNone(same_strain)
        self.assertIsNotNone(workload)
        self.assertLessEqual(
            same_strain, separation["max_match_distance"],
            "same strain on another host must fall inside the match radius")
        self.assertGreater(
            workload, separation["max_match_distance"],
            "legitimate backup work must fall outside the match radius")

    def test_behavioural_registry_records_independent_nodes(self):
        registry = BehavioralIntelExchange(
            os.path.join(self.tmp, "exchange.db"), node_id="test")
        try:
            stats = registry.stats()
            self.assertGreaterEqual(stats["fingerprints"], 1)
            self.assertGreaterEqual(stats["corroborated_fingerprints"], 1)
            self.assertEqual(stats["mode"], "local_shared_registry")
        finally:
            registry.close()


if __name__ == "__main__":
    unittest.main()
