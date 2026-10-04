"""The benchmark harness itself must be trustworthy: pin the behaviors
of the current rule engine so regressions (and improvements) are visible.
"""

import tempfile
import unittest
from pathlib import Path

from benchmark import runner
from benchmark.scenarios import (attack_backup_tamper, attack_image_blindspot,
                                 attack_note_dropper, attack_polymorphic,
                                 workload_archive_creation,
                                 workload_document_editing)


def _root() -> Path:
    return Path(tempfile.mkdtemp(prefix="bench_test_"))


class BenchmarkHarnessTests(unittest.TestCase):
    def test_battery_runs_and_reports(self):
        runs = runner.run_battery(
            seeds=(1,),
            attacks=[attack_polymorphic, attack_image_blindspot],
            workloads=[workload_document_editing, workload_archive_creation],
        )
        self.assertEqual(len(runs), 2 * 2 + 2)  # attacks x2 modes + workloads

        summary = runner.summarize(runs)
        self.assertEqual(summary["engine"], "rules")
        self.assertIn("attacks", summary)
        self.assertIn("workloads", summary)
        self.assertIn("known_blind_spots", summary)
        self.assertEqual(summary["summary"]["attack_runs"], 4)

    def test_polymorphic_attack_detected_in_both_modes(self):
        for baseline in (False, True):
            run = runner.simulate_scenario(
                attack_polymorphic(1), baseline=baseline, root=_root(),
            )
            self.assertTrue(run["detected"], f"baseline={baseline}")
            self.assertGreaterEqual(run["max_action"], 1)

    def test_polymorphic_quarantined_in_both_modes(self):
        """The campaign escalator confirms a multi-file disguise
        rename attack even WITHOUT a startup baseline (no entropy-delta
        signal available): quarantine must happen in both modes."""
        without = runner.simulate_scenario(
            attack_polymorphic(1), baseline=False, root=_root(),
        )
        with_baseline = runner.simulate_scenario(
            attack_polymorphic(1), baseline=True, root=_root(),
        )
        self.assertEqual(without["max_action"], 3)
        self.assertEqual(with_baseline["max_action"], 3)

    def test_single_file_disguise_rename_stays_alert(self):
        """Per-file conservatism is preserved: a SINGLE file renamed to
        a disguise extension with high entropy is suspicious (ALERT)
        but is not, on its own, a confirmed campaign (no quarantine)."""
        from benchmark.scenarios import Op, Scenario, random_bytes
        import random
        rng = random.Random(7)
        # A high-entropy baseline file (delta ~0 after "encryption")
        # renamed to a disguise extension: the per-file score is
        # ALERT-level (range + extension, 60), below the quarantine
        # bar — with only ONE file, the campaign must not fire.
        scenario = Scenario(
            "single_disguise", "attack",
            "One high-entropy file renamed to a disguise extension",
            [("Data/blob.dat", random_bytes(rng, 65536))],
            [Op("rename", "Data/blob.dat", random_bytes(rng, 65536),
                new_path="Data/blob.dat.wnaCry", delay_before=1.0)],
        )
        run = runner.simulate_scenario(scenario, baseline=True, root=_root())
        self.assertTrue(run["detected"])
        self.assertEqual(run["max_action"], 1)  # ALERT, not QUARANTINE

    def test_campaign_never_fires_on_high_entropy_media(self):
        """Legitimate high-entropy multi-file work (photo import: no
        renames, no entropy jumps) must never confirm a campaign —
        the 0-false-quarantine bar includes the campaign layer."""
        from benchmark.scenarios import workload_photo_import
        run = runner.simulate_scenario(
            workload_photo_import(1), baseline=False, root=_root(),
        )
        self.assertEqual(run["max_action"], 0,
                         f"{run['scenario']} must not alert: "
                         f"{run['ops_record']}")

    def test_clean_workloads_produce_no_quarantine(self):
        for builder in (workload_document_editing, workload_archive_creation):
            run = runner.simulate_scenario(
                builder(1), baseline=False, root=_root(),
            )
            self.assertEqual(
                run["max_action"], 0,
                f"{run['scenario']} must not alert: {run['ops_record']}",
            )

    def test_ransom_note_detects_blindspot_payload(self):
        """The note is the only signal here: the encrypted image itself
        is the entropy blind spot. Detection must come from the note."""
        for baseline in (False, True):
            run = runner.simulate_scenario(
                attack_note_dropper(1), baseline=baseline, root=_root(),
            )
            self.assertTrue(run["detected"], f"baseline={baseline}")
            self.assertEqual(run["first_detection_op"], 0)
            self.assertEqual(run["max_action"], 3)  # confirmed, not alert

    def test_backup_tamper_detected_on_first_deletion(self):
        run = runner.simulate_scenario(
            attack_backup_tamper(1), baseline=False, root=_root(),
        )
        self.assertTrue(run["detected"])
        self.assertEqual(run["first_detection_op"], 0)
        self.assertEqual(run["max_action"], 3)

    def test_image_blindspot_is_reported_honestly(self):
        """In-place encryption of in-range media is a documented blind
        spot of entropy-only detection: pin it so a future fix changes
        the report on purpose, not by accident."""
        for baseline in (False, True):
            run = runner.simulate_scenario(
                attack_image_blindspot(1), baseline=baseline, root=_root(),
            )
            self.assertFalse(run["detected"], f"baseline={baseline}")
            summary = runner.summarize([run])
            self.assertIn("image_blindspot", summary["known_blind_spots"])


if __name__ == "__main__":
    unittest.main()
