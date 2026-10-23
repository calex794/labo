"""EXP-017: nearest-gateway decision audit with fail-closed cohort accounting."""
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from exp012_cross_environment import SOURCES
from exp015_gateway_comparison import evaluate_sources
from exp017_route_choice import analyze, render, CLAIM
from test_exp015_gateway_comparison import fixture


class GatewayDecisionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        with patch.dict(SOURCES, {"fixture": {
            "path": "fixture", "blob": "test-blob", "page": "fixture",
            "license": "synthetic", "citation": "test",
        }}):
            cls.data = evaluate_sources(
                {"fixture": fixture()}, Path(cls.tmp.name),
                seeds=(21,), fractions=(10,), pickup_hours=(1,),
                letters_per_kind=4, ttl_hours=2,
            )

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def analyze(self, mutate=None):
        rows = deepcopy(self.data["rows"])
        nearest = deepcopy(self.data["paired_to_nearest"])
        if mutate:
            mutate(rows, nearest)
        return analyze(rows, nearest)

    def test_rows_preserved_and_two_comparisons_per_cohort(self):
        result = self.analyze()
        self.assertEqual(result["claim"], CLAIM)
        self.assertEqual(len(self.data["rows"]), 16)
        self.assertEqual(len(self.data["paired"]), 12)
        self.assertEqual(len(self.data["paired_to_nearest"]), 8)
        self.assertEqual(len(result["conditions"]), 1)
        self.assertEqual(len(result["aggregates"]), 4)
        self.assertEqual(result["conditions"][0]["messages"], 8)
        self.assertEqual(result["max_copy_cap"], 4)

    def test_byte_cost_is_counted_once_not_twice(self):
        result = self.analyze()
        per_policy = result["aggregates"]
        for entry in per_policy:
            source = entry["source"]
            policy = entry["policy"]
            same = [r for r in self.data["rows"]
                    if r["source"] == source and r["policy"] == policy]
            self.assertEqual(len(same), 2)
            for original, result_field in (
                ("ble_data_bytes_all_categories", "radio_bytes"),
                ("model_control_bytes_all_categories", "control_bytes"),
                ("assumed_internet_bytes_all_categories", "internet_bytes"),
            ):
                self.assertEqual(entry[result_field], int(same[0][original]))
            self.assertEqual(entry["messages"], sum(int(x["messages"]) for x in same))
            self.assertEqual(entry["accepted"], sum(int(x["accepted"]) for x in same))

    def test_paired_nearest_exactly_partitions_same_letters(self):
        decision = self.analyze()["conditions"][0]
        for policy, pair in decision["exact_nearest_pairs"].items():
            self.assertEqual(pair["messages"], sum(
                pair[x] for x in ("both", "only_test", "only_nearest", "neither")
            ))
            self.assertEqual(pair["both"]+pair["only_test"],
                             decision["accepted_by_policy"][policy])
            self.assertEqual(pair["both"]+pair["only_nearest"],
                             decision["accepted_by_policy"]["gateway_history_prophet4"])

    def test_mismatched_cohort_result_rejected(self):
        def mutate(rows, paired):
            for row in rows:
                if row["policy"] == "gateway_direct4":
                    row["accepted"] = int(row["accepted"]) + 1
                    row["accepted_mailbox"] = int(row["accepted_mailbox"]) + 1
                    break
        with self.assertRaises(ValueError):
            self.analyze(mutate)

    def test_duplicate_run_wide_bytes_rejected(self):
        def mutate(rows, paired):
            rows[0]["ble_data_bytes_all_categories"] = (
                int(rows[0]["ble_data_bytes_all_categories"])+320
            )
        with self.assertRaises(ValueError):
            self.analyze(mutate)

    def test_different_message_ids_and_wrong_capacity_rejected(self):
        def mutate_pair(rows, paired):
            paired[0]["pair_set_sha256"] = "not-the-original-messages"
        with self.assertRaises(ValueError):
            self.analyze(mutate_pair)

        def mutate_k(rows, paired):
            rows[0]["copy_cap"] = 8
        with self.assertRaises(ValueError):
            self.analyze(mutate_k)

    def test_missing_or_double_nearest_comparison_rejected(self):
        with self.assertRaises(ValueError):
            analyze(self.data["rows"], self.data["paired_to_nearest"][:-1])
        with self.assertRaises(ValueError):
            analyze(self.data["rows"], self.data["paired_to_nearest"]*2)

    def test_render_explicitly_distinguishes_model_and_real_delivery(self):
        rendered = render(self.analyze())
        self.assertIn("not geographic proximity", rendered)
        self.assertIn("Only nearest", rendered)
        self.assertIn("not** a confidence interval", rendered)
        self.assertIn("K=4", rendered)

    def test_provenance_rejects_non_cc0_mislabeled_real_data(self):
        copied = deepcopy(self.data)
        with self.assertRaises(ValueError):
            analyze(copied["rows"],copied["paired_to_nearest"],copied)
        copied["sources"]["fixture"]["license"]="CC0-1.0"
        self.assertEqual(analyze(copied["rows"],copied["paired_to_nearest"],copied)["claim"],CLAIM)


if __name__ == "__main__":
    unittest.main()
