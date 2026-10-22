"""Check equal-input accounting and Python-only measurement boundaries."""
import csv
from pathlib import Path
import tempfile
import tracemalloc
import unittest

from exp011_p1_metrics import (
    BENCH_SCHEMA, POLICIES, benchmark_policy, compare_equal_k4,
    delivery_summary, percentile95, run, scenario_checksum,
)
from exp006_temporal_contacts import build_temporal_graph, earliest_delivery


class P1MetricsTests(unittest.TestCase):
    def test_default_profiles_are_six_with_five_k4(self):
        self.assertEqual(POLICIES, (
            "direct", "spray4", "prophet4", "parallel4",
            "oneplusone_predict4", "oneplusone_adaptive4",
        ))

    def test_p95_successful_only_and_empty(self):
        self.assertIsNone(percentile95([]))
        self.assertEqual(percentile95([5]), 5)
        self.assertEqual(percentile95(list(range(1, 21))), 19)
        self.assertEqual(percentile95(list(range(1, 22))), 20)

    def test_delivery_summary_does_not_hide_zero_delivery(self):
        value = delivery_summary({
            "delivery_ticks": [None, None], "wire_bytes": 300,
        }, [(0, 2, 0, "a"), (1, 3, 0, "b")], "prophet4")
        self.assertEqual(value["undelivered"], 2)
        self.assertIsNone(value["p95_delay_ticks_accepted_only"])
        self.assertIsNone(value["wire_bytes_per_accepted"])

    def test_delivery_summary_uses_real_created_tick(self):
        value = delivery_summary({
            "delivery_ticks": [8, None, 13], "wire_bytes": 600,
        }, [(0, 2, 5, "a"), (1, 3, 3, "b"), (1, 4, 11, "b")], "spray4")
        self.assertEqual(value["accepted"], 2)
        self.assertEqual(value["undelivered"], 1)
        self.assertEqual(value["median_delay_ticks_accepted_only"], 2.5)
        self.assertEqual(value["p95_delay_ticks_accepted_only"], 3)
        self.assertEqual(value["wire_bytes_per_accepted"], 300)

    def test_check_sum_fingerprints_event_and_message_content(self):
        c = [(0, 0, 1, "meeting", 2500)]
        j = [(0, 2, 0, "letter")]
        self.assertEqual(scenario_checksum(c, j), scenario_checksum(c, j))
        self.assertNotEqual(scenario_checksum(c, j),
                            scenario_checksum(c, [(0, 2, 1, "letter")]))
        self.assertNotEqual(scenario_checksum(c, j),
                            scenario_checksum([(0, 0, 1, "meeting", 2400)], j))

    def test_direct_contact_one_acceptance_and_shared_bytes(self):
        events = [(0, 0, 2, "meeting", 2500)]
        jobs = [(0, 2, 0, "random-pair")]
        graph = build_temporal_graph(events)
        oracle = [earliest_delivery(graph, 0, 2, 0, 2)]
        r = benchmark_policy(events, jobs, oracle, "direct", seed=21021,
                             steps=2, ttl=2, repeats=1)
        self.assertEqual(r["accepted"], 1)
        self.assertEqual(r["random_accepted"], 1)
        self.assertEqual(r["control_accepted"], 0)
        self.assertEqual(r["undelivered"], 0)
        self.assertEqual(r["wire_bytes"], 320)
        self.assertEqual(r["wire_bytes_per_accepted"], 320)
        self.assertLessEqual(r["max_radio_ms_per_tick_model"], 6000)
        self.assertGreater(r["median_cpu_ms_python"], 0)
        self.assertGreater(r["tracemalloc_peak_bytes_python"], 0)
        self.assertFalse(tracemalloc.is_tracing())

    def test_equal_copy_comparison_rejects_input_mismatch(self):
        common = dict(wings=10, seed=21021, copy_budget=4, letters=12,
                      accepted=6, random_accepted=1, control_accepted=5,
                      wire_bytes=320, airtime_ms_model=100,
                      median_cpu_ms_python=10,
                      tracemalloc_peak_bytes_python=1000)
        good = [{**common, "policy": "prophet4", "input_sha256": "aaa"},
                {**common, "policy": "spray4", "input_sha256": "bbb"}]
        with self.assertRaises(AssertionError):
            compare_equal_k4(good)

    def test_direct_is_never_used_as_equal_k4_reference(self):
        common = dict(wings=1, seed=21021, letters=12, accepted=1,
                      random_accepted=1, control_accepted=0, wire_bytes=320,
                      airtime_ms_model=100, median_cpu_ms_python=10,
                      tracemalloc_peak_bytes_python=1000,
                      input_sha256="identical")
        rows = [{**common, "policy": "prophet4", "copy_budget": 4},
                {**common, "policy": "spray4", "copy_budget": 4},
                {**common, "policy": "direct", "copy_budget": 1}]
        paired = compare_equal_k4(rows)
        self.assertEqual(len(paired), 1)
        self.assertEqual(paired[0]["policy"], "spray4")
        self.assertEqual(paired[0]["delivery_delta"], 0)

    def test_small_run_separates_total_bytes_from_categories(self):
        # The historical policies are sufficient to exercise accounting;
        # CI also invokes the default six policies from current LABO main.
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            policies = ("direct", "spray4", "prophet4", "parallel4")
            rows, pair = run(root, wings=(1, 2), seeds=(21021,),
                             steps=10, ttl=5, letters_per_kind=3,
                             repeats=1, policies=policies)
            self.assertEqual(len(rows), 8)
            self.assertEqual(len(pair), 4)
            for row in rows:
                self.assertEqual(row["accepted"],
                                 row["random_accepted"] + row["control_accepted"])
                self.assertLessEqual(row["peak_copies_seen"], row["copy_budget"])
                self.assertEqual(row["claim"],
                                 "synthetic-routing-not-real-delivery")
            keys = {(x["wings"], x["seed"]): set() for x in rows}
            for x in rows:
                keys[x["wings"], x["seed"]].add(x["input_sha256"])
            self.assertTrue(all(len(x) == 1 for x in keys.values()))
            with (root / "p1-policy-metrics.csv").open(newline="") as stream:
                self.assertEqual(len(list(csv.DictReader(stream))), 8)
            with (root / "p1-equal-k4.csv").open(newline="") as stream:
                self.assertEqual(len(list(csv.DictReader(stream))), 4)
            self.assertIn(BENCH_SCHEMA,
                          (root / "p1-policy-metrics.json").read_text())

    def test_invalid_repeat_count_fails_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(ValueError):
                run(Path(folder), wings=(1,), seeds=(21,), repeats=0)
            with self.assertRaises(ValueError):
                run(Path(folder), wings=(0,), seeds=(21,), repeats=1)


if __name__ == "__main__":
    unittest.main()