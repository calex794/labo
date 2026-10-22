"""EXP-012 independent CC0 source parser and paired causal policy invariants."""
import gzip
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from exp012_cross_environment import (
    SOURCES, COMMIT, PROVENANCE, fetch_pinned, git_blob_sha, parse_pinned_gzip,
    split_chronology, choose_historic_pairs, make_jobs, paired_bootstrap,
    compare_two_policies, evaluate_sources,
)
from exp011_real_contacts import parse_real_tij


def fixture():
    """Invented unit-test events, never presented as measured source data."""
    lines = []
    for day in range(7):
        for at in range(90):
            tick = day * 4320 + 1000 + at * 10
            a = at % 8
            b = (a + (1 if day < 4 else 2)) % 8
            lines.append(f"{tick*20} {a} {b}")
    return parse_real_tij("\n".join(lines))


class IndependentTraceTests(unittest.TestCase):
    def test_real_source_pins_are_distinct_and_licensed(self):
        self.assertEqual(len(SOURCES), 2)
        self.assertEqual(len({x["blob"] for x in SOURCES.values()}), 2)
        self.assertEqual(len(COMMIT), 40)
        self.assertTrue(all(x["license"] == "CC0-1.0" for x in SOURCES.values()))

    def test_gzip_parser_handles_t_i_j(self):
        raw = b"20 100 200\n40 200 300\n60 300 400\n"
        data = parse_pinned_gzip(gzip.compress(raw))
        self.assertEqual(data["record_count"], 3)
        self.assertEqual(data["participant_count"], 4)
        self.assertEqual(len(data["events"]), 3)

    def test_invalid_compression_or_contact_is_rejected(self):
        for blob in (b"random", gzip.compress(b"bad row\n"),
                     gzip.compress(b"20 3 3\n40 2 3\n60 3 4\n")):
            with self.assertRaises(ValueError):
                parse_pinned_gzip(blob)

    def test_cached_source_must_match_git_blob_pin(self):
        with tempfile.TemporaryDirectory() as folder:
            local = Path(folder, "SFHH_tij.dat.gz")
            local.write_bytes(gzip.compress(b"20 1 2\n40 2 3\n60 3 4\n"))
            with self.assertRaisesRegex(ValueError, "checksum"):
                fetch_pinned("SFHH-conference-2009", Path(folder), False)

    def test_historical_messages_are_fixed_when_future_changes(self):
        data = fixture()
        ttl = 180
        split = split_chronology(data, ttl, 5)
        a = choose_historic_pairs(split, 10, 5)
        changed = fixture()
        # The historical prefix stays identical; future topology may change.
        changed["events"] = [e for e in changed["events"] if
                             e[0] <= split["train"]] + [
                            (tick, 0, 1, "changed", 1000) for tick in
                            range(split["train"] + 100, split["end"], 200)]
        b = choose_historic_pairs(split_chronology({
            "events": changed["events"],
        }, ttl, 5) if False else split, 10, 5)
        self.assertEqual(a, b)

    def test_no_time_horizon_end_censoring(self):
        data = fixture()
        s = split_chronology(data, 180, 4)
        self.assertLess(s["train"], s["early"])
        self.assertLess(s["early"] + 180, s["late"])
        self.assertLess(s["late"] + 180, s["end"])

    def test_paired_resampling_is_identical_for_identical_policies(self):
        x = [1, 0, 0, 1, 1, 0]
        low, high = paired_bootstrap(x, x, 41, draws=500)
        self.assertEqual((low, high), (0, 0))
        a = [1, 0, 1, 0]
        b = [0, 1, 0, 1]
        self.assertEqual(paired_bootstrap(a, b, 11),
                         paired_bootstrap(a, b, 11))

    def test_paired_discordants_are_reported_independently(self):
        jobs = [(0, 1, 0, "random"), (0, 2, 0, "random"),
                (1, 2, 0, "random"), (2, 3, 0, "random")]
        # 'not None' is acceptance (including tick zero).
        comparison = compare_two_policies(
            jobs, [0, None, 2, None], [None, 1, 2, None], "random", 42)
        self.assertEqual(comparison["both"], 1)
        self.assertEqual(comparison["parallel_only"], 1)
        self.assertEqual(comparison["prophet_only"], 1)
        self.assertEqual(comparison["neither"], 1)
        self.assertEqual(comparison["delta_parallel_minus_prophet_percent"], 0)

    def test_fixed_contact_graph_multi_policy_matrix(self):
        data = fixture()
        with tempfile.TemporaryDirectory() as d:
            with patch.dict(SOURCES, {"synthetic-fixture": {
                "path": "fixture", "blob": "test", "page": "none",
                "license": "synthetic", "citation": "unit test",
            }}):
                out = evaluate_sources({"synthetic-fixture": data}, Path(d),
                      seeds=(21,), policies=("direct", "prophet4", "parallel4"),
                      letters_per_kind=4, ttl_hours=1)
            self.assertEqual(out["claim"], PROVENANCE)
            self.assertEqual(len(out["rows"]), 3 * 2 * 2)
            self.assertEqual(len(out["paired"]), 2 * 2)
            self.assertTrue(Path(d, "independent-contact-routing.csv").exists())
            self.assertTrue(Path(d, "paired-policy-deltas.csv").exists())
            for row in out["rows"]:
                self.assertLessEqual(row["accepted"], row["oracle_reachable"])
                self.assertLessEqual(row["max_copies_seen"], row["copy_budget"])
                self.assertEqual(row["accepted"]+row["undelivered"], row["letters"])
                self.assertEqual(row["claim"], PROVENANCE)
            for key in ("early", "late"):
                md5s = {r["input_pairs_sha256"] for r in out["rows"]
                        if r["phase"] == key}
                self.assertEqual(len(md5s), 1)

    def test_invalid_ttl_is_rejected(self):
        with self.assertRaises(ValueError):
            evaluate_sources({}, Path("/never"), ttl_hours=0)


if __name__ == "__main__":
    unittest.main()
