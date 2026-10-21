#!/usr/bin/env python3
"""Offline unit tests: RF fit, CSV parsing, checksum, and extrapolation guard."""
import unittest
import math
from pathlib import Path
import tempfile
import sys

sys.path.insert(0, str(Path(__file__).parent))
from exp005_rssi_calibrate import parse_rss_csv, regression, fit_campaign, verified_bytes


class TestMeasuredRssi(unittest.TestCase):
    def test_exact_path_loss_known_solution(self):
        intercept, n = regression([(1, -50), (10, -70), (100, -90)])
        self.assertAlmostEqual(intercept, -50)
        self.assertAlmostEqual(n, 2)

    def test_invalid_distance_or_header(self):
        with self.assertRaises(ValueError):
            parse_rss_csv(b"t;signal;distance\n1;-55;2\n")
        with self.assertRaises(ValueError):
            regression([(1, -60), (1, -70)])

    def test_medians_keep_distance_weight_equal(self):
        samples = [["timestamp_ms", "rss_dBm", "distance_gt_m", "measurementId"]]
        for j in range(50):
            samples.append([j, -50 - (j % 3), 1, 0])
        for j in range(25):
            samples.append([100+j, -70 - (j % 3), 10, 1])
        for j in range(25):
            samples.append([200+j, -90 - (j % 3), 100, 2])
        payload = "\n".join(";".join(map(str, r)) for r in samples).encode()
        result = fit_campaign("fixture", "fixture.csv", "unused", payload)
        self.assertEqual(result["sample_count"], 100)
        self.assertEqual(result["distance_levels"], 3)
        self.assertAlmostEqual(result["path_loss_exponent"], 2.0, places=3)
        self.assertTrue(result["usable_for_labo_budget"])

    def test_pin_mismatch_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "x.csv").write_bytes(b"wrong")
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                verified_bytes(Path(tmp), "x.csv", "00000000000000000000000000000000", False)


if __name__ == "__main__":
    unittest.main()
