import unittest
from pathlib import Path
from exp_time001 import classify_probe, local_source, public_source, report, summary, server_config

class TimeExperimentTests(unittest.TestCase):
    def test_valid_ignored_offset(self):
        r=classify_probe({"returncode":0,"output":"System clock wrong by -0.001776 seconds (ignored)","elapsed_ms":73.33})
        self.assertEqual(r["status"],"measured")
        self.assertEqual(r["offset_ms"],-1.776)
    def test_correcting_output_not_accepted(self):
        r=classify_probe({"returncode":0,"output":"System clock wrong by 1.5 seconds (step)","elapsed_ms":100})
        self.assertEqual(r["status"],"unavailable")
    def test_failed_exit_not_accepted(self):
        r=classify_probe({"returncode":1,"output":"System clock wrong by 0 seconds (ignored)","elapsed_ms":10})
        self.assertEqual(r["status"],"unavailable")
    def test_summary_excludes_failures(self):
        rows=[{"status":"measured","offset_ms":-0.9,"elapsed_ms":12},{"status":"unavailable","offset_ms":None,"elapsed_ms":30},{"status":"measured","offset_ms":1.1,"elapsed_ms":20}]
        self.assertEqual(summary(rows)["median_abs_offset_ms"],1)
        self.assertEqual(summary(rows)["measured"],2)
    def test_unavailable_medians_null(self):
        self.assertIsNone(summary([{"status":"unavailable","offset_ms":None,"elapsed_ms":10}])["median_abs_offset_ms"])
    def test_nts_only(self):
        self.assertIn(" nts",local_source())
        self.assertIn(" nts",public_source("time.cloudflare.com"))
        with self.assertRaises(ValueError):
            public_source("bad;cat /etc/passwd")
    def test_local_only(self):
        s=server_config(Path("/tmp/example"))
        self.assertIn("bindaddress 127.0.0.1",s)
        self.assertIn("allow 127.0.0.1",s)
        self.assertIn("cmdport 0",s)
    def test_reporting_disclaimers(self):
        s={"attempts":1,"measured":0,"failed":1,"median_abs_offset_ms":None,"median_probe_duration_ms":None}
        d={"system_before":{"utc":"2026-10-23"},"summary":{"public_nts":s,"own_loopback_nts":s},"local_server":{"status":"failed"},"outage":{"status":"not-run"},"public_reachability":"blocked"}
        x=report(d)
        self.assertIn("NOT prove accuracy",x)
        self.assertIn("NOT packet RTT",x)

if __name__=="__main__":
    unittest.main()
