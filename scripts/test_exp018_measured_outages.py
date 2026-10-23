"""EXP-018 model acceptance tests on a SYNTHETIC fixture (not CC0 field data)."""
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

from exp012_cross_environment import SOURCES
from exp015_gateway_comparison import evaluate_sources
from exp018_measured_outages import (
    CLAIM, POLICIES, SCENARIOS, RETURN_DELAY_TICKS,
    compare, failure_schedules, normalize_storage, paired,
)
from exp018_gateway_recovery import Window, observed_while_awake
from test_exp015_gateway_comparison import fixture


class ContactReplayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.d = Path(cls.temp.name)
        cls.mapping = {"fixture": {
            "path": "synthetic-test", "blob": "pinned-fixture-only",
            "page": "fixture", "license": "synthetic",
        }}
        with patch.dict(SOURCES, cls.mapping):
            cls.record = compare(
                {"fixture": fixture()}, cls.d,
                seeds=(21,), gateway_percent=(10,),
                pickup_hours=(1,), letters_per_kind=4, ttl_hours=2,
            )

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_exact_same_jobs_for_policy_per_scenario(self):
        r = self.record
        self.assertEqual(r["claim"], CLAIM)
        self.assertEqual(r["parameters"]["copy_cap"], 4)
        self.assertEqual(len(r["rows"]), 2*5*2)
        self.assertEqual(len(r["pairs"]), 2*5*2)
        self.assertEqual(len(r["aggregates"]), 5*2)
        self.assertEqual(len(r["pair_summary"]), 5*2)
        self.assertEqual(set(SCENARIOS), {x["scenario"] for x in r["rows"]})
        self.assertEqual(set(POLICIES), {x["policy"] for x in r["rows"]})
        self.assertTrue((self.d/"outage-report.md").is_file())
        self.assertTrue((self.d/"outage-comparison.json").is_file())

    def test_no_source_confirmation_without_recipient(self):
        for r in self.record["rows"]:
            self.assertEqual(r["claim"], CLAIM)
            self.assertEqual(r["messages"], 8)
            self.assertLessEqual(r["source_confirmed"], r["recipient_stored"])
            self.assertEqual(r["missing_receipt"],
                             r["recipient_stored"] - r["source_confirmed"])
            self.assertLessEqual(r["max_copies"], 4)
            self.assertLessEqual(r["max_radio_ms_per_node_tick"], 6000)

    def test_pair_partition_and_matching_marginals(self):
        rows = {(r["phase"], r["scenario"], r["policy"]):r
                for r in self.record["rows"]}
        for p in self.record["pairs"]:
            phase, scenario = p["phase"], p["scenario"]
            self.assertEqual(sum(p[k] for k in (
                "both","only_direct","only_hybrid","neither"
            )), p["messages"])
            d=rows[(phase,scenario,"gateway_direct4")]
            h=rows[(phase,scenario,"hybrid_parallel4")]
            milestone=p["milestone"]
            self.assertEqual(p["both"]+p["only_direct"],d[milestone])
            self.assertEqual(p["both"]+p["only_hybrid"],h[milestone])
            self.assertEqual(d["pair_set_sha256"],h["pair_set_sha256"])
            self.assertEqual(d["pair_set_sha256"],p["pair_set_sha256"])

    def test_control_replays_baseline_without_changed_contact_population(self):
        with patch.dict(SOURCES,self.mapping):
            with tempfile.TemporaryDirectory() as td:
                baseline=evaluate_sources({"fixture":fixture()},Path(td),
                    seeds=(21,),fractions=(10,),pickup_hours=(1,),
                    letters_per_kind=4,ttl_hours=2)
        for policy in POLICIES:
            orig=sum(r["accepted"] for r in baseline["rows"]
                     if r["policy"]==policy)
            recovered=sum(r["recipient_stored"] for r in self.record["rows"]
                          if r["policy"]==policy and r["scenario"]=="control")
            self.assertEqual(recovered,orig)

    def test_return_blackout_does_not_erase_recipient_acceptance(self):
        rows={r["policy"]:r for r in self.record["aggregates"]
              if r["scenario"]=="return_channel_unavailable"}
        base={r["policy"]:r for r in self.record["aggregates"]
              if r["scenario"]=="control"}
        for policy in POLICIES:
            self.assertEqual(rows[policy]["recipient_stored"],
                             base[policy]["recipient_stored"])
            self.assertLessEqual(rows[policy]["source_confirmed"],
                                 base[policy]["source_confirmed"])
        self.assertGreater(RETURN_DELAY_TICKS,0)

    def test_model_cost_is_not_doubled_by_recipient_cohorts(self):
        agg={(r["scenario"],r["policy"]):r for r in self.record["aggregates"]}
        for scene in SCENARIOS:
            for policy in POLICIES:
                parts=[r for r in self.record["rows"]
                       if (r["scenario"],r["policy"])==(scene,policy)]
                self.assertEqual(len(parts),2)  # early+late, NOT 4 cohorts
                total=sum(sum(x[f] for f in (
                    "modeled_data_bytes","modeled_engine_control_bytes",
                    "modeled_internet_bytes","modeled_return_marker_bytes"
                )) for x in parts)
                self.assertEqual(total,agg[(scene,policy)]["model_total_bytes"])

    def test_disjoint_training_and_synthetic_gateway_selection(self):
        jobs=[(1,2,120,"x"),(4,5,130,"x")]
        g=frozenset({3,9,12,16})
        radio,internet,disk,affected=failure_schedules(
            g,jobs,100,"gateway_radio_offline",21)
        self.assertEqual(len(affected),2)
        self.assertFalse(internet)
        self.assertFalse(disk)
        self.assertEqual(len(radio),2)
        self.assertTrue(all(v[0].covers(150) for v in radio.values()))
        observed=[(150,3,2,"x",20000),(150,99,98,"x",20000)]
        kept=observed_while_awake(observed,radio)
        self.assertIn(observed[1],kept)
        self.assertEqual(len(kept),1 if 3 in affected else 2)

    def test_radio_internet_disk_are_separate_events(self):
        jobs=[(1,2,120,"x")]
        g=frozenset({3})
        radio,network,loss,affected=failure_schedules(g,jobs,100,
            "gateway_disk_reset",21)
        self.assertFalse(radio)
        self.assertTrue(network[3][0].covers(140))
        self.assertTrue(loss[3][0].covers(153))
        radio2,network2,loss2,_=failure_schedules(g,jobs,100,
            "gateway_internet_offline",21)
        self.assertFalse(radio2)
        self.assertTrue(network2)
        self.assertFalse(loss2)

    def test_unsupported_outage_fails_closed(self):
        with self.assertRaises(ValueError):
            failure_schedules({1},[(1,2,0,"x")],100,"future-oracle",21)
        with self.assertRaises(ValueError):
            compare({"fixture":fixture()},self.d,scenarios=("bad",))
        with self.assertRaises(ValueError):
            compare({"fixture":fixture()},self.d,scenarios=("control","control"))
        with self.assertRaises(ValueError):
            compare({"fixture":fixture()},self.d,pickup_hours=(9,),ttl_hours=4)

    def test_pair_helper_not_a_synthetic_w4_signature(self):
        d={"recipient_stored":[1,None,3],
           "source_confirmed":[None,None,None]}
        h={"recipient_stored":[1,2,None],
           "source_confirmed":[1,None,None]}
        self.assertEqual(paired(d,h,"recipient_stored"),
                         dict(messages=3,both=1,only_direct=1,
                              only_hybrid=1,neither=0))
        self.assertEqual(paired(d,h,"source_confirmed")["only_hybrid"],1)
        self.assertIn("w4-markers",CLAIM)


if __name__=="__main__":
    unittest.main()
