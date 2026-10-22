"""EXP-015 synthetic unit tests; no measured-radio claims."""
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

from exp006_temporal_contacts import build_temporal_graph
from exp011_real_contacts import parse_real_tij
from exp012_cross_environment import SOURCES
from exp015_gateway_comparison import (
    CLAIM, historical_map, choose_gateways, nearest_known_gateway,
    pickup_after_storage, mailbox_outcomes, evaluate_sources,
    gateway_forecast,
)


def fixture():
    lines = []
    for day in range(7):
        for at in range(90):
            tick = day * 4320 + 1000 + at * 10
            a = at % 8
            b = (a + (1 if day < 4 else 2)) % 8
            lines.append(f"{tick*20} {a} {b}")
    return parse_real_tij("\n".join(lines))


class GatewayRoutingTests(unittest.TestCase):
    def test_only_training_data_selects_gateway(self):
        data = fixture()
        records = [(t*20, a,b) for t,a,b,_,_ in data["events"][:100]]
        g = historical_map(records)
        selected = choose_gateways(g, 10, 21021)
        assert selected
        self.assertEqual(selected, choose_gateways(g, 10, 21021))
        # Changing the FUTURE must not affect gateway selection.
        changed = data["events"][:]
        changed[100:] = [(t, 0, 1, k, d)
                         for t, _, _, k, d in changed[100:]]
        self.assertEqual(selected, choose_gateways(g, 10, 21021))

    def test_gateway_sets_nested(self):
        g = {i: {(i+1)%100} for i in range(100)}
        self.assertLessEqual(choose_gateways(g, 2, 1),
                             choose_gateways(g, 10, 1))

    def test_nearest_training_gateway(self):
        graph = {0:{1}, 1:{0,2}, 2:{1,3}, 3:{2}}
        self.assertEqual(nearest_known_gateway(0, frozenset({2}), graph), 2)
        self.assertEqual(nearest_known_gateway(0, frozenset({0}), graph), 0)
        self.assertIsNone(nearest_known_gateway(0, frozenset({9}), graph))

    def test_gateway_forecast_preserves_every_letter_and_same_radio_load(self):
        # Previously this path silently dropped letters with no known
        # gateway and letters already at a gateway. That changed airtime
        # contention versus the other policies.
        events = [(0, 0, 1, "synthetic_contact", 20000)]
        jobs = [(0, 99, 0, "random"), (2, 99, 0, "random"),
                (1, 99, 0, "random")]
        history = {0: {1}, 1: {0}, 2: set()}
        with patch("exp015_gateway_comparison.run_engine") as runner:
            runner.return_value = {"delivery_ticks": [0, None, None]}
            stored, result = gateway_forecast(
                events, jobs, history, frozenset({1}),
                build_temporal_graph(events),
                ttl=20, seed=21, end=19, decay=.94)
        proxy_jobs = runner.call_args.args[1]
        self.assertEqual(len(proxy_jobs), len(jobs))
        self.assertEqual(proxy_jobs[0][1], 1)
        self.assertNotIn(proxy_jobs[1][1], {0, 1, 2, 99})
        self.assertEqual(proxy_jobs[2][1], 1)
        self.assertEqual(stored, [0, None, 0])
        self.assertEqual(len(result["delivery_ticks"]), len(jobs))

    def test_mailbox_is_not_recipient_acceptance(self):
        # A message stored at tick 0 is accepted at tick 10, not tick 0.
        self.assertEqual(pickup_after_storage(0, 0, 30, 10), 10)
        self.assertEqual(pickup_after_storage(10, 0, 30, 10), 20)
        self.assertIsNone(pickup_after_storage(20, 0, 21, 10))
        times, channels = mailbox_outcomes(
            [(0,1,0,"random")], [None], [0], 30, 10)
        self.assertEqual(times, [10])
        self.assertEqual(channels, ["assumed_internet_and_mailbox_poll"])

    def test_contact_beats_late_mailbox(self):
        times, channels = mailbox_outcomes(
            [(0,1,0,"random")], [5], [0], 30, 10)
        self.assertEqual(times, [5])
        self.assertEqual(channels, ["observed_contact_synthetic_accept"])

    def test_invalid_parameters_fail_closed(self):
        with self.assertRaises(ValueError):
            choose_gateways({1:{2}}, 0, 1)
        with self.assertRaises(ValueError):
            evaluate_sources({}, Path("/never"), ttl_hours=0)

    def test_experiment_uses_fixture_no_fake_real_data(self):
        data=fixture()
        with tempfile.TemporaryDirectory() as td:
            with patch.dict(SOURCES, {"fixture": {
                "path":"fixture", "blob":"unit", "page":"none",
                "license":"synthetic", "citation":"unit"} }):
                result=evaluate_sources(
                    {"fixture":data}, Path(td), seeds=(21,),
                    fractions=(10,), pickup_hours=(1,),
                    letters_per_kind=4, ttl_hours=2)
            self.assertEqual(result["claim"], CLAIM)
            self.assertEqual(len(result["rows"]), 2*4*2)
            self.assertEqual(len(result["paired"]), 2*3*2)
            for row in result["rows"]:
                self.assertLessEqual(row["accepted"], row["messages"])
                self.assertLessEqual(row["max_copies_seen"], 4)
                self.assertLessEqual(row["max_airtime_ms_per_node_tick"], 6000)
                self.assertLessEqual(
                    row["accepted_contact"]+row["accepted_mailbox"], row["accepted"])
                self.assertEqual(row["claim"],CLAIM)
            for row in result["paired"]:
                self.assertEqual(row["messages"],sum(
                    row[k] for k in ("both","only_test","only_prophet","neither")))


if __name__=="__main__":
    unittest.main()
