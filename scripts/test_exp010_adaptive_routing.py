"""LABO EXP-010: adaptive, causal 1+(1) routing tests (synthetic only)."""
import csv
import tempfile
from pathlib import Path
import unittest

from exp008_recipient_routes import ContactForecast, policy_budget, simulate


def meet(t, a, b, duration=2500):
    return (t, a, b, "meeting", duration)


def trial(events, dest, created=0, policy="oneplusone_adaptive4", **opts):
    params = dict(policy=policy, observation_end=20, ttl=18,
                  volunteer=lambda _n: True)
    params.update(opts)
    events = sorted(events, key=lambda e: (e[0], e[1], e[2], e[3]))
    return simulate(events, [(0, dest, created, "manual")], **params)


class AdaptiveOnePlusOneTests(unittest.TestCase):

    def test_policy_budget_is_shared_not_per_algorithm(self):
        self.assertEqual(policy_budget("oneplusone_adaptive2"), 2)
        self.assertEqual(policy_budget("oneplusone_adaptive4"), 4)
        with self.assertRaises(ValueError):
            policy_budget("oneplusone_adaptive99")

    def test_age_of_forecast_follows_completed_ticks(self):
        p = ContactForecast(max_entries=16, tracked_targets=[5])
        self.assertIsNone(p.evidence_age(4, 5, 0))
        p.learn_tick([meet(0, 4, 5)], 0)
        self.assertEqual(p.evidence_age(4, 5, 1), 1)
        self.assertEqual(p.evidence_age(4, 5, 8), 8)

    def test_unknown_contact_path_uses_new_wing_and_couriers(self):
        events = [meet(0, 0, 1), meet(1, 1, 2000),
                  meet(2, 2000, 2001), meet(3, 2001, 4000)]
        adaptive = trial(events, 4000)
        strict = trial(events, 4000, policy="oneplusone_predict4")
        self.assertEqual(adaptive["delivery_ticks"], [3])
        self.assertEqual(strict["delivery_ticks"], [None])
        self.assertEqual(adaptive["frozen_backups"], 3)
        self.assertEqual(adaptive["exploration_runner_handoffs"], 3)
        self.assertEqual(adaptive["forecast_runner_handoffs"], 0)
        self.assertEqual(adaptive["max_copies_seen"], 4)
        self.assertEqual(adaptive["accepted_count"], [1])

    def test_small_budget_runner_remains_mobile_after_parking(self):
        events = [meet(0, 0, 1), meet(1, 1, 2000),
                  meet(2, 2000, 2001), meet(3, 2001, 4000)]
        r = trial(events, 4000, policy="oneplusone_adaptive2")
        self.assertEqual(r["delivery_ticks"], [3])
        self.assertEqual(r["max_copies_seen"], 2)
        self.assertEqual(r["frozen_backups"], 1)
        self.assertEqual(r["rolling_runner_handoffs"], 2)

    def test_stale_prediction_skipped_in_favor_of_new_courier(self):
        events = [meet(0, 4, 5), meet(8, 0, 4),
                  meet(8, 0, 2001), meet(9, 2001, 5)]
        strict = trial(events, 5, created=8, policy="oneplusone_predict4")
        adaptive = trial(events, 5, created=8)
        self.assertIsNone(strict["delivery_ticks"][0])
        self.assertEqual(adaptive["delivery_ticks"], [9])
        self.assertEqual(adaptive["exploration_runner_handoffs"], 1)
        self.assertEqual(adaptive["forecast_runner_handoffs"], 0)

    def test_fresh_recipient_forecast_selects_ordinary_non_courier(self):
        events = [meet(0, 2, 5), meet(1, 0, 2), meet(2, 2, 5)]
        r = trial(events, 5, created=1)
        self.assertEqual(r["delivery_ticks"], [2])
        self.assertEqual(r["forecast_runner_handoffs"], 1)
        self.assertEqual(r["exploration_runner_handoffs"], 0)

    def test_fresh_self_prediction_avoids_blind_diversion(self):
        events = [meet(0, 0, 5), meet(1, 0, 2001), meet(2, 0, 5)]
        r = trial(events, 5, created=1)
        self.assertEqual(r["delivery_ticks"], [2])
        self.assertEqual(r["exploration_runner_handoffs"], 0)
        self.assertEqual(r["max_copies_seen"], 1)

    def test_non_courier_no_history_cannot_borrow_future_knowledge(self):
        events = [meet(0, 0, 2), meet(1, 2, 5)]
        r = trial(events, 5)
        self.assertEqual(r["delivery_ticks"], [None])
        self.assertEqual(r["exploration_runner_handoffs"], 0)

    def test_parked_holder_serves_only_exact_recipient(self):
        events = [meet(0, 0, 1), meet(1, 0, 2), meet(2, 0, 5)]
        r = trial(events, 5)
        self.assertEqual(r["delivery_ticks"], [2])
        self.assertEqual(r["direct_from_backup"], 1)
        self.assertEqual(r["frozen_backups"], 1)
        self.assertEqual(r["transmissions"], 2)
        self.assertEqual(r["accepted_count"], [1])

    def test_exploration_hard_budget_limits_repeated_moves(self):
        nodes = [0, 1, 2000, 2001, 4000, 4001]
        events = [meet(t, nodes[t], nodes[t + 1]) for t in range(5)]
        r = trial(events, 8000, policy="oneplusone_adaptive2")
        self.assertEqual(r["exploration_runner_handoffs"], 4)
        self.assertEqual(r["frozen_backups"], 1)
        self.assertEqual(r["rolling_runner_handoffs"], 3)
        self.assertEqual(r["max_copies_seen"], 2)

    def test_limited_airtime_and_no_opt_in_prevent_exploration(self):
        events = [meet(0, 0, 1, duration=100), meet(1, 1, 5)]
        slow = trial(events, 5)
        self.assertEqual(slow["frozen_backups"], 0)
        self.assertIsNone(slow["delivery_ticks"][0])
        refused = trial([meet(0, 0, 1), meet(1, 1, 5)], 5,
                        volunteer=lambda n: n != 1)
        self.assertEqual(refused["frozen_backups"], 0)
        self.assertIsNone(refused["delivery_ticks"][0])

    def test_ttl_does_not_extend_while_waiting_for_final_recipient(self):
        events = [meet(0, 0, 1), meet(6, 1, 5)]
        r = trial(events, 5, ttl=5)
        self.assertEqual(r["delivery_ticks"], [None])
        self.assertEqual(r["frozen_backups"], 1)

    def test_single_message_cannot_accept_twice(self):
        events = [meet(0, 0, 1), meet(1, 0, 5), meet(2, 1, 5)]
        r = trial(events, 5)
        self.assertEqual(r["delivery_ticks"], [1])
        self.assertEqual(r["accepted_count"], [1])
        self.assertLessEqual(r["max_copies_seen"], 4)

    def test_wrong_first_bridge_can_lose_to_spread(self):
        events = [meet(0, 0, 1), meet(1, 0, 2), meet(2, 2, 5)]
        a = trial(events, 5)
        spray = trial(events, 5, policy="spray4")
        self.assertEqual(a["delivery_ticks"], [None])
        self.assertEqual(spray["delivery_ticks"], [2])

    def test_exp010_driver_keeps_copy_matched_comparisons(self):
        from exp010_adaptive_routing import run
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            rows, manual = run(root, wings=(1, 2), seeds=(21,),
                               steps=8, ttl=4, letters_per_kind=2)
            self.assertEqual(len(rows), 30)
            self.assertEqual(len(manual), 60)
            self.assertEqual({r["policy"] for r in rows}, {
                "direct", "spray4", "prophet4", "parallel4",
                "oneplusone2", "oneplusone_predict2", "oneplusone_adaptive2",
                "oneplusone4", "oneplusone_predict4", "oneplusone_adaptive4",
            })
            with (root / "equal-copy-comparisons.csv").open(newline="") as stream:
                paired = list(csv.DictReader(stream))
            self.assertEqual(len(paired), 18)
            self.assertTrue(all(
                int(x["copy_budget"]) == int(x["baseline_budget"]) for x in paired))
            traces = {(r["case"], r["policy"]): r for r in manual}
            self.assertEqual(traces[("no_history_bridge", "oneplusone_adaptive4")]
                             ["recipient_accepted"], 1)
            self.assertEqual(traces[("no_history_bridge", "oneplusone_predict4")]
                             ["recipient_accepted"], 0)


if __name__ == "__main__":
    unittest.main()
