"""Causal targeted forwarding, global copy rights and finite-contact checks."""
import tempfile
from pathlib import Path
import unittest

from exp008_recipient_routes import (
    POLICIES, CLAIM, ContactForecast, observed_events,
    run_matrix, simulate,
)
from exp006_temporal_contacts import contact_events


def event(t, a, b, duration=2500, kind="meeting"):
    return (t, a, b, kind, duration)


class RecipientRoutingTests(unittest.TestCase):
    def check(self, events, pairs, **opts):
        params = dict(message_bytes=256, goodput_kbps=64,
                      residents_per_wing=2000, ttl=10,
                      observation_end=12, volunteer=lambda node: True)
        params.update(opts)
        return simulate(events, pairs, **params)

    def test_predictor_uses_only_past_encounters(self):
        memory = ContactForecast(max_entries=2)
        self.assertEqual(memory.score(1, 7, 0), 0)
        memory.learn_tick([event(0, 1, 7)], 0)
        self.assertGreater(memory.score(1, 7, 1), 0.5)
        self.assertLess(memory.score(1, 7, 5), memory.score(1, 7, 1))
        with self.assertRaises(ValueError):
            memory.learn_tick([event(0, 7, 8)], 0)

    def test_past_contact_makes_prophet_select_recipient_neighbor(self):
        # Past meeting 1<->3 is causal evidence when sender sees 1 at t=1.
        events = [event(0, 1, 3), event(1, 0, 1), event(1, 0, 2),
                  event(2, 1, 3)]
        jobs = [(0, 3, 1, "letter")]
        result = self.check(events, jobs, policy="prophet4", observation_end=3)
        self.assertEqual(result["delivery_ticks"], [2])
        self.assertLessEqual(result["max_copies_seen"], 4)

    def test_no_future_contact_knowledge(self):
        events = [event(0, 0, 1), event(2, 1, 3)]
        result = self.check(events, [(0, 3, 0, "letter")], policy="prophet4")
        self.assertEqual(result["delivery_ticks"], [None])
        explorer = self.check(events, [(0, 3, 0, "letter")], policy="parallel4")
        self.assertEqual(explorer["delivery_ticks"], [2])

    def test_simultaneous_copies_recipient_sees_one_letter(self):
        events = [event(0, 3, 4), event(1, 0, 1), event(1, 0, 2),
                  event(1, 0, 3), event(2, 1, 4), event(2, 2, 4),
                  event(2, 3, 4), event(4, 0, 4)]
        result = self.check(events, [(0, 4, 1, "letter")], policy="parallel4",
                            observation_end=5)
        self.assertEqual(result["accepted_count"], [1])
        self.assertEqual(result["delivery_ticks"], [2])
        self.assertGreaterEqual(result["duplicate_contact_attempts"], 1)
        self.assertLessEqual(result["max_copies_seen"], 4)
        self.assertEqual(result["source_receipt_ticks"], [4])
        self.assertGreater(result["attempts_by_role"].get("explore", 0), 0)
        self.assertGreater(result["attempts_by_role"].get("predict", 0), 0)

    def test_no_instant_hops_same_tick(self):
        jobs = [(0, 3, 0, "letter")]
        short = [event(0, 0, 1), event(0, 1, 3)]
        long = short + [event(1, 1, 3)]
        self.assertEqual(self.check(short, jobs, policy="parallel4")["delivery_ticks"], [None])
        self.assertEqual(self.check(long, jobs, policy="parallel4")["delivery_ticks"], [1])

    def test_shared_copies_never_multiply_policy_budget(self):
        events = [event(i, 0, i+1) for i in range(9)]
        jobs = [(0, 300, 0, "letter")]
        for mode in ("parallel4", "parallel8", "sequential4", "spray4", "spray8", "prophet4", "prophet8", "random4"):
            result = self.check(events, jobs, policy=mode, observation_end=10)
            cap = 8 if mode in ("parallel8", "spray8", "prophet8") else 4
            self.assertLessEqual(result["max_copies_seen"], cap)

    def test_gateways_are_not_magic_recipient_ack(self):
        events = [event(0, 0, 5)]
        jobs = [(0, 4, 0, "letter")]
        result = self.check(events, jobs, policy="gateway4", gateways=(5,),
                            mailbox_authorized=True)
        self.assertEqual(result["mailbox_ticks"], [0])
        self.assertEqual(result["delivery_ticks"], [None])
        self.assertEqual(result["accepted_count"], [0])
        self.assertEqual(result["source_receipt_ticks"], [None])
        no_consent = self.check(events, jobs, policy="gateway4", gateways=(5,),
                                mailbox_authorized=False)
        self.assertEqual(no_consent["mailbox_ticks"], [None])
        offline = self.check(events, jobs, policy="gateway4", gateways=(5,),
                             gateway_online=False, mailbox_authorized=True)
        self.assertEqual(offline["mailbox_ticks"], [None])

    def test_mailbox_pickup_is_explicit_separate_transport(self):
        events = [event(0, 0, 5)]
        jobs = [(0, 4, 0, "letter")]
        result = self.check(events, jobs, policy="gateway4", gateways=(5,),
                            mailbox_authorized=True, mailbox_pickups={0: 3},
                            observation_end=4)
        self.assertEqual(result["delivery_ticks"], [3])
        self.assertEqual(result["delivery_channel"], ["mailbox_pickup"])
        self.assertEqual(result["source_receipt_ticks"], [None])
        self.assertEqual(result["groups"]["letter"]["oracle_ble_reachable"], 0)

    def test_parallel8_reserves_slot_for_forecast_and_courier(self):
        trace = contact_events(2, 25, 21, True)
        job = [(0, 2000, 0, "hub")]
        for policy in ("parallel4", "parallel8"):
            result = self.check(trace, job, policy=policy, ttl=25, observation_end=24)
            self.assertIsNotNone(result["delivery_ticks"][0], policy)
            self.assertLessEqual(result["max_copies_seen"], 8 if policy == "parallel8" else 4)

    def test_gateway_not_reached_without_real_contact(self):
        result = self.check([], [(0, 4, 0, "letter")], policy="parallel4",
                            gateways=(5,), mailbox_authorized=True,
                            mailbox_pickups={0: 3})
        self.assertEqual(result["mailbox_ticks"], [None])
        self.assertEqual(result["delivery_ticks"], [None])

    def test_ttl_stops_late_routes(self):
        result = self.check([event(4, 0, 4)], [(0, 4, 0, "letter")],
                            policy="parallel4", ttl=4, observation_end=5)
        self.assertIsNone(result["delivery_ticks"][0])
        permitted = self.check([event(4, 0, 4)], [(0, 4, 0, "letter")],
                               policy="parallel4", ttl=5, observation_end=5)
        self.assertEqual(permitted["delivery_ticks"], [4])

    def test_payload_needs_real_time_and_shared_radio(self):
        trace = [event(0, 0, 1, 3000)]
        pairs = [(0, 1, 0, "a")]
        slow = self.check(trace, pairs, goodput_kbps=8, message_bytes=4096)
        fast = self.check(trace, pairs, goodput_kbps=64, message_bytes=4096)
        self.assertIsNone(slow["delivery_ticks"][0])
        self.assertEqual(fast["delivery_ticks"], [0])
        simultaneous = [event(0, 0, 1, 1500), event(0, 0, 2, 1500)]
        two = [(0, 1, 0, "a"), (0, 2, 0, "a")]
        constrained = self.check(simultaneous, two, goodput_kbps=8,
                                 message_bytes=512, radio_ms_per_tick=1100)
        unlimited = self.check(simultaneous, two, goodput_kbps=8,
                               message_bytes=512, radio_ms_per_tick=3000)
        self.assertEqual(constrained["groups"]["a"]["recipient_accepted"], 1)
        self.assertEqual(unlimited["groups"]["a"]["recipient_accepted"], 2)

    def test_no_cross_wing_delivery_without_carriers(self):
        no_courier = contact_events(2, 20, 21, False)
        message = [(0, 2000, 0, "hub")]
        for policy in POLICIES:
            result = self.check(no_courier, message, policy=policy,
                                observation_end=19)
            self.assertEqual(result["delivery_ticks"], [None], policy)

    def test_opt_in_required_for_relays_not_final_recipient(self):
        events = [event(0, 0, 1), event(1, 1, 2)]
        job = [(0, 2, 0, "a")]
        r = self.check(events, job, policy="spray4", volunteer=lambda n: n != 1)
        self.assertEqual(r["delivery_ticks"], [None])
        direct = self.check([event(0, 0, 2)], job, policy="direct",
                            volunteer=lambda n: n != 2)
        self.assertEqual(direct["delivery_ticks"], [0])

    def test_determinism_and_matching_corpus(self):
        events = contact_events(2, 24, 99, True)
        jobs = [(0, 2000, 0, "hub")]
        a = self.check(events, jobs, policy="parallel4", observation_end=23)
        b = self.check(events, jobs, policy="parallel4", observation_end=23)
        self.assertEqual(a, b)
        self.assertEqual(a["claim"], CLAIM)
        self.assertEqual(a["groups"]["hub"]["oracle_ble_reachable"], 1)
        self.assertEqual(a["max_copies_seen"] <= 4, True)

    def test_validation_of_unsorted_and_invalid_data(self):
        with self.assertRaises(ValueError):
            observed_events([event(2, 0, 1), event(0, 1, 2)])
        with self.assertRaises(ValueError):
            self.check([], [(0, 0, 0, "bad")])
        with self.assertRaises(ValueError):
            self.check([], [(0, 1, 0, "a")], goodput_kbps=0)
        with self.assertRaises(ValueError):
            self.check([], [(0, 1, 0, "a")], policy="unknown")


    def test_oneplusone2_preserves_backup_while_runner_moves(self):
        # 0 keeps parked; 1 moves the running copy to 2 at K=2.
        e = [event(0, 0, 1), event(1, 1, 2), event(2, 2, 3)]
        j = [(0, 3, 0, "letter")]
        r = self.check(e, j, policy="oneplusone2", observation_end=3)
        self.assertEqual(r["delivery_ticks"], [2])
        self.assertEqual(r["frozen_backups"], 1)
        self.assertEqual(r["rolling_runner_handoffs"], 1)
        self.assertEqual(r["max_copies_seen"], 2)
        self.assertEqual(r["accepted_count"], [1])

    def test_oneplusone_parked_does_not_pass_to_nonrecipient(self):
        # 0 is parked after sending to 1. It must not send to 4 at t=1.
        e = [event(0, 0, 1), event(1, 0, 4), event(2, 4, 3)]
        j = [(0, 3, 0, "letter")]
        for policy in ("oneplusone2", "oneplusone4"):
            r = self.check(e, j, policy=policy, observation_end=3)
            self.assertIsNone(r["delivery_ticks"][0])
            self.assertEqual(r["frozen_backups"], 1)
            self.assertEqual(r["rolling_runner_handoffs"], 0)
            self.assertEqual(r["transmissions"], 1)

    def test_oneplusone_reserved_backup_meets_exact_recipient(self):
        # Source waits for the exact ID 3; a similar-looking other ID 4
        # cannot read the letter from its parked storage.
        e = [event(0, 0, 1), event(1, 0, 4), event(2, 0, 3)]
        j = [(0, 3, 0, "letter")]
        r = self.check(e, j, policy="oneplusone2", observation_end=3)
        self.assertEqual(r["delivery_ticks"], [2])
        self.assertEqual(r["direct_from_backup"], 1)
        self.assertEqual(r["accepted_count"], [1])
        self.assertEqual(r["transmissions"], 2)
        self.assertEqual(r["max_copies_seen"], 2)

    def test_oneplusone4_freezes_three_then_only_moves_runner(self):
        e = [event(t, t, t+1) for t in range(5)] + [event(5, 5, 6)]
        j = [(0, 6, 0, "letter")]
        r = self.check(e, j, policy="oneplusone4", ttl=10, observation_end=6)
        self.assertEqual(r["frozen_backups"], 3)
        self.assertEqual(r["rolling_runner_handoffs"], 2)
        self.assertEqual(r["max_copies_seen"], 4)
        self.assertEqual(r["delivery_ticks"], [5])

    def test_oneplusone_shares_ttl_and_no_zero_cost_transfer(self):
        e = [event(0, 0, 1, duration=2500), event(1, 1, 2, duration=2500),
             event(6, 2, 3, duration=2500)]
        j = [(0, 3, 0, "letter")]
        for mode in ("oneplusone2", "oneplusone4"):
            early = self.check(e, j, policy=mode, ttl=5, observation_end=6)
            self.assertEqual(early["delivery_ticks"], [None])
            small = self.check(e, j, policy=mode, ttl=10,
                               goodput_kbps=8, message_bytes=4096,
                               observation_end=6)
            self.assertEqual(small["delivery_ticks"], [None])
            self.assertEqual(small["frozen_backups"], 0)

    def test_oneplusone_routing_can_succeed_without_history(self):
        # Causal PRoPHET has no history of destination; this scheme is
        # willing to explore, while retaining a direct-only copy.
        e = [event(0, 0, 1), event(1, 1, 2), event(2, 2, 3)]
        j = [(0, 3, 0, "letter")]
        direct = self.check(e, j, policy="prophet4", observation_end=3)
        one = self.check(e, j, policy="oneplusone2", observation_end=3)
        self.assertIsNone(direct["delivery_ticks"][0])
        self.assertEqual(one["delivery_ticks"], [2])

    def test_oneplusone_deduplicates_converging_routes(self):
        e = [event(0, 0, 1), event(1, 1, 2), event(2, 0, 3),
             event(3, 2, 3), event(4, 1, 3)]
        j = [(0, 3, 0, "letter")]
        for mode in ("oneplusone2", "oneplusone4"):
            result = self.check(e, j, policy=mode, observation_end=5)
            self.assertEqual(result["accepted_count"], [1])
            self.assertEqual(result["delivery_ticks"], [2])
            # A recipient receipt can pre-empt the redundant transfer.
            self.assertGreaterEqual(result["receipt_bytes"], 48)
            self.assertLessEqual(result["max_copies_seen"], 2 if mode.endswith("2") else 4)

    def test_small_paired_matrix(self):
        with tempfile.TemporaryDirectory() as directory:
            rows = run_matrix(Path(directory), wings=(1,2), seeds=(21,),
                              steps=8, ttl=4, letters_per_kind=2,
                              scan_modes=(False,), courier_modes=(False, True),
                              gateway_modes=(False, True))
            # (one category in 1 wing, two in 2 wings) * 2 couriers *
            # 2 gateway states * 11 policies = 132 rows.
            self.assertEqual(len(rows), 132)
            self.assertEqual({r["policy"] for r in rows}, set(POLICIES))
            self.assertTrue(all(r["recipient_accepted"] <= r["letters"] for r in rows))
            self.assertTrue(all(r["max_copies_seen"] <= r["copies_limit"] for r in rows))
            self.assertTrue(Path(directory, "routing-matrix.csv").exists())

if __name__ == "__main__":
    unittest.main()