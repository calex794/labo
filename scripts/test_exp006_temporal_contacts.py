#!/usr/bin/env python3
"""LABO time-respecting path tests. No external dependencies."""
import unittest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent))
from exp006_temporal_contacts import (
    build_temporal_graph, earliest_delivery, contact_events, sample_messages,
    evaluate, found_via_ble,
)


class TemporalReachabilityTests(unittest.TestCase):
    def test_time_order_blocks_backwards_information(self):
        graph = build_temporal_graph([
            (2, 1, 2, "contact", 1000),
            (3, 0, 1, "contact", 1000),
        ])
        self.assertIsNone(earliest_delivery(graph, 0, 2, 0, 8))

    def test_same_tick_edges_do_not_allow_instant_multihop(self):
        g = build_temporal_graph([
            (1, 0, 1, "meeting", 2000),
            (1, 1, 2, "meeting", 2000),
        ])
        self.assertIsNone(earliest_delivery(g, 0, 2, 0, 2))
        self.assertEqual(earliest_delivery(g, 0, 1, 0, 2), 1)

    def test_expired_route_is_unavailable(self):
        g = build_temporal_graph([(10, 0, 1, "late", 1000)])
        self.assertIsNone(earliest_delivery(g, 0, 1, 0, 10))
        self.assertEqual(earliest_delivery(g, 0, 1, 0, 11), 10)

    def test_adjacent_wing_couriers_are_real_temporal_bridges(self):
        bare = contact_events(2, 20, 21, False, local_contacts_per_tick=0)
        active = contact_events(2, 20, 21, True, local_contacts_per_tick=0,
                                travel_steps=2, departure_period=12)
        self.assertIsNone(earliest_delivery(build_temporal_graph(bare), 0, 2000, 0, 15))
        self.assertEqual(earliest_delivery(build_temporal_graph(active),
                                           0, 2000, 0, 15), 2)
        self.assertTrue(all(e[1] // 2000 == e[2] // 2000
                            for e in bare))

    def test_more_contacts_cannot_reduce_oracle_reachability(self):
        jobs = sample_messages(3, 30, 100, 12)
        a = evaluate(contact_events(3, 30, 100, False), jobs, 20, False, 100)
        b = evaluate(contact_events(3, 30, 100, True), jobs, 20, False, 100)
        for group in a["groups"]:
            self.assertGreaterEqual(b["groups"][group]["reachable"],
                                    a["groups"][group]["reachable"])
        self.assertGreater(b["contacts_possible"], a["contacts_possible"])

    def test_discovery_duration_is_monotonic(self):
        small = (1, 0, 1, "contact", 100)
        big = (1, 0, 1, "contact", 12000)
        s = found_via_ble(small, 18, 400, 2000, 300)
        b = found_via_ble(big, 18, 400, 2000, 300)
        self.assertFalse(s and not b)
        self.assertTrue(b)

    def test_reproducibility(self):
        a = contact_events(4, 15, 21021, True)
        b = contact_events(4, 15, 21021, True)
        self.assertEqual(a, b)
        jobs = sample_messages(4, 15, 21, 20)
        self.assertEqual(evaluate(a, jobs, 10, True, 21),
                         evaluate(b, jobs, 10, True, 21))


if __name__ == "__main__":
    unittest.main()
