"""Fail-closed synthetic tests for EXP-018; not cryptographic W4 tests."""
import unittest
from exp018_gateway_recovery import (
    Window, offline, observed_while_awake, recovery_outcomes,
)

JOBS = [(1, 2, 0, "sample")]


def run(*, direct=None, stored=2, node=3, internet=None, loss=None,
        contacts=(), delay=None, period=10, ttl=40):
    return recovery_outcomes(
        JOBS, [direct], [stored], [node], ttl=ttl,
        pickup_period=period, internet_down=internet or {},
        disk_loss=loss or {}, receipt_contacts=contacts,
        receipt_internet_delay=delay)


class RecoveryTests(unittest.TestCase):
    def test_gateway_storage_does_not_equal_delivery(self):
        r = run(internet={3: [Window(0, 40)]})
        self.assertEqual(r["gateway_stored"], [2])
        self.assertEqual(r["recipient_stored"], [None])
        self.assertEqual(r["source_confirmed"], [None])

    def test_delayed_uplink_preserves_durable_copy(self):
        r = run(internet={3: [Window(0, 16)]})
        self.assertEqual(r["mailbox_uploaded"], [16])
        self.assertEqual(r["recipient_stored"], [20])

    def test_wakeup_after_ttl_never_delivers(self):
        self.assertEqual(run(internet={3: [Window(0, 41)]})["recipient_stored"], [None])

    def test_disk_loss_while_offline(self):
        r = run(internet={3: [Window(0, 15)]},
                loss={3: [Window(6, 10)]})
        self.assertEqual(r["recipient_stored"], [None])

    def test_internet_outage_does_not_break_direct_delivery(self):
        r = run(direct=8, internet={3: [Window(0, 40)]})
        self.assertEqual(r["recipient_stored"], [8])

    def test_receipt_is_independent_contact_after_delivery(self):
        r = run(contacts=((10, 1, 2), (21, 2, 1)))
        self.assertEqual(r["recipient_stored"], [10])
        self.assertEqual(r["source_confirmed"], [21])

    def test_source_must_not_know_before_receipt(self):
        self.assertEqual(run()["source_confirmed"], [None])
        self.assertEqual(run()["missing_receipt"], 1)

    def test_simulated_internet_return_not_w4_signature(self):
        r = run(delay=3)
        self.assertEqual(r["source_confirmed"], [13])
        self.assertIn("not-real-w4", r["claim"])

    def test_closed_on_inconsistent_vector_or_invalid_interval(self):
        with self.assertRaises(ValueError):
            Window(5, 5)
        with self.assertRaises(ValueError):
            recovery_outcomes(JOBS, [], [1], [3], ttl=40, pickup_period=10)
        with self.assertRaises(ValueError):
            run(stored=50)
        with self.assertRaises(ValueError):
            run(delay=0)

    def test_radio_sleep_suppresses_only_impacted_contacts(self):
        events = [(0, 1, 3, "x", 20000), (3, 3, 2, "x", 20000),
                  (4, 1, 2, "x", 20000)]
        alive = observed_while_awake(events, {3: [Window(2, 8)]})
        self.assertEqual([e[0] for e in alive], [0, 4])

    def test_offline_half_open_interval(self):
        w = Window(3, 8)
        self.assertFalse(offline(2, [w]))
        self.assertTrue(offline(3, [w]))
        self.assertFalse(offline(8, [w]))

    def test_gateway_identity_is_per_message(self):
        jobs = [(1, 2, 0, "x"), (4, 5, 0, "x")]
        r = recovery_outcomes(jobs, [None, None], [2, 2], [3, 6],
                              ttl=40, pickup_period=10,
                              internet_down={3: [Window(0, 40)]})
        self.assertEqual(r["recipient_stored"], [None, 10])


if __name__ == "__main__":
    unittest.main()
