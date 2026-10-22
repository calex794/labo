"""EXP-016: executable negative/positive checks, never production W3 claims."""
import base64
import json
import secrets
import tempfile
from pathlib import Path
import unittest

from exp016_custodian_network import (
    CLAIM, Node, Rejected, cap_hash, digest, make_initial, new_cap,
    run_experiment, signed_offer,
)


class ThreeCustodianTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.pins = {k: secrets.token_hex(32) for k in ("A", "P", "X", "Y")}
        self.p = self.node("P", "PERSONAL")
        self.x = self.node("X", "PUBLIC")
        self.y = self.node("Y", "PUBLIC")
        self.p_tag, self.x_tag, self.y_tag = [new_cap() for _ in range(3)]
        self.p_write, self.p_read = new_cap(), new_cap()
        self.x_write, self.x_read = new_cap(), new_cap()
        self.y_write, self.y_read = new_cap(), new_cap()
        for node, tag, write, read in (
            (self.p, self.p_tag, self.p_write, self.p_read),
            (self.x, self.x_tag, self.x_write, self.x_read),
            (self.y, self.y_tag, self.y_write, self.y_read)):
            node.enroll(tag, write, read, 103600, 2)

    def tearDown(self):
        self.p.db.close()
        self.x.db.close()
        self.y.db.close()
        self.tmp.cleanup()

    def node(self, label, mode, now=100000):
        return Node(self.root / (label + ".sqlite"), label, mode,
                    self.pins[label], self.pins, now)

    def initial(self, payload=b"random-synthetic-W3-not-real-ciphertext"):
        slot = secrets.token_hex(16)
        raw = make_initial(self.pins["A"], "P", slot, self.p_tag,
                           payload, secrets.token_hex(16))
        receipt = self.p.accept(raw, self.p_write)
        self.assertEqual(receipt["body"]["status"], "CustodianStored")
        return slot, payload, raw

    def test_fresh_processes_three_sqlite_and_offline_sender(self):
        with tempfile.TemporaryDirectory() as root:
            report = run_experiment(Path(root) / "results")
            self.assertEqual(report["claim"], CLAIM)
            self.assertEqual(report["databases"], 3)
            self.assertEqual(report["node_roles"],
                             {"P": "PERSONAL", "X": "PUBLIC", "Y": "PUBLIC"})
            self.assertTrue(report["sender_and_runner_offline_during_handoffs"])
            self.assertTrue(report["outcomes"]["known_Y_fetched"])
            self.assertTrue(report["outcomes"]["known_X_fetched_after_lost_ACK"])
            self.assertTrue(report["outcomes"]["double_issue_rejected"])
            self.assertFalse(report["outcomes"]["recipient_W4_signed"])
            self.assertEqual(
                report["final_states"],
                {"P": ["FORWARDED", "FORWARDED", "ACTIVE"],
                 "X": ["ABSENT", "ACTIVE", "ABSENT"],
                 "Y": ["ACTIVE", "ABSENT", "ABSENT"]})
            self.assertTrue((Path(root) / "results" / "report.md").exists())
            saved = json.loads(
                (Path(root) / "results" / "custodian-triad.json").read_text())
            self.assertEqual(saved["events"], report["events"])

    def test_put_duplicate_is_idempotent_even_after_sqlite_reopen(self):
        slot, payload, offer = self.initial()
        self.p.db.close()
        self.p = self.node("P", "PERSONAL")
        same = self.p.accept(offer, self.p_write)
        self.assertEqual(same["body"]["slot"], slot)
        self.assertEqual(self.p.local_state(slot)["state"], "ACTIVE")
        self.assertEqual(len(self.p.poll(self.p_tag, self.p_read)["letters"]), 1)
        self.assertEqual(
            base64.b64decode(self.p.poll(self.p_tag, self.p_read)
                             ["letters"][0]["payload"]), payload)

    def test_slot_conflict_refuses_new_content_and_new_offer(self):
        slot, payload, _ = self.initial()
        conflict = make_initial(self.pins["A"], "P", slot, self.p_tag,
                                payload + b"changed", secrets.token_hex(16))
        with self.assertRaisesRegex(Rejected, "slot_conflict_or_forwarded"):
            self.p.accept(conflict, self.p_write)

    def test_signed_offer_tamper_and_wrong_destination_rejected(self):
        slot, _, _ = self.initial()
        offer = self.p.prepare(slot, "X", self.x_tag, secrets.token_hex(16))
        bad = {"body": dict(offer["body"]), "mac": offer["mac"]}
        bad["body"]["hash"] = digest(b"different")
        with self.assertRaisesRegex(Rejected, "invalid_offer_mac"):
            self.x.accept(bad, self.x_write)
        with self.assertRaisesRegex(Rejected, "wrong_target_or_untrusted_source"):
            self.y.accept(offer, self.y_write)

    def test_lost_ack_rejects_second_target_then_safe_retry(self):
        slot, _, _ = self.initial()
        pending = self.p.prepare(slot, "X", self.x_tag, secrets.token_hex(16))
        signed = self.x.accept(pending, self.x_write)
        with self.assertRaisesRegex(Rejected, "custody_ambiguous"):
            self.p.prepare(slot, "Y", self.y_tag, secrets.token_hex(16))
        # No ACK delivered to P yet; P still holds exact ciphertext.
        self.assertTrue(self.p.local_state(slot)["has_bytes"])
        again = self.x.accept(pending, self.x_write)
        self.assertEqual(again, signed)
        self.p.finalize(again)
        self.assertFalse(self.p.local_state(slot)["has_bytes"])
        self.assertEqual(self.p.local_state(slot)["state"], "FORWARDED")
        self.assertTrue(self.x.local_state(slot)["has_bytes"])
        self.assertTrue(self.p.finalize(again)["duplicate"])
        with self.assertRaisesRegex(Rejected, "no_active_custody"):
            self.p.prepare(slot, "Y", self.y_tag, secrets.token_hex(16))

    def test_untrusted_recipient_cannot_read_public_mail(self):
        slot, _, _ = self.initial()
        transfer = self.p.prepare(slot, "Y", self.y_tag, secrets.token_hex(16))
        receipt = self.y.accept(transfer, self.y_write)
        self.p.finalize(receipt)
        with self.assertRaisesRegex(Rejected, "not_authorized"):
            self.y.poll(self.y_tag, new_cap())
        with self.assertRaisesRegex(Rejected, "not_authorized"):
            self.x.poll(self.y_tag, self.y_read)
        self.assertEqual(self.y.poll(self.y_tag, self.y_read)
                         ["letters"][0]["slot"], slot)

    def test_forged_custody_receipt_cannot_release_source(self):
        slot, _, _ = self.initial()
        offer = self.p.prepare(slot, "X", self.x_tag, secrets.token_hex(16))
        receipt = self.x.accept(offer, self.x_write)
        forged = {"body": dict(receipt["body"]), "mac": receipt["mac"]}
        forged["body"]["hash"] = digest(b"fake")
        with self.assertRaisesRegex(Rejected, "invalid_custodian_receipt"):
            self.p.finalize(forged)
        self.assertTrue(self.p.local_state(slot)["has_bytes"])

    def test_no_mailbox_enumeration_in_public_advertisements(self):
        for n in (self.p, self.x, self.y):
            public = n.advertise()
            raw = json.dumps(public)
            self.assertNotIn(self.p_tag, raw)
            self.assertNotIn(self.x_tag, raw)
            self.assertNotIn(self.y_tag, raw)
            self.assertNotIn("recipient_id", raw)
            self.assertNotIn("read_cap", raw)
            self.assertNotIn("write_cap", raw)

    def test_capacity_applies_per_mailbox_and_rejects_overflow(self):
        # Reenrollment with changed maximum is intentionally forbidden.
        tag, wr, rd = new_cap(), new_cap(), new_cap()
        self.x.enroll(tag, wr, rd, 103600, max_letters=1)
        self.x.accept(make_initial(self.pins["A"], "X",
                                   secrets.token_hex(16), tag,
                                   b"first", secrets.token_hex(16)), wr)
        with self.assertRaisesRegex(Rejected, "mailbox_capacity_exceeded"):
            self.x.accept(make_initial(self.pins["A"], "X",
                                       secrets.token_hex(16), tag,
                                       b"second", secrets.token_hex(16)), wr)

    def test_expiry_is_enforced_even_with_valid_capability(self):
        tag, wr, rd = new_cap(), new_cap(), new_cap()
        self.y.enroll(tag, wr, rd, expires=100001)
        self.y.db.close()
        self.y = self.node("Y", "PUBLIC", now=100002)
        with self.assertRaisesRegex(Rejected, "expired_mailbox"):
            self.y.poll(tag, rd)
        with self.assertRaisesRegex(Rejected, "expired_mailbox"):
            self.y.accept(make_initial(self.pins["A"], "Y",
                                       secrets.token_hex(16), tag,
                                       b"data", secrets.token_hex(16)), wr)

    def test_same_db_cannot_change_operator_role(self):
        with self.assertRaisesRegex(Rejected, "cannot_change_node_role_silently"):
            other = self.node("P", "PUBLIC")
            other.db.close()

    def test_different_handoff_offer_cannot_replace_reserved_slot(self):
        slot, _, _ = self.initial()
        offer_id = secrets.token_hex(16)
        original = self.p.prepare(slot, "X", self.x_tag, offer_id)
        self.assertEqual(
            self.p.prepare(slot, "X", self.x_tag, offer_id), original)
        with self.assertRaisesRegex(Rejected, "custody_ambiguous"):
            self.p.prepare(slot, "X", self.x_tag, secrets.token_hex(16))
        with self.assertRaisesRegex(Rejected, "custody_ambiguous"):
            self.p.prepare(slot, "Y", self.y_tag, offer_id)


if __name__ == "__main__":
    unittest.main()
