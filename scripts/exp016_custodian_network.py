#!/usr/bin/env python3
"""LABO EXP-016: three voluntary mail custodians with independent SQLite files.

Executable process/SQLite protocol experiment, NOT deployed WOW or Akula.
Each node operation uses a fresh OS process; transport is local JSON stdio.
Payloads are RANDOM BYTES, not W3/HPKE; lab HMAC is not Ed25519/W4.
The simulation has no real BLE/QUIC links, physical servers or W4 signing.
"""
import argparse
import base64
import hashlib
import hmac
import json
import secrets
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

CLAIM = "real-isolated-sqlite-processes-synthetic-envelope-test-hmac"
ROLES = ("PERSONAL", "COMMUNITY", "PUBLIC")
MAX_WIRE_BYTES = 4096


class Rejected(Exception):
    """A denied action; never silently succeed."""


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def cap_hash(value):
    return digest(("cap-v1:" + value).encode())


def signature(value, secret_hex):
    return hmac.new(bytes.fromhex(secret_hex), canonical(value), hashlib.sha256).hexdigest()


def check_signature(value, sig, secret_hex):
    return (isinstance(sig, str) and
            hmac.compare_digest(signature(value, secret_hex), sig))


def signed_offer(body, source_key):
    return {"body": body, "mac": signature(body, source_key)}


def tx(db, action):
    db.execute("BEGIN IMMEDIATE")
    try:
        out = action()
        db.commit()
        return out
    except BaseException:
        db.rollback()
        raise


def demand(condition, label):
    if not condition:
        raise Rejected(label)


class Node:
    """One isolated custodial service: one SQLite ledger and own HMAC key.

    Pinning a shared lab-only HMAC secret emulates trusted signatures and is
    NOT a production crypto design. Callers control the simulation clock.
    """

    def __init__(self, dbpath, label, mode, secret_key, trusted, now=100000):
        demand(mode in ROLES and label and label in trusted, "bad_node_configuration")
        demand(trusted[label] == secret_key, "node_key_not_pinned")
        self.label, self.mode, self.key = label, mode, secret_key
        self.trusted, self.now = trusted, int(now)
        self.db = sqlite3.connect(str(dbpath), isolation_level=None, timeout=10)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS node_meta (
                label TEXT PRIMARY KEY, mode TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS mailboxes (
                tag TEXT PRIMARY KEY,
                write_hash TEXT NOT NULL,
                read_hash TEXT NOT NULL,
                expires INTEGER NOT NULL,
                max_letters INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS letters (
                slot TEXT PRIMARY KEY,
                offer TEXT NOT NULL UNIQUE,
                tag TEXT NOT NULL,
                hash TEXT NOT NULL,
                payload BLOB,
                expires INTEGER NOT NULL,
                state TEXT NOT NULL,
                source TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS handoffs (
                slot TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                offer TEXT NOT NULL UNIQUE,
                target_tag TEXT NOT NULL,
                state TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS receipts (
                offer TEXT PRIMARY KEY,
                data TEXT NOT NULL
            );
        """)
        existing = self.db.execute(
            "SELECT mode FROM node_meta WHERE label=?", (label,)).fetchone()
        if existing:
            demand(existing[0] == mode, "cannot_change_node_role_silently")
        else:
            self.db.execute("INSERT INTO node_meta(label,mode) VALUES(?,?)",
                            (label, mode))
        demand(self.db.execute("SELECT COUNT(*) FROM node_meta").fetchone()[0] == 1,
               "node_file_mixed_identities")

    def advertise(self):
        # Public advertisement must NEVER contain customer, inbox or message IDs.
        return {"kind": "MAIL_CUSTODIAN", "node": self.label,
                "mode": self.mode, "max_wire_bytes": MAX_WIRE_BYTES,
                "protocol": "EXP016_ONLY"}

    def enroll(self, tag, write_cap, read_cap, expires, max_letters=3):
        demand(isinstance(tag, str) and len(tag) >= 24 and
               write_cap != read_cap and len(write_cap) >= 24 and
               len(read_cap) >= 24, "weak_mailbox_capabilities")
        demand(self.now < int(expires) and 1 <= int(max_letters) <= 30,
               "invalid_mailbox_lease")

        def action():
            existing = self.db.execute(
                "SELECT write_hash,read_hash,expires,max_letters FROM mailboxes "
                "WHERE tag=?", (tag,)).fetchone()
            record = (cap_hash(write_cap), cap_hash(read_cap),
                      int(expires), int(max_letters))
            if existing is not None:
                demand(tuple(existing) == record, "mailbox_conflict")
                return {"enrolled": True, "duplicate": True}
            self.db.execute(
                "INSERT INTO mailboxes VALUES(?,?,?,?,?)",
                (tag, *record))
            return {"enrolled": True, "duplicate": False}
        return tx(self.db, action)

    def mailbox(self, tag, cap, right):
        row = self.db.execute(
            "SELECT write_hash,read_hash,expires,max_letters "
            "FROM mailboxes WHERE tag=?", (tag,)).fetchone()
        # Same response on absence and wrong secret; do not enumerate tags.
        demand(row is not None and
               hmac.compare_digest(row[0 if right == "write" else 1],
                                   cap_hash(cap)), "not_authorized")
        demand(self.now < row[2], "expired_mailbox")
        return row

    def accept(self, message, write_cap):
        body = message.get("body")
        demand(isinstance(body, dict), "malformed_offer")
        required = {"slot", "offer", "source", "target", "tag",
                    "hash", "payload", "expires"}
        demand(set(body) == required, "unexpected_offer_fields")
        demand(body["target"] == self.label and body["source"] in self.trusted,
               "wrong_target_or_untrusted_source")
        demand(check_signature(body, message.get("mac"),
                               self.trusted[body["source"]]), "invalid_offer_mac")
        demand(isinstance(body["slot"], str) and len(body["slot"]) >= 16 and
               isinstance(body["offer"], str) and len(body["offer"]) >= 16,
               "weak_offer_id")
        demand(self.now < int(body["expires"]), "expired_offer")
        try:
            binary = base64.b64decode(body["payload"], validate=True)
        except (ValueError, TypeError) as exc:
            raise Rejected("invalid_payload_encoding") from exc
        demand(0 < len(binary) <= MAX_WIRE_BYTES and
               hmac.compare_digest(digest(binary), body["hash"]),
               "payload_digest_mismatch")
        self.mailbox(body["tag"], write_cap, "write")

        def action():
            found = self.db.execute(
                "SELECT offer,tag,hash,payload,expires,state,source "
                "FROM letters WHERE slot=?", (body["slot"],)).fetchone()
            if found is not None:
                demand((found[0], found[1], found[2], found[4], found[6]) ==
                       (body["offer"], body["tag"], body["hash"],
                        int(body["expires"]), body["source"]) and
                       found[5] == "ACTIVE" and found[3] == binary,
                       "slot_conflict_or_forwarded")
                previous = self.db.execute(
                    "SELECT data FROM receipts WHERE offer=?",
                    (body["offer"],)).fetchone()
                demand(previous is not None, "missing_idempotent_receipt")
                return json.loads(previous[0])
            used = self.db.execute(
                "SELECT COUNT(*) FROM letters WHERE tag=? AND state='ACTIVE'",
                (body["tag"],)).fetchone()[0]
            allowed = self.db.execute(
                "SELECT max_letters FROM mailboxes WHERE tag=?",
                (body["tag"],)).fetchone()[0]
            demand(used < allowed, "mailbox_capacity_exceeded")
            # SQLite transaction commits after inserting the exact bytes and
            # receipt. Only after commit does the caller see the receipt.
            receipt_body = {"node": self.label, "source": body["source"],
                            "slot": body["slot"], "offer": body["offer"],
                            "hash": body["hash"], "status": "CustodianStored"}
            receipt = {"body": receipt_body,
                       "mac": signature(receipt_body, self.key)}
            self.db.execute(
                "INSERT INTO letters VALUES(?,?,?,?,?,?,?,?)",
                (body["slot"], body["offer"], body["tag"], body["hash"],
                 binary, int(body["expires"]), "ACTIVE", body["source"]))
            self.db.execute("INSERT INTO receipts VALUES(?,?)",
                            (body["offer"], json.dumps(receipt, sort_keys=True)))
            return receipt
        return tx(self.db, action)

    def prepare(self, slot, target, target_tag, offer):
        demand(target in self.trusted and target != self.label and
               isinstance(offer, str) and len(offer) >= 16,
               "bad_handoff_target_or_offer")

        def action():
            current = self.db.execute(
                "SELECT offer,tag,hash,payload,expires,state "
                "FROM letters WHERE slot=?", (slot,)).fetchone()
            demand(current is not None and current[5] == "ACTIVE"
                   and current[3] is not None, "no_active_custody")
            demand(self.now < current[4], "expired_custody")
            previous = self.db.execute(
                "SELECT target,offer,target_tag,state FROM handoffs "
                "WHERE slot=?", (slot,)).fetchone()
            if previous:
                demand(previous == (target, offer, target_tag, "PENDING"),
                       "custody_ambiguous_do_not_reissue")
            else:
                self.db.execute(
                    "INSERT INTO handoffs VALUES(?,?,?,?,?)",
                    (slot, target, offer, target_tag, "PENDING"))
            body = {
                "slot": slot, "offer": offer, "source": self.label,
                "target": target, "tag": target_tag, "hash": current[2],
                "payload": base64.b64encode(current[3]).decode("ascii"),
                "expires": current[4],
            }
            return signed_offer(body, self.key)
        return tx(self.db, action)

    def finalize(self, receipt):
        body = receipt.get("body")
        demand(isinstance(body, dict), "bad_receipt")
        required = {"node", "source", "slot", "offer", "hash", "status"}
        demand(set(body) == required and
               body["node"] in self.trusted and
               body["source"] == self.label and
               body["status"] == "CustodianStored" and
               check_signature(body, receipt.get("mac"),
                               self.trusted[body["node"]]), "invalid_custodian_receipt")

        def action():
            pending = self.db.execute(
                "SELECT target,offer,state FROM handoffs WHERE slot=?",
                (body["slot"],)).fetchone()
            letter = self.db.execute(
                "SELECT hash,state FROM letters WHERE slot=?",
                (body["slot"],)).fetchone()
            demand(pending is not None and letter is not None and
                   pending[0] == body["node"] and pending[1] == body["offer"]
                   and letter[0] == body["hash"], "receipt_not_for_pending_offer")
            if pending[2] == "COMPLETED":
                demand(letter[1] == "FORWARDED", "bad_completion_replay")
                return {"released": True, "duplicate": True}
            demand(pending[2] == "PENDING" and letter[1] == "ACTIVE",
                   "bad_handoff_state")
            self.db.execute(
                "UPDATE letters SET state='FORWARDED',payload=NULL "
                "WHERE slot=?", (body["slot"],))
            self.db.execute(
                "UPDATE handoffs SET state='COMPLETED' WHERE slot=?",
                (body["slot"],))
            return {"released": True, "duplicate": False}
        return tx(self.db, action)

    def poll(self, tag, read_cap):
        self.mailbox(tag, read_cap, "read")
        rows = self.db.execute(
            "SELECT slot,hash,payload FROM letters WHERE tag=? "
            "AND state='ACTIVE' AND expires>? ORDER BY slot LIMIT 30",
            (tag, self.now)).fetchall()
        return {"letters": [{"slot": slot, "hash": hash_value,
                             "payload": base64.b64encode(data).decode("ascii")}
                            for slot, hash_value, data in rows]}

    def local_state(self, slot):
        """Test-harness-only admin inspection, not a public node endpoint."""
        row = self.db.execute(
            "SELECT state,payload IS NOT NULL,hash FROM letters WHERE slot=?",
            (slot,)).fetchone()
        handoff = self.db.execute(
            "SELECT target,state FROM handoffs WHERE slot=?",
            (slot,)).fetchone()
        return {"state": row[0] if row else "ABSENT",
                "has_bytes": bool(row[1]) if row else False,
                "digest": row[2] if row else None,
                "handoff": list(handoff) if handoff else None}


def node_command(args):
    request = json.loads(sys.stdin.read())
    n = Node(args.db, args.label, args.mode, args.key,
             json.loads(args.trust), request.get("now", 100000))
    op = request["op"]
    p = request.get("args", {})
    actions = {"advertise": n.advertise, "enroll": n.enroll,
               "accept": n.accept, "prepare": n.prepare,
               "finalize": n.finalize, "poll": n.poll,
               "local_state": n.local_state}
    demand(op in actions, "unknown_operation")
    return actions[op](**p)


class Processes:
    """Every RPC launches a fresh process with its own independent database."""

    def __init__(self, root):
        self.root = Path(root)
        self.trust = {k: secrets.token_hex(32) for k in ("A", "P", "X", "Y")}
        self.modes = {"P": "PERSONAL", "X": "PUBLIC", "Y": "PUBLIC"}
        self.calls = 0

    def call(self, node, op, **kwargs):
        demand(node in self.modes, "unknown_node")
        req = {"op": op, "args": kwargs, "now": 100000}
        cmd = [sys.executable, str(Path(__file__).resolve()), "node",
               "--db", str(self.root / (node + ".sqlite")),
               "--label", node, "--mode", self.modes[node],
               "--key", self.trust[node],
               "--trust", json.dumps(self.trust)]
        done = subprocess.run(cmd, input=json.dumps(req), text=True,
                              capture_output=True, check=False, timeout=20)
        self.calls += 1
        demand(done.returncode == 0 and bool(done.stdout),
               "subprocess_error:" + done.stderr[-250:])
        answer = json.loads(done.stdout)
        if not answer["ok"]:
            raise Rejected(answer["error"])
        return answer["value"]

    def start(self):
        # Real, separate SQLite files, re-opened from different OS processes.
        return [self.call(x, "advertise") for x in ("P", "X", "Y")]


def make_initial(key, target, slot, tag, binary, offer, expiry=103600):
    body = {"slot": slot, "offer": offer, "source": "A",
            "target": target, "tag": tag, "hash": digest(binary),
            "payload": base64.b64encode(binary).decode("ascii"),
            "expires": expiry}
    return signed_offer(body, key)


def new_cap():
    return secrets.token_hex(24)


def run_experiment(output):
    """Positive offline handoff and ambiguous-ACK case; failures are asserted."""
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    events = []
    with tempfile.TemporaryDirectory(prefix="exp016-custodian-") as temp:
        process = Processes(temp)
        public_info = process.start()
        demand(len({i["node"] for i in public_info}) == 3, "node_identity_collision")
        demand(len(list(Path(temp).glob("*.sqlite"))) == 3,
               "databases_not_independent")
        demand(all("tag" not in i and "recipient" not in i and
                   "sender" not in i for i in public_info),
               "public_map_leaks_mailbox")

        # B's private invitation names X/Y; his mailbox setup is simulated.
        p_tag, x_tag, y_tag = (new_cap() for _ in range(3))
        p_w, p_r, x_w, x_r, y_w, y_r = (new_cap() for _ in range(6))
        process.call("P", "enroll", tag=p_tag, write_cap=p_w,
                     read_cap=p_r, expires=103600, max_letters=4)
        for n, tag, w, r in (("X", x_tag, x_w, x_r),
                             ("Y", y_tag, y_w, y_r)):
            process.call(n, "enroll", tag=tag, write_cap=w,
                         read_cap=r, expires=103600, max_letters=2)
        invited = {"X": (x_tag, x_r), "Y": (y_tag, y_r)}
        slots = [secrets.token_hex(16) for _ in range(3)]
        payloads = [secrets.token_bytes(320) for _ in slots]
        receipts = []
        for slot, blob in zip(slots, payloads):
            initial = make_initial(process.trust["A"], "P", slot, p_tag,
                                   blob, secrets.token_hex(16))
            receipts.append(process.call("P", "accept", message=initial,
                                         write_cap=p_w))
        demand(all(x["body"]["status"] == "CustodianStored" for x in receipts),
               "initial_durable_store_unconfirmed")
        events.append("three_random_opaque_letters_stored_at_personal_P")

        # Sender A and mobile runner R are now OFF: not one further operation
        # requires them. X is offline for message 1; P selects Y.
        sender_online = False
        x_online = False
        slot1, slot2, slot3 = slots
        offered_y = process.call("P", "prepare", slot=slot1, target="Y",
                                 target_tag=y_tag, offer=secrets.token_hex(16))
        ack_y = process.call("Y", "accept", message=offered_y, write_cap=y_w)
        process.call("P", "finalize", receipt=ack_y)
        demand(process.call("P", "local_state", slot=slot1)["state"] == "FORWARDED",
               "P_kept_active_copy_after_handoff")
        demand(process.call("Y", "local_state", slot=slot1)["state"] == "ACTIVE",
               "Y_did_not_persist_after_restart")
        events.append("offline_sender_P_handoff_to_public_Y_after_X_unavailable")

        # Bob knows only X and Y from his private invitation. P is not a
        # recipient-known mailbox. Both public services can be queried.
        x_online = True
        found_y = process.call("Y", "poll", tag=y_tag, read_cap=y_r)["letters"]
        demand(len(found_y) == 1 and found_y[0]["slot"] == slot1 and
               base64.b64decode(found_y[0]["payload"]) == payloads[0],
               "recipient_cannot_find_known_Y")
        demand(not process.call("X", "poll", tag=x_tag, read_cap=x_r)["letters"],
               "cross_custodian_leak")
        events.append("recipient_fetched_Y_by_private_invitation_not_global_ID")

        # Message 2: X durably accepts, its reply is lost. P must NOT give
        # the same logical C credit to Y. Retrying the exact offer with X
        # is idempotent and returns the same signed custodial receipt.
        offered_x = process.call("P", "prepare", slot=slot2, target="X",
                                 target_tag=x_tag, offer=secrets.token_hex(16))
        lost_ack = process.call("X", "accept", message=offered_x, write_cap=x_w)
        try:
            process.call("P", "prepare", slot=slot2, target="Y",
                         target_tag=y_tag, offer=secrets.token_hex(16))
            raise AssertionError("unsafe_double_issue_after_lost_ACK")
        except Rejected as exc:
            demand(str(exc) == "custody_ambiguous_do_not_reissue",
                   "wrong_failure_mode_for_ambiguous")
        replay_ack = process.call("X", "accept", message=offered_x,
                                  write_cap=x_w)
        demand(replay_ack == lost_ack, "idempotent_receipt_changed")
        process.call("P", "finalize", receipt=replay_ack)
        demand(process.call("P", "local_state", slot=slot2)["state"] == "FORWARDED",
               "sender_credit_doubled")
        pulled_x = process.call("X", "poll", tag=x_tag, read_cap=x_r)["letters"]
        demand(len(pulled_x) == 1 and pulled_x[0]["slot"] == slot2 and
               base64.b64decode(pulled_x[0]["payload"]) == payloads[1],
               "lost_ACK_recovery_failed")
        events.append("lost_ACK_ambiguous_slot_fenced_then_idempotent_replay")

        # Message 3 stays at an unknown-to-recipient personal P. Presence of
        # stored ciphertext alone is NOT a successful find/delivery.
        found_public = ([x["slot"] for x in process.call(
            n, "poll", tag=invited[n][0], read_cap=invited[n][1])["letters"]]
            for n in ("X", "Y"))
        demand(slot3 not in [x for bucket in found_public for x in bucket],
               "unknown_private_custodian_false_discovery")
        demand(process.call("P", "local_state", slot=slot3)["has_bytes"],
               "negative_control_not_stored")
        events.append("unknown_personal_location_not_found_by_public_search")

        # Public C must reject unauthorised fetching and tampered transfer.
        try:
            process.call("Y", "poll", tag=y_tag, read_cap=new_cap())
            raise AssertionError("unauthorized_read_succeeded")
        except Rejected as exc:
            demand(str(exc) == "not_authorized", "bad_read_error")
        forged = {"body": dict(offered_x["body"]), "mac": offered_x["mac"]}
        forged["body"]["target"] = "Y"
        try:
            process.call("Y", "accept", message=forged, write_cap=y_w)
            raise AssertionError("tampered_transfer_succeeded")
        except Rejected as exc:
            demand(str(exc) in ("invalid_offer_mac",
                                "wrong_target_or_untrusted_source"),
                   "bad_forgery_error")
        events.append("wrong_read_cap_and_tampered_handoff_rejected")

        states = {n: [process.call(n, "local_state", slot=s)["state"]
                      for s in slots] for n in ("P", "X", "Y")}
        demand(states["P"] == ["FORWARDED", "FORWARDED", "ACTIVE"] and
               states["X"] == ["ABSENT", "ACTIVE", "ABSENT"] and
               states["Y"] == ["ACTIVE", "ABSENT", "ABSENT"],
               "unexpected_final_ownership")
        demand(not sender_online and x_online, "offline_precondition")
        report = {
            "schema": "labo-exp016-custodian-triad-v1",
            "claim": CLAIM,
            "physical_servers_tested": False,
            "real_radio_or_quic_tested": False,
            "real_W3_HPKE_or_Ed25519_W4_tested": False,
            "trust": "test-only pinned shared HMAC secrets; orchestrator trusted",
            "process_model": "new separate subprocess for each node RPC",
            "databases": 3,
            "node_roles": {"P": "PERSONAL", "X": "PUBLIC", "Y": "PUBLIC"},
            "sender_and_runner_offline_during_handoffs": True,
            "known_recipient_nodes": ["X", "Y"],
            "logical_K": 3,
            "slot_semantics": "one original, one runner, one custodial right",
            "outcomes": {
                "known_Y_fetched": True, "known_X_fetched_after_lost_ACK": True,
                "unknown_P_not_discoverable": True,
                "double_issue_rejected": True,
                "recipient_W4_signed": False,
                "custody_receipts_test_MAC_only": True,
            },
            "final_states": states,
            "events": events,
            "subprocess_invocations": process.calls,
        }
        (output / "custodian-triad.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8")
        (output / "report.md").write_text(
            "# LABO EXP-016 — three custodians, offline sender\n\n"
            "**RESULT: LABORATORY MODEL ONLY.** Real, isolated SQLite files, "
            "one subprocess per node operation. Transport is local stdio; "
            "W3 payloads are random bytes; MACs are test-only HMAC, "
            "not WOW's Ed25519 W4 or HPKE.\n\n"
            "Three custodians P (personal), X and Y (public). The sender "
            "and mobile runner stop participating after initial deposit. "
            "When X is unavailable, P transfers its one logical custody "
            "right to Y; the recipient finds it using a private invitation "
            "listing X/Y. A second transfer to X loses its ACK: the slot "
            "stays ambiguous at P until the exact X offer is retried and "
            "its same receipt recovered. A third message at unknown P "
            "is deliberately NOT discoverable from X/Y.\n\n"
            "No source knows a public recipient ID from an advertisement. "
            "The node RPC is local, not a real secure network protocol. "
            "No actual end-recipient signed receipt or durability under "
            "physical power loss was tested.\n\n"
            "**Passes:** " + "; ".join(events) + ".\n", encoding="utf-8")
        print("EXP016_TRIPLE_CUSTODIAN_PASS",
              len(events), "checks", process.calls, "isolated calls", flush=True)
        return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("node", "run"))
    parser.add_argument("--db")
    parser.add_argument("--label")
    parser.add_argument("--mode")
    parser.add_argument("--key")
    parser.add_argument("--trust")
    parser.add_argument("--output", default="results/exp016")
    args = parser.parse_args()
    if args.action == "run":
        run_experiment(args.output)
    else:
        try:
            answer = node_command(args)
            print(json.dumps({"ok": True, "value": answer}, sort_keys=True))
        except (Rejected, KeyError, TypeError, ValueError, sqlite3.Error) as exc:
            # Do not reveal private capability strings in error messages.
            print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))


if __name__ == "__main__":
    main()
