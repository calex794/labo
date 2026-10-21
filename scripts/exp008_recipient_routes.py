#!/usr/bin/env python3
"""LABO EXP-008: target-aware routing and concurrent strategies for ONE message.

Synthetic causal contact traces only. No production Akula/W4 signatures, private
lookup, real BLE RSS, foreground/background guarantees or device measurement.
"""
import argparse
from collections import defaultdict
from dataclasses import dataclass
import csv
import hashlib
import json
import math
from pathlib import Path
import statistics

from exp006_temporal_contacts import (
    build_temporal_graph, contact_events, earliest_delivery, found_via_ble,
    sample_messages,
)

# EXP-008's original 11-way comparison remains the default and reproducible.
POLICIES = ("direct", "random", "random4", "spray4", "spray8",
            "prophet4", "prophet8", "gateway4", "sequential4",
            "parallel4", "parallel8")
ONEPLUSONE_POLICIES = ("oneplusone2", "oneplusone4")
SUPPORTED_POLICIES = POLICIES + ONEPLUSONE_POLICIES
SEEDS = (21021, 21022, 21023)
WINGS = (1, 10, 100)
CLAIM = "synthetic-routing-not-real-delivery"


def stable_random(*parts):
    raw = ":".join(str(part) for part in parts).encode("ascii")
    return int.from_bytes(hashlib.blake2s(raw, digest_size=8).digest(), "big") / (1 << 64)


@dataclass(frozen=True)
class Holder:
    role: str
    ready: int
    attempt: int


class ContactForecast:
    """Sparse causal encounter estimates, never reading future events.

    Values are *rank scores*, not calibrated delivery probabilities. Summaries
    are deliberately limited to 16 destinations per node in this experiment.
    The recipient identifier is visible in this synthetic oracle and is NOT a
    privacy-preserving network discovery scheme.
    """

    def __init__(self, max_entries=16, decay=0.94, direct_gain=0.65, transitive=0.4, tracked_targets=None):
        self.rows = defaultdict(dict)
        self.tracked_targets = None if tracked_targets is None else frozenset(tracked_targets)
        self.max_entries = max_entries
        self.decay = decay
        self.direct_gain = direct_gain
        self.transitive = transitive
        self.last_ingested_tick = -1
        self.entry_peak = 0
        self.entry_count = 0

    def score(self, node, destination, tick):
        if node == destination:
            return 1.0
        item = self.rows.get(node, {}).get(destination)
        return 0.0 if item is None else item[0] * self.decay ** max(0, tick - item[1])

    def _put(self, node, destination, value, tick):
        if node == destination:
            return
        row = self.rows[node]
        value = min(0.999, max(0.0, value))
        if value < 0.0005:
            return
        if destination not in row and len(row) >= self.max_entries:
            weakest = min(row, key=lambda key: (self.score(node, key, tick), key))
            if self.score(node, weakest, tick) >= value:
                return
            del row[weakest]
            self.entry_count -= 1
        if destination not in row:
            self.entry_count += 1
        row[destination] = (value, tick)
        self.entry_peak = max(self.entry_peak, self.entry_count)

    def learn_tick(self, events, tick):
        if tick <= self.last_ingested_tick:
            raise ValueError("future/reused contact data or noncausal history update")
        # Every contact at tick reads ONLY the forecast as of tick-1. This also
        # forbids instantaneous gossip across multiple same-tick encounters.
        decisions = []
        for _, a, b, _kind, _length in events:
            ab = self.score(a, b, tick)
            ba = self.score(b, a, tick)
            direct_ab = ab + (1 - ab) * self.direct_gain
            direct_ba = ba + (1 - ba) * self.direct_gain
            if self.tracked_targets is None or b in self.tracked_targets:
                decisions.append((a, b, direct_ab))
            if self.tracked_targets is None or a in self.tracked_targets:
                decisions.append((b, a, direct_ba))
            # For the batch experiment we track only explicitly addressed
            # destinations. Otherwise the history of 200k devices would
            # become an immense contact directory, unnecessary for routing.
            targets_a = (self.rows.get(b, {}) if self.tracked_targets is None
                         else self.tracked_targets)
            targets_b = (self.rows.get(a, {}) if self.tracked_targets is None
                         else self.tracked_targets)
            for target in targets_a:
                if target != a:
                    score = self.transitive * direct_ab * self.score(b, target, tick)
                    if score > self.score(a, target, tick):
                        decisions.append((a, target, score))
            for target in targets_b:
                if target != b:
                    score = self.transitive * direct_ba * self.score(a, target, tick)
                    if score > self.score(b, target, tick):
                        decisions.append((b, target, score))
        for node, target, value in decisions:
            if value > self.score(node, target, tick):
                self._put(node, target, value, tick)
        self.last_ingested_tick = tick


def observed_events(events, scan_filter=False, seed=21021):
    if any(e[0] < 0 or e[1] < 0 or e[2] < 0 or e[1] == e[2] or e[4] < 0 for e in events):
        raise ValueError("invalid contacts")
    if events != sorted(events, key=lambda e: (e[0], e[1], e[2], e[3])):
        raise ValueError("contact sequence must be chronologically sorted")
    return [e for e in events if not scan_filter or found_via_ble(e, seed, 400, 2000, 300)]


def policy_budget(policy):
    if policy == "direct" or policy == "random":
        return 1
    if policy == "oneplusone2":
        return 2
    if policy in ("parallel8", "spray8", "prophet8"):
        return 8
    if policy in SUPPORTED_POLICIES:
        return 4
    raise ValueError(f"unknown policy: {policy}")


def _volunteer(node, residents_per_wing):
    # Explicit synthetic consent predicate: hubs/couriers always volunteer;
    # roughly 80% of other devices do, independently of their location.
    return node % residents_per_wing in (0, 1) or stable_random("opt-in", node) < .80


def simulate(events, jobs, *, policy="parallel4", ttl=40, goodput_kbps=64,
             message_bytes=256, envelope_bytes=64, setup_ms=300,
             radio_ms_per_tick=6000, seed=21021, residents_per_wing=2000,
             gateways=(), gateway_online=True, mailbox_authorized=False,
             mailbox_pickups=None, volunteer=None, oracle_ticks=None,
             observation_end=None):
    """Simulate distinct delivery attempts under a *single global copy cap*.

    Immutable message identity is the jobs list index. Each local copy carries
    a unique attempt number and route policy. A locally generated receipt can
    spread only through observed future contacts. ACK is a *synthetic marker*,
    never a cryptographically verified W4 record.
    """
    k_limit = policy_budget(policy)
    if not (1 <= ttl <= 10000 and 1 <= goodput_kbps <= 10000 and
            1 <= message_bytes <= 1_000_000 and 0 <= envelope_bytes <= 65535 and
            0 <= setup_ms <= 60000 and 1 <= radio_ms_per_tick <= 60000 and
            2 <= residents_per_wing <= 200000):
        raise ValueError("invalid transfer or scenario parameter")
    if any(not (isinstance(a, int) and isinstance(b, int) and isinstance(t, int)
                    and a >= 0 and b >= 0 and t >= 0 and a != b)
           for a, b, t, _category in jobs):
        raise ValueError("invalid message pairs")
    if mailbox_pickups is None:
        mailbox_pickups = {}
    if any(mid < 0 or mid >= len(jobs) or tick < jobs[mid][2]
           for mid, tick in mailbox_pickups.items()):
        raise ValueError("invalid mailbox pickup schedule")
    events = observed_events(events, seed=seed)
    graph = build_temporal_graph(events) if oracle_ticks is None else None
    if oracle_ticks is not None and len(oracle_ticks) != len(jobs):
        raise ValueError("oracle count mismatch")
    gateway_nodes = frozenset(gateways)
    if any(node < 0 for node in gateway_nodes):
        raise ValueError("invalid gateway node")
    may_carry = volunteer or (lambda node: _volunteer(node, residents_per_wing))
    max_tick = observation_end if observation_end is not None else max(
        [t for t, *_ in events] + [x[2] + ttl - 1 for x in jobs] + [0])
    if max_tick < 0:
        raise ValueError("invalid observation end")
    by_tick = defaultdict(list)
    for event in events:
        if event[0] <= max_tick:
            by_tick[event[0]].append(event)

    # route attempts are local storage copies of one logical letter. A shared
    # in-memory ledger models atomic token accounting for honest nodes only.
    holdings = [{src: Holder("anchor", created, 0)} for src, _, created, _ in jobs]
    inventory = defaultdict(set)
    for mid, (src, _, _, _) in enumerate(jobs):
        inventory[src].add(mid)
    history = ContactForecast(tracked_targets=(dest for _, dest, _, _ in jobs))
    needs_forecast = policy in ("prophet4", "prophet8", "sequential4", "parallel4", "parallel8")
    receipts = defaultdict(set)
    delivered = [None] * len(jobs)
    delivery_channel = [None] * len(jobs)
    mailbox_stored = [None] * len(jobs)
    source_receipt_at = [None] * len(jobs)
    accepted_count = [0] * len(jobs)
    next_attempt = [1] * len(jobs)
    max_copies_per_message = [1] * len(jobs)
    route_holders_by_role = defaultdict(set)
    transmissions = duplicate_contacts = data_bytes = receipt_bytes = 0
    frozen_backups = rolling_runner_handoffs = direct_from_backup = 0
    airtime_data_ms = airtime_ack_ms = blocked_airtime = 0
    max_radio_per_device_tick = 0
    load_by_node = defaultdict(int)
    estimated_coverage = defaultdict(set)
    service_attempts = defaultdict(int)
    data_duration = math.ceil(8 * (message_bytes + envelope_bytes) / goodput_kbps)
    ack_duration = math.ceil(8 * 48 / goodput_kbps)

    def forget(mid, node):
        copy = holdings[mid].pop(node, None)
        if copy is not None:
            inventory[node].discard(mid)
            route_holders_by_role[(mid, copy.role)].discard(node)

    def can_use_capacity(left, right, state, duration):
        return (state["time_left"] >= duration and
                state["remaining"][left] >= duration and
                state["remaining"][right] >= duration)

    def use_capacity(left, right, state, duration, is_ack):
        nonlocal airtime_data_ms, airtime_ack_ms, max_radio_per_device_tick
        if not state["setup"]:
            state["remaining"][left] -= setup_ms
            state["remaining"][right] -= setup_ms
            state["time_left"] -= setup_ms
            state["setup"] = True
        state["remaining"][left] -= duration
        state["remaining"][right] -= duration
        state["time_left"] -= duration
        if is_ack:
            airtime_ack_ms += duration
        else:
            airtime_data_ms += duration
        max_radio_per_device_tick = max(max_radio_per_device_tick,
                                        radio_ms_per_tick-state["remaining"][left],
                                        radio_ms_per_tick-state["remaining"][right])

    def choose_action(mid, sender, receiver, holder, tick, encounter_kind):
        src, dest, created, _ = jobs[mid]
        score_sender = history.score(sender, dest, tick)
        score_receiver = history.score(receiver, dest, tick)
        better = score_receiver > score_sender + .08 and score_receiver >= .10
        current = len(holdings[mid])
        available = current < k_limit
        at_gateway = (receiver in gateway_nodes and gateway_online
                      and mailbox_authorized and may_carry(receiver))
        if policy in ("oneplusone2", "oneplusone4"):
            # One moving letter and (at most K-1) parked backups. A parked
            # copy can only meet the EXACT destination, handled by the outer
            # receiver == dest check; it must NEVER recruit another carrier.
            if holder.role == "parked":
                return None
            if holder.role not in ("anchor", "runner"):
                raise AssertionError("oneplusone needs one active runner")
            # First K-1 successful handoffs leave parked copies. Thereafter
            # the active runner MOVES without minting another parked copy.
            return ("copy" if available else "move", "runner")
        if policy == "direct":
            return None
        if policy in ("random", "random4"):
            if stable_random("random", seed, mid, tick, sender, receiver) < .55:
                return ("copy" if policy == "random4" and available else "move", "random")
            return None
        if policy in ("spray4", "spray8"):
            return ("copy", "spray") if available else None
        if policy in ("prophet4", "prophet8"):
            if better:
                return ("copy" if available else "move", "predict")
            return None
        if policy == "gateway4":
            if at_gateway:
                return ("copy" if available else "move", "gateway")
            return None
        if policy == "sequential4":
            age = tick - created
            if age < 4:
                return None
            if age < 12:
                return (("copy" if available else "move"), "predict") if better else None
            if age < 22:
                return ("copy", "spray") if available else None
            if at_gateway:
                return ("copy" if available else "move", "gateway")
            return ("copy", "fallback") if available else None
        # Concurrent strategy: first copy stays at sender (direct); independent
        # named lanes are filled when useful contacts *actually occur*.
        if policy.startswith("parallel"):
            if holder.role == "anchor":
                if not available:
                    return None
                present = {c.role for c in holdings[mid].values()}
                if at_gateway and "gateway" not in present:
                    return "copy", "gateway"
                if better and "predict" not in present:
                    return "copy", "predict"
                # Different social/community routes get first preference. We
                # only know wing membership, not real people's associations.
                if "explore" not in present:
                    return "copy", "explore"
                if "fallback" not in present and (not (gateway_nodes and mailbox_authorized) or k_limit > 4):
                    return "copy", "fallback"
                if k_limit > 4:
                    reserve_predict = int("predict" not in present)
                    reserve_gateway = int(bool(gateway_nodes and mailbox_authorized)
                                          and "gateway" not in present)
                    if k_limit - current <= reserve_predict + reserve_gateway:
                        return None
                    # Do not fill extra budgets with 7 redundant residents of
                    # one wing and miss the only useful visiting courier.
                    covered = {node // residents_per_wing for node in holdings[mid]}
                    other_wing = receiver // residents_per_wing not in covered
                    courier = receiver % residents_per_wing == 1
                    if other_wing or courier:
                        return "copy", "extra"
                return None
            if holder.role in ("predict", "extra") and better:
                return "move", holder.role
            # At the copy limit exploration may move, not mint more copies.
            if holder.role == "fallback" and better:
                return "move", "fallback"
            return None
        raise AssertionError("unknown routing policy")

    for tick in range(max_tick + 1):
        # A time slice freezes all holdings and known receipts for forwarding;
        # a new relay cannot chain into a second contact in this same tick.
        snapshot_inventory = {node: mids.copy() for node, mids in inventory.items() if mids}
        snapshot_receipts = {node: mids.copy() for node, mids in receipts.items() if mids}
        remaining = defaultdict(lambda: radio_ms_per_tick)
        for _t, left, right, encounter_kind, duration_ms in by_tick.get(tick, ()):
            state = {"time_left": duration_ms, "setup": False, "remaining": remaining}
            # Propagate only acknowledgements already known at tick start.
            # Both participants must have consent for receipt forwarding; direct
            # recipient receipt to sender is allowed without public broadcasting.
            ack_offers = ((left, right), (right, left))
            for from_node, to_node in ack_offers:
                candidates = snapshot_receipts.get(from_node, set()) - receipts[to_node]
                if not candidates or (not may_carry(to_node) and all(
                        jobs[mid][0] != to_node for mid in candidates)):
                    continue
                for mid in sorted(candidates):
                    if not can_use_capacity(left, right, state, ack_duration + (0 if state["setup"] else setup_ms)):
                        break
                    use_capacity(left, right, state, ack_duration, True)
                    receipt_bytes += 48
                    receipts[to_node].add(mid)
                    if jobs[mid][0] == to_node and source_receipt_at[mid] is None:
                        source_receipt_at[mid] = tick
                    forget(mid, to_node)
            # Give each message at most one payload transfer per contact. Shared
            # capacity across messages prevents independent lanes from free airtime.
            active = sorted(snapshot_inventory.get(left, set()) | snapshot_inventory.get(right, set()),
                            key=lambda mid: (jobs[mid][2], mid))
            for mid in active:
                src, dest, created, _label = jobs[mid]
                if tick < created or tick >= created + ttl:
                    continue
                if mid in receipts[left] and mid in receipts[right]:
                    continue
                if mid in snapshot_inventory.get(left, set()) and left in holdings[mid] and right not in holdings[mid]:
                    sender, receiver = left, right
                elif mid in snapshot_inventory.get(right, set()) and right in holdings[mid] and left not in holdings[mid]:
                    sender, receiver = right, left
                else:
                    continue
                holder = holdings[mid][sender]
                if holder.ready > tick or mid in receipts[sender]:
                    continue
                if receiver == dest and delivered[mid] is not None:
                    duplicate_contacts += 1
                    continue
                action = None
                if receiver == dest:
                    action = ("accept", "recipient")
                elif may_carry(receiver) and mid not in receipts[receiver]:
                    action = choose_action(mid, sender, receiver, holder, tick, encounter_kind)
                if action is None:
                    continue
                how, role = action
                if how == "copy" and len(holdings[mid]) >= k_limit:
                    raise AssertionError("shared copy quota exceeded")
                if not can_use_capacity(left, right, state, data_duration + (0 if state["setup"] else setup_ms)):
                    blocked_airtime += 1
                    continue
                use_capacity(left, right, state, data_duration, False)
                data_bytes += message_bytes + envelope_bytes
                transmissions += 1
                service_attempts[(mid, role)] += 1
                load_by_node[sender] += message_bytes + envelope_bytes
                load_by_node[receiver] += message_bytes + envelope_bytes
                if how == "accept":
                    if policy in ("oneplusone2", "oneplusone4") and holder.role == "parked":
                        direct_from_backup += 1
                    delivered[mid] = tick
                    delivery_channel[mid] = "ble_contact"
                    accepted_count[mid] += 1
                    receipts[receiver].add(mid)  # simulated recipient-local acceptance
                    # The source learns only if the receipt later returns by
                    # observed contact. No instantaneous global W4 notification.
                else:
                    if policy in ("oneplusone2", "oneplusone4"):
                        if how == "copy":
                            # Only a confirmed, airtime-paid handoff freezes
                            # the previous runner. Failed contacts do nothing.
                            if holder.role not in ("anchor", "runner"):
                                raise AssertionError("a parked copy was forwarded")
                            holdings[mid][sender] = Holder("parked", holder.ready, holder.attempt)
                            route_holders_by_role[(mid, holder.role)].discard(sender)
                            route_holders_by_role[(mid, "parked")].add(sender)
                            frozen_backups += 1
                        elif how == "move":
                            if holder.role != "runner":
                                raise AssertionError("active path lost its runner")
                            rolling_runner_handoffs += 1
                    if how == "move":
                        forget(mid, sender)
                    new_attempt = next_attempt[mid]
                    next_attempt[mid] += 1
                    holdings[mid][receiver] = Holder(role, tick+1, new_attempt)
                    inventory[receiver].add(mid)
                    route_holders_by_role[(mid, role)].add(receiver)
                    estimated_coverage[mid].add(receiver // residents_per_wing)
                    max_copies_per_message[mid] = max(max_copies_per_message[mid], len(holdings[mid]))
                    if (receiver in gateway_nodes and gateway_online and
                        mailbox_authorized and mailbox_stored[mid] is None):
                        mailbox_stored[mid] = tick
                if len(holdings[mid]) > k_limit:
                    raise AssertionError("per-letter global quota exceeded")
        # Explicit mailbox retrieval: only a previously deposited message and a
        # separately scheduled recipient check establish a synthetic delivery.
        for mid, at in mailbox_pickups.items():
            if at == tick and delivered[mid] is None and mailbox_stored[mid] is not None:
                created = jobs[mid][2]
                if created <= tick < created + ttl:
                    delivered[mid] = tick
                    delivery_channel[mid] = "mailbox_pickup"
                    accepted_count[mid] += 1
                    receipts[jobs[mid][1]].add(mid)
        # Only now learn any contacts at tick: no knowledge of future encounters.
        if needs_forecast and tick in by_tick:
            history.learn_tick(by_tick[tick], tick)
        for mid, (_, _, created, _label) in enumerate(jobs):
            if tick == created + ttl:
                for node in list(holdings[mid]):
                    forget(mid, node)
    # Consistent return even if the observation horizon ended before expiry.
    oracle = (oracle_ticks if oracle_ticks is not None else
              [earliest_delivery(graph, src, dest, created, ttl)
               for src, dest, created, _ in jobs])
    by_category = defaultdict(list)
    for mid, (src, dest, created, category) in enumerate(jobs):
        estimated_coverage[mid].add(src // residents_per_wing)
        if accepted_count[mid] > 1:
            raise AssertionError("recipient displayed one letter more than once")
        if max_copies_per_message[mid] > k_limit:
            raise AssertionError("shared copy budget exceeded")
        # An explicit mailbox pickup may outrun the *BLE-only* contact oracle;
        # this is a real separate synthetic transport, reported distinctly.
        if delivery_channel[mid] == "ble_contact":
            if oracle[mid] is None or delivered[mid] < oracle[mid]:
                raise AssertionError("physical delivery beat its contact oracle")
        by_category[category].append(mid)
    groups = {}
    for label, mids in sorted(by_category.items()):
        successes = sorted(delivered[mid] - jobs[mid][2] for mid in mids if delivered[mid] is not None)
        oracles = sum(oracle[mid] is not None for mid in mids)
        mailbox = sum(mailbox_stored[mid] is not None for mid in mids)
        acknowledgements = sum(source_receipt_at[mid] is not None for mid in mids)
        groups[label] = {
            "letters": len(mids),
            "oracle_ble_reachable": oracles,
            "recipient_accepted": len(successes),
            "accepted_percent": round(100 * len(successes) / len(mids), 5),
            "mailbox_stored": mailbox,
            "source_knows_receipt": acknowledgements,
            "undelivered": len(mids) - len(successes),
            "median_delivery_ticks": statistics.median(successes) if successes else None,
            "p95_delivery_ticks": successes[math.ceil(.95*len(successes))-1] if successes else None,
        }
    return {
        "claim": CLAIM,
        "policy": policy,
        "k_limit": k_limit,
        "groups": groups,
        "delivery_ticks": delivered,
        "mailbox_ticks": mailbox_stored,
        "delivery_channel": delivery_channel,
        "source_receipt_ticks": source_receipt_at,
        "accepted_count": accepted_count,
        "max_copies_per_message": max_copies_per_message,
        "transmissions": transmissions,
        "wire_bytes": data_bytes + receipt_bytes,
        "airtime_ms": airtime_data_ms + airtime_ack_ms,
        "data_bytes": data_bytes,
        "receipt_bytes": receipt_bytes,
        "duplicate_contact_attempts": duplicate_contacts,
        "frozen_backups": frozen_backups,
        "rolling_runner_handoffs": rolling_runner_handoffs,
        "direct_from_backup": direct_from_backup,
        "airtime_blocked": blocked_airtime,
        "max_radio_per_device_tick_ms": max_radio_per_device_tick,
        "peak_predictor_entries": history.entry_peak,
        "unique_courier_nodes": len(load_by_node),
        "max_node_bytes": max(load_by_node.values(), default=0),
        "max_copies_seen": max(max_copies_per_message, default=0),
        "mean_wings_with_carriers": round(
            statistics.fmean(len(estimated_coverage[mid]) for mid in range(len(jobs))), 4
        ) if jobs else 0.0,
        "max_wings_with_carriers": max((len(x) for x in estimated_coverage.values()), default=0),
        "attempts_by_role": {role: sum(count for (mid, p), count in service_attempts.items() if p == role)
                             for role in sorted({p for (_, p) in service_attempts})},
    }


def run_matrix(out_dir, *, wings=(1,10,100), seeds=SEEDS, steps=80,
               ttl=40, letters_per_kind=12, policies=POLICIES,
               scan_modes=(False, True), courier_modes=(False, True),
               gateway_modes=(False, True)):
    if not (1 <= ttl <= steps <= 2000 and letters_per_kind >= 1):
        raise ValueError("invalid matrix size")
    rows = []
    for wing in wings:
        for seed in seeds:
            jobs = sample_messages(wing, steps, seed, letters_per_kind)
            for courier in courier_modes:
                physical_events = contact_events(wing, steps, seed, courier)
                for scanning in scan_modes:
                    contacts = observed_events(physical_events, scanning, seed)
                    oracle_graph = build_temporal_graph(contacts)
                    ble_oracle = [earliest_delivery(oracle_graph, source, target, created, ttl)
                                  for source, target, created, _ in jobs]
                    for gateway_enabled in gateway_modes:
                        # Explicit special case: campus hub nodes have opted-in
                        # gateway role. Recipient mailbox pickup occurs only if
                        # a synthetic separate path is enabled and deposited.
                        hubs = tuple(w * 2000 for w in range(wing)) if gateway_enabled else ()
                        pickups = {mid: min(steps-1, job[2] + 21)
                                   for mid, job in enumerate(jobs)} if gateway_enabled else {}
                        for policy in policies:
                            result = simulate(
                                contacts, jobs, policy=policy, seed=seed, ttl=ttl,
                                observation_end=steps-1, gateways=hubs,
                                mailbox_authorized=gateway_enabled,
                                mailbox_pickups=pickups,
                                oracle_ticks=ble_oracle,
                            )
                            for category, group in result["groups"].items():
                                rows.append({
                                    "wings": wing, "population": wing*2000, "seed": seed,
                                    "couriers": courier, "scan_filter": scanning,
                                    "gateway_enabled": gateway_enabled, "policy": policy,
                                    "copies_limit": result["k_limit"], "category": category,
                                    "letters": group["letters"],
                                    "oracle_ble_reachable": group["oracle_ble_reachable"],
                                    "recipient_accepted": group["recipient_accepted"],
                                    "undelivered": group["undelivered"],
                                    "accepted_percent": group["accepted_percent"],
                                    "mailbox_stored": group["mailbox_stored"],
                                    "source_knows_receipt": group["source_knows_receipt"],
                                    "median_delivery_ticks": group["median_delivery_ticks"],
                                    "p95_delivery_ticks": group["p95_delivery_ticks"],
                                    "transmissions": result["transmissions"],
                                    "wire_bytes": result["wire_bytes"],
                                    "airtime_ms": result["airtime_ms"],
                                    "max_node_bytes": result["max_node_bytes"],
                                    "max_copies_seen": result["max_copies_seen"],
                                    "peak_predictor_entries": result["peak_predictor_entries"],
                                    "mean_wings_with_carriers": result["mean_wings_with_carriers"],
                                    "duplicate_contact_attempts": result["duplicate_contact_attempts"],
                                    "frozen_backups": result["frozen_backups"],
                                    "rolling_runner_handoffs": result["rolling_runner_handoffs"],
                                    "direct_from_backup": result["direct_from_backup"],
                                    "max_radio_per_device_tick_ms": result["max_radio_per_device_tick_ms"],
                                    "claim": result["claim"],
                                })
            print("WING_SEED_COMPLETE", wing, seed, flush=True)
    out_dir.mkdir(parents=True, exist_ok=True)
    with (out_dir / "routing-matrix.csv").open("w", encoding="utf8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    (out_dir / "routing-matrix.json").write_text(json.dumps({
        "schema": "labo-exp008-recipient-routing-v1", "claim": CLAIM,
        "seeds": list(seeds), "wings": list(wings), "steps": steps,
        "ttl": ttl, "policies": list(policies), "rows": rows,
    }, indent=2, ensure_ascii=False) + "\n", encoding="utf8")
    report = [
        "# LABO EXP-008 — search for the actual recipient of one letter", "",
        "**All delivery rates here are synthetic; receipt markers are NOT W4 signatures.**",
        "All policies share the same observed encounters, message pairs,",
        "scan-window filter, airtime costs, packet size and TTL inside each cell.",
        "Compare K4 policies together; Parallel K8 pays a strictly larger copy budget.",
        "Gateway success requires explicit deposit AND separate mailbox pickup.",
        "History only reflects already completed ticks. Recipient IDs are synthetic",
        "model labels, not a secure discovery protocol or private social graph.", "",
        "| Wings | Couriers | Scanning | Gateway | Policy | Category | First recipient % | Mailbox stored | Wire bytes |",
        "|---:|---|---|---|---|---|---:|---:|---:|",
    ]
    for wing in wings:
        for courier in courier_modes:
            for scan in scan_modes:
                for gateway in gateway_modes:
                    for policy in policies:
                        categories = ("random-pair",) if wing == 1 else ("random-pair", "adjacent-hubs-control")
                        for category in categories:
                            selected = [r for r in rows if r["wings"] == wing and
                                        r["couriers"] == courier and r["scan_filter"] == scan and
                                        r["gateway_enabled"] == gateway and r["policy"] == policy and
                                        r["category"] == category]
                            report.append(
                                f"| {wing} | {courier} | {scan} | {gateway} | {policy} | {category} | "
                                f"{statistics.fmean(x['accepted_percent'] for x in selected):.3f}% | "
                                f"{statistics.fmean(x['mailbox_stored'] for x in selected):.2f} | "
                                f"{statistics.fmean(x['wire_bytes'] for x in selected):.0f} |"
                            )
    report.extend(["", "A detected route does not prove delivery on a real phone.",
                   "Do not interpret mailbox STORED as recipient ACCEPTED.",
                   "Future: real contacts, privacy-preserving routing identifiers,",
                   "durable copy leases, crash recovery, W4-signed receipts.", ""])
    (out_dir / "report.md").write_text("\n".join(report), encoding="utf8")
    print("EXP008_COMPLETE", len(rows), "category rows", flush=True)
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("results/exp008"))
    parser.add_argument("--wings", type=int, nargs="+", default=list(WINGS))
    parser.add_argument("--seeds", type=int, nargs="+", default=list(SEEDS))
    parser.add_argument("--steps", type=int, default=80)
    parser.add_argument("--ttl", type=int, default=40)
    parser.add_argument("--letters-per-kind", type=int, default=12)
    args = parser.parse_args()
    if any(wing < 1 or wing > 100 for wing in args.wings):
        parser.error("wings must be 1..100")
    run_matrix(args.output, wings=args.wings, seeds=args.seeds, steps=args.steps,
               ttl=args.ttl, letters_per_kind=args.letters_per_kind)


if __name__ == "__main__":
    main()