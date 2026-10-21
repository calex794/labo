#!/usr/bin/env python3
"""LABO EXP-007: bounded packet transfer on explicit BLE encounters.

Independent synthetic extension of EXP-006. Goodput is assumed, not measured.
An entire message must fit inside ONE encounter; no fragment persistence yet.
Neither reaching an endpoint nor an oracle route is a real signed ACK.
"""
import argparse
from collections import defaultdict
import csv
import json
import math
from pathlib import Path
import statistics

from exp006_temporal_contacts import (
    build_temporal_graph, contact_events, earliest_delivery, found_via_ble,
    sample_messages,
)

SEEDS = (21021, 21022, 21023)
WINGS = (1, 10, 100)
STEP_COUNT = 80
TTL = 40


def simulate(events, jobs, *, message_bytes, goodput_kbps, ttl=TTL,
             setup_ms=300, envelope_bytes=64, radio_ms_per_tick=6000,
             copy_limit=4, scan_filter=False, seed=21021):
    """Bounded store-carry-forward on a given *chronological* contact trace.

    Each tick uses an immutable snapshot of holders: a fresh copy cannot be
    relayed within the same tick, even through another contact. Radios share
    one airtime budget per device/tick and one encounter's remaining duration.
    With copy_limit=1 a sent copy is moved, otherwise it is duplicated up to
    the per-message global ceiling. Contacts do not guarantee delivery.
    """
    if not (1 <= message_bytes <= 1_000_000 and 1 <= goodput_kbps <= 10_000
            and 0 <= setup_ms <= 60_000 and 0 <= envelope_bytes <= 65_535
            and 1 <= radio_ms_per_tick <= 60_000 and 1 <= copy_limit <= 64
            and 1 <= ttl <= 10_000):
        raise ValueError("invalid simulation resource or transfer parameter")
    if any(not (0 <= src and 0 <= dst and src != dst and created >= 0)
           for src, dst, created, _ in jobs):
        raise ValueError("invalid source, destination or creation time")
    selected = [e for e in events if not scan_filter or
                found_via_ble(e, seed, 400, 2000, 300)]
    if selected != sorted(selected, key=lambda e: (e[0], e[1], e[2], e[3])):
        raise ValueError("contacts must be chronologically sorted")
    # For every message all the holders are explicitly represented, unlike an
    # ideal upper-bound oracle which can duplicate the payload without limit.
    holders = [set([source]) for source, _, _, _ in jobs]
    inventories = defaultdict(set)
    for mid, (src, _, _, _) in enumerate(jobs):
        inventories[src].add(mid)
    delivered_at = [None] * len(jobs)
    skipped_too_short = 0
    sent_bytes = 0
    payload_bytes = 0
    airtime_ms = 0
    transfers = 0
    peak_copies = len(jobs)
    last_tick = None
    observed_at_start = {}
    remaining_radio_ms = {}
    packet_duration_ms = math.ceil(8 * (message_bytes + envelope_bytes) / goodput_kbps)
    for tick, left, right, _kind, duration_ms in selected:
        if tick < 0 or left == right or duration_ms < 0:
            raise ValueError("invalid contact")
        if tick != last_tick:
            if last_tick is not None and tick < last_tick:
                raise ValueError("time moved backwards")
            last_tick = tick
            observed_at_start = {node: ids.copy() for node, ids in inventories.items()}
            remaining_radio_ms = defaultdict(lambda: radio_ms_per_tick)
        contact_time_ms = min(max(0, duration_ms - setup_ms),
                              max(0, remaining_radio_ms[left] - setup_ms),
                              max(0, remaining_radio_ms[right] - setup_ms))
        if not contact_time_ms:
            continue
        initial_a = observed_at_start.get(left, set())
        initial_b = observed_at_start.get(right, set())
        active = sorted(initial_a | initial_b, key=lambda mid: (jobs[mid][2], mid))
        setup_paid = False
        for mid in active:
            src, dst, created, _label = jobs[mid]
            if created > tick or tick >= created + ttl or delivered_at[mid] is not None:
                continue
            # A tick-start holder must still physically possess the payload.
            a_to_b = (mid in initial_a and mid in inventories[left]
                      and right not in holders[mid])
            b_to_a = (mid in initial_b and mid in inventories[right]
                      and left not in holders[mid])
            if a_to_b:
                sender, receiver = left, right
            elif b_to_a:
                sender, receiver = right, left
            else:
                continue
            at_copy_limit = len(holders[mid]) >= copy_limit
            # At copy limit the holder can still hand its copy to the
            # intended recipient, or to a physically scheduled courier,
            # without minting an extra copy.
            if at_copy_limit and copy_limit > 1 and (receiver != dst and _kind not in ("depart", "arrival")):
                continue
            move_existing = copy_limit == 1 or at_copy_limit
            if packet_duration_ms > contact_time_ms:
                skipped_too_short += 1
                continue
            # The connection setup is once per actual encounter with traffic.
            if not setup_paid:
                remaining_radio_ms[left] -= setup_ms
                remaining_radio_ms[right] -= setup_ms
                setup_paid = True
            remaining_radio_ms[left] -= packet_duration_ms
            remaining_radio_ms[right] -= packet_duration_ms
            contact_time_ms -= packet_duration_ms
            sent_bytes += message_bytes + envelope_bytes
            payload_bytes += message_bytes
            airtime_ms += packet_duration_ms
            transfers += 1
            if move_existing:
                holders[mid].remove(sender)
                inventories[sender].remove(mid)
            holders[mid].add(receiver)
            inventories[receiver].add(mid)
            if receiver == dst:
                delivered_at[mid] = tick
            peak_copies = max(peak_copies, sum(len(s) for s in holders))
    oracle = build_temporal_graph(selected)
    groups = defaultdict(list)
    for mid, (src, dst, created, label) in enumerate(jobs):
        best = earliest_delivery(oracle, src, dst, created, ttl)
        delivered = delivered_at[mid]
        # Every actual store-carry-forward transfer must correspond to a
        # chronological edge, so an actual message can never beat the oracle.
        if delivered is not None and (best is None or delivered < best):
            raise AssertionError("bounded transfer bypassed the contact oracle")
        groups[label].append((delivered, best, created))
    outcome = {}
    for label, records in sorted(groups.items()):
        delays = sorted(done - created for done, _, created in records if done is not None)
        reachable = sum(ideal is not None for _, ideal, _ in records)
        outcome[label] = {
            "messages": len(records),
            "oracle_reachable": reachable,
            "delivered": len(delays),
            "oracle_percent": round(100 * reachable / len(records), 5),
            "bounded_percent": round(100 * len(delays) / len(records), 5),
            "median_delay_ticks_delivered": statistics.median(delays) if delays else None,
        }
    return {
        "claim": "synthetic-contact-capacity-not-real-delivery",
        "possible_contacts": len(events),
        "discovered_contacts": len(selected),
        "payload_bytes": payload_bytes,
        "wire_bytes": sent_bytes,
        "airtime_ms_payload": airtime_ms,
        "transfers": transfers,
        "capacity_blocked_attempts": skipped_too_short,
        "peak_total_copies": peak_copies,
        "groups": outcome,
        "individual_delivered_ticks": delivered_at,
    }


def run_matrix(output, *, steps=STEP_COUNT, ttl=TTL):
    rows = []
    for wings in WINGS:
        for seed in SEEDS:
            jobs = sample_messages(wings, steps, seed, 30)
            for couriers in (False, True):
                contacts = contact_events(wings, steps, seed, couriers)
                for scan_filter in (False, True):
                    for message_bytes in (256, 4096):
                        for goodput_kbps in (8, 64):
                            result = simulate(
                                contacts, jobs, ttl=ttl,
                                message_bytes=message_bytes,
                                goodput_kbps=goodput_kbps,
                                scan_filter=scan_filter, seed=seed,
                            )
                            for group, stats in result["groups"].items():
                                rows.append({
                                    "wings": wings, "population": wings * 2000,
                                    "seed": seed, "couriers": couriers,
                                    "scan_filter": scan_filter,
                                    "message_bytes": message_bytes,
                                    "goodput_kbps": goodput_kbps,
                                    "category": group,
                                    "messages": stats["messages"],
                                    "oracle_reachable": stats["oracle_reachable"],
                                    "bounded_delivered": stats["delivered"],
                                    "oracle_percent": stats["oracle_percent"],
                                    "bounded_percent": stats["bounded_percent"],
                                    "median_delivery_ticks": stats["median_delay_ticks_delivered"],
                                    "wire_bytes": result["wire_bytes"],
                                    "transfers": result["transfers"],
                                    "capacity_blocked_attempts": result["capacity_blocked_attempts"],
                                    "claim": result["claim"],
                                })
    output.mkdir(parents=True, exist_ok=True)
    with (output / "throughput-matrix.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    (output / "throughput-matrix.json").write_text(
        json.dumps({"schema": "labo-exp007-capacity-v1", "steps": steps,
                    "ttl": ttl, "claim": "synthetic-contact-capacity-not-real-delivery",
                    "rows": rows}, indent=2) + "\n", encoding="utf-8")
    lines = [
        "# LABO EXP-007 — finite BLE encounter capacity",
        "",
        "Synthetic assumed goodput and contacts, NOT measurements or real ACKs.",
        "A whole message must fit inside ONE encountered session; no resumable chunks.",
        "Sender must have payload before that tick; at most one hop per tick.",
        "Every device gets only 6 seconds of radio time per 60-second tick.",
        "Each contact pays 300 ms setup and 64 bytes framing per message.",
        "Maximum 4 total copies per message; no recipient-signed receipts.",
        "",
        "| Wings | Couriers | Scan | Size (B) | Goodput (kbit/s) | Category | Oracle % | Bounded % |",
        "|---:|---|---|---:|---:|---|---:|---:|",
    ]
    for wings in WINGS:
        for courier in (False, True):
            for scanned in (False, True):
                for size in (256, 4096):
                    for rate in (8, 64):
                        labels = ["random-pair"] + (["adjacent-hubs-control"] if wings > 1 else [])
                        for label in labels:
                            cell = [r for r in rows if
                                    r["wings"] == wings and r["couriers"] == courier and
                                    r["scan_filter"] == scanned and r["message_bytes"] == size and
                                    r["goodput_kbps"] == rate and r["category"] == label]
                            lines.append(
                                f"| {wings} | {courier} | {scanned} | {size} | {rate} | {label} | "
                                f"{statistics.mean(c['oracle_percent'] for c in cell):.3f} | "
                                f"{statistics.mean(c['bounded_percent'] for c in cell):.3f} |")
    lines += ["", "Do not treat the model's delivered field as app-level signed confirmation.", ""]
    (output / "report.md").write_text("\n".join(lines), encoding="utf-8")
    print("EXP007_COMPLETE", len(rows), "rows", len(SEEDS), "seeds", flush=True)
    return rows


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, default=Path("results/exp007"))
    p.add_argument("--steps", type=int, default=STEP_COUNT)
    p.add_argument("--ttl", type=int, default=TTL)
    args = p.parse_args()
    if not (2 <= args.steps <= 1000 and 1 <= args.ttl <= args.steps):
        p.error("2 <= steps <= 1000 and 1 <= ttl <= steps required")
    run_matrix(args.output, steps=args.steps, ttl=args.ttl)


if __name__ == "__main__":
    main()