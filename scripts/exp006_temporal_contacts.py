#!/usr/bin/env python3
"""LABO EXP-006: bounded temporal-path oracle + BLE scanning overlap experiment.

It is deliberately independent of the Rust radio gate and Akula app:
- contact *availability* is an explicit, unmeasured schedule;
- scanning/advertising windows filter potential encounters;
- oracle upper bound uses unlimited copying and zero packet transfer time.

One tick is a hypothetical minute, NOT the EXP-004 abstract tick. No radio
measurement, phone OS guarantee, message storage or W4 recipient receipt.
"""
import argparse
from collections import defaultdict
import csv
from functools import lru_cache
import hashlib
import json
import math
from pathlib import Path
import random
import statistics

RESIDENTS_PER_WING = 2_000
STEP_MS = 60_000


def stable_phase(seed, role, device, period):
    data = f"{seed}:{role}:{device}".encode("ascii")
    h = int.from_bytes(hashlib.blake2b(data, digest_size=8).digest(), "big")
    return h % period


def hears_advertising(start_ms, duration_ms, advertiser, scanner, seed,
                      adv_period_ms, scan_period_ms, scan_window_ms):
    if duration_ms <= 0 or scan_window_ms <= 0:
        return False
    if scan_window_ms >= scan_period_ms:
        return duration_ms >= adv_period_ms
    advert_offset = stable_phase(seed, "adv", advertiser, adv_period_ms)
    scan_offset = stable_phase(seed, "scan", scanner, scan_period_ms)
    first_index = max(0, math.ceil((start_ms - advert_offset) / adv_period_ms))
    first_time = advert_offset + first_index * adv_period_ms
    end_ms = start_ms + duration_ms
    for instant in range(first_time, end_ms, adv_period_ms):
        if (instant - scan_offset) % scan_period_ms < scan_window_ms:
            return True
    return False


def found_via_ble(event, seed, adv_period_ms, scan_period_ms, scan_window_ms):
    t, a, b, _kind, duration_ms = event
    start = t * STEP_MS
    # Either endpoint can advertise to its peer. No collisions modeled.
    return (
        hears_advertising(start, duration_ms, a, b, seed,
                           adv_period_ms, scan_period_ms, scan_window_ms)
        or hears_advertising(start, duration_ms, b, a, seed,
                              adv_period_ms, scan_period_ms, scan_window_ms)
    )


def contact_events(wings, steps, seed, couriers, residents_per_wing=RESIDENTS_PER_WING,
                   local_contacts_per_tick=8, travel_steps=2, departure_period=12):
    """Only explicit local lobby encounters and physically timed courier trips.

    Wing b has a stationary hub device b*n and one roaming courier b*n+1.
    Courier b goes to b+1 along an adjacent-wings road, then returns home.
    Contact with destination hub happens only at arrival after travel_steps.
    """
    if wings < 1 or steps < 1 or residents_per_wing < 3 or travel_steps < 1:
        raise ValueError("invalid campus/time parameters")
    out = []
    for t in range(steps):
        for wing in range(wings):
            hub = wing * residents_per_wing
            draw = random.Random(seed * 9_973 + 23_017 * wing + t * 41_927)
            for _ in range(local_contacts_per_tick):
                resident = hub + 2 + draw.randrange(residents_per_wing - 2)
                out.append((t, hub, resident, "lobby", 1_500))
    if couriers:
        for wing in range(wings - 1):
            home_hub = wing * residents_per_wing
            courier = home_hub + 1
            next_hub = (wing + 1) * residents_per_wing
            for depart in range(0, steps, departure_period):
                # A courier does not appear in another building at the same tick.
                for at, other, kind in (
                    (depart, home_hub, "depart"),
                    (depart + travel_steps, next_hub, "arrival"),
                    (depart + 2 * travel_steps, home_hub, "return"),
                ):
                    if at < steps:
                        out.append((at, courier, other, kind, 3_000))
    out.sort(key=lambda e: (e[0], e[1], e[2], e[3]))
    return out


def build_temporal_graph(events):
    adj = {}
    for tick, a, b, kind, duration in events:
        by_node = adj.setdefault(tick, defaultdict(set))
        by_node[a].add(b)
        by_node[b].add(a)
    return adj


def earliest_delivery(graph, source, target, created, ttl):
    """Unlimited copy oracle. A path may use at most one hop per virtual tick.

    Simultaneous contacts cannot chain instantaneously through many devices.
    """
    if ttl <= 0:
        raise ValueError("positive TTL required")
    if source == target:
        return created
    reachable = {source}
    for tick in range(created, created + ttl):
        day = graph.get(tick, {})
        next_reached = set()
        for node in reachable:
            next_reached.update(day.get(node, ()))
        reachable.update(next_reached)
        if target in reachable:
            return tick
    return None


def sample_messages(wings, steps, seed, per_kind, residents_per_wing=RESIDENTS_PER_WING):
    draw = random.Random(seed ^ 0x51A9BEEF)
    all_nodes = wings * residents_per_wing
    jobs = []
    for _ in range(per_kind):
        src = draw.randrange(all_nodes)
        dst = draw.randrange(all_nodes - 1)
        if dst >= src:
            dst += 1
        created = draw.randrange(max(1, steps // 2))
        jobs.append((src, dst, created, "random-pair"))
    if wings > 1:
        for _ in range(per_kind):
            wing = draw.randrange(wings - 1)
            created = draw.randrange(max(1, steps // 2))
            jobs.append((wing * residents_per_wing,
                         (wing + 1) * residents_per_wing, created,
                         "adjacent-hubs-control"))
    return jobs


def evaluate(events, jobs, ttl, discovery, seed, adv_ms=400,
             scan_period_ms=2000, scan_window_ms=300):
    selected = [e for e in events if not discovery or
                found_via_ble(e, seed, adv_ms, scan_period_ms, scan_window_ms)]
    graph = build_temporal_graph(selected)
    by_kind = defaultdict(list)
    for source, target, created, kind in jobs:
        arrival = earliest_delivery(graph, source, target, created, ttl)
        by_kind[kind].append(None if arrival is None else arrival - created)
    outcomes = {}
    for kind, ages in sorted(by_kind.items()):
        successful = sorted(d for d in ages if d is not None)
        outcomes[kind] = {
            "messages": len(ages),
            "reachable": len(successful),
            "delivery_upper_bound_percent": round(100 * len(successful) / len(ages), 5),
            "median_delay_ticks_among_reachable": (
                statistics.median(successful) if successful else None),
        }
    return {
        "contacts_possible": len(events),
        "contacts_pass_scan": len(selected),
        "groups": outcomes,
    }


def run_matrix(output, seeds=(21021, 21022, 21023),
               wings_options=(1, 10, 100), steps=80, ttl=40, samples_per_kind=50):
    rows = []
    for wing_count in wings_options:
        for seed in seeds:
            jobs = sample_messages(wing_count, steps, seed, samples_per_kind)
            for courier in (False, True):
                contacts = contact_events(wing_count, steps, seed, courier)
                for discovery in (False, True):
                    result = evaluate(contacts, jobs, ttl, discovery, seed)
                    for label, stats in result["groups"].items():
                        rows.append({
                            "wings": wing_count,
                            "population": wing_count * RESIDENTS_PER_WING,
                            "seed": seed,
                            "courier": courier,
                            "scan_filter": discovery,
                            "message_category": label,
                            "messages": stats["messages"],
                            "oracle_reachable": stats["reachable"],
                            "oracle_reachable_percent": stats["delivery_upper_bound_percent"],
                            "median_delay_ticks": stats["median_delay_ticks_among_reachable"],
                            "possible_contacts": result["contacts_possible"],
                            "observed_contacts": result["contacts_pass_scan"],
                            "claim": "synthetic-temporal-upper-bound",
                        })
    output.mkdir(parents=True, exist_ok=True)
    with (output / "contact-matrix.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    (output / "contact-matrix.json").write_text(
        json.dumps({"schema": "labo-exp006-temporal-v1",
                    "claim": "synthetic-temporal-upper-bound",
                    "steps": steps, "ttl_steps": ttl, "seeds": list(seeds),
                    "rows": rows}, indent=2) + "\n", encoding="utf-8")
    lines = [
        "# LABO EXP-006 — temporal reachability and BLE discovery windows",
        "",
        "**All values are synthetic upper bounds, NOT physical delivery measurements.**",
        "A route may carry unlimited instant copies; no message bytes, queues,",
        "radio loss, true acknowledgements, or smartphone OS background limitations.",
        "One tick is hypothetically 60 seconds, with abstract lobby contacts",
        "and explicitly scheduled road couriers. Campus has a linear chain of",
        "buildings; no artificial cross-building link without courier movement.",
        "The adjacent-hubs-control message category intentionally uses stationary",
        "volunteer hubs: it is a topology test, not a population-wide delivery rate.",
        "",
        "| Wings | Couriers | Scanning | Category | Median reachable % over seeds |",
        "|---:|---|---|---|---:|",
    ]
    for wing_count in wings_options:
        for courier in (False, True):
            for scanning in (False, True):
                labels = ["random-pair"] + (["adjacent-hubs-control"] if wing_count > 1 else [])
                for label in labels:
                    vals = [row["oracle_reachable_percent"] for row in rows
                            if row["wings"] == wing_count and row["courier"] == courier
                            and row["scan_filter"] == scanning
                            and row["message_category"] == label]
                    lines.append(f"| {wing_count} | {courier} | {scanning} | {label} | "
                                 f"{statistics.median(vals):.3f}% |")
    lines += [
        "",
        "Interpretation: a missing temporal route is impossible for any protocol",
        "under these assumed encounters; reaching a graph destination does NOT",
        "mean a packet transfer, discovery handshake or recipient W4 confirmation.",
        "Full empirical BLE calibration is separate: EXP-005 measured RSS only.",
        "",
    ]
    (output / "report.md").write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines), flush=True)
    return rows


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, default=Path("results/exp006"))
    p.add_argument("--steps", type=int, default=80)
    p.add_argument("--ttl", type=int, default=40)
    args = p.parse_args()
    if not (1 <= args.ttl <= args.steps <= 2000):
        p.error("1 <= ttl <= steps <= 2000 required")
    run_matrix(args.output, steps=args.steps, ttl=args.ttl)


if __name__ == "__main__":
    main()
