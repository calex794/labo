#!/usr/bin/env python3
"""LABO EXP-015: gateway-first vs recipient routing on pinned CC0 contact traces.

MEASURED: anonymous 20-second encounters in two SocioPatterns datasets.
ASSUMED: volunteers, gateway internet access, BLE transfer, mailbox polling,
application acceptance, signed receipts, and radio/Internet byte costs.
This is NOT a tested WOW deployment or a privacy-preserving route protocol.
"""
import argparse
from collections import defaultdict, deque
import csv
import hashlib
import json
import math
from pathlib import Path
import random
import statistics

from exp006_temporal_contacts import build_temporal_graph, earliest_delivery
from exp008_recipient_routes import simulate
from exp011_real_contacts import SAMPLE_SECONDS
from exp012_cross_environment import (
    SOURCES, SEEDS, PROVENANCE, fetch_pinned, parse_pinned_gzip,
    split_chronology, choose_historic_pairs, make_jobs,
)

POLICIES = ("recipient_prophet4", "gateway_direct4",
            "gateway_history_prophet4", "hybrid_parallel4")
DEFAULT_GATEWAY_PCT = (2, 10)
DEFAULT_PICKUP_HOURS = (1, 2)
MESSAGE_WIRE_BYTES = 320  # assumed 256-byte payload + 64-byte wrapper
RETURN_WIRE_BYTES = 48    # accounting placeholder, NOT signed W4
CLAIM = "real-human-encounters-synthetic-gateways-mailbox-and-routing"


def historical_map(train_records):
    """Only pre-holdout undirected encounters; never examine future events."""
    adjacency = defaultdict(set)
    for _, a, b in train_records:
        adjacency[a].add(b)
        adjacency[b].add(a)
    return dict(adjacency)


def choose_gateways(graph, percent, seed):
    """Known hypothetical volunteers chosen WITHOUT reading holdout contacts.

    Percent is of historically observed people, not the population of a city.
    A common shuffled ordering gives nested 2% and 10% groups at the same seed.
    """
    if not (1 <= percent <= 50):
        raise ValueError("gateway percentage must be 1..50")
    participants = sorted(graph)
    if not participants:
        raise ValueError("no historical gateway candidates")
    participants.sort(key=lambda node: hashlib.blake2s(
        f"gw:{seed}:{node}".encode(), digest_size=16).digest())
    count = max(1, round(percent * len(participants) / 100))
    return frozenset(participants[:count])


def nearest_known_gateway(source, gateways, graph):
    """Minimum hops in TRAINING graph, tie-break on previous neighbor degree.

    This is optimistic gateway discovery: it assumes consented gateway beacons
    were learned in advance, without revealing the recipient's DeviceId.
    """
    if source in gateways:
        return source
    queue = deque([source])
    distance = {source: 0}
    while queue:
        node = queue.popleft()
        for neighbor in graph.get(node, ()):
            if neighbor not in distance:
                distance[neighbor] = distance[node] + 1
                queue.append(neighbor)
    reachable = gateways.intersection(distance)
    if not reachable:
        return None
    return min(reachable, key=lambda node:
               (distance[node], -len(graph.get(node, ())), node))


def pickup_after_storage(stored_tick, created_tick, ttl_ticks, period_ticks):
    """One independent periodic mailbox check, not an omniscient pickup.

    The first check occurs a full period after creation. A deposit at the exact
    check tick is seen only at the NEXT check. Expired mail is never accepted.
    """
    if stored_tick is None:
        return None
    if (period_ticks <= 0 or ttl_ticks <= 0 or stored_tick < created_tick):
        raise ValueError("invalid mailbox time")
    delay = (stored_tick - created_tick) // period_ticks + 1
    pickup = created_tick + delay * period_ticks
    return pickup if pickup < created_tick + ttl_ticks else None


def mailbox_outcomes(jobs, direct_ticks, stored_ticks, ttl, period):
    """Keep intermediary STORED separate from final synthetic recipient check."""
    if not (len(jobs) == len(direct_ticks) == len(stored_ticks)):
        raise ValueError("inconsistent output vector lengths")
    final, channels = [], []
    for (_, _, created, _), direct, stored in zip(
            jobs, direct_ticks, stored_ticks):
        if direct is not None and not (created <= direct < created + ttl):
            raise AssertionError("recipient before creation or after expiry")
        mailbox = pickup_after_storage(stored, created, ttl, period)
        if direct is not None and (mailbox is None or direct <= mailbox):
            final.append(direct)
            channels.append("observed_contact_synthetic_accept")
        elif mailbox is not None:
            final.append(mailbox)
            channels.append("assumed_internet_and_mailbox_poll")
        else:
            final.append(None)
            channels.append(None)
    return final, channels


def run_engine(observed, jobs, policy, *, ttl, seed, end, decay,
               oracle, gateways=()):
    result = simulate(
        observed, jobs, policy=policy, ttl=ttl, seed=seed,
        residents_per_wing=100000,
        volunteer=lambda _node: True,
        gateways=tuple(sorted(gateways)),
        gateway_online=bool(gateways),
        mailbox_authorized=bool(gateways),
        mailbox_pickups={},  # do not invent a recipient W4 in route simulation
        observation_end=end, oracle_ticks=oracle,
        forecast_decay=decay, forecast_all_contacts=True,
    )
    if result["claim"] != "synthetic-routing-not-real-delivery":
        raise AssertionError("wrong simulation evidence class")
    if (result["max_copies_seen"] > 4 or
            result["max_radio_per_device_tick_ms"] > 6000 or
            any(v > 1 for v in result["accepted_count"])):
        raise AssertionError("copy/radio/dedup invariants failed")
    return result


def gateway_forecast(observed, jobs, graph, gateways, contact_graph, **engine):
    """PRoPHET4 to ONE historically selected gateway, same global message load.

    All letters, including unknown-gateway and already-at-gateway letters, MUST
    remain in the same simulation. Filtering them out changes contention and
    message indices; a comparison with Parallel4 then becomes misleading.

    Synthetic recipient acceptance here means arrival at a gateway only, not
    final end-user delivery or a signed W4 receipt.
    """
    targets = [nearest_known_gateway(src, gateways, graph)
               for src, _, _, _ in jobs]
    if not jobs:
        raise ValueError("no messages")
    known_ids = [x for event in observed for x in event[1:3]]
    known_ids.extend(x for job in jobs for x in job[:2])
    known_ids.extend(gateways)
    # Nonexistent destination makes a letter with no known gateway inert,
    # while keeping its place in the same global simulator and copy ledger.
    absent_target = max(known_ids, default=0) + 1
    proxy_jobs = [
        (src, target if target is not None and target != src else absent_target,
         created, category)
        for (src, _dest, created, category), target in zip(jobs, targets)
    ]
    oracle = [
        earliest_delivery(contact_graph, src, target, created, engine["ttl"])
        if target is not None and target != src else None
        for (src, _dest, created, _category), target in zip(jobs, targets)
    ]
    result = run_engine(observed, proxy_jobs, "prophet4", oracle=oracle, **engine)
    if len(result["delivery_ticks"]) != len(jobs):
        raise AssertionError("proxy changed the number of messages")
    stored = [
        created if target == src else
        result["delivery_ticks"][i] if target is not None else None
        for i, ((src, _dest, created, _category), target) in
        enumerate(zip(jobs, targets))
    ]
    return stored, result


def pairwise_outcomes(jobs, accepted, baseline, category):
    indices = [i for i, job in enumerate(jobs) if job[3] == category]
    left = [accepted[i] is not None for i in indices]
    right = [baseline[i] is not None for i in indices]
    return {
        "messages": len(indices),
        "both": sum(a and b for a, b in zip(left, right)),
        "only_test": sum(a and not b for a, b in zip(left, right)),
        "only_prophet": sum(b and not a for a, b in zip(left, right)),
        "neither": sum(not a and not b for a, b in zip(left, right)),
    }


def evaluate_sources(datasets, output, *, seeds=SEEDS, fractions=DEFAULT_GATEWAY_PCT,
                     pickup_hours=DEFAULT_PICKUP_HOURS, letters_per_kind=12,
                     ttl_hours=4, half_life_hours=24):
    if not (datasets and seeds and 2 <= letters_per_kind <= 100
            and 1 <= ttl_hours <= 12 and 1 <= half_life_hours <= 240
            and fractions and pickup_hours
            and all(1 <= p <= 50 for p in fractions)
            and all(0 < hour < ttl_hours for hour in pickup_hours)
            and all(0 <= s < 2**32 for s in seeds)):
        raise ValueError("invalid experiment parameters")
    ttl = ttl_hours * 3600 // SAMPLE_SECONDS
    decay = math.exp(-math.log(2) * SAMPLE_SECONDS /
                     (half_life_hours * 3600))
    rows, pairs, nearest_pairs = [], [], []
    source_manifest = {}
    for source, data in datasets.items():
        split = split_chronology(data, ttl, letters_per_kind)
        graph = historical_map(split["train_records"])
        source_manifest[source] = {
            "measured_encounters": data["record_count"],
            "participants": data["participant_count"],
            "source_url": SOURCES[source]["page"],
            "source_blob_sha": SOURCES[source]["blob"],
            "license": SOURCES[source]["license"],
            "training_tick": split["train"],
            "early_tick": split["early"],
            "late_tick": split["late"],
        }
        for seed in seeds:
            sampled_pairs = choose_historic_pairs(split, seed, letters_per_kind)
            pair_hash = hashlib.sha256(repr(sampled_pairs).encode()).hexdigest()
            gateway_sets = {p: choose_gateways(graph, p, seed)
                            for p in fractions}
            for phase in ("early", "late"):
                jobs = make_jobs(sampled_pairs, split[phase])
                end = max(job[2] for job in jobs) + ttl - 1
                if end > split["end"]:
                    raise AssertionError("window exceeds measured trace")
                observed = [e for e in data["events"] if e[0] <= end]
                temporal_graph = build_temporal_graph(observed)
                oracle = [earliest_delivery(temporal_graph, src, dst, created, ttl)
                          for src, dst, created, _ in jobs]
                args = dict(ttl=ttl, seed=seed, end=end, decay=decay)
                baseline = run_engine(observed, jobs, "prophet4",
                                      oracle=oracle, **args)
                for fraction in fractions:
                    gateways = gateway_sets[fraction]
                    direct_gateway = run_engine(
                        observed, jobs, "gateway4", oracle=oracle,
                        gateways=gateways, **args)
                    hybrid = run_engine(
                        observed, jobs, "parallel4", oracle=oracle,
                        gateways=gateways, **args)
                    forecast_stored, forecast = gateway_forecast(
                        observed, jobs, graph, gateways, temporal_graph, **args)
                    for period_hours in pickup_hours:
                        period = period_hours * 3600 // SAMPLE_SECONDS
                        snapshots = {}
                        for label, engine in (
                            ("recipient_prophet4", baseline),
                            ("gateway_direct4", direct_gateway),
                            ("hybrid_parallel4", hybrid),
                            ("gateway_history_prophet4", forecast)):
                            if label == "gateway_history_prophet4":
                                stores = forecast_stored
                                direct = [None] * len(jobs)
                            elif label == "recipient_prophet4":
                                stores = [None] * len(jobs)
                                direct = engine["delivery_ticks"]
                            else:
                                stores = list(engine["mailbox_ticks"])
                                # Already-online sender needs no BLE hop to its
                                # own consented gateway: normalize source case.
                                stores = [created if src in gateways and
                                          (at is None or created < at) else at
                                          for (src, _, created, _), at in zip(jobs, stores)]
                                direct = engine["delivery_ticks"]
                            accepted, channels = mailbox_outcomes(
                                jobs, direct, stores, ttl, period)
                            snapshots[label] = accepted
                            for category in sorted({job[3] for job in jobs}):
                                indices = [i for i, job in enumerate(jobs)
                                           if job[3] == category]
                                by_contact = sum(channels[i] ==
                                                 "observed_contact_synthetic_accept"
                                                 for i in indices)
                                by_mailbox = sum(channels[i] ==
                                                 "assumed_internet_and_mailbox_poll"
                                                 for i in indices)
                                stored_count = sum(stores[i] is not None for i in indices)
                                tested_engine = engine or {}
                                all_stored = sum(at is not None for at in stores)
                                all_mailbox = sum(ch == "assumed_internet_and_mailbox_poll"
                                                  for ch in channels)
                                # Hypothetical wire accounting: one upload per
                                # stored letter and one download + return marker
                                # per mailbox acceptance. Not measured LTE/QUIC.
                                internet_bytes = (
                                    MESSAGE_WIRE_BYTES * all_stored +
                                    (MESSAGE_WIRE_BYTES + RETURN_WIRE_BYTES) *
                                    all_mailbox)
                                rows.append({
                                    "source": source, "phase": phase, "seed": seed,
                                    "historical_gateway_percent": fraction,
                                    "known_gateway_count": len(gateways),
                                    "pickup_hours": period_hours,
                                    "policy": label, "copy_cap": 4,
                                    "category": category, "messages": len(indices),
                                    "accepted": by_contact + by_mailbox,
                                    "accepted_contact": by_contact,
                                    "accepted_mailbox": by_mailbox,
                                    "gateway_stored": stored_count,
                                    "ble_oracle_reachable": sum(
                                        oracle[i] is not None for i in indices),
                                    "ble_data_bytes_all_categories":
                                        tested_engine.get("data_bytes", 0),
                                    "model_control_bytes_all_categories":
                                        tested_engine.get("receipt_bytes", 0),
                                    "assumed_internet_bytes_all_categories": internet_bytes,
                                    "max_copies_seen": tested_engine.get("max_copies_seen", 1),
                                    "max_airtime_ms_per_node_tick":
                                        tested_engine.get("max_radio_per_device_tick_ms", 0),
                                    "pair_set_sha256": pair_hash,
                                    "claim": CLAIM,
                                })
                        for category in sorted({job[3] for job in jobs}):
                            for tested in ("gateway_direct4",
                                           "gateway_history_prophet4",
                                           "hybrid_parallel4"):
                                pairs.append({
                                    "source": source, "phase": phase, "seed": seed,
                                    "gateway_percent": fraction,
                                    "pickup_hours": period_hours,
                                    "category": category, "policy": tested,
                                    "against": "recipient_prophet4",
                                    **pairwise_outcomes(
                                        jobs, snapshots[tested],
                                        snapshots["recipient_prophet4"], category),
                                    "pair_set_sha256": pair_hash,
                                })
                            # EXP-017: paired comparison against the SAME
                            # nearest historical gateway algorithm, not just
                            # against destination PRoPHET. Cohorts and exact
                            # message indices remain identical in each cell.
                            for tested in ("gateway_direct4", "hybrid_parallel4"):
                                comparison = pairwise_outcomes(
                                    jobs, snapshots[tested],
                                    snapshots["gateway_history_prophet4"], category)
                                nearest_pairs.append({
                                    "source": source, "phase": phase, "seed": seed,
                                    "gateway_percent": fraction,
                                    "pickup_hours": period_hours,
                                    "category": category, "policy": tested,
                                    "against": "gateway_history_prophet4",
                                    "messages": comparison["messages"],
                                    "both": comparison["both"],
                                    "only_test": comparison["only_test"],
                                    "only_nearest": comparison["only_prophet"],
                                    "neither": comparison["neither"],
                                    "pair_set_sha256": pair_hash,
                                })
                    print("EXP015_CELL", source, phase, "seed", seed,
                          "gateways", fraction, len(gateways), flush=True)
    if not rows or not pairs or not nearest_pairs:
        raise AssertionError("empty experiment")
    output.mkdir(parents=True, exist_ok=True)
    for filename, dataset in (
        ("gateway-routing.csv", rows), ("paired-gateway-deltas.csv", pairs),
        ("paired-nearest-deltas.csv", nearest_pairs)):
        with (output / filename).open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(dataset[0]))
            writer.writeheader()
            writer.writerows(dataset)
    record = {
        "schema": "labo-exp015-gateway-comparison-v1", "claim": CLAIM,
        "measured": "only original face-to-face 20-second contacts",
        "assumed": [
            "gateway opt-in and always-online Internet availability",
            "known gateway invitations from historical roster",
            "BLE goodput 64 kbit/s and packet transfers",
            "mailbox availability and periodic recipient pickup",
            "application acceptance and simulated receipts (not WOW W4)",
        ],
        "parameters": {
            "sources": list(datasets), "seeds": list(seeds),
            "gateways_percent": list(fractions),
            "pickup_hours": list(pickup_hours),
            "ttl_hours": ttl_hours, "letters_per_kind": letters_per_kind,
            "copy_cap": 4, "payload_bytes": MESSAGE_WIRE_BYTES,
            "forecast_half_life_hours": half_life_hours,
        },
        "sources": source_manifest, "rows": rows, "paired": pairs,
        "paired_to_nearest": nearest_pairs,
    }
    (output / "gateway-comparison.json").write_text(
        json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    # Summarize by independent source; repeated category rows duplicate the
    # same full-run bytes and must not be added twice.
    report = [
        "# LABO EXP-015 — gateway-first vs recipient search on measured contacts",
        "",
        "**Measured:** two CC0 logs of human face-to-face encounters.",
        "**Hypothetical:** gateways, consent, Internet reachability, BLE radio,",
        "mailbox checks, real recipient acceptance, and all W4 security.",
        "No live network, real authenticated W4 or phone battery measurement.",
        "",
        "All methods have K=4 and identical messages and observed contacts.",
        "Gateway-first uses ONLY the historical contact graph to select its",
        "single nearest known public gateway; PRoPHET4 forwards toward that",
        "gateway (NOT toward the private recipient). Gateway-direct waits for",
        "a gateway contact. Hybrid Parallel4 retains recipient and gateway",
        "lanes under ONE common K4. A gateway deposit is NOT delivery.",
        "",
        "| Source | Gateway % | Pickup hours | Policy | Accepted / total | Contact | Mailbox |",
        "|---|---:|---:|---|---:|---:|---:|",
    ]
    for source in sorted(datasets):
        for p in fractions:
            for hours in pickup_hours:
                for policy in POLICIES:
                    sel = [r for r in rows if (r["source"], r["historical_gateway_percent"],
                           r["pickup_hours"], r["policy"]) == (source,p,hours,policy)]
                    delivered = sum(r["accepted"] for r in sel)
                    total = sum(r["messages"] for r in sel)
                    report.append(f"| {source} | {p} | {hours} | {policy} | "
                                  f"{delivered}/{total} ({delivered/total*100:.1f}%) | "
                                  f"{sum(r['accepted_contact'] for r in sel)} | "
                                  f"{sum(r['accepted_mailbox'] for r in sel)} |")
    report.extend([
        "",
        "**Accounting:** run-wide radio bytes repeat on each recipient cohort",
        "and pickup schedule; do NOT sum across rows without deduplication.",
        "Gateway ingress and mailbox return bytes are stipulated, not measured.",
        "A proxy-target simulation produces simulated custody traffic; it",
        "must NOT be interpreted as a recipient-signed W4.",
        "",
        "**Interpretation:** the gateway directory, consent, always-on Internet,",
        "and periodic mailbox checks are assumed. Historic proximity is not",
        "proof of a real BLE link; this cannot validate W3 v3 address privacy.",
        "A user at a gateway is normalized as an immediate mailbox deposit.",
        "The 1/2-hour pickup scenarios are evaluated post hoc from deposits",
        "without feedback into route decisions; source may keep sending",
        "until a separately verified recipient receipt arrives.",
        "Pairwise wins refer to the very SAME letters, but shared contacts",
        "make them descriptive, not population confidence intervals.",
        "",
    ])
    (output / "report.md").write_text("\n".join(report), encoding="utf-8")
    print("EXP015_COMPLETE", len(rows), "rows", len(pairs), "pairs", flush=True)
    return record


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--cache", type=Path, default=Path("results/exp012-source-cache"))
    ap.add_argument("--output", type=Path, default=Path("results/exp015"))
    ap.add_argument("--download", action="store_true")
    ap.add_argument("--seeds", type=int, nargs="+", default=list(SEEDS))
    ap.add_argument("--gateway-percent", type=int, nargs="+",
                    default=list(DEFAULT_GATEWAY_PCT))
    ap.add_argument("--pickup-hours", type=int, nargs="+",
                    default=list(DEFAULT_PICKUP_HOURS))
    ap.add_argument("--letters-per-kind", type=int, default=12)
    ap.add_argument("--ttl-hours", type=int, default=4)
    args = ap.parse_args()
    datasets = {name: parse_pinned_gzip(
        fetch_pinned(name, args.cache, args.download)) for name in SOURCES}
    evaluate_sources(
        datasets, args.output, seeds=tuple(args.seeds),
        fractions=tuple(args.gateway_percent),
        pickup_hours=tuple(args.pickup_hours),
        letters_per_kind=args.letters_per_kind, ttl_hours=args.ttl_hours)


if __name__ == "__main__":
    main()
