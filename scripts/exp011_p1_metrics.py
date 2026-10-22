#!/usr/bin/env python3
"""EXP-011: fair-ish P1 routing measurements on identical synthetic contacts.

Outputs ONE row per (topology, seed, algorithm). Unlike EXP-008, scenario-wide
bytes and CPU metrics are not repeated for each recipient category. CPU and
tracemalloc are Python process measurements, never phone energy or hardware RAM.
"""
import argparse
import csv
import gc
import hashlib
import json
import math
from pathlib import Path
import statistics
import time
import tracemalloc

from exp006_temporal_contacts import (
    build_temporal_graph, contact_events, earliest_delivery, sample_messages,
)
from exp008_recipient_routes import CLAIM, policy_budget, simulate

POLICIES = ("direct", "spray4", "prophet4", "parallel4",
            "oneplusone_predict4", "oneplusone_adaptive4")
BENCH_SCHEMA = "labo-exp011-p1-metrics-v1"


def percentile95(items):
    """Nearest rank on *successful delivery delays*; never impute failures."""
    return sorted(items)[math.ceil(.95 * len(items)) - 1] if items else None


def delivery_summary(result, jobs, policy):
    if len(result["delivery_ticks"]) != len(jobs):
        raise AssertionError("one result per original message required")
    good = [at - created for at, (_, _, created, _) in
            zip(result["delivery_ticks"], jobs) if at is not None]
    if any(delay < 0 for delay in good):
        raise AssertionError("delivery precedes creation")
    return {
        "letters": len(jobs),
        "accepted": len(good),
        "undelivered": len(jobs) - len(good),
        "delivery_percent": round(100.0 * len(good) / len(jobs), 5) if jobs else 0,
        "median_delay_ticks_accepted_only": statistics.median(good) if good else None,
        "p95_delay_ticks_accepted_only": percentile95(good),
        "wire_bytes_per_accepted": (round(result["wire_bytes"] / len(good), 3)
                                    if good else None),
        "accepted_per_million_wire_bytes": (round(1e6 * len(good) / result["wire_bytes"], 5)
                                             if result["wire_bytes"] else None),
        "copy_budget": policy_budget(policy),
    }


def fingerprint(result):
    """Detect nondeterminism between warming, timed and allocated-memory runs."""
    return (tuple(result["delivery_ticks"]), tuple(result["max_copies_per_message"]),
            result["wire_bytes"], result["airtime_ms"],
            result["peak_predictor_entries"], result["max_node_bytes"])


def benchmark_policy(events, jobs, oracle, policy, *, seed, steps, ttl, repeats=3):
    """Report CPU/wall timings separately from traced allocation measurement."""
    if repeats < 1 or repeats > 10:
        raise ValueError("repeats must be in 1..10")
    kw = dict(policy=policy, seed=seed, ttl=ttl, oracle_ticks=oracle,
              observation_end=steps - 1)
    warmed = simulate(events, jobs, **kw)
    known = fingerprint(warmed)
    cpu_ms, wall_ms = [], []
    for _ in range(repeats):
        # Measure routing+per-policy bookkeeping; contact generation and
        # unlimited-copy oracle were computed once outside the timed section.
        wall_start = time.perf_counter_ns()
        cpu_start = time.process_time_ns()
        result = simulate(events, jobs, **kw)
        cpu_ms.append((time.process_time_ns() - cpu_start) / 1_000_000)
        wall_ms.append((time.perf_counter_ns() - wall_start) / 1_000_000)
        if fingerprint(result) != known:
            raise AssertionError("a repeated scenario changed its result")
    gc.collect()
    tracemalloc.start()
    try:
        mem = simulate(events, jobs, **kw)
        _, allocation_peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    if fingerprint(mem) != known:
        raise AssertionError("allocation instrumentation changed routing result")
    if any(peak > policy_budget(policy) for peak in mem["max_copies_per_message"]):
        raise AssertionError("shared copy budget breached")
    if mem["max_radio_per_device_tick_ms"] > 6000:
        raise AssertionError("per-node per-tick radio airtime breached")
    if mem["claim"] != CLAIM:
        raise AssertionError("synthetic provenance tag missing")
    output = delivery_summary(mem, jobs, policy)
    by_category = mem["groups"]
    for name, prefix in (("random-pair", "random"),
                         ("adjacent-hubs-control", "control")):
        grp = by_category.get(name)
        output[f"{prefix}_letters"] = grp["letters"] if grp else 0
        output[f"{prefix}_accepted"] = grp["recipient_accepted"] if grp else 0
        output[f"{prefix}_oracle_reachable"] = grp["oracle_ble_reachable"] if grp else 0
        output[f"{prefix}_median_delay_ticks"] = grp["median_delivery_ticks"] if grp else None
        output[f"{prefix}_p95_delay_ticks"] = grp["p95_delivery_ticks"] if grp else None
    if output["random_accepted"] + output["control_accepted"] != output["accepted"]:
        raise AssertionError("category totals must partition logical deliveries")
    output.update({
        "transmissions": mem["transmissions"],
        "wire_bytes": mem["wire_bytes"],
        "airtime_ms_model": mem["airtime_ms"],
        "peak_copies_seen": mem["max_copies_seen"],
        "peak_predictor_entries_model": mem["peak_predictor_entries"],
        "max_node_processed_bytes_model": mem["max_node_bytes"],
        "participating_nodes_model": mem["unique_courier_nodes"],
        "max_radio_ms_per_tick_model": mem["max_radio_per_device_tick_ms"],
        "median_cpu_ms_python": round(statistics.median(cpu_ms), 4),
        "median_wall_ms_python": round(statistics.median(wall_ms), 4),
        "tracemalloc_peak_bytes_python": allocation_peak,
        "claim": CLAIM,
    })
    return output


def scenario_checksum(events, jobs):
    # Compact digest identifies one shared input stream for all algorithms.
    digest = hashlib.sha256()
    for label, items in ((b"contacts", events), (b"messages", jobs)):
        digest.update(label + b"\n")
        for item in items:
            digest.update(json.dumps(item, separators=(",", ":")).encode("utf-8"))
            digest.update(b"\n")
    return digest.hexdigest()


def compare_equal_k4(rows, reference="prophet4"):
    """Matched comparison: no unfair direct(K1) vs K4 resource claims."""
    keys = {(r["wings"], r["seed"], r["policy"]): r for r in rows}
    out = []
    for r in rows:
        if r["policy"] == reference or r["copy_budget"] != 4:
            continue
        baseline = keys[(r["wings"], r["seed"], reference)]
        if (r["input_sha256"] != baseline["input_sha256"] or
                r["copy_budget"] != baseline["copy_budget"] or
                r["letters"] != baseline["letters"]):
            raise AssertionError("not identical input and total copy budget")
        out.append({
            "wings": r["wings"], "seed": r["seed"],
            "policy": r["policy"], "reference": reference,
            "equal_copy_budget": 4,
            "delivery_delta": r["accepted"] - baseline["accepted"],
            "random_delta": r["random_accepted"] - baseline["random_accepted"],
            "control_delta": r["control_accepted"] - baseline["control_accepted"],
            "wire_bytes_delta": r["wire_bytes"] - baseline["wire_bytes"],
            "airtime_ms_delta_model": r["airtime_ms_model"] - baseline["airtime_ms_model"],
            "median_cpu_ms_delta_python": round(
                r["median_cpu_ms_python"] - baseline["median_cpu_ms_python"], 4),
            "memory_peak_bytes_delta_python": (
                r["tracemalloc_peak_bytes_python"] - baseline["tracemalloc_peak_bytes_python"]),
            "claim": CLAIM,
        })
    return out


def _write_csv(path, rows):
    if not rows:
        raise ValueError("cannot emit empty experiment")
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def run(output, *, wings=(1, 10, 100), seeds=(21021, 21022, 21023),
        steps=80, ttl=40, letters_per_kind=12, repeats=3, policies=POLICIES):
    if (not wings or not seeds or not policies or
            min(wings) < 1 or max(wings) > 100 or min(seeds) < 0 or
            not 1 <= ttl <= steps <= 2000 or letters_per_kind < 1 or
            not 1 <= repeats <= 10 or len(set(policies)) != len(policies)):
        raise ValueError("invalid experimental matrix")
    for policy in policies:
        policy_budget(policy)  # reject unknown profiles
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    rows = []
    for wing in wings:
        for seed in seeds:
            jobs = sample_messages(wing, steps, seed, letters_per_kind)
            events = contact_events(wing, steps, seed, True)
            graph = build_temporal_graph(events)
            oracle = [earliest_delivery(graph, src, dst, created, ttl)
                      for src, dst, created, _ in jobs]
            digest = scenario_checksum(events, jobs)
            # Change order between scenarios to avoid a fixed warm-cache bias.
            offset = (wing + seed) % len(policies)
            order = policies[offset:] + policies[:offset]
            for policy in order:
                stats = benchmark_policy(events, jobs, oracle, policy, seed=seed,
                                         steps=steps, ttl=ttl, repeats=repeats)
                stats = {"wings": wing, "population": wing * 2000, "seed": seed,
                         "policy": policy, "input_sha256": digest,
                         "contacts": len(events), "oracle_reachable": sum(x is not None for x in oracle),
                         **stats}
                if stats["accepted"] > stats["oracle_reachable"]:
                    raise AssertionError("delivery cannot beat unlimited temporal oracle")
                rows.append(stats)
                print("P1_PROFILE", wing, seed, policy,
                      "delivered", stats["accepted"], "of", stats["letters"],
                      "cpu_ms", stats["median_cpu_ms_python"], flush=True)
    rows.sort(key=lambda r: (r["wings"], r["seed"], r["policy"]))
    paired = compare_equal_k4(rows) if "prophet4" in policies else []
    _write_csv(output / "p1-policy-metrics.csv", rows)
    if paired:
        _write_csv(output / "p1-equal-k4.csv", paired)
    (output / "p1-policy-metrics.json").write_text(json.dumps({
        "schema": BENCH_SCHEMA,
        "claim": CLAIM,
        "units": {
            "median_cpu_ms_python": "Python process time ms, 3 untraced repeats by default",
            "median_wall_ms_python": "wall clock ms, same samples",
            "tracemalloc_peak_bytes_python": "peak traced Python allocations (not RSS)",
            "max_node_processed_bytes_model": "cumulative bytes handled by one node, NOT resident RAM",
            "airtime_ms_model": "hypothetical radio air time, NOT energy joules",
        },
        "rows": rows,
        "paired_k4": paired,
    }, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    lines = [
        "# LABO EXP-011 — unified P1 algorithm metrics", "",
        "**Synthetic simulation only: not performance of Akula, a phone or BLE radio.**",
        "The same timestamped contacts, recipients, virtual time, 64 kbit/s and",
        "one global K4 budget apply to all non-direct profiles. Direct is K1",
        "and a lower-baseline control, NOT an equal-resource competitor.",
        "For each scenario, the temporal oracle and contacts are precomputed",
        "ONCE outside timed runs; one record per policy avoids double counting.",
        "CPU process time and Python traced allocations are performance of this",
        "Python simulation on its GitHub runner, NOT embedded Rust, native BLE,",
        "phone RAM or real battery use. Wall time has environmental noise.",
        "Latency p50/p95 is ONLY among delivered messages; report failures too.",
        "Metric max_node_processed_bytes_model is cumulative handled traffic,",
        "NOT buffer size or memory usage. Radio time is hypothetical, not Joules.",
        "Memory profiling uses a separate tracemalloc execution to avoid biasing",
        "CPU time with allocation instrumentation. Per-run process snapshots",
        "exclude precomputed contacts and the Python interpreter/module imports.", "",
        "| Wings | Policy | Received/letters | Wire bytes | Accepted / 1 MB | "
        "Median CPU ms | Peak traced bytes |",
        "|---:|---|---:|---:|---:|---:|---:|",
    ]
    for r in rows:
        efficiency = r["accepted_per_million_wire_bytes"]
        lines.append(f"| {r['wings']} | {r['policy']} | {r['accepted']}/{r['letters']} | "
                     f"{r['wire_bytes']} | {efficiency if efficiency is not None else '-'} | "
                     f"{r['median_cpu_ms_python']:.3f} | {r['tracemalloc_peak_bytes_python']} |")
    lines.extend(["", "For category-specific success see random_accepted/control_accepted columns.",
                  "p1-equal-k4.csv compares each K4 policy with PRoPHET4 on",
                  "exactly the same scenario. It omits Direct(K1) from equal-K",
                  "comparisons by construction.", "",
                  "Next: independent real encounter traces, repeat on stable hardware,",
                  "signed end-recipient W4 and privacy-safe discovery remain missing.", ""])
    (output / "report.md").write_text("\n".join(lines), encoding="utf-8")
    print("EXP011_COMPLETE", len(rows), "policy runs", len(paired),
          "equal-K4 comparisons", flush=True)
    return rows, paired


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("results/exp011"))
    parser.add_argument("--wings", type=int, nargs="+", default=[1, 10, 100])
    parser.add_argument("--seeds", type=int, nargs="+", default=[21021, 21022, 21023])
    parser.add_argument("--steps", type=int, default=80)
    parser.add_argument("--ttl", type=int, default=40)
    parser.add_argument("--letters-per-kind", type=int, default=12)
    parser.add_argument("--repeats", type=int, default=3)
    args = parser.parse_args()
    run(args.output, wings=tuple(args.wings), seeds=tuple(args.seeds),
        steps=args.steps, ttl=args.ttl, letters_per_kind=args.letters_per_kind,
        repeats=args.repeats)


if __name__ == "__main__":
    main()