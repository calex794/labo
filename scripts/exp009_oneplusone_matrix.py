#!/usr/bin/env python3
"""LABO EXP-009: compare parked-direct-only backups against moving copies.

All movements, contacts, copy ceilings, bytes and acknowledgements are
synthetic. The previous 11-algorithm EXP-008 default matrix is unaffected.
"""
import argparse
import csv
from pathlib import Path

from exp008_recipient_routes import CLAIM, run_matrix, simulate

POLICIES = (
    "random4", "spray4", "prophet4", "parallel4",
    "oneplusone2", "oneplusone4",
)
PREDICTIVE_POLICIES = ("oneplusone_predict2", "oneplusone_predict4")


def synthetic_diagnostics(policies=POLICIES, include_predictive=False):
    def meet(t, a, b):
        return (t, a, b, "meeting", 2500)
    traces = {
        "runner_finds_recipient": (
            [meet(0, 0, 1), meet(1, 1, 2), meet(2, 2, 3)], 3),
        "recipient_visits_intermediate_backup": (
            [meet(0, 0, 1), meet(1, 1, 2), meet(2, 1, 3)], 3),
        "stalled_runner_could_use_second_candidate": (
            [meet(0, 0, 1), meet(1, 1, 4), meet(2, 4, 5),
             meet(3, 0, 2), meet(4, 2, 3)], 3),
        "sender_backup_meets_recipient": (
            [meet(0, 0, 1), meet(3, 0, 3)], 3),
        "never_meets_recipient": (
            [meet(0, 0, 1), meet(1, 1, 2)], 3),
    }
    if include_predictive:
        traces.update({
            "known_bridge_vs_first_bystander": (
                [meet(0, 3, 5), meet(1, 0, 2), meet(1, 0, 3), meet(2, 3, 5)], 5, 1),
            "changed_habits_favor_parallel": (
                [meet(0, 1, 5), meet(1, 0, 1), meet(1, 0, 2), meet(2, 2, 5)], 5, 1),
        })
    rows = []
    for name, case in traces.items():
        events, dest = case[:2]
        created = case[2] if len(case) == 3 else 0
        events.sort(key=lambda e: (e[0], e[1], e[2], e[3]))
        for policy in policies:
            r = simulate(events, [(0, dest, created, "manual")],
                         policy=policy, volunteer=lambda _node: True,
                         observation_end=6, ttl=7, seed=21021)
            rows.append({
                "trace": name, "policy": policy,
                "first_received_tick": r["delivery_ticks"][0],
                "seen_once": r["accepted_count"][0],
                "peak_copies": r["max_copies_seen"],
                "copy_limit": r["k_limit"],
                "wire_bytes": r["wire_bytes"],
                "frozen_backups": r["frozen_backups"],
                "runner_moves_at_limit": r["rolling_runner_handoffs"],
                "received_from_backup": r["direct_from_backup"],
                "claim": CLAIM,
            })
    return rows


def run(output, wings=(1, 10, 100), seeds=(21021, 21022, 21023),
        steps=80, ttl=40, letters_per_kind=12, include_predictive=False):
    output.mkdir(parents=True, exist_ok=True)
    policies = POLICIES + PREDICTIVE_POLICIES if include_predictive else POLICIES
    results = run_matrix(output, wings=wings, seeds=seeds,
                         steps=steps, ttl=ttl, letters_per_kind=letters_per_kind,
                         policies=policies, scan_modes=(False,),
                         courier_modes=(True,), gateway_modes=(False,))
    expected_categories = sum(1 if wing == 1 else 2 for wing in wings)
    assert len(results) == len(seeds) * expected_categories * len(policies)
    for row in results:
        if row["claim"] != CLAIM or row["max_copies_seen"] > row["copies_limit"]:
            raise AssertionError("invalid routing or copy budget")
        if row["max_radio_per_device_tick_ms"] > 6000:
            raise AssertionError("radio budget exceeded")
        if row["category"] == "adjacent-hubs-control" and row["recipient_accepted"] > row["oracle_ble_reachable"]:
            raise AssertionError("unexpected delivery beyond BLE oracle")
    if include_predictive:
        by_key = {(r["wings"], r["seed"], r["category"], r["policy"]): r
                  for r in results}
        compared = (
            ("oneplusone_predict2", "oneplusone2"),
            ("oneplusone_predict4", "oneplusone4"),
            ("oneplusone_predict4", "prophet4"),
            ("oneplusone_predict4", "parallel4"),
        )
        paired = []
        for (wing, seed, category, mode), now in by_key.items():
            for improved, baseline in compared:
                if mode != improved:
                    continue
                old = by_key[(wing, seed, category, baseline)]
                assert now["letters"] == old["letters"]
                assert now["copies_limit"] == old["copies_limit"]
                assert now["oracle_ble_reachable"] == old["oracle_ble_reachable"]
                paired.append({
                    "wings": wing, "seed": seed, "category": category,
                    "policy": improved, "baseline": baseline,
                    "equal_copy_budget": now["copies_limit"],
                    "recipient_accepted": now["recipient_accepted"],
                    "baseline_accepted": old["recipient_accepted"],
                    "delta_percentage_points": round(
                        now["accepted_percent"] - old["accepted_percent"], 5),
                    # This is total wire use across *all* letters in the run.
                    # The value appears twice when there are two categories.
                    "total_scenario_wire_delta": now["wire_bytes"] - old["wire_bytes"],
                    "claim": CLAIM,
                })
        with (output / "same-budget-deltas.csv").open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(paired[0]))
            writer.writeheader()
            writer.writerows(paired)
        expected_pairs = len(seeds) * expected_categories * len(compared)
        assert len(paired) == expected_pairs
    diagnostics = synthetic_diagnostics(policies=policies,
                                        include_predictive=include_predictive)
    with (output / "handcrafted-cases.csv").open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(diagnostics[0]))
        writer.writeheader()
        writer.writerows(diagnostics)
    lines = [
        "", "## Handcrafted causal encounters (no real people)", "",
        "The 1+(1) moving copy can win when PRoPHET has no history; a parked",
        "holder can also directly meet the destination after the runner leaves.",
        "It can lose when the runner takes a wrong branch and a parked holder",
        "later meets another *relay* rather than the actual recipient.",
        "This is an intentional comparison, not a guarantee of superiority.", "",
        "| Trace | Strategy | First accepted tick | Peak copies | Parked backups |",
        "|---|---|---:|---:|---:|",
    ]
    for row in diagnostics:
        received = row["first_received_tick"]
        lines.append(f"| {row['trace']} | {row['policy']} | "
                     f"{received if received is not None else '-'} | "
                     f"{row['peak_copies']} | {row['frozen_backups']} |")
    with (output / "report.md").open("a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print("EXP009_COMPLETE", len(results), "matrix rows", len(diagnostics),
          "manual trace rows", flush=True)
    return results, diagnostics


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("results/exp009"))
    parser.add_argument("--wings", type=int, nargs="+", default=[1, 10, 100])
    parser.add_argument("--seeds", type=int, nargs="+", default=[21021, 21022, 21023])
    parser.add_argument("--steps", type=int, default=80)
    parser.add_argument("--ttl", type=int, default=40)
    parser.add_argument("--letters-per-kind", type=int, default=12)
    args = parser.parse_args()
    if any(w < 1 or w > 100 for w in args.wings):
        parser.error("wings must be 1..100")
    run(args.output, wings=tuple(args.wings), seeds=tuple(args.seeds),
        steps=args.steps, ttl=args.ttl, letters_per_kind=args.letters_per_kind)


if __name__ == "__main__":
    main()
