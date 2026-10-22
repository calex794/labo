#!/usr/bin/env python3
"""LABO EXP-010: causal adaptive 1+(1), stale encounters and newcomer bridges.

Every contact, score, copy and delivery is SYNTHETIC, not field smartphone data.
Run equal-K comparisons on identical jobs and observed event streams. One logical
letter can have a moving copy and several stationary direct-recipient backups.
"""
import argparse
import csv
import json
import statistics
from pathlib import Path

from exp008_recipient_routes import CLAIM, run_matrix, simulate


POLICIES = (
    "direct", "spray4", "prophet4", "parallel4",
    "oneplusone2", "oneplusone_predict2", "oneplusone_adaptive2",
    "oneplusone4", "oneplusone_predict4", "oneplusone_adaptive4",
)
COMPARISONS = (
    ("oneplusone_adaptive2", "oneplusone2"),
    ("oneplusone_adaptive2", "oneplusone_predict2"),
    ("oneplusone_adaptive4", "oneplusone4"),
    ("oneplusone_adaptive4", "oneplusone_predict4"),
    ("oneplusone_adaptive4", "prophet4"),
    ("oneplusone_adaptive4", "parallel4"),
)


def meet(t, a, b, length=2500):
    return (t, a, b, "meeting", length)


def manual_cases():
    """Known, synthetic topology motifs; no oracle is passed to the policy.

    Freshness and changing routines are explicitly controlled. These are NOT
    a random sample of human mobility or empirical recipient successes.
    """
    return {
        "no_history_bridge": (
            [meet(0, 0, 1), meet(1, 1, 2000),
             meet(2, 2000, 2001), meet(3, 2001, 4000)], 4000, 0),
        "stale_routine_change": (
            [meet(0, 4, 5), meet(8, 0, 4),
             meet(8, 0, 2001), meet(9, 2001, 5)], 5, 8),
        "fresh_history_carries": (
            [meet(0, 2, 5), meet(1, 0, 2), meet(2, 2, 5)], 5, 1),
        "parked_backup_exact_delivery": (
            [meet(0, 0, 1), meet(1, 0, 2), meet(2, 0, 5)], 5, 0),
        "misleading_first_bridge": (
            [meet(0, 0, 1), meet(1, 0, 2), meet(2, 2, 5)], 5, 0),
        "no_recipient_bridge": (
            [meet(0, 0, 2), meet(1, 2, 5)], 5, 0),
    }


def analyze_manual():
    outcomes = []
    for name, (contacts, recipient, created) in manual_cases().items():
        contacts = sorted(contacts, key=lambda e: (e[0], e[1], e[2], e[3]))
        for policy in POLICIES:
            r = simulate(contacts, [(0, recipient, created, name)],
                         policy=policy, seed=21021, ttl=18,
                         observation_end=20, volunteer=lambda _node: True)
            outcomes.append({
                "case": name,
                "policy": policy,
                "copies_limit": r["k_limit"],
                "recipient_accepted": r["accepted_count"][0],
                "first_delivery_tick": r["delivery_ticks"][0],
                "frozen_backups": r["frozen_backups"],
                "direct_from_backup": r["direct_from_backup"],
                "forecast_runner_handoffs": r["forecast_runner_handoffs"],
                "exploration_runner_handoffs": r["exploration_runner_handoffs"],
                "peak_copies": r["max_copies_seen"],
                "wire_bytes": r["wire_bytes"],
                "claim": CLAIM,
            })
    return outcomes


def run(output, *, wings=(1, 10, 100), seeds=(21021, 21022, 21023),
        steps=80, ttl=40, letters_per_kind=12):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    rows = run_matrix(
        output, wings=wings, seeds=seeds, steps=steps, ttl=ttl,
        letters_per_kind=letters_per_kind, policies=POLICIES,
        scan_modes=(False,), courier_modes=(True,), gateway_modes=(False,))
    categories = sum(1 if wing == 1 else 2 for wing in wings)
    assert len(rows) == len(POLICIES) * len(seeds) * categories
    for row in rows:
        assert row["claim"] == CLAIM
        assert row["max_copies_seen"] <= row["copies_limit"]
        assert row["max_radio_per_device_tick_ms"] <= 6000
        assert row["recipient_accepted"] <= row["oracle_ble_reachable"]
    lookup = {
        (row["wings"], row["seed"], row["category"], row["policy"]): row
        for row in rows
    }
    paired = []
    for wing in wings:
        for seed in seeds:
            for category in ("random-pair",) if wing == 1 else (
                    "random-pair", "adjacent-hubs-control"):
                for adaptive, baseline in COMPARISONS:
                    now = lookup[wing, seed, category, adaptive]
                    previous = lookup[wing, seed, category, baseline]
                    assert now["letters"] == previous["letters"]
                    assert now["copies_limit"] == previous["copies_limit"]
                    assert now["oracle_ble_reachable"] == previous["oracle_ble_reachable"]
                    paired.append({
                        "wings": wing, "seed": seed, "category": category,
                        "policy": adaptive, "baseline": baseline,
                        "copy_budget": now["copies_limit"],
                        "baseline_budget": previous["copies_limit"],
                        "recipient_accepted": now["recipient_accepted"],
                        "baseline_accepted": previous["recipient_accepted"],
                        "delta_percentage_points": round(
                            now["accepted_percent"] - previous["accepted_percent"], 5),
                        "total_scenario_wire_delta_bytes": (
                            now["wire_bytes"] - previous["wire_bytes"]),
                        # NOTE: wire counters repeat on each category row!
                        "claim": CLAIM,
                    })
    assert len(paired) == len(COMPARISONS) * len(seeds) * categories
    with (output / "equal-copy-comparisons.csv").open(
            "w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(paired[0]))
        writer.writeheader()
        writer.writerows(paired)

    manual = analyze_manual()
    with (output / "changing-routines.csv").open(
            "w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(manual[0]))
        writer.writeheader()
        writer.writerows(manual)
    (output / "changing-routines.json").write_text(json.dumps({
        "schema": "labo-exp010-changing-contact-motifs-v1",
        "claim": CLAIM, "cases": len(manual_cases()), "policies": list(POLICIES),
        "rows": manual,
    }, indent=2) + "\n", encoding="utf-8")

    # The older run_matrix report remains valid; append a distinct section
    # rather than rewriting EXP-008's original published report.
    lines = [
        "", "# EXP-010 — adaptive 1+(1): fresh history or bounded bridge search", "",
        "**All results are synthetic, NOT delivery rates on real Bluetooth phones.**",
        "Sampled residents are deliberately sparse, and manual motifs are",
        "purposefully constructed topology controls, not population statistics.",
        "Policy sees only earlier encounters. 'Fresh' means the stored estimate",
        "was updated within 6 ticks (directly or transitively); it is NOT",
        "proof that the recipient was seen. Explore is limited to 2*K handoffs,",
        "only to a previously unused synthetic courier or a new wing.",
        "The old holder parks a direct-only copy; when K is full the runner MOVES.",
        "The 1/10/100 wing simulation retains EXP-009's existing encounters.",
        "Per-category rows repeat scenario-wide byte counters: never add them.",
        "When no history or relay exists, no route is invented.", "",
        "| Case | Algorithm | Accepted | First accepted tick | Forecast hops | Explore hops |",
        "|---|---|---:|---:|---:|---:|",
    ]
    for r in manual:
        if r["policy"] not in ("oneplusone4", "oneplusone_predict4",
                              "oneplusone_adaptive4", "prophet4", "parallel4"):
            continue
        lines.append(
            f"| {r['case']} | {r['policy']} | {r['recipient_accepted']} | "
            f"{r['first_delivery_tick'] if r['first_delivery_tick'] is not None else '-'} | "
            f"{r['forecast_runner_handoffs']} | {r['exploration_runner_handoffs']} |")
    lines += ["", "## Same K4 budget: pilot of 1/10/100 buildings", "",
              "| Wings | Method | Targeted adjacent-hub accepted % (3 seeds) |",
              "|---:|---|---:|"]
    for wing in wings:
        if wing == 1:
            continue
        for method in ("oneplusone4", "oneplusone_predict4",
                       "oneplusone_adaptive4", "prophet4", "parallel4"):
            selected = [r["accepted_percent"] for r in rows if
                        r["wings"] == wing and r["policy"] == method and
                        r["category"] == "adjacent-hubs-control"]
            lines.append(f"| {wing} | {method} | "
                         f"{statistics.fmean(selected):.3f}% |")
    lines += [
        "", "Different conditions can favor different algorithms. In particular,",
        "a random new courier can also lead the sole moving copy into a dead end.",
        "No algorithm can use later contacts to predict without evidence.",
        "Future studies: real timestamped meetings, group changes, privacy-safe",
        "discovery of recipient, durable copy tokens and actual signed receipts.", "",
    ]
    with (output / "report.md").open("a", encoding="utf-8") as stream:
        stream.write("\n".join(lines))
    print("EXP010_COMPLETE", len(rows), "category rows",
          len(paired), "budget-matched comparisons",
          len(manual), "causal manual cases", flush=True)
    return rows, manual


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("results/exp010"))
    parser.add_argument("--wings", type=int, nargs="+", default=[1, 10, 100])
    parser.add_argument("--seeds", type=int, nargs="+", default=[21021, 21022, 21023])
    parser.add_argument("--steps", type=int, default=80)
    parser.add_argument("--ttl", type=int, default=40)
    parser.add_argument("--letters-per-kind", type=int, default=12)
    args = parser.parse_args()
    if (not args.wings or not args.seeds or min(args.wings) < 1
            or max(args.wings) > 100 or not 1 <= args.ttl <= args.steps <= 2000):
        parser.error("require 1<=wings<=100 and 1<=ttl<=steps<=2000")
    run(args.output, wings=tuple(args.wings), seeds=tuple(args.seeds),
        steps=args.steps, ttl=args.ttl, letters_per_kind=args.letters_per_kind)


if __name__ == "__main__":
    main()
