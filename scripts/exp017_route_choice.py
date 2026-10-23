#!/usr/bin/env python3
"""EXP-017: decision analysis of EXP-015 measured contact trace simulations.

Inputs are EXP-015 derived CSV (not original participant-level CC0 contacts).
No real gateways, radio measurements, Wi-Fi, mailbox service or signed W4.
The same four K4 policies and exact messages are compared; copy count is a
MAXIMUM not an assertion that algorithms used equal airtime or copies.
"""
import argparse
from collections import defaultdict
import csv
import json
from pathlib import Path

POLICIES = (
    "recipient_prophet4", "gateway_history_prophet4",
    "gateway_direct4", "hybrid_parallel4",
)
PAIR_POLICIES = ("gateway_direct4", "hybrid_parallel4")
KEY_FIELDS = ("source", "phase", "seed", "historical_gateway_percent",
              "pickup_hours")
METRIC_FIELDS = ("ble_data_bytes_all_categories",
                 "model_control_bytes_all_categories",
                 "assumed_internet_bytes_all_categories")
CLAIM = "real-human-encounters-with-synthetic-gateway-policy-decision"


def read_csv(path):
    with path.open(newline="", encoding="utf-8") as stream:
        return list(csv.DictReader(stream))


def analyze(rows, nearest_pairs, manifest=None):
    """Strictly separate per-category acceptance from whole-run byte totals.

    EXP-015 emits TWO cohort rows with identical cost fields for each actual
    simulation. Counting those costs twice corrupts bytes per accepted letter.
    The paired-nearest ledger resolves WHICH exact same letters succeeded:
    a larger marginal total does not imply a strict superset.
    """
    if not rows or not nearest_pairs:
        raise ValueError("missing EXP-015 evidence")
    row_index = {}
    scenarios = defaultdict(list)
    for row in rows:
        if row["policy"] not in POLICIES or int(row["copy_cap"]) != 4:
            raise ValueError("unknown policy or unequal K4 capacity")
        if row.get("claim") != (
            "real-human-encounters-synthetic-gateways-mailbox-and-routing"
        ):
            raise ValueError("incorrect original evidence class")
        if int(row["max_copies_seen"]) > 4 or (
            int(row["max_airtime_ms_per_node_tick"]) > 6000
        ):
            raise ValueError("EXP-015 cap exceeded")
        msgs, accepted = int(row["messages"]), int(row["accepted"])
        if msgs <= 0 or not 0 <= accepted <= msgs:
            raise ValueError("invalid message counts")
        if accepted != int(row["accepted_contact"]) + int(row["accepted_mailbox"]):
            raise ValueError("deposits confused with recipient pickups")
        scenario = tuple(row[name] for name in KEY_FIELDS) + (row["policy"],)
        full_key = scenario + (row["category"],)
        if full_key in row_index:
            raise ValueError("duplicate source/phase/seed/policy/cohort")
        row_index[full_key] = row
        scenarios[scenario].append(row)

    reduced = {}
    base_scenarios = set()
    for scenario, cohort in scenarios.items():
        if len(cohort) != 2 or len({r["category"] for r in cohort}) != 2:
            raise ValueError("expected two distinct recipient cohorts")
        for metric in METRIC_FIELDS:
            if len({r[metric] for r in cohort}) != 1:
                raise ValueError("run-wide bytes must be identical in cohorts")
            if int(cohort[0][metric]) < 0:
                raise ValueError("negative modeled bytes")
        if len({r["pair_set_sha256"] for r in cohort}) != 1:
            raise ValueError("different letters across cohorts")
        reduced[scenario] = {
            "accepted": sum(int(r["accepted"]) for r in cohort),
            "messages": sum(int(r["messages"]) for r in cohort),
            "by_contact": sum(int(r["accepted_contact"]) for r in cohort),
            "by_mailbox": sum(int(r["accepted_mailbox"]) for r in cohort),
            "stored": sum(int(r["gateway_stored"]) for r in cohort),
            "radio_bytes": int(cohort[0][METRIC_FIELDS[0]]),
            "control_bytes": int(cohort[0][METRIC_FIELDS[1]]),
            "internet_bytes": int(cohort[0][METRIC_FIELDS[2]]),
            "max_copies_seen": max(int(r["max_copies_seen"]) for r in cohort),
            "pair_sha": cohort[0]["pair_set_sha256"],
        }
        base_scenarios.add(scenario[:-1])

    if len(reduced) != len(base_scenarios) * len(POLICIES):
        raise ValueError("missing policies for paired scenario")
    for base in base_scenarios:
        if {k[-1] for k in reduced if k[:-1] == base} != set(POLICIES):
            raise ValueError("not all four strategies were run")
        if len({reduced[base + (p,)]["pair_sha"] for p in POLICIES}) != 1:
            raise ValueError("different synthetic letters between strategies")
        if len({reduced[base + (p,)]["messages"] for p in POLICIES}) != 1:
            raise ValueError("different message population across strategies")

    pair_index = {}
    for row in nearest_pairs:
        if row["policy"] not in PAIR_POLICIES or row["against"] != (
            "gateway_history_prophet4"
        ):
            raise ValueError("wrong nearest-gateway comparator")
        orig = (
            row["source"], row["phase"], row["seed"],
            row["gateway_percent"], row["pickup_hours"],
        )
        pk = orig + (row["policy"], row["category"])
        if pk in pair_index:
            raise ValueError("duplicate paired letter comparison")
        pair_index[pk] = row
        rtest = row_index.get(orig + (row["policy"], row["category"]))
        rnear = row_index.get(orig + ("gateway_history_prophet4", row["category"]))
        if rtest is None or rnear is None:
            raise ValueError("missing corresponding cohort")
        n = int(row["messages"])
        fields = ("both", "only_test", "only_nearest", "neither")
        if any(int(row[x]) < 0 for x in fields):
            raise ValueError("invalid negative paired values")
        if n != sum(int(row[x]) for x in fields):
            raise ValueError("paired population does not partition")
        if n != int(rtest["messages"]) or n != int(rnear["messages"]):
            raise ValueError("comparing dissimilar populations")
        if int(row["both"]) + int(row["only_test"]) != int(rtest["accepted"]):
            raise ValueError("test wins do not match actual acceptance")
        if int(row["both"]) + int(row["only_nearest"]) != int(rnear["accepted"]):
            raise ValueError("nearest wins do not match actual acceptance")
        if not (rtest["pair_set_sha256"] == rnear["pair_set_sha256"] ==
                row["pair_set_sha256"]):
            raise ValueError("paired experiments use different letters")

    if len(pair_index) != len(row_index) // len(POLICIES) * len(PAIR_POLICIES):
        raise ValueError("missing nearest-gateway paired comparison")

    summed = defaultdict(lambda: defaultdict(int))
    scenario_results = defaultdict(list)
    for scenario, data in reduced.items():
        source, phase, seed, pct, pickup, policy = scenario
        summary_key = (source, int(pct), int(pickup), policy)
        for field in ("accepted", "messages", "by_contact", "by_mailbox",
                      "stored", "radio_bytes", "control_bytes", "internet_bytes"):
            summed[summary_key][field] += data[field]
        scenario_results[summary_key].append(data["accepted"])
    aggregated = {}
    for key in sorted(summed):
        metrics = dict(summed[key])
        metrics["total_modeled_bytes"] = sum(
            metrics[x] for x in ("radio_bytes", "control_bytes", "internet_bytes")
        )
        metrics["modeled_bytes_per_accept"] = (
            round(metrics["total_modeled_bytes"] / metrics["accepted"], 2)
            if metrics["accepted"] else None
        )
        metrics["scenario_wins"] = len(scenario_results[key])
        aggregated[key] = metrics

    pair_summary = defaultdict(lambda: defaultdict(int))
    for pk, row in pair_index.items():
        source, phase, seed, pct, pickup, policy, category = pk
        key = (source, int(pct), int(pickup), policy)
        for field in ("messages", "both", "only_test", "only_nearest", "neither"):
            pair_summary[key][field] += int(row[field])

    decisions = []
    conditions = sorted({k[:-1] for k in aggregated})
    for condition in conditions:
        per_policy = {p: aggregated[condition+(p,)] for p in POLICIES}
        ranked = sorted(POLICIES, key=lambda p: (
            -per_policy[p]["accepted"],
            per_policy[p]["total_modeled_bytes"], p,
        ))
        decisions.append({
            "source": condition[0], "gateway_percent": condition[1],
            "pickup_hours": condition[2], "messages": per_policy[POLICIES[0]]["messages"],
            "max_delivery_policy": ranked[0],
            "accepted_by_policy": {p: per_policy[p]["accepted"] for p in POLICIES},
            "extra_hybrid_over_direct": (
                per_policy["hybrid_parallel4"]["accepted"] -
                per_policy["gateway_direct4"]["accepted"]
            ),
            "extra_direct_over_nearest": (
                per_policy["gateway_direct4"]["accepted"] -
                per_policy["gateway_history_prophet4"]["accepted"]
            ),
            "cost_hybrid_minus_direct": (
                per_policy["hybrid_parallel4"]["total_modeled_bytes"] -
                per_policy["gateway_direct4"]["total_modeled_bytes"]
            ),
            "exact_nearest_pairs": {
                p: dict(pair_summary[condition + (p,)]) for p in PAIR_POLICIES
            },
        })

    if manifest is not None:
        sources = manifest.get("sources", {})
        if set(sources) != {key[0] for key in conditions}:
            raise ValueError("source metadata does not match runs")
        if not all(s.get("license") == "CC0-1.0" and s.get("source_blob_sha")
                   for s in sources.values()):
            raise ValueError("pinned CC0 source provenance is missing")
    return {
        "schema": "labo-exp017-gateway-decision-v1",
        "claim": CLAIM,
        "sources": manifest["sources"] if manifest else None,
        "conditions": decisions,
        "aggregates": [
            {"source": s, "gateway_percent": p, "pickup_hours": h,
             "policy": policy, **metrics}
            for (s, p, h, policy), metrics in aggregated.items()
        ],
        "max_copy_cap": 4,
        "notes": [
            "Real observations: only anonymous contact occurrence/time; all routes synthetic.",
            "Nearest means minimum hops in a training-only contact graph, not geographic proximity.",
            "K=4 is a common maximum; actual radio utilization differs across policies.",
            "Whole-run byte fields appear twice across EXP015 recipient cohorts and are counted once.",
            "Accepted means synthetic recipient pickup/contact before TTL, never signed recipient W4.",
            "Reused contacts within phases/seeds prevent independent-population inference.",
            "The one-gateway predictor uses a historical graph unavailable to a privacy-first deployment without authorized discovery.",
        ],
    }


def render(result):
    lookup = {
        (r["source"], r["gateway_percent"], r["pickup_hours"], r["policy"]): r
        for r in result["aggregates"]
    }
    lines = [
        "# LABO EXP-017 — nearest known gateway vs PRoPHET vs Parallel4",
        "",
        "**Evidence:** EXP-015 derived from two independently pinned SocioPatterns",
        "CC0 face-to-face contact traces (SFHH 2009; InVS 2015), 20-second ticks.",
        "**Assumptions:** opt-in gateways, always-online Internet, BLE goodput,",
        "periodic mailbox checks, model radio/control byte costs, end acceptance.",
        "**Not measured:** live Bluetooth, Internet quality, signing W4, power, or",
        "actual authorized custodian availability. All policies cap at K=4.",
        "",
        "Nearest gateway is minimum historical TRAINING-GRAPH hop distance, not",
        "nearest GPS/radio device; proxy PRoPHET4 chases exactly one chosen",
        "gateway. Direct-gateway waits for *any* eligible encountered gateway;",
        "Parallel4 shares a common copy cap across independent lanes.",
        "",
        "## Delivery comparison (same letters, bounded K4)",
        "",
        "| Source | Gateways | Pickup | PRoPHET recipient | Nearest gateway | Any gateway | Parallel4 |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for c in result["conditions"]:
        d = c["accepted_by_policy"]
        lines.append(
            f"| {c['source']} | {c['gateway_percent']}% | {c['pickup_hours']} h "
            f"| {d['recipient_prophet4']}/{c['messages']} "
            f"| {d['gateway_history_prophet4']}/{c['messages']} "
            f"| {d['gateway_direct4']}/{c['messages']} "
            f"| {d['hybrid_parallel4']}/{c['messages']} |"
        )
    lines += [
        "",
        "## Model traffic and per-accepted-envelope cost",
        "",
        "The following costs count BLE data + model control bytes + *assumed*",
        "Internet upload/download **once per full simulation**, not once per",
        "recipient cohort. Model control traffic does not represent real W4.",
        "",
        "| Source | Gateways | Pickup | Route | Accepted | Total modeled bytes | Bytes/accepted |",
        "|---|---:|---:|---|---:|---:|---:|",
    ]
    for a in result["aggregates"]:
        cost = a["modeled_bytes_per_accept"]
        lines.append(
            f"| {a['source']} | {a['gateway_percent']}% | {a['pickup_hours']} h "
            f"| {a['policy']} | {a['accepted']} | {a['total_modeled_bytes']} "
            f"| {cost if cost is not None else 'n/a'} |"
        )
    lines += [
        "",
        "## Paired outcomes against *nearest gateway*",
        "",
        "These counts refer to EXACTLY the same synthetic letters; an increased",
        "total can still conceal letters lost by the new strategy.",
        "",
        "| Source | Gateways | Pickup | Comparator | Both | Only comparator | Only nearest | Neither |",
        "|---|---:|---:|---|---:|---:|---:|---:|",
    ]
    for c in result["conditions"]:
        for policy, exact in c["exact_nearest_pairs"].items():
            lines.append(
                f"| {c['source']} | {c['gateway_percent']}% "
                f"| {c['pickup_hours']} h | {policy} "
                f"| {exact['both']} | {exact['only_test']} "
                f"| {exact['only_nearest']} | {exact['neither']} |"
            )
    lines += [
        "",
        "## Decision rule (laboratory, not production)",
        "",
        "1. **Delivery-first:** Parallel4 ranked highest by model acceptances",
        "   in the evaluated conditions, but its added margin over direct gateway",
        "   is small and may cost substantial radio/control traffic.",
        "2. **Traffic-sensitive:** prefer a direct handoff to ANY consenting",
        "   online gateway when available. Never lock the only copy to a",
        "   static historical nearest-gateway choice.",
        "3. **Offline fallback:** retain recipient PRoPHET/Parallel exploration",
        "   only within an explicitly budgeted copy/airtime policy; real-time",
        "   evidence or consent may override these two trace-specific findings.",
        "4. **Do not deploy based on these alone:** prospective traces from",
        "   independent sites, gateway failures, connection/setup latency,",
        "   returned signed W4, radio energy, actual opt-in, and privacy are",
        "   essential independent admission gates.",
        "",
        "**Uncertainty:** only two contact environments, four scenarios per",
        "condition (two phases x two seeds) that reuse one human contact",
        "history. This table is descriptive and **not** a confidence interval",
        "for a city, global network, or future mobile contacts.",
        "",
    ]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=Path("results/exp015"))
    parser.add_argument("--output", type=Path, default=Path("results/exp017"))
    args = parser.parse_args()
    manifest = json.loads((args.input/"gateway-comparison.json").read_text())
    result = analyze(
        read_csv(args.input/"gateway-routing.csv"),
        read_csv(args.input/"paired-nearest-deltas.csv"),
        manifest,
    )
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output/"route-decision.json").write_text(
        json.dumps(result, indent=2, ensure_ascii=False)+"\n", encoding="utf-8"
    )
    (args.output/"route-decision.md").write_text(
        render(result), encoding="utf-8"
    )
    print("EXP017_COMPLETE", len(result["aggregates"]),
          "aggregates", len(result["conditions"]), "conditions", flush=True)


if __name__ == "__main__":
    main()
