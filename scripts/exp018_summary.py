#!/usr/bin/env python3
"""Aggregate Rust LABO EXP-018 outputs. No hot-path simulation in Python."""

import argparse
import json
import statistics
from pathlib import Path


def summarize(files: list[Path]) -> tuple[dict, str]:
    runs = [json.loads(path.read_text(encoding="utf-8")) for path in files]
    if not runs:
        raise ValueError("at least one run is required")
    seeds = set()
    rows = []
    for r in runs:
        assert r["schema"] == "labo-exp018-custodian-reputation-v1"
        assert r["claim"] == "synthetic-not-measured"
        assert r["receipt_semantics"] == "simulated-terminal-ack-not-a-real-W4"
        assert r["max_logical_c_slots_per_message"] == 1
        assert r["seed"] not in seeds, "duplicate seed"
        seeds.add(r["seed"])
        a = r["policy_random"]
        b = r["policy_scored"]
        assert a["created"] == b["created"] == r["messages"]
        for policy in (a, b):
            assert 0 <= policy["delivered_synthetic_w4"] <= policy["valid_reads"]
            assert policy["valid_reads"] <= policy["created"]
            assert policy["max_c_slots_per_message"] <= 1
            assert policy["untrusted_votes_ignored"] > 0
            assert policy["false_suspended_honest"] == 0
        random_pct = 100.0 * a["delivered_synthetic_w4"] / r["messages"]
        scored_pct = 100.0 * b["delivered_synthetic_w4"] / r["messages"]
        rows.append({
            "seed": r["seed"],
            "random_delivered": a["delivered_synthetic_w4"],
            "scored_delivered": b["delivered_synthetic_w4"],
            "random_percent_all_created": round(random_pct, 5),
            "scored_percent_all_created": round(scored_pct, 5),
            "paired_gain_percentage_points": round(scored_pct - random_pct, 5),
            "false_deprioritized_honest": b["false_deprioritized_honest"],
            "corrupt_nodes_detected": b["corrupt_nodes_detected"],
            "audit_bytes_per_policy": b["audit_bytes_model"],
        })
    rows.sort(key=lambda x: x["seed"])
    gains = [x["paired_gain_percentage_points"] for x in rows]
    summary = {
        "schema": "labo-exp018-summary-v1",
        "claim": "synthetic-not-measured",
        "seeds": sorted(seeds),
        "n_seeds": len(rows),
        "messages_per_seed": runs[0]["messages"],
        "custodians": runs[0]["custodians"],
        "mean_gain_percentage_points_of_created": round(statistics.fmean(gains), 5),
        "min_paired_gain_percentage_points": min(gains),
        "max_paired_gain_percentage_points": max(gains),
        "positive_seeds": sum(gain > 0 for gain in gains),
        "negative_seeds": sum(gain < 0 for gain in gains),
        "max_false_deprioritized_honest": max(x["false_deprioritized_honest"] for x in rows),
        "min_corrupt_nodes_detected": min(x["corrupt_nodes_detected"] for x in rows),
        "rows": rows,
    }
    report = [
        "# LABO EXP-018 — local reputation (Rust), reproducible synthetic pilot",
        "",
        "**Only synthetic delivery and assumed authenticated evidence.**",
        "This is NOT real WOW W3, Ed25519 W4, BLAKE3, QUIC, recipient consent,",
        "multiple physical hosts, real resource use, or a global reputation service.",
        "The same message IDs, recipient intent, authorized candidate sets, ticks,",
        "and per-node outcome draws are used in both policies.",
        "Primary endpoint: simulated acknowledgments per ALL created messages",
        "(avoids conditioning on policy-dependent successful storage).",
        "A message chooses at most one logical C slot. Existing slots are never",
        "reissued, even after lost ACK. No actual W8 handoff is executed.",
        "",
        f"Seeds: {len(rows)}; custodians: {summary['custodians']}; "
        f"messages per seed: {summary['messages_per_seed']}.",
        "",
        "| Seed | Random synthetic W4 | Locally scored synthetic W4 | Gain, pp | "
        "False honest deprioritized | Proven corrupt nodes detected |",
        "|---:|---:|---:|---:|---:|---:|",
    ]
    for row in rows:
        report.append(
            f"| {row['seed']} | {row['random_delivered']} | "
            f"{row['scored_delivered']} | "
            f"{row['paired_gain_percentage_points']:+.3f} | "
            f"{row['false_deprioritized_honest']} | "
            f"{row['corrupt_nodes_detected']} |"
        )
    report.extend([
        "",
        f"Mean paired gain: {summary['mean_gain_percentage_points_of_created']:+.3f} pp "
        f"(range {summary['min_paired_gain_percentage_points']:+.3f} to "
        f"{summary['max_paired_gain_percentage_points']:+.3f}).",
        f"Improved seeds: {summary['positive_seeds']}/{len(rows)}.",
        "",
        "## Critical limitations",
        "",
        "- Corrupt replies and observable refusals are scripted model parameters.",
        "- Independent audit witnesses, signed QUIC transcripts and real privacy",
        "  protections are NOT implemented.",
        "- Fake reputation votes are counted and ignored; this does not solve Sybil.",
        "- Honest model peers are defined not to produce bad bytes, so zero",
        "  false *suspensions* is a fixture property, not a real-world guarantee.",
        "- Effective error rates and score thresholds are illustrative, not",
        "  estimated from field traces or calibrated to hardware.",
        "- No automatic reassignment of an existing C slot; no claims of full K3",
        "  Byzantine protection or durable storage of real messages.",
    ])
    return summary, "\n".join(report) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="+", type=Path)
    parser.add_argument("--out", type=Path, default=Path("results/exp018"))
    args = parser.parse_args()
    data, report = summarize(args.inputs)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "summary.json").write_text(
        json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (args.out / "report.md").write_text(report, encoding="utf-8")
    print(report)


if __name__ == "__main__":
    main()
