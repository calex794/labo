#!/usr/bin/env python3
"""EXP-012: reproduce recipient routing on two INDEPENDENT CC0 contact datasets.

Only 20-second face-to-face encounters are measured by SocioPatterns.
All BLE, application installation, consent, forwarding, acknowledgments and
energy are hypothetical; success means SIMULATED recipient acceptance, NOT W4.
Do not publish the underlying anonymous participant-level contact records.
"""
import argparse
from collections import defaultdict
import csv
import hashlib
import json
import math
from pathlib import Path
import random
import statistics
import zlib
from urllib.request import Request, urlopen

from exp006_temporal_contacts import build_temporal_graph, earliest_delivery
from exp008_recipient_routes import simulate, policy_budget
from exp011_real_contacts import (
    SAMPLE_SECONDS, choose_letters, git_blob_sha, parse_real_tij,
)

COMMIT = "d3fed34de6ca1cdeabe7c21dfc3475a19f46fe8f"
REPO = "SocioPatterns/sociopatterns.github.io"
MAX_COMPRESSED = 1_000_000
MAX_UNCOMPRESSED = 12_000_000
POLICIES = ("direct", "random4", "spray4", "prophet4", "parallel4")
SEEDS = (21021, 21022)
PROVENANCE = "real-face-to-face-contacts-with-synthetic-routing-not-real-delivery"
SOURCES = {
    "SFHH-conference-2009": {
        "path": "assets/data/SFHH_tij.dat.gz",
        "blob": "1f323d7ca92ffba0e1b660575a081aa982903f71",
        "page": "https://sociopatterns.org/datasets/sfhh-conference-data-set/",
        "citation": "SFHH 2009; Genois and Barrat, EPJ Data Science 7:11 (2018)",
        "license": "CC0-1.0",
    },
    "InVS-office-2015": {
        "path": "assets/data/workplace_InVS15_tij.dat.gz",
        "blob": "cd6866d2edcc191c81eece645ae14a9ed98f47bd",
        "page": "https://sociopatterns.org/datasets/contacts-in-a-workplace-2/",
        "citation": "InVS second deployment (2015); Genois and Barrat, EPJ Data Science 7:11 (2018)",
        "license": "CC0-1.0",
    },
}


def fetch_pinned(name, cache, download):
    """Pinned raw archive, no 'latest' fallback that could silently change."""
    spec = SOURCES[name]
    local = cache / Path(spec["path"]).name
    cache.mkdir(parents=True, exist_ok=True)
    if not local.exists():
        if not download:
            raise FileNotFoundError(f"missing pinned source {name}: use --download")
        urls = (
            f"https://raw.githubusercontent.com/{REPO}/{COMMIT}/{spec['path']}",
            f"https://sociopatterns.org/{spec['path']}",
        )
        errors = []
        for url in urls:
            try:
                with urlopen(Request(url, headers={
                    "User-Agent": "Labo-EXP012-CC0-ContactStudy/1.0",
                }), timeout=45) as response:
                    content = response.read(MAX_COMPRESSED + 1)
                if not (8 <= len(content) <= MAX_COMPRESSED):
                    raise ValueError("invalid compressed source length")
                if git_blob_sha(content) != spec["blob"]:
                    raise ValueError("pinned Git blob checksum mismatch")
                local.write_bytes(content)
                break
            except (OSError, ValueError) as exc:
                errors.append(f"{url}: {exc}")
        else:
            raise RuntimeError("pinned source unavailable: " + "; ".join(errors))
    content = local.read_bytes()
    if not (8 <= len(content) <= MAX_COMPRESSED):
        raise ValueError("invalid cached compressed source length")
    if git_blob_sha(content) != spec["blob"]:
        raise ValueError("pinned Git blob checksum mismatch on cached source")
    return content


def parse_pinned_gzip(payload):
    """Bound memory, validate shape; actual encounter parser from EXP-011."""
    if payload[:2] != b"\x1f\x8b":
        raise ValueError("not a gzip file")
    dec = zlib.decompressobj(16 + zlib.MAX_WBITS)
    text = dec.decompress(payload, MAX_UNCOMPRESSED + 1)
    if len(text) > MAX_UNCOMPRESSED or dec.unconsumed_tail:
        raise ValueError("contact source decompression limit exceeded")
    text += dec.flush(MAX_UNCOMPRESSED + 1 - len(text))
    if not dec.eof or dec.unused_data or len(text) > MAX_UNCOMPRESSED:
        raise ValueError("gzip source truncated, trailing, or oversized")
    data = parse_real_tij(text.decode("ascii"))
    return data


def split_chronology(data, ttl_ticks, count_each):
    """Disjoint historic training window and earlier/later holdout start times.

    Positions 25/45/70% of observed *unique timestamps* are chosen independent
    of the policy and before creating any letter destinations. Their existence
    is experiment design, NOT information provided to routing algorithms.
    """
    events = data["events"]
    times = sorted({event[0] for event in events})
    if len(times) < 100:
        raise ValueError("trace too short for independent historical windows")
    t0 = times[len(times) // 4]
    early = times[len(times) * 45 // 100]
    late = times[len(times) * 70 // 100]
    offset = 30 + (min(count_each * 2 - 1, 5) % 6) * 5
    horizon = ttl_ticks + offset
    if not (t0 + 30 < early and early + horizon < late
            and late + horizon <= times[-1]):
        raise ValueError("trace cannot provide separated history and full TTL followup")
    history = [(tick * SAMPLE_SECONDS, a, b)
               for tick, a, b, _kind, _duration in events if tick <= t0]
    return {
        "train": t0,
        "early": early,
        "late": late,
        "end": times[-1],
        "train_records": history,
    }


def choose_historic_pairs(split, seed, letters):
    # The source's chosen future contacts and recipient activity are never used.
    pseudo_data = {"days": {0: split["train_records"]}}
    return choose_letters(pseudo_data, 0, seed,
                          random_count=letters, twohop_count=letters)


def make_jobs(pairs, start):
    return [(src, dst, start + 30 + (i % 6) * 5, category)
            for i, (category, src, dst) in enumerate(pairs)]


def paired_bootstrap(outcomes_a, outcomes_b, seed, draws=1200):
    """Descriptive paired resampling across letters, not a population CI.

    Sources are fixed observational contact graphs and multiple letters share
    participants. This cannot establish generalization to future communities.
    """
    if len(outcomes_a) != len(outcomes_b) or not outcomes_a:
        raise ValueError("mismatched paired outcomes")
    n = len(outcomes_a)
    rng = random.Random(seed)
    diffs = []
    for _ in range(draws):
        chosen = [rng.randrange(n) for _ in range(n)]
        diffs.append(100 * sum(outcomes_a[i] - outcomes_b[i]
                               for i in chosen) / n)
    diffs.sort()
    return (round(diffs[int(.025 * (draws - 1))], 4),
            round(diffs[int(.975 * (draws - 1))], 4))


def compare_two_policies(jobs, delivery_a, delivery_b, kind, seed):
    indices = [i for i, job in enumerate(jobs) if job[3] == kind]
    a = [int(delivery_a[i] is not None) for i in indices]
    b = [int(delivery_b[i] is not None) for i in indices]
    joint = {
        "both": sum(x and y for x, y in zip(a, b)),
        "parallel_only": sum(x and not y for x, y in zip(a, b)),
        "prophet_only": sum(y and not x for x, y in zip(a, b)),
        "neither": sum(not x and not y for x, y in zip(a, b)),
    }
    lower, upper = paired_bootstrap(a, b, seed)
    return {
        "category": kind, "paired_messages": len(indices), **joint,
        "delta_parallel_minus_prophet_percent": round(
            100 * (sum(a) - sum(b)) / len(indices), 4),
        "paired_resample_low_percent": lower,
        "paired_resample_high_percent": upper,
        "resampling_note": "finite_fixed_contacts_not_population_confidence_interval",
    }


def evaluate_sources(datasets, output, *, seeds=SEEDS, policies=POLICIES,
                     letters_per_kind=12, ttl_hours=4, half_life_hours=24):
    if not (1 <= ttl_hours <= 12 and 1 <= half_life_hours <= 240
            and 2 <= letters_per_kind <= 100 and seeds
            and all(0 <= seed <= 2**32 for seed in seeds)
            and set(policies).issubset(POLICIES) and "prophet4" in policies
            and "parallel4" in policies):
        raise ValueError("invalid scientific scenario parameters")
    ttl = 3600 * ttl_hours // SAMPLE_SECONDS
    decay = math.exp(-math.log(2) * SAMPLE_SECONDS / (3600 * half_life_hours))
    rows = []
    paired = []
    manifests = {}
    for source_name, data in datasets.items():
        split = split_chronology(data, ttl, letters_per_kind)
        manifests[source_name] = {
            "source_url": SOURCES[source_name]["page"],
            "git_pin": SOURCES[source_name]["blob"],
            "license": SOURCES[source_name]["license"],
            "citation": SOURCES[source_name]["citation"],
            "sample_seconds": SAMPLE_SECONDS,
            "measured_contacts": data["record_count"],
            "participants": data["participant_count"],
            "training_tick": split["train"],
            "early_start_tick": split["early"],
            "late_start_tick": split["late"],
            "last_recorded_tick": split["end"],
        }
        for seed in seeds:
            pairs = choose_historic_pairs(split, seed, letters_per_kind)
            pair_digest = hashlib.sha256(repr(pairs).encode()).hexdigest()
            for period in ("early", "late"):
                jobs = make_jobs(pairs, split[period])
                end = max(j[2] for j in jobs) + ttl - 1
                if end > split["end"]:
                    raise AssertionError("evaluation runs past observed contact horizon")
                observed = [e for e in data["events"] if e[0] <= end]
                # Oracle is post-hoc upper bound; simulator never uses it to route.
                graph = build_temporal_graph(observed)
                oracle = [earliest_delivery(graph, src, dst, created, ttl)
                          for src, dst, created, _ in jobs]
                snapshot = {}
                for policy in policies:
                    result = simulate(
                        observed, jobs, policy=policy, ttl=ttl, seed=seed,
                        residents_per_wing=100000,
                        volunteer=lambda node: True,
                        gateways=(), mailbox_authorized=False,
                        observation_end=end, oracle_ticks=oracle,
                        forecast_decay=decay, forecast_all_contacts=True,
                    )
                    if result["claim"] != "synthetic-routing-not-real-delivery":
                        raise AssertionError("unexpected simulation data class")
                    if result["max_copies_seen"] > policy_budget(policy):
                        raise AssertionError("shared copy quota exceeded")
                    if result["max_radio_per_device_tick_ms"] > 6000:
                        raise AssertionError("radio budget exceeded")
                    if any(value > 1 for value in result["accepted_count"]):
                        raise AssertionError("recipient deduplication broken")
                    if any(at is not None and (oracle[i] is None or at < oracle[i])
                           for i, at in enumerate(result["delivery_ticks"])):
                        raise AssertionError("delivery beat temporal oracle")
                    snapshot[policy] = result
                    for category, group in result["groups"].items():
                        rows.append({
                            "source": source_name, "seed": seed,
                            "phase": period, "policy": policy,
                            "copy_budget": policy_budget(policy),
                            "category": category, "letters": group["letters"],
                            "accepted": group["recipient_accepted"],
                            "undelivered": group["undelivered"],
                            "oracle_reachable": group["oracle_ble_reachable"],
                            "accepted_percent": group["accepted_percent"],
                            "p50_ticks_accepted_only": group["median_delivery_ticks"],
                            "p95_ticks_accepted_only": group["p95_delivery_ticks"],
                            "run_wire_bytes_all_categories": result["wire_bytes"],
                            "run_transmissions_all_categories": result["transmissions"],
                            "max_copies_seen": result["max_copies_seen"],
                            "max_radio_ms_per_device_tick": result["max_radio_per_device_tick_ms"],
                            "input_pairs_sha256": pair_digest,
                            "claim": PROVENANCE,
                        })
                for category in sorted({job[3] for job in jobs}):
                    outcome = compare_two_policies(
                        jobs, snapshot["parallel4"]["delivery_ticks"],
                        snapshot["prophet4"]["delivery_ticks"], category,
                        seed ^ (1 if period == "early" else 2) ^
                        int(hashlib.sha256(source_name.encode()).hexdigest()[:8],16),
                    )
                    paired.append({
                        "source": source_name, "phase": period, "seed": seed,
                        "input_pairs_sha256": pair_digest, **outcome,
                    })
                print("MEASURED_CC0_REPLAY", source_name, period,
                      "seed", seed, "source_rows", data["record_count"],
                      "letters", len(jobs), flush=True)
    if not rows:
        raise AssertionError("no real contact comparisons")
    output.mkdir(parents=True, exist_ok=True)
    with (output / "independent-contact-routing.csv").open(
            "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    with (output / "paired-policy-deltas.csv").open(
            "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(paired[0]))
        writer.writeheader()
        writer.writerows(paired)
    record = {
        "schema": "labo-exp012-cc0-replication-v1",
        "claim": PROVENANCE, "pinned_commit": COMMIT,
        "conditions": {"ttl_hours": ttl_hours, "forecast_half_life_hours": half_life_hours,
                       "message_bytes": 256, "goodput_kbps_assumed": 64,
                       "all_nodes_hypothetically_consent": True,
                       "virtual_radio_ms_per_node_tick": 6000,
                       "seeds": list(seeds), "policies": list(policies)},
        "sources": manifests, "rows": rows, "paired": paired,
    }
    (output / "independent-contact-routing.json").write_text(
        json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    report = [
        "# LABO EXP-012 — independent CC0 contact graph replication",
        "",
        "**REAL:** two independent published 20-second face-to-face encounter traces.",
        "**SYNTHETIC:** all BLE transfer, online status, volunteered relay, routing,",
        "application acceptance, copy quotas, acknowledgements and energy.",
        "This does not prove real phone message delivery.",
        "",
        "Data CC0, sources and citations pinned in JSON. Raw anonymous encounter",
        "lists are transient and deliberately NOT stored in LABO or CI artifacts.",
        "Training: first 25% of unique observed time slots; two disjoint 4-hour",
        "message-delivery windows begin near 45%/70% of measured time slots,",
        "and their complete TTL horizon lies before the last source event.",
        "Correspondents for both windows chosen ONLY from training contacts.",
        "Two-hop-selected correspondents are a diagnostic cohort, not population sample.",
        "At most 16 prior-contact forecast entries per node; one-day half-life",
        "hypothesis. No predictor sees the future or the holdout pair selection.",
        "Direct K1 is a diagnostic, K4 methods share the same total copy cap.",
        "The seed controls message selection, but does not create new independent",
        "human contact traces. Paired bootstrap bounds are finite fixed-graph",
        "descriptive resampling, NOT valid population confidence intervals.",
        "",
        "| Data source | Phase | Type of letter | Policy | Accepted / total | Oracle reachable | Mean run bytes* |",
        "|---|---|---|---|---:|---:|---:|",
    ]
    keys = {(r["source"], r["phase"], r["category"], r["policy"]) for r in rows}
    for source_name, phase, category, policy in sorted(keys):
        selected = [r for r in rows if (r["source"], r["phase"],
                    r["category"], r["policy"]) == (source_name, phase, category, policy)]
        total = sum(r["letters"] for r in selected)
        accepted = sum(r["accepted"] for r in selected)
        oracle = sum(r["oracle_reachable"] for r in selected)
        bytes_mean = statistics.fmean(r["run_wire_bytes_all_categories"] for r in selected)
        report.append(f"| {source_name} | {phase} | {category} | {policy} | "
                      f"{accepted}/{total} ({100*accepted/total:.2f}%) | "
                      f"{oracle}/{total} | {bytes_mean:.0f} |")
    report += [
        "", "* The bytes are for both letter types in ONE run; repeated on",
        "separate category rows. Do not sum the repeated bytes across types.",
        "",
        "## Paired Parallel4 vs PRoPHET4",
        "",
        "| Source | Phase | Category | Parallel-only | Prophet-only | Delta (pp) |",
        "|---|---|---|---:|---:|---:|",
    ]
    for x in paired:
        report.append(
            f"| {x['source']} | {x['phase']} | {x['category']} | "
            f"{x['parallel_only']} | {x['prophet_only']} | "
            f"{x['delta_parallel_minus_prophet_percent']:.2f} |")
    report += [
        "",
        "Positive or negative discrepancies do not establish real-world",
        "performance. Independent social environments are not independent",
        "smartphone measurements, and CC0 face-to-face badges are not BLE.",
        "Never turn on real participant IDs, raw traces, or endpoint names",
        "in a public routing announcement for Akula.",
        "",
    ]
    (output / "report.md").write_text("\n".join(report), encoding="utf-8")
    print("EXP012_COMPLETE", len(rows), "category rows",
          len(paired), "paired delta rows", flush=True)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, default=Path("results/exp012-source-cache"))
    parser.add_argument("--output", type=Path, default=Path("results/exp012"))
    parser.add_argument("--download", action="store_true")
    parser.add_argument("--seeds", type=int, nargs="+", default=list(SEEDS))
    parser.add_argument("--letters-per-kind", type=int, default=12)
    parser.add_argument("--ttl-hours", type=int, default=4)
    parser.add_argument("--forecast-half-life-hours", type=int, default=24)
    args = parser.parse_args()
    if not (1 <= len(args.seeds) <= 20 and
            all(0 <= seed <= 2**32 for seed in args.seeds)):
        parser.error("invalid seed list")
    data = {name: parse_pinned_gzip(fetch_pinned(
        name, args.cache, args.download)) for name in SOURCES}
    evaluate_sources(data, args.output, seeds=tuple(args.seeds),
                     letters_per_kind=args.letters_per_kind,
                     ttl_hours=args.ttl_hours,
                     half_life_hours=args.forecast_half_life_hours)


if __name__ == "__main__":
    main()
