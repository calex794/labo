#!/usr/bin/env python3
"""Run genuinely paired, fully reproducible Labo synthetic mobility experiments.

This is NOT a physical BLE/Wi-Fi field test, statistical claim about phones,
or proof of Akula end-to-end signed receipt delivery.
"""
import csv
import json
import os
import pathlib
import random
import statistics
import subprocess
import sys
import time

SEEDS = list(range(21021, 21041))  # 20 distinct independent seeds
MODES = ("wifi", "ble", "hybrid", "exclusive")
MOBILITIES = ("static", "quarter", "all")
OUTAGES = ("never", "once", "periodic")
BASE = ("--map", "building", "--devices", "2000", "--messages", "3000",
        "--steps", "120", "--ttl", "60", "--contact-probes", "8",
        "--relay-percent", "20")
PROGRAM = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "target/release/labo").resolve()
OUT = pathlib.Path(sys.argv[2] if len(sys.argv) > 2 else "results/paired-20")
OUT.mkdir(parents=True, exist_ok=True)


def run_one(seed, mode, mobility, outages):
    args = [str(PROGRAM), *BASE, "--seed", str(seed), "--mode", mode,
            "--mobility", mobility, "--outages", outages]
    start = time.monotonic()
    completed = subprocess.run(args, capture_output=True, text=True, check=True)
    sample = json.loads(completed.stdout.strip())
    assert sample["schema"] == "labo-sim-v0", sample
    assert sample["claim"] == "synthetic-not-measured", sample
    assert sample["devices"] == 2000 and sample["created"] == 3000
    assert sample["created"] == sample["delivered"] + sample["expired"] + sample["pending"]
    assert len(sample["message_pairs_fingerprint"]) == 16, sample
    assert len(sample["initial_devices_fingerprint"]) == 16, sample
    assert sample["seed"] == seed
    sample["duration_s"] = round(time.monotonic() - start, 5)
    return sample


def mean(xs):
    return statistics.fmean(xs)


def bootstrap_ci(deltas, rng, count=2500):
    """Percentile paired bootstrap; descriptive interval, not physical accuracy."""
    n = len(deltas)
    means = sorted(mean([deltas[rng.randrange(n)] for _ in range(n)])
                   for _ in range(count))
    return means[int(count * 0.025)], means[int(count * 0.975)]


def main():
    records = []
    by_case = {}
    fingerprint_checks = 0
    started = time.monotonic()
    with (OUT / "runs.ndjson").open("w", encoding="utf8") as raw:
        for seed in SEEDS:
            pair_baseline = None
            radio_baselines = {}
            mobility_counts = {}
            for mode in MODES:
                for mobility in MOBILITIES:
                    sample = run_one(seed, mode, mobility, "periodic")
                    key = (seed, mode, mobility, "periodic")
                    by_case[key] = sample
                    records.append(sample)
                    raw.write(json.dumps(sample, sort_keys=True) + "\n")
                    # Message identities, sender/recipient pairs and created
                    # times MUST be identical in all scenarios for the seed.
                    pair = sample["message_pairs_fingerprint"]
                    if pair_baseline is None:
                        pair_baseline = pair
                    assert pair == pair_baseline, (seed, mode, mobility, pair, pair_baseline)
                    # Device positions, radios and voluntary relay selection
                    # MUST not change with the movement mode or outages.
                    dev = sample["initial_devices_fingerprint"]
                    if mode in radio_baselines:
                        assert dev == radio_baselines[mode], (seed, mode, mobility)
                    else:
                        radio_baselines[mode] = dev
                    mobility_counts[mobility] = sample["mobile_devices"]
                    fingerprint_checks += 1
            assert mobility_counts["static"] == 0
            assert 0 < mobility_counts["quarter"] < 2000
            assert mobility_counts["all"] == 2000
            # Same seed/population again, only frequency of disconnection
            # varies. "periodic" already recorded in the main 12 cases.
            for outages in ("never", "once"):
                sample = run_one(seed, "ble", "quarter", outages)
                assert sample["message_pairs_fingerprint"] == pair_baseline
                assert sample["initial_devices_fingerprint"] == radio_baselines["ble"]
                fingerprint_checks += 1
                records.append(sample)
                by_case[(seed, "ble", "quarter", outages)] = sample
                raw.write(json.dumps(sample, sort_keys=True) + "\n")
            print("SEED_COMPLETE", seed, "records", len(records), flush=True)

    assert len(records) == 20 * 14
    fields = list(records[0].keys())
    with (OUT / "all-runs.csv").open("w", newline="", encoding="utf8") as f:
        writer = csv.DictWriter(f, fields)
        writer.writeheader()
        writer.writerows(records)

    summary = []
    delta_table = []
    grouped = {}
    for mode in MODES:
        for mobility in MOBILITIES:
            xs = [by_case[(seed, mode, mobility, "periodic")] for seed in SEEDS]
            delivery = [r["delivery_ratio"] for r in xs]
            summary.append({
                "mode": mode, "mobility": mobility,
                "n_seeds": len(SEEDS),
                "mean_delivery_pct": round(100 * mean(delivery), 4),
                "sd_delivery_pp": round(100 * statistics.stdev(delivery), 4),
                "min_delivery_pct": round(100 * min(delivery), 4),
                "max_delivery_pct": round(100 * max(delivery), 4),
                "mean_relay_transfers": round(mean([r["relay_transfers"] for r in xs]), 2),
            })
            grouped[(mode, mobility)] = delivery

    rng = random.Random(21022)
    paired = []
    for mode in MODES:
        baseline = grouped[(mode, "static")]
        for mobility in ("quarter", "all"):
            alternative = grouped[(mode, mobility)]
            diffs = [100 * (b - a) for a, b in zip(baseline, alternative)]
            lo, hi = bootstrap_ci(diffs, rng)
            item = {
                "mode": mode, "contrast": mobility + "_minus_static",
                "n_seeds": len(SEEDS),
                "mean_gain_pp": round(mean(diffs), 4),
                "bootstrap95_lower_pp": round(lo, 4),
                "bootstrap95_upper_pp": round(hi, 4),
                "improved_seeds": sum(x > 1e-8 for x in diffs),
                "worsened_seeds": sum(x < -1e-8 for x in diffs),
                "tied_seeds": sum(abs(x) <= 1e-8 for x in diffs),
            }
            paired.append(item)
            print("PAIRED", json.dumps(item, sort_keys=True), flush=True)
            for seed, delta in zip(SEEDS, diffs):
                delta_table.append({"seed": seed, "mode": mode,
                                    "contrast": item["contrast"],
                                    "gain_pp": round(delta, 6)})

    outages = []
    for state in OUTAGES:
        vals = [by_case[(seed, "ble", "quarter", state)]["delivery_ratio"]
                for seed in SEEDS]
        outages.append({"outages": state, "n_seeds": 20,
                        "mean_delivery_pct": round(100 * mean(vals), 4),
                        "sd_delivery_pp": round(100 * statistics.stdev(vals), 4)})

    def write_csv(path, rows):
        with path.open("w", newline="", encoding="utf8") as f:
            w = csv.DictWriter(f, list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)

    write_csv(OUT / "scenario-summary.csv", summary)
    write_csv(OUT / "paired-differences.csv", delta_table)
    write_csv(OUT / "paired-effects.csv", paired)
    write_csv(OUT / "ble-outages.csv", outages)

    manifest = {
        "schema": "labo-paired-experiment-v1",
        "description": "Synthetic matched-input experiment, NOT calibrated RF/phones",
        "source_sha": os.environ.get("GITHUB_SHA", "local"),
        "seed_start": SEEDS[0], "seed_end": SEEDS[-1],
        "n_seeds": len(SEEDS), "scenarios_per_seed": 14,
        "total_scenarios": len(records),
        "fixed_parameters": list(BASE),
        "fingerprint_assertions_passed": fingerprint_checks,
        "elapsed_seconds": round(time.monotonic() - started, 2),
    }
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf8")
    print("VERIFIED", json.dumps(manifest, sort_keys=True), flush=True)
    lines = [
        "# LABO EXP-002: paired mobility study (20 seeds)",
        "",
        "**Scope:** 2,000 synthetic devices in 5-floor/350-office building,",
        "3,000 messages per run, 120 virtual steps and TTL 60 steps.",
        "Every variant for each seed has exactly the same initial",
        "device locations, radio hardware, consent choices and message pairs.",
        "Only the intentionally changed experimental factor differs.",
        "",
        f"**Completed:** {len(records)} scenarios using {len(SEEDS)} seeds.",
        f"**Fingerprint assertions passed:** {fingerprint_checks}.",
        f"**Runner duration:** {manifest['elapsed_seconds']} seconds.",
        "",
        "## Mean delivery rates across 20 seeds",
        "",
        "| Radio mode | Static (%) | 25% mobile (%) | All mobile (%) |",
        "|---|---:|---:|---:|",
    ]
    for mode in MODES:
        vals = {r["mobility"]: r["mean_delivery_pct"] for r in summary if r["mode"] == mode}
        lines.append(f"| {mode} | {vals['static']:.3f} | {vals['quarter']:.3f} | {vals['all']:.3f} |")
    lines += [
        "",
        "## Paired mean change from static (percentage points)",
        "",
        "| Radio mode | Moving fraction | Mean Δ pp | Descriptive bootstrap 95% interval | Better / worse / tied seeds |",
        "|---|---|---:|---|---|",
    ]
    for p in paired:
        lines.append(
            f"| {p['mode']} | {p['contrast'].split('_')[0]} "
            f"| {p['mean_gain_pp']:+.3f} | [{p['bootstrap95_lower_pp']:+.3f}, "
            f"{p['bootstrap95_upper_pp']:+.3f}] | "
            f"{p['improved_seeds']}/{p['worsened_seeds']}/{p['tied_seeds']} |"
        )
    lines += [
        "",
        "## BLE quarter-mobile: outage comparison",
        "",
        "| Outages | Mean delivered (%) | Across-seed SD (percentage points) |",
        "|---|---:|---:|",
    ]
    for row in outages:
        lines.append(f"| {row['outages']} | {row['mean_delivery_pct']:.3f} | {row['sd_delivery_pp']:.3f} |")
    lines += [
        "",
        "## Validity limits",
        "",
        "- **Paired only inside the synthetic model.** Random initial participants,",
        "  radios, volunteers and message pairs now do not change with mobility.",
        "  Per-node movement trajectories share random draws across variants.",
        "  Per-message/time contact candidates also have independent seeded draws.",
        "- BLE contact distance, wall losses and Wi-Fi accessibility are assumed,",
        "  not measured. There is no device operating-system background model.",
        "- No signed WOW W4 confirmation or recipient durable write is simulated.",
        "  'Delivered' denotes contact between a carrier and the destination.",
        "- The 20 seeds support a paired variability assessment for this",
        "  model only, NOT real-world probabilities or verified E2E delivery.",
        "",
        "Raw measurements, per-seed deltas and manifest are included in the",
        "same GitHub Actions artifact as this report.",
    ]
    (OUT / "report.md").write_text("\n".join(lines) + "\n", encoding="utf8")


if __name__ == "__main__":
    main()
