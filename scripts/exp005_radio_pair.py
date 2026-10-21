#!/usr/bin/env python3
"""LABO EXP-005: paired legacy-radius vs. opt-in BLE link-budget runs.

Inputs match EXP-004's BLE/all-moving cases: same map, seed, traffic,
outages, 80 steps and TTL=40. All results remain synthetic.
"""
import argparse
import csv
import json
import statistics
import subprocess
from pathlib import Path

SIZES = (2000, 20000, 200000)
MAPS = ("building", "plaza")
SEEDS = (21021, 21022, 21023)
MODELS = ("legacy", "budget")
KNOWN_EXP004_LEGACY_PERCENT = {
    (2000, "building"): 4.311,
    (2000, "plaza"): 0.711,
    (20000, "building"): 0.402,
    (20000, "plaza"): 0.080,
    (200000, "building"): 0.0414,
    (200000, "plaza"): 0.0074,
}


def evaluate(program: Path, size: int, map_name: str, seed: int, physics: str):
    command = [
        str(program), "--geometry-scale", "density",
        "--devices", str(size), "--messages", str(int(size * 1.5)),
        "--map", map_name, "--mode", "ble",
        "--mobility", "all", "--outages", "periodic",
        "--steps", "80", "--ttl", "40", "--contact-probes", "8",
        "--relay-percent", "20", "--seed", str(seed),
        "--ble-physics", physics,
    ]
    result = subprocess.run(command, capture_output=True, text=True, check=True)
    row = json.loads(result.stdout.strip())
    assert row["claim"] == "synthetic-not-measured"
    assert row["created"] == row["delivered"] + row["pending"] + row["expired"]
    assert row["created"] == int(size * 1.5)
    assert row["geometry_scale"] == "density"
    assert row["map"] == map_name and row["mode"] == "ble"
    assert row["seed"] == seed
    if physics == "legacy":
        assert "ble_physics" not in row, "legacy output must stay EXP-004 compatible"
    else:
        assert row["ble_physics"] == "budget-v1"
    return row


def run_scale(size: int, program: Path, destination: Path):
    destination.mkdir(parents=True, exist_ok=True)
    rows = []
    for map_name in MAPS:
        for seed in SEEDS:
            legacy = evaluate(program, size, map_name, seed, "legacy")
            budget = evaluate(program, size, map_name, seed, "budget")
            for key in ("initial_devices_fingerprint",
                        "interface_consent_fingerprint", "message_pairs_fingerprint"):
                assert legacy[key] == budget[key], (size, map_name, seed, key)
            assert legacy["created"] == budget["created"]
            rows.append({
                "devices": size,
                "map": map_name,
                "seed": seed,
                "messages": legacy["created"],
                "initial_devices_fingerprint": legacy["initial_devices_fingerprint"],
                "message_pairs_fingerprint": legacy["message_pairs_fingerprint"],
                "interface_consent_fingerprint": legacy["interface_consent_fingerprint"],
                "legacy_delivered": legacy["delivered"],
                "budget_delivered": budget["delivered"],
                "legacy_percent": round(100 * legacy["delivery_ratio"], 8),
                "budget_percent": round(100 * budget["delivery_ratio"], 8),
                "delta_percentage_points": round(
                    100 * (budget["delivery_ratio"] - legacy["delivery_ratio"]), 8),
                "budget_tx_dbm": budget["rf_tx_dbm"],
                "budget_rx_sensitivity_dbm": budget["rf_rx_sensitivity_dbm"],
                "budget_path_loss_exponent": budget["rf_path_loss_exponent"],
            })
            print("PAIR_OK", size, map_name, seed,
                  legacy["delivered"], budget["delivered"], flush=True)
    with (destination / f"paired-{size}.csv").open("w", newline="", encoding="utf8") as file:
        writer = csv.DictWriter(file, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    (destination / f"paired-{size}.json").write_text(
        json.dumps({"schema": "labo-exp005-paired-v1",
                    "claim": "synthetic-not-measured",
                    "rows": rows}, indent=2) + "\n", encoding="utf8")
    print("SIZE_COMPLETE", size, len(rows), "paired scenarios", flush=True)


def combine(source: Path, destination: Path):
    destination.mkdir(parents=True, exist_ok=True)
    rows = []
    for size in SIZES:
        with (source / f"paired-{size}.csv").open(newline="", encoding="utf8") as file:
            case_rows = list(csv.DictReader(file))
        assert len(case_rows) == len(SEEDS) * len(MAPS)
        rows.extend(case_rows)
    results = []
    for size in SIZES:
        for map_name in MAPS:
            matched = [r for r in rows if int(r["devices"]) == size and r["map"] == map_name]
            assert len(matched) == 3
            old = statistics.fmean(float(r["legacy_percent"]) for r in matched)
            new = statistics.fmean(float(r["budget_percent"]) for r in matched)
            # Published EXP-004 percentages were rounded for presentation.
            known = KNOWN_EXP004_LEGACY_PERCENT[(size, map_name)]
            tolerance = 0.0002 if size == 200000 else 0.002
            assert abs(old - known) < tolerance, (size, map_name, old, known)
            results.append({
                "devices": size, "map": map_name, "seeds": len(matched),
                "legacy_delivery_percent": round(old, 6),
                "budget_delivery_percent": round(new, 6),
                "delta_percentage_points": round(new - old, 6),
            })
    with (destination / "summary.csv").open("w", newline="", encoding="utf8") as file:
        writer = csv.DictWriter(file, fieldnames=list(results[0]))
        writer.writeheader()
        writer.writerows(results)
    lines = [
        "# LABO EXP-005 — paired BLE radio-budget pilot", "",
        "**Synthetic comparisons only, NOT real radio or phone measurements.**",
        "Identical seeds, original populations, message pairs and mobility.",
        "6 cells × 3 paired seeds = 18 pairs (36 complete simulations).",
        "100% moving, periodic outages, 80 virtual steps, TTL 40, 1.5 messages/device.",
        "The RF budget uses a homogeneous illustrative 0 dBm Tx, -95 dBm Rx",
        "threshold, -3 dB per antenna, n=3, walls/floors/exterior losses.",
        "BLE discovery windows, background mobile OS, capacity and ACKs are not modeled.",
        "Human walking between campus wings is still absent.", "",
        "| Devices | Map | EXP-004 legacy | RF budget v1 | Difference, percentage points |",
        "|---:|---|---:|---:|---:|",
    ]
    for r in results:
        lines.append(
            f"| {r['devices']:,} | {r['map']} | "
            f"{r['legacy_delivery_percent']:.5f}% | "
            f"{r['budget_delivery_percent']:.5f}% | "
            f"{r['delta_percentage_points']:+.5f} |")
    lines.extend([
        "", "Interpretation: this is a **model sensitivity contrast**, not validation",
        "of any assumed power, propagation exponent, walls or actual BLE delivery.",
        "EXP-004 legacy rounded percentages must reproduce within stated tolerance.",
        "Next: smartphone RSS calibration, advertisements/scanning, airtime and",
        "controlled factor study of inter-wing carriers.", "",
    ])
    (destination / "report.md").write_text("\n".join(lines), encoding="utf8")
    print("\n".join(lines), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--devices", type=int, choices=SIZES)
    parser.add_argument("--program", type=Path, default=Path("target/release/labo"))
    parser.add_argument("--output", type=Path, default=Path("results/exp005"))
    parser.add_argument("--combine", action="store_true")
    parser.add_argument("--source", type=Path)
    args = parser.parse_args()
    if args.combine:
        if not args.source:
            parser.error("--combine requires --source")
        combine(args.source, args.output)
    else:
        if not args.devices:
            parser.error("--devices required without --combine")
        run_scale(args.devices, args.program.resolve(), args.output)


if __name__ == "__main__":
    main()
