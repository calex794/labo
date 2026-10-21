#!/usr/bin/env python3
"""Pair measured-RSSI-derived BLE hypotheses against the same LABO seed cases.

This DOES NOT estimate the probability of discovering a device or receiving
a message; only the prior link-budget gate is replaced with measured RSS fits.
"""
import argparse
import csv
import json
import math
from pathlib import Path
import subprocess

SEEDS = (21021, 21022, 21023)
MAPS = ("plaza", "building")


def one_run(binary, seed, map_name, args):
    argv = [
        str(binary),
        "--geometry-scale", "density", "--map", map_name, "--mode", "ble",
        "--ble-physics", "budget", "--devices", "2000", "--messages", "3000",
        "--steps", "80", "--ttl", "40", "--contact-probes", "8",
        "--relay-percent", "20", "--outages", "periodic", "--mobility", "all",
        "--seed", str(seed), *args,
    ]
    p = subprocess.run(argv, capture_output=True, text=True, check=True)
    r = json.loads(p.stdout)
    assert r["claim"] == "synthetic-not-measured"
    assert r["created"] == r["delivered"] + r["pending"] + r["expired"]
    return r


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--profiles", type=Path, required=True)
    cli.add_argument("--binary", type=Path, default=Path("target/release/labo"))
    cli.add_argument("--output", type=Path, default=Path("results/rssi-compare"))
    args = cli.parse_args()
    profiles = json.loads(args.profiles.read_text(encoding="utf-8"))
    assert profiles["claim"] == "measured-RSSI-fitted-model-not-delivery"
    candidates = [p for p in profiles["phones"] if p["usable_for_labo_budget"]]
    if not candidates:
        raise RuntimeError("no phone regression lies inside the validated LABO model bounds")
    out = []
    baseline_signatures = {}
    for place in MAPS:
        for seed in SEEDS:
            ref = one_run(args.binary.resolve(), seed, place, [])
            baseline_signatures[(place, seed)] = ref
            out.append({
                "device": "synthetic_analytic_baseline",
                "map": place, "seed": seed, "cap_m": 200,
                "rss_at_1m_dbm": "",
                "n": 3.0,
                "delivered": ref["delivered"],
                "delivered_percent": round(100 * ref["delivery_ratio"], 7),
                "sample_count": 0,
                "empirical": False,
            })
    for p in candidates:
        # A calibration fitted on observed RSS is not justified past observed d.
        cap = max(1, min(200, math.floor(float(p["max_distance_m"]))))
        extra = [
            "--ble-reference-rssi-at-1m", str(p["rssi_at_1m_dbm"]),
            "--ble-path-loss", str(p["path_loss_exponent"]),
            "--ble-range-cap-m", str(cap),
        ]
        for place in MAPS:
            for seed in SEEDS:
                actual = one_run(args.binary.resolve(), seed, place, extra)
                baseline = baseline_signatures[(place, seed)]
                for key in ("initial_devices_fingerprint",
                            "interface_consent_fingerprint",
                            "message_pairs_fingerprint"):
                    assert actual[key] == baseline[key], (p["device"], place, seed, key)
                assert actual["rf_reference_rssi_at_1m_dbm"] == p["rssi_at_1m_dbm"]
                out.append({
                    "device": p["device"],
                    "map": place, "seed": seed,
                    "cap_m": cap,
                    "rss_at_1m_dbm": p["rssi_at_1m_dbm"],
                    "n": p["path_loss_exponent"],
                    "delivered": actual["delivered"],
                    "delivered_percent": round(100 * actual["delivery_ratio"], 7),
                    "sample_count": p["sample_count"],
                    "empirical": True,
                })
        print("PHONE_PROBE", p["device"], "fit_n", p["path_loss_exponent"],
              "rss_1m", p["rssi_at_1m_dbm"], "cap", cap, flush=True)
    args.output.mkdir(parents=True, exist_ok=True)
    with (args.output / "comparison.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(out[0]))
        w.writeheader()
        w.writerows(out)
    (args.output / "comparison.json").write_text(
        json.dumps({"schema": "labo-measured-rssi-model-contrast-v1",
                    "claim": "synthetic-delivery-using-measured-rssi-regressions",
                    "rows": out}, indent=2) + "\n", encoding="utf-8")
    lines = [
        "# LABO — effect of phone-specific measured RSS coefficients",
        "",
        "Every delivery rate below remains **synthetic**, not a field delivery measurement.",
        "The captured smartphone RSS is real, but its extrapolated link-budget",
        "comparison retains hypothetical receiver sensitivity, wall losses,",
        "movement, scanning and routing. Inter-wing movement is absent.",
        "Baseline RF and calibrated RF vary in reference RSS, n AND distance cap;",
        "these are profiles, not an isolated causal contrast of power.",
        "The cap prevents using a measured fit beyond its largest observed distance.",
        "",
        "| Source | Map | RSS@1m (dBm) | n | Cap (m) | Delivery, mean of 3 seeds |",
        "|---|---|---:|---:|---:|---:|",
    ]
    for device in dict.fromkeys(x["device"] for x in out):
        for place in MAPS:
            rows = [r for r in out if r["device"] == device and r["map"] == place]
            from statistics import fmean
            pct = fmean(r["delivered_percent"] for r in rows)
            r = rows[0]
            lines.append(f"| {device} | {place} | {r['rss_at_1m_dbm']} | "
                         f"{r['n']} | {r['cap_m']} | {pct:.4f}% |")
    lines.append("")
    (args.output / "report.md").write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines), flush=True)


if __name__ == "__main__":
    main()
