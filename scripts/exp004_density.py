#!/usr/bin/env python3
"""LABO EXP-004: expanding geometries with proportional message volume.

No real radio/phone measurement. Compares 2k/20k/200k at 1.5
messages per device, 80 synthetic ticks, separate building campus/plaza,
and fixed participant density. GNU time measures the Rust process.
"""
import argparse
import csv
import itertools
import json
import math
import os
from pathlib import Path
import statistics as stats
import subprocess
import tempfile
import time

SIZES = (2000, 20000, 200000)
MAPS = ("building", "plaza")
MODES = ("ble", "hybrid")
MOBILITIES = ("static", "quarter", "all")
SEEDS = (21021, 21022, 21023)
STEPS = 80
TTL = 40
MSGS_PER_DEVICE = 1.5
BASE_DEVICES = 2000

def evaluate(program, arguments):
    meter = Path("/usr/bin/time")
    if not meter.is_file():
        raise RuntimeError("GNU /usr/bin/time is required to measure child RSS")
    with tempfile.TemporaryDirectory() as tmp:
        measure = Path(tmp) / "usage"
        before = time.perf_counter()
        child = subprocess.run(
            [str(meter), "-f", "%U,%S,%M", "-o", str(measure),
             str(program), *arguments],
            capture_output=True, text=True, check=False,
        )
        elapsed = time.perf_counter() - before
        if child.returncode != 0:
            raise RuntimeError(
                f"model failed exit={child.returncode}; stderr={child.stderr[-4000:]}"
            )
        cpu_u, cpu_s, peak_rss_kib = measure.read_text().strip().split(",")
    result = json.loads(child.stdout.strip())
    assert result["claim"] == "synthetic-not-measured"
    result["wall_seconds"] = round(elapsed, 6)
    result["cpu_seconds"] = round(float(cpu_u) + float(cpu_s), 6)
    result["peak_rss_mib"] = round(int(peak_rss_kib) / 1024.0, 6)
    return result

def expected_side(n):
    return round(500 * math.sqrt(n / BASE_DEVICES))

def run_scale(size, binary, output):
    output.mkdir(parents=True, exist_ok=True)
    profiles = []
    before = time.perf_counter()
    expected_messages = int(MSGS_PER_DEVICE * size)
    pairs_verified = 0
    initial_verified = 0
    equipment_verified = 0
    with (output / f"raw-{size}.ndjson").open("w", encoding="utf8") as f:
        for seed in SEEDS:
            seed_messages = None
            device_by_map_mode = {}
            equipment_by_mode = {}
            for map_name, mode, mobility in itertools.product(MAPS, MODES, MOBILITIES):
                args = (
                    "--geometry-scale", "density",
                    "--map", map_name,
                    "--mode", mode,
                    "--mobility", mobility,
                    "--outages", "periodic",
                    "--devices", str(size),
                    "--messages", str(expected_messages),
                    "--steps", str(STEPS),
                    "--ttl", str(TTL),
                    "--contact-probes", "8",
                    "--relay-percent", "20",
                    "--seed", str(seed),
                )
                r = evaluate(binary, args)
                assert r["devices"] == size
                assert r["geometry_scale"] == "density"
                assert r["created"] == expected_messages
                assert r["created"] == r["delivered"] + r["pending"] + r["expired"]
                assert (r["mode"], r["map"], r["mobility"], r["seed"]) == (
                    mode, map_name, mobility, seed)
                assert r["building_wings"] == size // BASE_DEVICES
                assert r["plaza_side_m"] == expected_side(size)
                assert len(r["initial_devices_fingerprint"]) == 16
                assert len(r["interface_consent_fingerprint"]) == 16
                assert len(r["message_pairs_fingerprint"]) == 16
                if seed_messages is None:
                    seed_messages = r["message_pairs_fingerprint"]
                assert seed_messages == r["message_pairs_fingerprint"], "pairs changed"
                pairs_verified += 1
                key = (map_name, mode)
                baseline = device_by_map_mode.setdefault(key, r["initial_devices_fingerprint"])
                assert baseline == r["initial_devices_fingerprint"], "population changed with mobility"
                initial_verified += 1
                hw = equipment_by_mode.setdefault(mode, r["interface_consent_fingerprint"])
                assert hw == r["interface_consent_fingerprint"], "hardware/consent changed across maps"
                equipment_verified += 1
                if mobility == "static":
                    assert r["mobile_devices"] == 0
                if mobility == "all":
                    assert r["mobile_devices"] == size
                if mobility == "quarter":
                    assert 0 < r["mobile_devices"] < size
                profiles.append(r)
                f.write(json.dumps(r, sort_keys=True) + "\n")
            print("SEED_COMPLETED", size, seed, "scenarios", len(profiles), flush=True)
    assert len(profiles) == 36
    with (output / f"raw-{size}.csv").open("w", encoding="utf8", newline="") as f:
        w = csv.DictWriter(f, list(profiles[0]))
        w.writeheader()
        w.writerows(profiles)
    manifest = {
        "schema": "labo-exp004-run-v1",
        "claim": "synthetic-not-measured",
        "devices": size,
        "messages_per_run": expected_messages,
        "messages_per_device": MSGS_PER_DEVICE,
        "steps": STEPS,
        "ttl_steps": TTL,
        "seeds": SEEDS,
        "geometry_scale": "density",
        "building_wings": size // BASE_DEVICES,
        "plaza_side_m": expected_side(size),
        "scenarios": len(profiles),
        "matching_message_pairs": pairs_verified,
        "matching_population": initial_verified,
        "matching_interfaces_and_consent": equipment_verified,
        "wall_seconds_total": round(time.perf_counter() - before, 3),
        "code_sha": os.environ.get("GITHUB_SHA", "local"),
    }
    (output / f"manifest-{size}.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print("SIZE_COMPLETE", json.dumps(manifest, sort_keys=True), flush=True)

def combine(source, target):
    target.mkdir(parents=True, exist_ok=True)
    all_rows = []
    for size in SIZES:
        with (source / f"raw-{size}.csv").open(newline="") as f:
            rows = list(csv.DictReader(f))
        assert len(rows) == 36, (size, len(rows))
        for r in rows:
            assert r["claim"] == "synthetic-not-measured"
            assert int(r["devices"]) == size
            assert int(r["created"]) == int(MSGS_PER_DEVICE * size)
            assert int(r["created"]) == sum(map(int, (r["delivered"],r["expired"],r["pending"])))
            assert int(r["plaza_side_m"]) == expected_side(size)
            assert int(r["building_wings"]) == size // BASE_DEVICES
            assert r["geometry_scale"] == "density"
            for k in ("delivery_ratio","wall_seconds","cpu_seconds","peak_rss_mib"):
                r[k] = float(r[k])
        all_rows.extend(rows)
    assert len(all_rows) == 108
    cells = {}
    for r in all_rows:
        key = (int(r["devices"]), r["map"], r["mode"], r["mobility"])
        cells.setdefault(key, []).append(r)
    assert len(cells) == 36 and all(len(v) == len(SEEDS) for v in cells.values())
    summary = []
    for (size,place,mode,mobility),rs in sorted(cells.items()):
        pct=[100*r["delivery_ratio"] for r in rs]
        summary.append({
            "devices":size, "map":place, "mode":mode, "mobility":mobility,
            "n_seeds":len(rs), "mean_delivery_percent":round(stats.fmean(pct),5),
            "min_delivery_percent":round(min(pct),5),
            "max_delivery_percent":round(max(pct),5),
            "median_wall_seconds":round(stats.median(r["wall_seconds"] for r in rs),6),
            "median_cpu_seconds":round(stats.median(r["cpu_seconds"] for r in rs),6),
            "median_peak_rss_mib":round(stats.median(r["peak_rss_mib"] for r in rs),5),
            "mean_relay_transfers":round(stats.fmean(int(r["relay_transfers"]) for r in rs),2),
        })
    contrasts=[]
    for size,place,mode in itertools.product(SIZES,MAPS,MODES):
        base={int(x["seed"]):x["delivery_ratio"] for x in cells[(size,place,mode,"static")]}
        for m in ("quarter","all"):
            trial={int(x["seed"]):x["delivery_ratio"] for x in cells[(size,place,mode,m)]}
            diffs=[100*(trial[seed]-base[seed]) for seed in SEEDS]
            contrasts.append({
                "devices":size,"map":place,"mode":mode,"mobility":m,
                "seed_count":len(SEEDS),
                "mean_paired_gain_percentage_points":round(stats.fmean(diffs),5),
                "increased_seeds":sum(x>1e-8 for x in diffs),
                "decreased_seeds":sum(x< -1e-8 for x in diffs),
                "unchanged_seeds":sum(abs(x)<=1e-8 for x in diffs),
            })
    for name,rows in (("summary.csv",summary),("contrasts.csv",contrasts)):
        with (target/name).open("w",newline="") as f:
            w=csv.DictWriter(f,list(rows[0]))
            w.writeheader()
            w.writerows(rows)
    index={(r["devices"],r["map"],r["mode"],r["mobility"]):r for r in summary}
    lines=[
        "# LABO EXP-004 — density-controlled scaling with proportional traffic",
        "",
        "Synthetic software simulation, NOT physical Bluetooth or real message delivery.",
        f"{len(all_rows)} runs = 3 sizes x 2 maps x 2 radios x 3 movement modes x 3 paired seeds.",
        "Three seeds provide a PILOT comparison only, not narrow uncertainty bounds.",
        "1.5 messages per virtual device, 80 virtual steps, TTL 40.",
        "Maps scale in area: plaza 500m/1581m/5000m per side; building 1/10/100 wings.",
        "Each building wing is 5 floors, 70 rooms per floor and 5 staircases.",
        "The wings are separated, with NO modeled human movement between wings.",
        "A shared Wi-Fi infrastructure may be global for IP peers; BLE cannot jump wings.",
        "",
        "## Delivered percentage, mean of 3 seeds",
        "",
        "| Devices | Messages | Map | Mode | Static | 25% moving | All moving |",
        "|---:|---:|---|---|---:|---:|---:|",
    ]
    for size,place,mode in itertools.product(SIZES,MAPS,MODES):
        values=[index[(size,place,mode,m)]["mean_delivery_percent"] for m in MOBILITIES]
        lines.append(f"| {size:,} | {int(size*MSGS_PER_DEVICE):,} | {place} | {mode} | " +
            " | ".join(f"{v:.3f}%" for v in values) + " |")
    lines += [
        "", "## Rust simulation resources, 25% moving, medians of 3 seeds",
        "",
        "| Devices | Map | Radio | Wall seconds | Peak RSS MiB |",
        "|---:|---|---|---:|---:|",
    ]
    for size,place,mode in itertools.product(SIZES,MAPS,MODES):
        r=index[(size,place,mode,"quarter")]
        lines.append(f"| {size:,} | {place} | {mode} | {r['median_wall_seconds']:.4f} | {r['median_peak_rss_mib']:.2f} |")
    lines += [
        "", "## Interpretation",
        "",
        "- Relative to EXP-003, BOTH geometry scale and offered load are different;",
        "  they are not isolated in this study. No claim of caused effect from the",
        "  difference between EXP-003 and EXP-004 is justified.",
        "- A wing campus is NOT one uninterrupted five-floor building:",
        "  node movement between wings is not implemented, which fragments BLE.",
        "- Device contacts are simplified stochastic geometry; no real RF",
        "  measurements, background Android/iOS modes or radio interference.",
        "- Wi-Fi and cellular infrastructure still use idealized IP reachability;",
        "  ordinary W4 recipient signatures / app delivery are not implemented.",
        "- Each result is synthetic; CPU/RSS describe CI Rust simulator, not phones.",
        "- Data includes every run, identical seed initial-state fingerprints,",
        "  per-run wall and peak memory, and matched movement contrasts.",
    ]
    (target/"report.md").write_text("\n".join(lines)+"\n")
    (target/"manifest.json").write_text(json.dumps({
        "schema":"labo-exp004-summary-v1",
        "claim":"synthetic-not-measured",
        "scenarios":len(all_rows),"cells":len(cells),
        "seeds":SEEDS,"code_sha":os.environ.get("GITHUB_SHA","local"),
    },indent=2)+"\n")
    print("AGGREGATE_COMPLETE",len(all_rows),"runs",len(cells),"cells",flush=True)
    print("\n".join(lines),flush=True)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--devices",type=int,choices=SIZES)
    parser.add_argument("--program",type=Path,default=Path("target/release/labo"))
    parser.add_argument("--output",type=Path,default=Path("results/exp004"))
    parser.add_argument("--combine",action="store_true")
    parser.add_argument("--source",type=Path)
    args=parser.parse_args()
    if args.combine:
        if not args.source: parser.error("--combine requires --source")
        combine(args.source,args.output)
    else:
        if args.devices is None: parser.error("required --devices or --combine")
        run_scale(args.devices,args.program.resolve(),args.output)
if __name__=="__main__":
    main()
