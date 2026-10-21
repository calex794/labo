#!/usr/bin/env python3
"""LABO EXP-003: paired fixed-load comparison of 2k, 20k and 200k devices.
Measures synthetic delivery, process wall/CPU seconds and Linux peak RSS.
NOT physical radio testing or the Akula application itself.
"""
import argparse
import csv
import itertools
import json
import os
from pathlib import Path
import statistics as stats
import subprocess
import sys
import tempfile
import time

SIZES = (2000, 20000, 200000)
MAPS = ("building", "plaza")
MODES = ("wifi", "ble", "hybrid", "exclusive")
MOBILITY = ("static", "quarter", "all")
SEEDS = tuple(range(21021, 21031))
LOAD = 3000
STEPS = 120

def call(program, args):
    assert sys.platform.startswith("linux"), "RSS requires Linux os.wait4"
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        start = time.perf_counter()
        child = subprocess.Popen([str(program), *args], stdout=out, stderr=err)
        _, wait_status, resources = os.wait4(child.pid, 0)
        elapsed = time.perf_counter() - start
        out.seek(0)
        err.seek(0)
        stdout = out.read().decode()
        stderr = err.read().decode()
    if os.waitstatus_to_exitcode(wait_status) != 0:
        raise RuntimeError(stderr[-5000:])
    result = json.loads(stdout.strip())
    assert result["claim"] == "synthetic-not-measured"
    result["wall_seconds"] = round(elapsed, 6)
    result["cpu_seconds"] = round(resources.ru_utime + resources.ru_stime, 6)
    result["peak_rss_mib"] = round(resources.ru_maxrss / 1024.0, 6)
    return result

def run_size(devices, program, output):
    output.mkdir(parents=True, exist_ok=True)
    records = []
    checks = 0
    start = time.perf_counter()
    with (output / f"runs-{devices}.ndjson").open("w") as stream:
        for seed in SEEDS:
            message_pairs = None
            hardware_by_mode = {}
            initial_by_map_mode = {}
            for place, mode, mobility in itertools.product(MAPS, MODES, MOBILITY):
                args = [
                    "--map", place, "--mode", mode, "--mobility", mobility,
                    "--outages", "periodic", "--devices", str(devices),
                    "--messages", str(LOAD), "--steps", str(STEPS),
                    "--ttl", "60", "--contact-probes", "8",
                    "--relay-percent", "20", "--seed", str(seed),
                ]
                r = call(program, args)
                assert r["devices"] == devices and r["created"] == LOAD
                assert r["created"] == r["delivered"] + r["expired"] + r["pending"]
                assert (r["map"], r["mode"], r["mobility"], r["seed"]) == (place, mode, mobility, seed)
                assert len(r["message_pairs_fingerprint"]) == 16
                assert len(r["initial_devices_fingerprint"]) == 16
                assert len(r["interface_consent_fingerprint"]) == 16
                if message_pairs is None:
                    message_pairs = r["message_pairs_fingerprint"]
                assert r["message_pairs_fingerprint"] == message_pairs, "unpaired messages"
                key = (place, mode)
                initial = initial_by_map_mode.setdefault(key, r["initial_devices_fingerprint"])
                assert initial == r["initial_devices_fingerprint"], "changed devices in movement comparison"
                hw = hardware_by_mode.setdefault(mode, r["interface_consent_fingerprint"])
                assert hw == r["interface_consent_fingerprint"], "unpaired radio/relay consent across maps"
                if mobility == "static":
                    assert r["mobile_devices"] == 0
                if mobility == "all":
                    assert r["mobile_devices"] == devices
                if mobility == "quarter":
                    assert 0 < r["mobile_devices"] < devices
                records.append(r)
                checks += 1
                stream.write(json.dumps(r, sort_keys=True) + "\n")
            print("SEED_DONE", devices, seed, len(records), flush=True)
    assert len(records) == 240
    with (output / f"runs-{devices}.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, list(records[0]))
        w.writeheader()
        w.writerows(records)
    manifest = {
        "schema": "labo-exp003-run-v1",
        "devices": devices, "seeds": list(SEEDS), "simulations": len(records),
        "fingerprint_assertions_passed": checks, "messages_per_run": LOAD,
        "steps": STEPS, "source_sha": os.environ.get("GITHUB_SHA", "local"),
        "elapsed_seconds": round(time.perf_counter() - start, 3),
        "measurement": "Linux child os.wait4 ru_maxrss; shared CI runner",
        "note": "Fixed maps and fixed messages, increasing population density; synthetic radio contacts",
    }
    (output / f"manifest-{devices}.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print("SIZE_VERIFIED", json.dumps(manifest, sort_keys=True), flush=True)

def summarize(source, dest):
    dest.mkdir(parents=True, exist_ok=True)
    records = []
    for devices in SIZES:
        name = source / f"runs-{devices}.csv"
        assert name.is_file(), f"missing scale {devices}"
        with name.open(newline="") as f:
            rows = list(csv.DictReader(f))
        assert len(rows) == 240, (devices, len(rows))
        for r in rows:
            assert r["claim"] == "synthetic-not-measured"
            assert int(r["devices"]) == devices
            assert int(r["created"]) == int(r["delivered"]) + int(r["expired"]) + int(r["pending"])
            for field in ("delivery_ratio", "wall_seconds", "cpu_seconds", "peak_rss_mib"):
                r[field] = float(r[field])
        records.extend(rows)
    assert len(records) == 720
    groups = {}
    for r in records:
        key = (int(r["devices"]), r["map"], r["mode"], r["mobility"])
        groups.setdefault(key, []).append(r)
    assert len(groups) == 72 and all(len(v) == len(SEEDS) for v in groups.values())
    summary = []
    for (devices, place, mode, mobility), rs in sorted(groups.items()):
        delivery = [r["delivery_ratio"] * 100 for r in rs]
        summary.append({
            "devices": devices, "map": place, "mode": mode, "mobility": mobility,
            "n_seeds": len(rs),
            "mean_delivery_pct": round(stats.fmean(delivery), 5),
            "sd_delivery_pp": round(stats.stdev(delivery), 5),
            "median_wall_s": round(stats.median(r["wall_seconds"] for r in rs), 6),
            "median_cpu_s": round(stats.median(r["cpu_seconds"] for r in rs), 6),
            "median_peak_rss_mib": round(stats.median(r["peak_rss_mib"] for r in rs), 5),
        })
    comparisons = []
    for devices, place, mode in itertools.product(SIZES, MAPS, MODES):
        static = {int(r["seed"]):r["delivery_ratio"] for r in groups[(devices,place,mode,"static")]}
        for moving in ("quarter", "all"):
            active = {int(r["seed"]):r["delivery_ratio"] for r in groups[(devices,place,mode,moving)]}
            diffs = [100 * (active[s] - static[s]) for s in SEEDS]
            comparisons.append({
                "devices": devices, "map": place, "mode": mode, "mobility": moving,
                "n_seeds": len(SEEDS), "paired_change_pp": round(stats.fmean(diffs), 5),
                "better": sum(d > 1e-8 for d in diffs),
                "worse": sum(d < -1e-8 for d in diffs),
                "equal": sum(abs(d) <= 1e-8 for d in diffs),
            })
    def csv_write(name, rows):
        with (dest/name).open("w",newline="") as f:
            w = csv.DictWriter(f, list(rows[0]))
            w.writeheader()
            w.writerows(rows)
    csv_write("summary.csv", summary)
    csv_write("paired-differences.csv", comparisons)
    lookup = {(r["devices"],r["map"],r["mode"],r["mobility"]):r for r in summary}
    lines = [
        "# LABO EXP-003 — 720 synthetic scale/geometry experiments", "",
        "10 random seeds for each configuration, 3,000 messages and 120 virtual steps per run.",
        "Identical message pairs, radios and voluntary relays within a seed, even across maps.",
        "Fixed-area building: 5 floors, 350 offices; fixed-area plaza: 500x500 metres.",
        "200k in a building means ~571 devices per office; this is a mathematical stress test.",
        "Synthetic deliveries are NOT real BLE/Wi-Fi field measurements or verified WOW receipts.", "",
        "## Delivery, mean percent across 10 seeds", "",
        "| Devices | Map | Radio | Static | 25% moving | All moving |",
        "|---:|---|---|---:|---:|---:|",
    ]
    for n, place, mode in itertools.product(SIZES, MAPS, ("ble","hybrid","exclusive","wifi")):
        vals = [lookup[(n,place,mode,m)]["mean_delivery_pct"] for m in MOBILITY]
        lines.append(f"| {n} | {place} | {mode} | {vals[0]:.3f}% | {vals[1]:.3f}% | {vals[2]:.3f}% |")
    lines += ["", "## Actual model process performance (median of 10 trials)", "",
        "| Devices | Map | Mode | Mobility | Wall seconds | CPU seconds | Peak RSS MiB |",
        "|---:|---|---|---|---:|---:|---:|"]
    for n, place, mode in itertools.product(SIZES, MAPS, ("ble","hybrid")):
        r = lookup[(n,place,mode,"quarter")]
        lines.append(f"| {n} | {place} | {mode} | quarter | {r['median_wall_s']:.4f} | {r['median_cpu_s']:.4f} | {r['median_peak_rss_mib']:.2f} |")
    lines += [
        "", "## Important design limitations", "",
        "- All scales have the same 3,000 messages: messages per device decrease as N grows.",
        "- Both geometries have fixed area: population density increases dramatically.",
        "- Idealized shared Wi-Fi is a fully routable local network, yielding 100% by assumption.",
        "- Bluetooth range and wall loss are assumed, not measured.",
        "- CPU/wall and max RSS are measured for the simulator subprocess on GitHub runners.",
        "- There is no physical phone energy, operating system background BLE, or real WOW receipt.",
        "- Raw per-seed runs and the paired comparison are preserved in the same workflow.",
    ]
    (dest/"report.md").write_text("\n".join(lines)+"\n")
    (dest/"manifest.json").write_text(json.dumps({
        "schema":"labo-exp003-summary-v1", "simulations":len(records),
        "groups":len(groups),"seeds":len(SEEDS),"source_sha":os.environ.get("GITHUB_SHA","local"),
        "claim":"synthetic-not-measured"},indent=2)+"\n")
    print("AGGREGATE_SUCCESS 720 scenarios, 72 groups, 10 seeds",flush=True)
    print("\n".join(lines),flush=True)

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--devices",type=int,choices=SIZES)
    ap.add_argument("--program",type=Path,default=Path("target/release/labo"))
    ap.add_argument("--output",type=Path,default=Path("results/exp003"))
    ap.add_argument("--aggregate",action="store_true")
    ap.add_argument("--input-dir",type=Path)
    args = ap.parse_args()
    if args.aggregate:
        if not args.input_dir:
            ap.error("needs --input-dir")
        summarize(args.input_dir,args.output)
    elif args.devices:
        run_size(args.devices,args.program.resolve(),args.output)
    else:
        ap.error("specify --devices or --aggregate")
if __name__ == "__main__":
    main()
