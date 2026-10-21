#!/usr/bin/env python3
"""LABO: reproduce BLE RSS-vs-distance fits from six published phone campaigns.

Dataset: Aranda Polo et al., DOI 10.5281/zenodo.14835351.
Raw files are downloaded at runtime with pinned MD5 hashes; do not commit them.
RSS is observed advertising reception, not delivery probability or Tx power.
"""
import argparse
import csv
import hashlib
import io
import json
import math
from pathlib import Path
import statistics
import time
from urllib.request import Request, urlopen

SOURCE = "https://zenodo.org/records/14835351"
CAMPAIGNS = {
    "BQ_Aquaris_X": ("BQ_Aquaris_X_campaign_1.csv", "211b142b442d557b51e21a6531553b0c"),
    "Huawei_P30": ("Huawei_P30_campaign_1.csv", "6d192201d5010c1756b3ff43331f0764"),
    "Xiaomi_Mi_10": ("Xiaomi_Mi_10_campaign_1.csv", "81a5d9b13d8a73d4926b383f4efe8c5f"),
    "Xiaomi_Mi_8": ("Xiaomi_Mi_8_campaign_1.csv", "3097aabee7bd6983d7ad766dc8fb56dd"),
    "Xiaomi_Mi_A3": ("Xiaomi_Mi_A3_campaign_1.csv", "b11b1eead0828dc54d22acf5cec1cfa6"),
    "Xiaomi_Redmi_Note_Pro_8": (
        "Xiaomi_Redmi_Note_Pro_8_campaign_1.csv",
        "e9170aab2938be7b11ea1fd39ca9cdf3",
    ),
}
MAX_BYTES_PER_FILE = 1_000_000


def download_campaign(filename):
    from urllib.error import HTTPError, URLError
    urls = [
        f"{SOURCE}/files/{filename}?download=1",
        f"https://zenodo.org/api/records/14835351/files/{filename}/content",
    ]
    last_error = None
    for url in urls:
        for retry in range(3):
            try:
                request = Request(url, headers={
                    "User-Agent": "LaboAcademicResearch/1.0",
                    "Accept": "text/csv,*/*",
                })
                with urlopen(request, timeout=50) as response:
                    data = response.read(MAX_BYTES_PER_FILE + 1)
                if not data or len(data) > MAX_BYTES_PER_FILE:
                    raise ValueError("empty or oversized campaign")
                return data
            except (HTTPError, URLError, TimeoutError, OSError) as error:
                last_error = error
                time.sleep(retry + 1)
    raise RuntimeError(f"could not retrieve {filename}: {last_error}")


def verified_bytes(directory, filename, expected_md5, download):
    path = directory / filename
    if download and not path.exists():
        data = download_campaign(filename)
        actual = hashlib.md5(data).hexdigest()
        if actual != expected_md5:
            raise ValueError(f"checksum mismatch for {filename}: {actual}")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    data = path.read_bytes()
    if not data or len(data) > MAX_BYTES_PER_FILE:
        raise ValueError(f"file missing/oversized: {filename}")
    actual = hashlib.md5(data).hexdigest()
    if actual != expected_md5:
        raise ValueError(f"checksum mismatch for {filename}: expected {expected_md5}, got {actual}")
    return data


def parse_rss_csv(data):
    text = data.decode("utf-8-sig")
    reader = csv.DictReader(io.StringIO(text), delimiter=";")
    if not reader.fieldnames:
        raise ValueError("missing CSV header")
    labels = {name.strip().lower(): name for name in reader.fieldnames}
    if not {"rss_dbm", "distance_gt_m"}.issubset(labels):
        raise ValueError(f"unrecognized dataset header {reader.fieldnames}")
    groups = {}
    rejected = 0
    seen = 0
    for row in reader:
        seen += 1
        try:
            rssi = float(row[labels["rss_dbm"]])
            distance = float(row[labels["distance_gt_m"]])
        except (ValueError, TypeError, KeyError):
            rejected += 1
            continue
        if not (math.isfinite(rssi) and -125.0 <= rssi <= -10.0
                and math.isfinite(distance) and 0.1 <= distance <= 1000.0):
            rejected += 1
            continue
        groups.setdefault(distance, []).append(rssi)
    if seen < 20 or seen - rejected < 20 or rejected > seen // 20:
        raise ValueError(f"insufficient / unreliable raw data: valid={seen-rejected}, bad={rejected}")
    return groups, seen, rejected


def regression(pairs):
    """Ordinary least squares on x=log10(distance) and y=RSS in dBm."""
    if len(pairs) < 2:
        raise ValueError("at least two unique distances required")
    xs = [math.log10(float(d)) for d, _ in pairs]
    ys = [float(r) for _, r in pairs]
    x_mean = statistics.fmean(xs)
    y_mean = statistics.fmean(ys)
    variance = sum((x - x_mean) ** 2 for x in xs)
    if variance < 1e-9:
        raise ValueError("insufficient spread of distances")
    slope = sum((x - x_mean) * (y - y_mean) for x, y in zip(xs, ys)) / variance
    intercept = y_mean - slope * x_mean
    return intercept, -slope / 10.0


def fit_campaign(name, filename, checksum, data):
    groups, seen, rejected = parse_rss_csv(data)
    if len(groups) < 3:
        raise ValueError(f"{name}: fewer than three distinct measured distances")
    medians = [(distance, statistics.median(samples))
               for distance, samples in sorted(groups.items())]
    intercept, exponent = regression(medians)
    all_errors = []
    for d, values in groups.items():
        predicted = intercept - 10.0 * exponent * math.log10(d)
        all_errors.extend(value - predicted for value in values)
    # Leave-one-distance-out predicts an *unseen measured distance*.
    holdout_errors = []
    for i, (distance, median) in enumerate(medians):
        remaining = medians[:i] + medians[i+1:]
        fitted_intercept, fitted_exponent = regression(remaining)
        predicted = fitted_intercept - 10.0 * fitted_exponent * math.log10(distance)
        holdout_errors.append(predicted - median)
    result = {
        "device": name,
        "source_filename": filename,
        "source_md5": checksum,
        "sample_count": seen - rejected,
        "rejected_samples": rejected,
        "distance_levels": len(groups),
        "min_distance_m": min(groups),
        "max_distance_m": max(groups),
        "rssi_at_1m_dbm": round(intercept, 4),
        "path_loss_exponent": round(exponent, 5),
        "raw_residual_rmse_db": round(
            math.sqrt(statistics.fmean(e*e for e in all_errors)), 4),
        "holdout_median_rmse_db": round(
            math.sqrt(statistics.fmean(e*e for e in holdout_errors)), 4),
        "rssi_measured_only": True,
        "fit_method": "OLS on equally weighted per-distance median RSS",
    }
    # Parameters that do not meet runtime bounds must never be silently clipped.
    result["usable_for_labo_budget"] = (
        0.5 <= exponent <= 6.0 and -120.0 <= intercept <= -10.0
    )
    result["measured_medians"] = [
        {"distance_m": d, "median_rssi_dbm": round(m, 3), "samples": len(groups[d])}
        for d, m in medians
    ]
    return result


def check_pinned_snapshot(results, path):
    with path.open(newline="", encoding="utf-8") as f:
        existing = list(csv.DictReader(f))
    if len(existing) != len(results):
        raise AssertionError(f"pinned profile count changed: {len(existing)} != {len(results)}")
    found = {r["device"]: r for r in results}
    for old in existing:
        current = found.pop(old["device"], None)
        if current is None:
            raise AssertionError(f"unknown pinned phone: {old['device']}")
        for field in ("source_md5", "sample_count", "distance_levels",
                      "min_distance_m", "max_distance_m", "rssi_at_1m_dbm",
                      "path_loss_exponent", "holdout_median_rmse_db"):
            expected = old[field]
            actual = current[field]
            if field == "source_md5":
                equal = expected == actual
            else:
                equal = abs(float(expected) - float(actual)) < 0.000051
            if not equal:
                raise AssertionError(
                    f"published RF snapshot changed: {old['device']} {field}: "
                    f"stored={expected} current={actual}")
    if found:
        raise AssertionError(f"unrecognized new device fits: {sorted(found)}")


def fit_all(source_dir, output_dir, download, snapshot=None):
    results = []
    for name, (filename, checksum) in CAMPAIGNS.items():
        data = verified_bytes(source_dir, filename, checksum, download)
        result = fit_campaign(name, filename, checksum, data)
        results.append(result)
        print("MEASURED_RSSI_FIT",
              result["device"], "samples", result["sample_count"],
              "d_range", (result["min_distance_m"], result["max_distance_m"]),
              "rss_1m_dbm", result["rssi_at_1m_dbm"],
              "pathloss_n", result["path_loss_exponent"],
              "heldout_rmse_db", result["holdout_median_rmse_db"],
              "usable", result["usable_for_labo_budget"], flush=True)
    if snapshot is not None:
        check_pinned_snapshot(results, snapshot)
        print("PINNED_MEASURED_RSSI_SNAPSHOT_VERIFIED", len(results), flush=True)
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "schema": "labo-rssi-calibration-v1",
        "dataset_doi": "10.5281/zenodo.14835351",
        "dataset_url": SOURCE,
        "claim": "measured-RSSI-fitted-model-not-delivery",
        "parameters_are_transmitter_receiver_pair_effects": True,
        "phones": results,
    }
    (output_dir / "profiles.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    headers = [
        "device", "source_filename", "source_md5", "sample_count",
        "rejected_samples", "distance_levels", "min_distance_m", "max_distance_m",
        "rssi_at_1m_dbm", "path_loss_exponent", "raw_residual_rmse_db",
        "holdout_median_rmse_db", "usable_for_labo_budget",
    ]
    with (output_dir / "profiles.csv").open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=headers, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(results)
    summary = [
        "# LABO — fitted real Bluetooth RSS from published phone campaigns",
        "",
        "Measured *received signal strength*, NOT true delivery or transmit output power.",
        f"Source: {SOURCE}; DOI 10.5281/zenodo.14835351.",
        "Only observed received advertisements are in the dataset: no samples",
        "for invisible devices; fit does not identify missed advertisements or packets.",
        "Campaign setup, room and antenna differ from Akula. Power sensitivity,",
        "walls, foreground/background behavior and interference are still hypotheses.",
        "Do not extrapolate beyond each phone's measured distance range.",
        "",
        "| Device | Valid observations | Distances | RSS at 1 m, dBm | n | Leave-distance-out RMSE, dB | Runtime-compatible |",
        "|---|---:|---:|---:|---:|---:|---|",
    ]
    for r in results:
        summary.append(
            f"| {r['device']} | {r['sample_count']} | {r['distance_levels']} | "
            f"{r['rssi_at_1m_dbm']:.2f} | {r['path_loss_exponent']:.3f} | "
            f"{r['holdout_median_rmse_db']:.2f} | {r['usable_for_labo_budget']} |"
        )
    summary += [
        "", "Model: RSS(d) = RSS(1m) - 10*n*log10(d/metre),",
        "OLS on one median per distance, not a per-packet iid fit.",
        "LODO validation holds out entire distance groups, not random packets.",
        "Phone-specific intercept is **not** a measurement of antenna Tx power.",
        "Values outside supported runtime parameter bounds remain in CSV marked unusable.",
        "",
    ]
    (output_dir / "report.md").write_text("\n".join(summary), encoding="utf-8")
    print("\n".join(summary), flush=True)
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", type=Path, default=Path("results/zenodo-14835351"))
    parser.add_argument("--output", type=Path, default=Path("results/rssi-calibration"))
    parser.add_argument("--download", action="store_true", help="fetch missing pinned files")
    parser.add_argument("--verify-snapshot", type=Path,
                        help="compare measured fits to tracked exact derived coefficients")
    args = parser.parse_args()
    fit_all(args.input_dir, args.output, args.download, snapshot=args.verify_snapshot)


if __name__ == "__main__":
    main()
