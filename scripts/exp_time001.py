#!/usr/bin/env python3
"""LABO EXP-TIME-001: non-mutating clock observations via chronyd -Q.

This is a single-host experiment, not an assertion of absolute UTC accuracy.
"""

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import json
from pathlib import Path
import platform
import re
import socket
import statistics
import subprocess
import tempfile
import time

OFFSET = re.compile(r"System clock wrong by\s+([+-]?\d+(?:\.\d+)?)\s+seconds\s+\(ignored\)")
NTP_PORT = 11123
NTS_PORT = 14460


def run_command(args, timeout=12):
    start = time.monotonic_ns()
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                              check=False)
        return {"returncode": proc.returncode,
                "output": (proc.stdout + "\n" + proc.stderr)[-10000:],
                "elapsed_ms": round((time.monotonic_ns() - start) / 1e6, 3)}
    except subprocess.TimeoutExpired as exc:
        return {"returncode": None, "output": str(exc),
                "elapsed_ms": round((time.monotonic_ns() - start) / 1e6, 3)}
    except OSError as exc:
        return {"returncode": None, "output": str(exc),
                "elapsed_ms": round((time.monotonic_ns() - start) / 1e6, 3)}


def classify_probe(result):
    match = OFFSET.search(result["output"])
    ok = result["returncode"] == 0 and match is not None
    return {"status": "measured" if ok else "unavailable",
            "offset_ms": round(float(match.group(1)) * 1000, 6) if ok else None,
            "elapsed_ms": result["elapsed_ms"],
            "exit_code": result["returncode"],
            "evidence": result["output"][-2500:]}


def snapshot():
    cmds = ["timedatectl", "show", "-p", "NTPSynchronized", "-p", "NTP"]
    state = run_command(cmds, timeout=3)
    return {"utc": datetime.now(timezone.utc).isoformat(),
            "host_epoch_ns": time.time_ns(),
            "monotonic_ns": time.monotonic_ns(),
            "platform": platform.platform(),
            "timedatectl": state["output"].strip() if state["returncode"] == 0 else None,
            "chronyd_version": run_command(["chronyd", "-v"], timeout=3)["output"].strip()}


def probe(source, *, timeout, config="/dev/null"):
    args = ["chronyd", "-Q", "-t", str(timeout), "-f", str(config), source]
    result = run_command(args, timeout=timeout + 3)
    return classify_probe(result)


def server_config(home):
    return (f"pidfile {home / 'server.pid'}\n"
            "cmdport 0\n"
            "bindcmdaddress /\n"
            "bindaddress 127.0.0.1\n"
            f"port {NTP_PORT}\n"
            f"ntsport {NTS_PORT}\n"
            "allow 127.0.0.1\n"
            "local stratum 10\n"
            f"ntsservercert {home / 'cert.pem'}\n"
            f"ntsserverkey {home / 'key.pem'}\n"
            f"ntsdumpdir {home / 'nts'}\n")


def local_source():
    return (f"server 127.0.0.1 iburst maxsamples 1 nts "
            f"port {NTP_PORT} ntsport {NTS_PORT} certset 1")


def public_source(host):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,250}", host):
        raise ValueError("Only a DNS host name is permitted")
    return f"server {host} iburst maxsamples 1 nts"


@contextmanager
def local_nts_server(home):
    openssl = ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
               "-sha256", "-days", "1", "-keyout", str(home / 'key.pem'),
               "-out", str(home / 'cert.pem'), "-subj", "/CN=localhost",
               "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
               "-addext", "extendedKeyUsage=serverAuth", "-batch"]
    created = run_command(openssl, timeout=10)
    if created["returncode"] != 0:
        raise RuntimeError("Could not create ephemeral certificate: " + created["output"][-400:])
    (home / "nts").mkdir()
    (home / "server.conf").write_text(server_config(home), encoding="utf-8")
    (home / "client.conf").write_text(
        f"nosystemcert\nntstrustedcerts 1 {home / 'cert.pem'}\n", encoding="utf-8")
    with (home / "server.log").open("w", encoding="utf-8") as log:
        server = subprocess.Popen(["chronyd", "-U", "-x", "-d", "-f",
                                   str(home / "server.conf")], stdout=log,
                                  stderr=subprocess.STDOUT, start_new_session=True)
        try:
            until = time.monotonic() + 7
            ready = False
            while time.monotonic() < until and server.poll() is None:
                try:
                    with socket.create_connection(("127.0.0.1", NTS_PORT), timeout=0.3):
                        ready = True
                        break
                except OSError:
                    time.sleep(0.15)
            if not ready:
                raise RuntimeError("Local NTS-KE server did not listen: " +
                                   (home / "server.log").read_text(errors="replace")[-1200:])
            yield server
        finally:
            if server.poll() is None:
                server.terminate()
                try:
                    server.wait(timeout=4)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait(timeout=3)


def summary(rows):
    measured = [r for r in rows if r["status"] == "measured"]
    offsets = [abs(r["offset_ms"]) for r in measured]
    durations = [r["elapsed_ms"] for r in measured]
    return {"attempts": len(rows), "measured": len(measured),
            "failed": len(rows) - len(measured),
            "median_abs_offset_ms": round(statistics.median(offsets), 6) if offsets else None,
            "median_probe_duration_ms": round(statistics.median(durations), 3) if durations else None}


def report(data):
    lines = ["# LABO EXP-TIME-001 — measured on one hosted Linux runner", "",
             f"Date: {data['system_before']['utc']}",
             "", "**Not a physical two-device test. Not an absolute-UTC accuracy test.**",
             "", "| Mode | Attempts | Measured | Median abs offset vs server, ms | Median whole probe, ms |",
             "|---|---:|---:|---:|---:|"]
    for key, label in [("public_nts", "Public NTS"), ("own_loopback_nts", "Local Akula-like NTS")]:
        s = data["summary"][key]
        lines.append(f"| {label} | {s['attempts']} | {s['measured']} | "
                     f"{s['median_abs_offset_ms'] if s['median_abs_offset_ms'] is not None else 'N/A'} | "
                     f"{s['median_probe_duration_ms'] if s['median_probe_duration_ms'] is not None else 'N/A'} |")
    lines.extend(["", f"Local server: {data['local_server']['status']}; "
                  f"after-stop: {data['outage']['status']}.",
                  f"Public NTS: {data['public_reachability']}.", "",
                  "Interpretation:",
                  "- Baseline system clock was observed but **never adjusted**.",
                  "- All probes used only NTS sources, without insecure NTP fallback.",
                  "- The local server uses the **same host clock** as its client; a near-zero offset "
                  "does NOT prove accuracy against UTC or improvement over public NTS.",
                  "- Whole-probe duration includes NTS-KE, DNS, startup and NTP samples; it is NOT packet RTT.",
                  "- The outage is a short server-stop/connection check, not a multi-day drift study.",
                  "- Real-device comparison requires an independent reference and physical client machines."])
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--public-host", default="time.cloudflare.com")
    parser.add_argument("--samples", type=int, default=3)
    parser.add_argument("--timeout", type=int, default=9)
    args = parser.parse_args()
    if not 1 <= args.samples <= 30 or not 2 <= args.timeout <= 30:
        parser.error("Require 1..30 samples and timeout 2..30 seconds")
    args.output.mkdir(parents=True, exist_ok=True)
    data = {"schema": "labo-exp-time001-v1", "claim": "one-host-ci-observations",
            "physical_devices_tested": False, "system_clock_modified": False,
            "independent_utc_reference": False, "clock_sync_methods_applied": False,
            "system_before": snapshot(), "samples": {"public_nts": [], "own_loopback_nts": []},
            "local_server": {"status": "not-started"}, "outage": {"status": "not-run"}}
    with tempfile.TemporaryDirectory(prefix="labo-time001-") as td:
        home = Path(td)
        try:
            with local_nts_server(home):
                data["local_server"]["status"] = "listening"
                local_cfg = home / "client.conf"
                for i in range(args.samples):
                    modes = ["public_nts", "own_loopback_nts"]
                    if i % 2:
                        modes.reverse()
                    for mode in modes:
                        source = public_source(args.public_host) if mode == "public_nts" else local_source()
                        config = "/dev/null" if mode == "public_nts" else local_cfg
                        row = probe(source, timeout=args.timeout, config=config)
                        row["round"] = i + 1
                        data["samples"][mode].append(row)
            data["local_server"]["status"] = "stopped"
            data["outage"] = probe(local_source(), timeout=3, config=home / "client.conf")
            data["outage"]["status"] = ("unexpected-success" if data["outage"]["status"] == "measured"
                                        else "expected-unreachable")
            data["local_server"]["log_excerpt"] = (home / "server.log").read_text(
                encoding="utf-8", errors="replace")[-3000:]
        except (RuntimeError, OSError) as exc:
            data["local_server"]["status"] = "failed"
            data["local_server"]["error"] = str(exc)[-1500:]
    data["summary"] = {key: summary(rows) for key, rows in data["samples"].items()}
    data["public_reachability"] = ("measured" if data["summary"]["public_nts"]["measured"]
                                    else "blocked-or-unavailable")
    data["system_after"] = snapshot()
    (args.output / "observations.json").write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
    (args.output / "report.md").write_text(report(data))
    print(json.dumps({"summary": data["summary"], "outage": data["outage"]["status"],
                      "local_server": data["local_server"]["status"],
                      "public_reachability": data["public_reachability"]}, ensure_ascii=False))
    return 0 if (data["summary"]["own_loopback_nts"]["measured"] >= 1
                 and data["outage"]["status"] == "expected-unreachable") else 1


if __name__ == "__main__":
    raise SystemExit(main())
