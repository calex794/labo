#!/usr/bin/env python3
"""TIME-03: validate 504 paired synthetic rows and write decision evidence."""
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path
from statistics import mean

raw=Path(sys.argv[1]); out=Path(sys.argv[2]); out.mkdir(exist_ok=True,parents=True)
records=[json.loads(x) for x in raw.read_text().splitlines() if x.startswith("{")]
assert len(records)==3*6*7*4, len(records)
groups=defaultdict(list)
seen=set()
for r in records:
    assert r["schema"]=="labo-time03-byzantine-clock-v1"
    assert r["claim"]=="synthetic-not-a-time-service"
    assert r["cryptography"]=="ed25519-dalek-verified-lab-signatures"
    assert r["operator_diversity"]=="trusted-registry-model-assumption"
    assert r["utc_from_tag"] is False
    assert r["trials"]==256
    assert r["queries"]==r["trials"]*r["requested_witnesses"]
    assert r["naive_good"]+r["naive_false"]+r["naive_unknown"]==r["trials"]
    assert r["guarded_good"]+r["guarded_false"]+r["guarded_unknown"]==r["trials"]
    assert r["seed"] in (21,71,107)
    assert r["bad_percent"] in (1,5,10,20,40,70,90)
    assert r["requested_witnesses"] in (1,2,3,5)
    assert r["scenario"] in ("signed-false-time","replay","delayed-response","visible-split-view","sybil-same-operator","mixed")
    assert r["guarded_unknown"]==r["trials"] if r["requested_witnesses"]<3 else True
    k=(r["seed"],r["scenario"],r["bad_percent"],r["requested_witnesses"])
    assert k not in seen
    seen.add(k); groups[k[1:]].append(r)
assert len(groups)==6*7*4 and all(len(v)==3 for v in groups.values())
rows=[]
for (attack,pct,n),v in sorted(groups.items()):
    denom=sum(x["trials"] for x in v)
    def percent(key): return round(100*sum(x[key] for x in v)/denom,3)
    rows.append(dict(attack=attack,bad_percent=pct,witnesses=n,trials=denom,
      naive_correct_pct=percent("naive_good"),naive_false_pct=percent("naive_false"),
      guarded_correct_pct=percent("guarded_good"),guarded_false_pct=percent("guarded_false"),
      guarded_unknown_pct=percent("guarded_unknown"),
      replay_rejected=sum(x["replay_rejected"] for x in v),
      delayed_rejected=sum(x["delay_rejected"] for x in v),
      conflicting_pairs_detected=sum(x["forks_observed"] for x in v),
      repeated_operator_keys_ignored=sum(x["duplicate_operators"] for x in v)))
with (out/"summary.csv").open("w",newline="") as f:
    w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
(out/"summary.json").write_text(json.dumps({"schema":"labo-time03-summary-v1",
    "claim":"synthetic-not-a-time-service","cells":len(rows),"raw_runs":len(records),
    "trials_per_seed":256,"rows":rows},indent=2)+"\n")
report=["# LABO TIME-03 — signed Byzantine time witnesses",
"","**Ed25519 signatures are real but UTC truth, source diversity, RTT and compromise are synthetic.**",
"One/two signed timestamps are never enough for conservative automatic UTC acceptance.",
"Three-witness acceptance requires 3 agreeing independent operators; five requires 4.",
"The benchmark compares naive signed median and guarded agreement; neither proves UTC truth",
"when all witnesses sharing a timestamp are dishonest.",
"","| Attack | Bad sources | Sources | Naive false % | Guarded false % | Guarded correct % | Guarded unknown % |",
"|---|---:|---:|---:|---:|---:|---:|"]
for r in rows:
    if r["attack"] in ("signed-false-time","sybil-same-operator","mixed"):
        report.append(f'| {r["attack"]} | {r["bad_percent"]}% | {r["witnesses"]} | {r["naive_false_pct"]} | {r["guarded_false_pct"]} | {r["guarded_correct_pct"]} | {r["guarded_unknown_pct"]} |')
report+=["","## Model limits",
"- Operator ownership is a trusted oracle in this experiment; different real PeerIDs or IPs do NOT prove independence.",
"- Ed25519 signature authenticates a *claim*, not its factual accuracy.",
"- Replay old nonce is detected; malicious delays beyond 5s RTT are refused, but sub-threshold asymmetric delay is not modelled.",
"- Split-view is detected only when BOTH signed contradictory answers are observed by a verifier.",
"- Majority collusion can still force confidently wrong UTC; false-accept must not be described as impossible.",
"- No deployed Roughtime, NTS, W3, W4, CLOCK_BOOTTIME, SQLite/WAL, TPM, radio or real QUIC.",
"- A conservative UNKNOWN state is an intended safe outcome, not a recovered time.",
"- Synthetic Ed25519 private keys are derived from a predictable laboratory seed and are NEVER suitable for production."]
(out/"report.md").write_text("\n".join(report)+"\n")
print("\n".join(report))
