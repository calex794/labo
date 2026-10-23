#!/usr/bin/env python3
"""Validate seven adversarial fractions across seven profiles and aggregate Rust JSON."""
import argparse
import csv
import json
from pathlib import Path
from statistics import mean

FRACTIONS=(1,5,10,20,40,70,90)
PROFILES=("mixed","refusal","bad-bytes","audit-evasion","unstable","collusion","late-compromise")
SEEDS=(21,71,107)

def summarize(folder):
    rows=[]
    for profile in PROFILES:
        for pct in FRACTIONS:
            runs=[]
            for seed in SEEDS:
                p=folder/f"{profile}-{pct}-{seed}.json"
                r=json.loads(p.read_text())
                assert r["schema"]=="labo-exp019-adversarial-custodian-grid-v1"
                assert r["claim"]=="synthetic-not-measured"
                assert r["custodians"]==1000 and r["messages"]==50000
                assert r["profile"]==profile and r["bad_percent"]==pct and r["seed"]==seed
                assert r["actual_bad_nodes"]==pct*10
                assert sum(r["behavior_counts"].values())==1000
                assert r["max_logical_c_slots_per_message"]==1
                for name in ("random","scored"):
                    s=r[name]
                    assert s["max_logical_c_slots"]<=1
                    assert 0<=s["delivered_synthetic_exact_read"]<=s["actual_read"]<=s["stored"]<=s["selected"]<=s["created"]
                    assert s["intended_read"]>=s["actual_read"]
                    assert s["good_nodes_suspended"]==0
                    assert s["no_honest_candidate"]==r["random"]["no_honest_candidate"]
                runs.append(r)
            rows.append(dict(
                profile=profile, compromised_percent=pct, bad_nodes=pct*10,
                random_delivery_percent=round(mean(100*r["random"]["delivered_synthetic_exact_read"]/r["messages"] for r in runs),3),
                scored_delivery_percent=round(mean(100*r["scored"]["delivered_synthetic_exact_read"]/r["messages"] for r in runs),3),
                gain_pp=round(mean(r["paired_gain_pp_created"] for r in runs),3),
                all_compromised_candidate_percent=round(mean(100*r["scored"]["no_honest_candidate"]/r["messages"] for r in runs),3),
                bad_suspended_mean=round(mean(r["scored"]["bad_nodes_suspended"] for r in runs),1),
                bad_deprioritized_mean=round(mean(r["scored"]["bad_nodes_deprioritized"] for r in runs),1),
                honest_false_deprioritized_mean=round(mean(r["scored"]["good_nodes_deprioritized"] for r in runs),1),
                audit_bytes_per_policy=round(mean(r["scored"]["audit_bytes_model"] for r in runs)),
            ))
    assert len(rows)==49
    return rows

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--input",type=Path,default=Path("results/exp019"))
    a=p.parse_args()
    rows=summarize(a.input)
    with (a.input/"summary.csv").open("w",newline="") as f:
        writer=csv.DictWriter(f,fieldnames=rows[0].keys())
        writer.writeheader();writer.writerows(rows)
    (a.input/"summary.json").write_text(json.dumps({"schema":"labo-exp019-grid-summary-v1","claim":"synthetic-not-measured","custodians":1000,"messages_per_cell_per_seed":50000,"seeds":SEEDS,"fractions":FRACTIONS,"profiles":PROFILES,"cells":len(rows),"raw_runs":len(rows)*len(SEEDS),"rows":rows},indent=2)+"\n")
    lines=["# LABO EXP-019: 1000 synthetic custodians under 1–90% failures","",
      "**Modelled assumptions, not real W3/W4, cryptographic witnesses or physical server failures.**",
      "49 cells = seven fractions × seven attacks; three paired seeds/cell = 147 executions.",
      "Each policy sees identical creation times, intended recipients, candidate lists and keyed outcomes.",
      "Read success is a synthetic exact answer, NOT an authenticated recipient W4.",
      "The fixed private candidate set contains six eligible peers; old C-slots are never duplicated.",
      "Rows averaged across 3 seeds; percentages are of ALL 50,000 created messages, not attempted reads.","",
      "| Profile | Compromised | Random % | Scored % | Gain pp | No honest candidate % | False honest downgrades |",
      "|---|---:|---:|---:|---:|---:|---:|"]
    for r in rows:
        lines.append(f"| {r['profile']} | {r['compromised_percent']}% | {r['random_delivery_percent']} | {r['scored_delivery_percent']} | {r['gain_pp']:+.3f} | {r['all_compromised_candidate_percent']} | {r['honest_false_deprioritized_mean']} |")
    lines+=["","## Limits",
      "Corrupt responses, audit honesty, attributions, refusal probabilities, compromise timing and degree of collusion are scripted assumptions.",
      "No global reputation, actual HPKE/Ed25519 W3/W4, SQLite durable handoff, physical independence, or genuine quarantine is implemented.",
      "Collusion traffic is ignored rather than realistically injected into signed attestations; 0 false bans is conditional on a toy honest peer model.",
      "At high fractions, invitations with ALL compromised candidates can never reach an honest custodian; scoring alone cannot solve this.",
      "No user metadata appears in reports. Compromise ratios reflect exact deterministic sets nested within each seed."]
    (a.input/"report.md").write_text("\n".join(lines)+"\n")
    print("\n".join(lines))
if __name__=="__main__": main()
