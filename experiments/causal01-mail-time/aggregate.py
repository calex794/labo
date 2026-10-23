#!/usr/bin/env python3
import json,sys,csv
from pathlib import Path
source=Path(sys.argv[1]);target=Path(sys.argv[2]);target.mkdir(parents=True,exist_ok=True)
rows=[json.loads(x) for x in source.read_text().splitlines() if x.startswith("{")]
experiments=[x for x in rows if x["schema"]=="labo-causal01-mail-time-v1"]
sizes=[x for x in rows if x["schema"]=="labo-causal01-size-v1"]
assert len(experiments)==21 and len(sizes)==3,(len(experiments),len(sizes))
for r in experiments:
    assert r["claim"]=="synthetic-causality-not-clock"
    assert r["entries"]==602 and r["old_messages"]==100
    assert r["bad_signed_dates"]==r["bad_percent"]
    assert r["invalid_sequence_rejected"]==r["bad_percent"]
    assert r["witness_forks_detected"]==1
    assert r["age_upper_unknown"]==100
    assert r["dangerous_fetch_approved"]==0
    assert r["slot_duplicates"]==0
    assert r["retroactively_bounded"]==100
    assert r["clock_restored_from_mail"] is False
    assert r["public_receipt_graph_exported"] is False
for r in sizes:
    assert r["scalar_seq_parent_sig_bytes"]==104
    assert r["vector_clock_bytes"]==8*r["peers"]
with (target/"matrix.csv").open("w",newline="") as f:
    w=csv.DictWriter(f,fieldnames=experiments[0].keys());w.writeheader();w.writerows(experiments)
(target/"summary.json").write_text(json.dumps({"schema":"labo-causal01-report-v1","synthetic":True,"runs":len(experiments),"rows":experiments,"size":sizes},indent=2)+"\n")
lines=["# LABO CAUSAL-01: signed causal ledger, bounded age, UTC anchors","",
"**Synthetic model; Ed25519 signing is real but actor truth, disk durability, physical time and W3/W4 are not modelled.**",
"21 cases: 3 seeds x 1/5/10/20/40/70/90% malicious messages.","",
"| Bad signed date fraction | Rejected oversized signed seq | Wrongly authorized expiring FETCH | Duplicated logical C-credit |",
"|---:|---:|---:|---:|"]
for r in experiments:
    if r["seed"]==21:
        lines.append(f'| {r["bad_percent"]}% | {r["invalid_sequence_rejected"]} | {r["dangerous_fetch_approved"]} | {r["slot_duplicates"]} |')
lines+=["","All 100 synthetic messages per cell keep unknown upper age after missing RTC.",
"Retroactive UTC interval is inferred only from two assumed-trusted signed checkpoints and claimed causal links.",
"Such an interval is not the current UTC and does not allow expired-grant authorization.",
"","## Payload arithmetic only",
"| Total peers | seq+parent+signature bytes | complete vector clock bytes |","|---:|---:|---:|"]
for r in sizes:lines.append(f'| {r["peers"]} | {r["scalar_seq_parent_sig_bytes"]} | {r["vector_clock_bytes"]} |')
lines+=["","**Not covered:** 30-day real outage, 100 original W3 letters or durable storage; checkpoint tamper with a simultaneously compromised signer, hidden forks, controlled metadata leak, true physical clock measurements and actual signed W4. No guaranteed global causality under Byzantine peers. No performance throughput claims.",""]
(target/"report.md").write_text("\n".join(lines))
print("\n".join(lines))
