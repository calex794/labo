#!/usr/bin/env python3
"""EXP-020 aggregate 4620 synthetic rows; fail closed on contract violations."""
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path
from statistics import mean

src=Path(sys.argv[1])
out=Path(sys.argv[2])
rows=[json.loads(line) for line in src.read_text().splitlines() if line.startswith("{")]
assert len(rows)==3*7*4*5*11, len(rows)
seen=set()
groups=defaultdict(list)
for row in rows:
    assert row["schema"]=="labo-exp020-offline-rid-v1"
    assert row["claim"]=="synthetic-contact-not-real-network"
    assert row["custodians"]==1000 and row["offline_days"]==30
    assert row["tag_is_authorization"] is False
    assert row["trials"]==512
    assert row["bad_percent"] in (1,5,10,20,40,70,90)
    assert row["candidates"] in (3,6,10,20)
    assert row["rotation_seconds"] in (600,1200,3600,21600,86400)
    assert row["seed"] in (21,71,107)
    assert row["clock_skew_seconds"] in (-2592000,-86400,-3600,-300,-30,0,30,300,3600,86400,2592000)
    id=(row["seed"],row["bad_percent"],row["candidates"],row["rotation_seconds"],row["clock_skew_seconds"])
    assert id not in seen
    seen.add(id)
    n=row["trials"]
    for k in ("no_honest_in_invitation","honest_present_but_not_online","honest_tag_strict","honest_tag_adjacent","any_tag_strict","any_tag_adjacent","compromised_tag_adjacent"):
        assert 0<=row[k]<=n, (id,k,row[k])
    assert row["honest_tag_strict"]<=row["honest_tag_adjacent"]<=row["any_tag_adjacent"]
    assert row["any_tag_strict"]<=row["any_tag_adjacent"]
    assert row["no_honest_in_invitation"]+row["honest_tag_adjacent"]<=n
    assert row["client_hmac_calls_strict"]==n*row["candidates"]
    assert row["client_hmac_calls_adjacent"]==3*n*row["candidates"]
    assert row["service_hmac_calls"]==n*row["candidates"]
    groups[id[1:]].append(row)
assert len(groups)==7*4*5*11 and all(len(g)==3 for g in groups.values())
summary=[]
for (bad,count,period,skew),rs in sorted(groups.items()):
    n=sum(r["trials"] for r in rs)
    summary.append(dict(
      bad_percent=bad,candidates=count,period_seconds=period,skew_seconds=skew,trials=n,
      honest_strict_pct=round(100*sum(r["honest_tag_strict"] for r in rs)/n,3),
      honest_adjacent_pct=round(100*sum(r["honest_tag_adjacent"] for r in rs)/n,3),
      any_strict_pct=round(100*sum(r["any_tag_strict"] for r in rs)/n,3),
      any_adjacent_pct=round(100*sum(r["any_tag_adjacent"] for r in rs)/n,3),
      no_honest_pct=round(100*sum(r["no_honest_in_invitation"] for r in rs)/n,3),
      online_gap_pct=round(100*sum(r["honest_present_but_not_online"] for r in rs)/n,3),
      compromised_tag_pct=round(100*sum(r["compromised_tag_adjacent"] for r in rs)/n,3),
    ))
with (out/"summary.csv").open("w",newline="") as f:
    w=csv.DictWriter(f,fieldnames=list(summary[0]))
    w.writeheader();w.writerows(summary)
(out/"summary.json").write_text(json.dumps({"schema":"labo-exp020-summary-v1","synthetic":True,
    "cells":len(summary),"raw_runs":len(rows),"rows":summary},indent=2)+"\n")
lines=["# LABO EXP-020: rotating IDs after 30 days offline",
"","**Only deterministic synthetic contacts, not real BLE/Wi-Fi/QUIC and not W4.**",
"Each peer/client pair has a distinct lab HKDF secret; matching a tag does NOT grant storage/fetch permissions.",
"Numbers below average three seeds and 512 simulated encounters per seed/cell.",
"","## Clock synchronized, 20-minute rotation, adjacent-window search",
"| Bad nodes | Invited peers | Strict honest discovery % | Adjacent honest discovery % | No honest candidates % |",
"|---:|---:|---:|---:|---:|"]
for row in summary:
    if row["period_seconds"]==1200 and row["skew_seconds"]==0:
        lines.append(f'| {row["bad_percent"]}% | {row["candidates"]} | {row["honest_strict_pct"]} | {row["honest_adjacent_pct"]} | {row["no_honest_pct"]} |')
lines+=["","## Clock skew, 10% compromised, 6 invited, 20-minute rotation",
"| Skew (seconds) | Strict honest % | Adjacent honest % |",
"|---:|---:|---:|"]
for row in summary:
    if row["period_seconds"]==1200 and row["bad_percent"]==10 and row["candidates"]==6:
        lines.append(f'| {row["skew_seconds"]} | {row["honest_strict_pct"]} | {row["honest_adjacent_pct"]} |')
lines+=["","## Limits and assumptions",
"- The model assumes the same pair key remains available after 30 days offline.",
"- Both parties independently know the absolute time, except for the explicitly varied skew.",
"- A true RTC reset has not been repaired through a network sync: large skew MUST fail closed.",
"- Compromised peers still know their own proper pair key and create matching tags; tag coincidence cannot prove honesty.",
"- A six-peer invitation with no honest custodian cannot be fixed by rotating IDs.",
"- No authentic BLE constraints or relay byte cost; client HMAC budget scales with the number of known paired peers.",
"- Future work: trust-bound recovery, cloned keys, replay, revoked credentials and experimental RF conditions."]
(out/"report.md").write_text("\n".join(lines)+"\n")
print("\n".join(lines))
