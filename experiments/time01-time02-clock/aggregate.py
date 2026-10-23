#!/usr/bin/env python3
import json,sys,csv
from pathlib import Path
src=Path(sys.argv[1]);dest=Path(sys.argv[2]);dest.mkdir(parents=True,exist_ok=True)
records=[json.loads(line) for line in src.read_text().splitlines() if line.startswith("{")]
rtc=[r for r in records if r["schema"]=="labo-time01-v1"]
recovery=[r for r in records if r["schema"]=="labo-time02-v1"]
assert len(rtc)==5*4*4,len(rtc)
assert len(recovery)==5,len(recovery)
for r in rtc:
    assert r["claim"]=="arithmetic-assumption"
    assert 0<=r["strict_success"]<=r["adjacent_success"]<=r["samples"]
    assert r["client_hmac_budget_adjacent"]==3
    assert r["max_drift_seconds"]==(r["days"]*86400*r["ppm"]+999999)//1000000
cases={r["case"]:r for r in recovery}
assert cases["power_loss_no_rtc"]["clock"]=="Uncertain"
assert cases["snapshot_without_external_pin"]["clock"]=="Uncertain"
assert cases["snapshot_rollback_detected"]["clock"]=="Conflict"
assert cases["rtc_rollback"]["clock"]=="Conflict"
assert cases["retained_rtc"]["clock"]=="Bounded"
assert all(r["pending_slots"]==1 for r in recovery)
assert not cases["power_loss_no_rtc"]["tag_enabled"]
assert not cases["power_loss_no_rtc"]["expiring_fetch_enabled"]
assert cases["power_loss_no_rtc"]["timeless_fetch_enabled"]
assert cases["power_loss_no_rtc"]["external_evidence_valid"]
assert not cases["snapshot_rollback_detected"]["external_evidence_valid"]
with (dest/"time01.csv").open("w",newline="") as f:
    w=csv.DictWriter(f,fieldnames=list(rtc[0]));w.writeheader();w.writerows(rtc)
with (dest/"time02.csv").open("w",newline="") as f:
    w=csv.DictWriter(f,fieldnames=list(recovery[0]));w.writeheader();w.writerows(recovery)
lines=["# LABO TIME-01/TIME-02 — arithmetic RTC drift and fail-closed restore",
"","**This is a deterministic arithmetic/state model, not real RTC, flash disk, WAL or physical servers.**",
"","| Offline days | Drift ppm | Maximum error (s) | 20 min strict % | 20 min ±1 bucket % |",
"|---:|---:|---:|---:|---:|"]
for r in rtc:
    if r["period_seconds"]==1200:
        lines.append(f'| {r["days"]} | {r["ppm"]} | {r["max_drift_seconds"]} | {100*r["strict_success"]/r["samples"]:.2f} | {100*r["adjacent_success"]/r["samples"]:.2f} |')
lines+=["","## Recovery decisions","| Case | Clock | Rotating beacon | Expiring FETCH | Pre-existing C slots |","|---|---|---|---|---|"]
for r in recovery:
    lines.append(f'| {r["case"]} | {r["clock"]} | {r["tag_enabled"]} | {r["expiring_fetch_enabled"]} | {r["pending_slots"]} |')
lines+=["","**Limitations:** signed external evidence may be a signed lie; a successful signature test is NOT secure UTC. Recovering UTC needs independent reliable bounds. Same-OS snapshot and all locally-stored checkpoints can roll back together. W3/W4, receipts and actual storage durability NOT simulated.",""]
(dest/"report.md").write_text("\n".join(lines))
(dest/"summary.json").write_text(json.dumps({"schema":"labo-time01-time02-summary-v1","claim":"synthetic-arithmetic-no-hardware","rtc_rows":len(rtc),"recovery_rows":len(recovery),"samples":rtc,"cases":recovery},indent=2)+"\n")
print("\n".join(lines))
