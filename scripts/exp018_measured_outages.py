#!/usr/bin/env python3
"""EXP-018 stage 2: gateway outage replay on the same two CC0 contact traces.

Only *encounters* are measured. Gateway willingness, custody, Internet,
synthetic W4-return markers, outages and model byte costs are assumptions.
This does not claim receipt signature verification, BLE radio tests or
Byzantine quota enforcement.

For a given (source, seed, phase, gateway percentage), the exact same
messages and time-dependent outage schedule are replayed against gateway4
and parallel4 with ONE shared K=4 budget. For radio outages the actual
past/future encounters of *affected gateways* are removed before a new
causal routing simulation; no policy can see the future outage.
"""
import argparse
from collections import defaultdict
import csv
import hashlib
import json
import math
from pathlib import Path

from exp006_temporal_contacts import build_temporal_graph, earliest_delivery
from exp011_real_contacts import SAMPLE_SECONDS
from exp012_cross_environment import (
    SOURCES, SEEDS, fetch_pinned, parse_pinned_gzip,
    split_chronology, choose_historic_pairs, make_jobs,
)
from exp015_gateway_comparison import (
    choose_gateways, historical_map, run_engine,
    MESSAGE_WIRE_BYTES, RETURN_WIRE_BYTES,
)
from exp018_gateway_recovery import (
    Window, observed_while_awake, recovery_outcomes,
)

CLAIM = "measured-human-contact-times-with-synthetic-outages-and-w4-markers"
POLICIES = ("gateway_direct4", "hybrid_parallel4")
SCENARIOS = ("control", "gateway_radio_offline", "gateway_internet_offline",
             "gateway_disk_reset", "return_channel_unavailable")
RETURN_DELAY_TICKS = (30 * 60) // SAMPLE_SECONDS


def failure_schedules(gateways, jobs, ttl, scenario, seed):
    """Select affected gateways without reading *future* contact events.

    The named windows are intentionally deterministic experimental inputs,
    not predictions passed to a routing algorithm.
    """
    if scenario not in SCENARIOS or not gateways or ttl < 8 or not jobs:
        raise ValueError("invalid outage scenario")
    ordered = sorted(gateways, key=lambda node: hashlib.blake2s(
        f"outage:{seed}:{node}".encode(), digest_size=16
    ).digest())
    impacted = ordered[:max(1, (len(ordered)+1)//2)]
    start = min(job[2] for job in jobs)
    down_radio = {}
    down_internet = {}
    disk_loss = {}
    if scenario == "gateway_radio_offline":
        down_radio = {
            node: [Window(start+ttl//4, start+3*ttl//4)]
            for node in impacted
        }
    if scenario == "gateway_internet_offline":
        down_internet = {
            node: [Window(start, start+ttl//2)]
            for node in impacted
        }
    if scenario == "gateway_disk_reset":
        # Persist before failed uplink; one explicit loss of durable state.
        # No global rollback of the source, no claim of secure storage.
        down_internet = {
            node: [Window(start, start+3*ttl//4)]
            for node in impacted
        }
        disk_loss = {
            node: [Window(start+ttl//3, start+ttl//3+1)]
            for node in impacted
        }
    return down_radio, down_internet, disk_loss, tuple(impacted)


def normalize_storage(jobs, gateways, engine):
    """An origin that IS a willing gateway can immediately store its bytes."""
    if len(engine["mailbox_ticks"]) != len(jobs):
        raise AssertionError("unexpected engine output length")
    if len(engine["mailbox_gateway_nodes"]) != len(jobs):
        raise AssertionError("missing first gateway provenance")
    ticks, nodes = [], []
    for (src, _, created, _), at, node in zip(
            jobs, engine["mailbox_ticks"], engine["mailbox_gateway_nodes"]):
        if src in gateways and (at is None or created < at):
            ticks.append(created)
            nodes.append(src)
        else:
            ticks.append(at)
            nodes.append(node)
        if ticks[-1] is not None and nodes[-1] is None:
            raise AssertionError("deposited letter without custodian identity")
    return ticks, nodes


def paired(direct, hybrid, field):
    a = [tick is not None for tick in direct[field]]
    b = [tick is not None for tick in hybrid[field]]
    if len(a) != len(b):
        raise ValueError("dissimilar message populations")
    return dict(messages=len(a),
                both=sum(x and y for x,y in zip(a,b)),
                only_direct=sum(x and not y for x,y in zip(a,b)),
                only_hybrid=sum(y and not x for x,y in zip(a,b)),
                neither=sum(not x and not y for x,y in zip(a,b)))


def compare(datasets, output, *, seeds=SEEDS, gateway_percent=(2,10),
            pickup_hours=(1,2), letters_per_kind=12,
            ttl_hours=4, scenarios=SCENARIOS):
    if not datasets or not seeds or not gateway_percent or not pickup_hours:
        raise ValueError("empty scenario dimension")
    if not 2 <= letters_per_kind <= 100 or not 2 <= ttl_hours <= 12:
        raise ValueError("invalid job count or TTL")
    if any(s not in SCENARIOS for s in scenarios) or len(set(scenarios)) != len(scenarios):
        raise ValueError("unknown or repeated synthetic outage")
    if any(p<1 or p>50 for p in gateway_percent) or any(
            h<=0 or h>=ttl_hours for h in pickup_hours):
        raise ValueError("invalid gateway percentage or pickup cadence")
    if any(s<0 or s>=2**32 for s in seeds):
        raise ValueError("invalid seed")
    ttl = ttl_hours * 3600 // SAMPLE_SECONDS
    decay = math.exp(-math.log(2)*SAMPLE_SECONDS/(24*3600))
    rows, pairs = [], []
    manifest = {}
    for source, data in datasets.items():
        split = split_chronology(data, ttl, letters_per_kind)
        graph = historical_map(split["train_records"])
        manifest[source] = {
            "blob": SOURCES[source]["blob"],
            "license": SOURCES[source]["license"],
            "source": SOURCES[source]["page"],
            "measured_contacts": data["record_count"],
        }
        for seed in seeds:
            chosen = choose_historic_pairs(split, seed, letters_per_kind)
            pair_sha = hashlib.sha256(repr(chosen).encode()).hexdigest()
            gsets = {
                pct: choose_gateways(graph, pct, seed) for pct in gateway_percent
            }
            for phase in ("early", "late"):
                jobs = make_jobs(chosen, split[phase])
                end = max(job[2] for job in jobs) + ttl - 1
                if end > split["end"]:
                    raise AssertionError("holdout exceeds real encounters")
                observed = [e for e in data["events"] if e[0] <= end]
                for pct in gateway_percent:
                    gateways = gsets[pct]
                    for scenario in scenarios:
                        radio, internet, lost, impacted = failure_schedules(
                            gateways, jobs, ttl, scenario, seed)
                        filtered = observed_while_awake(observed, radio)
                        graph_after_filter = build_temporal_graph(filtered)
                        oracle = [
                            earliest_delivery(
                                graph_after_filter, src, dst, created, ttl
                            ) for src, dst, created, _ in jobs
                        ]
                        engines = {}
                        for policy, engine_name in (
                                ("gateway_direct4", "gateway4"),
                                ("hybrid_parallel4", "parallel4")):
                            engine = run_engine(
                                filtered, jobs, engine_name, ttl=ttl, seed=seed,
                                end=end, decay=decay, oracle=oracle,
                                gateways=gateways,
                            )
                            assert engine["max_copies_seen"] <= 4
                            assert engine["max_radio_per_device_tick_ms"] <= 6000
                            engines[policy] = engine
                        for hours in pickup_hours:
                            period = hours*3600//SAMPLE_SECONDS
                            outcomes = {}
                            for policy in POLICIES:
                                eng = engines[policy]
                                stored, nodes = normalize_storage(
                                    jobs, gateways, eng)
                                deposits_by_message = [
                                    ([(created, src)] if src in gateways else []) +
                                    [(at, node) for at, node in entries
                                     if node != src or src not in gateways]
                                    for (src, _, created, _), entries in
                                    zip(jobs, eng["mailbox_all_deposits"])
                                ]
                                result = recovery_outcomes(
                                    jobs, eng["delivery_ticks"], stored, nodes,
                                    ttl=ttl, pickup_period=period,
                                    internet_down=internet, disk_loss=lost,
                                    receipt_contacts=(
                                        (at,a,b) for at,a,b,*_ in filtered
                                    ),
                                    receipt_internet_delay=(
                                        None if scenario == "return_channel_unavailable"
                                        else RETURN_DELAY_TICKS,
                                    all_deposits=deposits_by_message),
                                )
                                outcomes[policy] = result
                                received = sum(v is not None for v in result["recipient_stored"])
                                confirmed = sum(v is not None for v in result["source_confirmed"])
                                uploaded = sum(v is not None for v in result["mailbox_uploaded"])
                                accepted_mailbox = sum(ch=="synthetic-mailbox-poll"
                                                       for ch in result["delivery_channel"])
                                stored_count = sum(v is not None for v in stored)
                                if not 0 <= confirmed <= received <= len(jobs):
                                    raise AssertionError("false signed W4 claim")
                                # Separate historical simulation radio control
                                # from the SECOND model's synthetic return path.
                                # Model Internet upload, accepted mailbox
                                # download, and explicit Internet-only return
                                # marker. NO measured BLE/energy/W4 bytes.
                                internet_bytes = MESSAGE_WIRE_BYTES * (
                                    uploaded + accepted_mailbox)
                                # Conservative upper bound: assume all synthetic
                                # source receipts consume an additional marker,
                                # even if carried by encounter radio.
                                marker_bytes = RETURN_WIRE_BYTES * confirmed
                                rows.append(dict(
                                    source=source, phase=phase, seed=seed,
                                    gateway_percent=pct, pickup_hours=hours,
                                    scenario=scenario, policy=policy,
                                    messages=len(jobs), gateway_stored=stored_count,
                                    mailbox_uploaded=uploaded, recipient_stored=received,
                                    source_confirmed=confirmed,
                                    missing_receipt=result["missing_receipt"],
                                    modeled_data_bytes=eng["data_bytes"],
                                    modeled_engine_control_bytes=eng["receipt_bytes"],
                                    modeled_internet_bytes=internet_bytes,
                                    modeled_return_marker_bytes=marker_bytes,
                                    max_copies=eng["max_copies_seen"],
                                    max_radio_ms_per_node_tick=eng["max_radio_per_device_tick_ms"],
                                    affected_gateways=len(impacted),
                                    pair_set_sha256=pair_sha, claim=CLAIM,
                                ))
                            for milestone in ("recipient_stored","source_confirmed"):
                                pairs.append(dict(
                                    source=source, phase=phase, seed=seed,
                                    gateway_percent=pct,pickup_hours=hours,
                                    scenario=scenario,milestone=milestone,
                                    pair_set_sha256=pair_sha,
                                    **paired(outcomes[POLICIES[0]],
                                             outcomes[POLICIES[1]],
                                             milestone),
                                ))
                        print("EXP018_CELL",source,phase,"seed",seed,"gateways",
                              pct,"scenario",scenario,flush=True)
    if not rows or not pairs:
        raise AssertionError("empty replay")
    grouped=defaultdict(lambda: defaultdict(int))
    for row in rows:
        k=(row["source"],row["gateway_percent"],row["pickup_hours"],
           row["scenario"],row["policy"])
        for col in ("messages","gateway_stored","mailbox_uploaded","recipient_stored",
                    "source_confirmed","missing_receipt","modeled_data_bytes",
                    "modeled_engine_control_bytes","modeled_internet_bytes",
                    "modeled_return_marker_bytes"):
            grouped[k][col]+=row[col]
    aggregates=[]
    for (source,pct,hours,scenario,policy),values in sorted(grouped.items()):
        row=dict(source=source,gateway_percent=pct,pickup_hours=hours,
                 scenario=scenario,policy=policy,**values)
        row["model_total_bytes"]=sum(values[col] for col in (
            "modeled_data_bytes","modeled_engine_control_bytes",
            "modeled_internet_bytes","modeled_return_marker_bytes"))
        aggregates.append(row)
    grouped_pairs=defaultdict(lambda: defaultdict(int))
    for row in pairs:
        k=(row["source"],row["gateway_percent"],row["pickup_hours"],
           row["scenario"],row["milestone"])
        for col in ("messages","both","only_direct","only_hybrid","neither"):
            grouped_pairs[k][col]+=row[col]
    comparison=[
        dict(source=s,gateway_percent=p,pickup_hours=h,scenario=mode,
             milestone=m,**values)
        for (s,p,h,mode,m),values in sorted(grouped_pairs.items())
    ]
    output.mkdir(parents=True,exist_ok=True)
    for name,dataset in (
        ("outage-runs.csv",rows),("outage-pairs.csv",pairs),
        ("outage-aggregates.csv",aggregates),("outage-paired-summary.csv",comparison),
    ):
        with (output/name).open("w",newline="",encoding="utf-8") as stream:
            writer=csv.DictWriter(stream,fieldnames=list(dataset[0]))
            writer.writeheader()
            writer.writerows(dataset)
    record=dict(schema="labo-exp018-outage-replay-v1",claim=CLAIM,
                assumptions=[
                    "Only human face-to-face encounters are real",
                    "Failures and gateway selection are deterministic synthetic injections",
                    "Gateway internet, durability, mailbox polling and marker return are synthetic",
                    "SourceConfirmed is a marker, NOT a verified WOW Ed25519 W4",
                    "A prior gateway's data loss cannot revoke already uploaded mailbox bytes",
                    "Model bytes exclude actual BLE link/retransmit radio measurements",
                    "Two independent real contact logs do not constitute population inference",
                ],
                sources=manifest,rows=rows,pairs=pairs,aggregates=aggregates,
                pair_summary=comparison,parameters=dict(
                    gateway_percent=list(gateway_percent),
                    pickup_hours=list(pickup_hours),seeds=list(seeds),
                    scenarios=list(scenarios),ttl_hours=ttl_hours,copy_cap=4,
                    letters_per_kind=letters_per_kind,
                    receipt_internet_delay_ticks=RETURN_DELAY_TICKS,
                ))
    (output/"outage-comparison.json").write_text(
        json.dumps(record,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    lines=[
        "# LABO EXP-018 — gateway outage replay on measured human encounters",
        "",
        "Only *contact times* were observed. Offline schedules, gateway choice,",
        "Internet, storage, mailbox and W4-return MARKERS were synthetically",
        "injected. SourceConfirmed is NOT a cryptographic WOW W4.",
        "",
        "All experiments compare exactly the same letters, same deterministic",
        "outages and one K=4 maximum. **GatewayStored is not RecipientStored.**",
        "",
        "| Source | Gateways | Pickup | Scenario | Direct recipient | Parallel recipient | Direct source marker | Parallel source marker |",
        "|---|---:|---:|---|---:|---:|---:|---:|",
    ]
    lookup={(r["source"],r["gateway_percent"],r["pickup_hours"],
             r["scenario"],r["policy"]):r for r in aggregates}
    for a in comparison:
        if a["milestone"]!="recipient_stored":continue
        k=(a["source"],a["gateway_percent"],a["pickup_hours"],a["scenario"])
        d=lookup[k+("gateway_direct4",)]
        p=lookup[k+("hybrid_parallel4",)]
        lines.append(f"| {k[0]} | {k[1]}% | {k[2]} h | {k[3]} "
                     f"| {d['recipient_stored']}/{d['messages']} "
                     f"| {p['recipient_stored']}/{p['messages']} "
                     f"| {d['source_confirmed']}/{d['messages']} "
                     f"| {p['source_confirmed']}/{p['messages']} |")
    lines += [
        "",
        "## Distinct return-path evidence",
        "",
        "The CSV has separate paired comparisons for synthetic recipient",
        "acceptance and subsequent source knowledge. Missing marker != lost mail.",
        "Some receipts intentionally arrive after the four-hour message TTL.",
        "The underlying W8 credit and a real signed W4 are NOT simulated here.",
        "",
        "## Limitations",
        "",
        "Do not infer real radio airtime/energy or a live gateway's willingness.",
        "Results are conditional on these particular synthetic failure windows.",
        "The same human encounters underlie multiple seeds/phases; no narrow",
        "population confidence interval is justified.",
        "",
    ]
    (output/"outage-report.md").write_text("\n".join(lines),encoding="utf-8")
    print("EXP018_COMPLETE",len(rows),"runs",len(pairs),"pairs",
          len(aggregates),"aggregates",len(comparison),"paired-summary",
          flush=True)
    return record


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache",type=Path,default=Path("results/exp012-source-cache"))
    parser.add_argument("--output",type=Path,default=Path("results/exp018"))
    parser.add_argument("--download",action="store_true")
    parser.add_argument("--seeds",type=int,nargs="+",default=list(SEEDS))
    parser.add_argument("--gateway-percent",type=int,nargs="+",default=[2,10])
    parser.add_argument("--pickup-hours",type=int,nargs="+",default=[1,2])
    parser.add_argument("--letters-per-kind",type=int,default=12)
    parser.add_argument("--ttl-hours",type=int,default=4)
    args=parser.parse_args()
    datasets={name:parse_pinned_gzip(fetch_pinned(name,args.cache,args.download))
              for name in SOURCES}
    compare(datasets,args.output,seeds=tuple(args.seeds),
            gateway_percent=tuple(args.gateway_percent),
            pickup_hours=tuple(args.pickup_hours),
            letters_per_kind=args.letters_per_kind,ttl_hours=args.ttl_hours)


if __name__=="__main__":
    main()
