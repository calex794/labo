# LABO EXP-009 — 1+(1): travelling message with parked direct-only backups

**Purpose:** test an alternative way for *one encrypted letter* to find its recipient without knowing their current position. This extends the already checked EXP-008 routing laboratory rather than replacing its existing policies. None of these results is a field Bluetooth delivery measurement or a released Akula protocol.

## Mechanism

The first copy lives with the sender. At the first successful forwarding encounter the sender keeps a **parked** copy and the chosen consenting neighbour gets one **runner** copy. Parked holders never forward their copy to another courier. They may deliver it **only to the intended recipient's exact identity**. The runner continues to follow eligible encounters and can create another parked copy after passing an unchanged ciphertext, subject to a single *global* per-letter copy limit K:

- `oneplusone2`: at most **1 parked + 1 runner**. Every later forwarder moves the runner onward without leaving another backup. This is the strict constant-size version of **1+(1)**.
- `oneplusone4`: at most **3 parked + 1 runner**. Up to 3 successful, paid handoffs leave parked backups; when full, the runner moves between couriers. It cannot clone another copy until a slot becomes free through authorized retirement.

At any moment, the number of simultaneously held logical copies is `<= K`; only one is active as `runner` (initial `anchor` becomes parked on first successful handoff). No copy may teleport to another building, hop twice in one tick, or appear when a BLE encounter is too short to transmit the whole packet. When no such encounter occurs, it waits. After TTL, remaining copies expire; the **synthetic** recipient receipt can suppress redundant deliveries after propagation through real future contacts, not via an imaginary broadcast. The actual return of cryptographic WOW/W4 proofs is **not implemented**.

Example: 

```
Ivan [anchor] --message--> Anna [runner]; Ivan [parked]
Anna [runner] --message--> Petr [runner]; Anna [parked] (if K>2)
Petr [runner] --message--> Oleg [runner]; Petr [parked] (if K>3)
...
Maria may accept from Ivan, Anna, Petr or whoever currently runs it.
```

The control model sees recipient `dest` as a fixed integer ID; it does **not** broadcast the identifier in BLE advertising and it does **not** authenticate a key. In production a matching string/UUID is insufficient — use a verified recipient key and a private lookup protocol consistent with [AK-NET-WIRE-10](https://app.notion.com/p/3fc32a84beec816ab4f1c6b5566efeb1). Having multiple ciphertext copies may expose linkability across carriers unless transport wrapping is separately designed.

## Implementation and regression boundaries

The routing engine is in `scripts/exp008_recipient_routes.py`. The original EXP-008 default **still compares exactly 11 strategies** and remains reproducible. The focused EXP-009 driver `scripts/exp009_oneplusone_matrix.py` compares **six** strategies by default (54 algorithm runs, 90 per-category rows: 3 population sizes × 3 seeds × 6 strategies, with movement enabled and no IP gateway). Add `--include-predictive` to compare **eight** strategies (72 algorithm runs, 120 per-category rows). This avoids rerunning the large full-factorial EXP-008 matrix for every change.

- `frozen_backups`: total successfully parked copies (not the simultaneous maximum), across all letters in the individual simulation.
- `rolling_runner_handoffs`: active runner moves made when K slots are already occupied.
- `direct_from_backup`: logical first receipts obtained by an exact destination from parked holders.
- `max_copies_seen`: peak simultaneous copies **for any one letter**, never greater than K.

Important: global counters are repeated in both per-category CSV rows for any one computational experiment. Do **not** add duplicated rows when calculating air and copy consumption. Comparisons of `oneplusone4` to `parallel4`/`spray4`/`prophet4` share the same maximum copies. `oneplusone2` is a smaller-budget option and cannot be called a fair K4 equivalent. More copies do not imply better performance or privacy.

## Reproduce

```bash
python3 -m unittest discover -s scripts -p 'test_exp008_recipient_routes.py' -v
python3 scripts/exp008_recipient_routes.py \
  --wings 1 10 100 --seeds 21021 21022 21023 \
  --steps 80 --ttl 40 --letters-per-kind 12 \
  --output results/exp009
```

The suite includes 7 new tests covering: K2 backup and moving runner, parked holder not forwarding to an unauthorized relay, direct-only exact-recipient delivery, K4 budget saturation and subsequent moves, TTL/airtime gating, positive exploration when PRoPHET has no relevant past data, and deduplication when a receipt can pre-empt later copies. Existing 17 regressions remain unchanged. CI uses the **existing one-job experiment workflow**, avoiding additional fan-out or repeated generic Rust matrix jobs when only the routing scripts change.

## Unresolved

A current neighbour is selected without secure social history when the oneplusone runner advances; it may land at an unhelpful volunteer, so this scheme is an exploration baseline, not a new globally optimal route algorithm. The backups consume storage and their historical presence may reveal who might be communicating. With physical intermittent nodes, an actual hard shared copy budget requires durable leases and crash recovery; the single-process simulation cannot prove that security property. We still need a *real* private exact-recipient handshake, signed end-recipient receipts, measured device-to-device contacts, diverse movement traces and actual energy/battery measurements.

[LABO-ROUTE-001 in Notion](https://app.notion.com/p/40032a84beec81768202c3faf8054e83) | [EXP-008 original report](EXP-008-RECIPIENT-ROUTING.md) | [GitHub issue #8](https://github.com/calex794/labo/issues/8).

## EXP-009b — guided runner while keeping direct-only backups

**Status:** opt-in synthetic experiment, implemented separately from production Akula. The original random-forwarding `oneplusone2`/`oneplusone4` stay available as negative baselines.

New selectable policies:
- `oneplusone_predict2`: at most **one parked backup + one active runner**, total K=2.
- `oneplusone_predict4`: at most **three parked backups + one active runner**, total K=4.

The **runner** considers a nearby consenting relay only when the preexisting, causal PRoPHET-style destination rank satisfies `score(next,recipient) > score(current,recipient) + 0.08` and `score(next,recipient) >= 0.10`. Ranking uses **finished prior ticks**: direct contact, time decay (default 0.94 per synthetic step) and bounded transitive hints. The current contact is ingested **only at the end of its tick**. These numbers are experimental decision thresholds; they are **not calibrated probabilities**. The algorithm is *greedy and online*: it cannot see all neighbors that might arrive later.

Once an eligible handoff actually transfers the full envelope within the available radio time, the former runner becomes **parked**, and a new runner is created. If the total K budget is full, only the active runner moves: it releases its old slot and reuses it at the next relay. A parked copy can serve only an observed encounter with the **exact synthetic recipient ID**, not another relay. It never advertises a public social graph or gains an invisible IP gateway. Delivery still requires a verified real identity and an end-recipient W4 in production; neither is implemented here. Copies are in memory, not durable or adversary-safe.

### Matched comparison

Reproduce the original six-policy EXP-009 matrix unchanged:

```bash
python3 scripts/exp009_oneplusone_matrix.py --output results/exp009
```

Run the **eight**-policy recipient-aware contrast:

```bash
python3 scripts/exp009_oneplusone_matrix.py --include-predictive --output results/exp009b
```

This writes the existing `routing-matrix.csv`, `routing-matrix.json`, and `report.md` plus `same-budget-deltas.csv` (60 matched comparisons) and `handcrafted-cases.csv` (56 rows, including a previously seen bridge and a changed-routine counterexample). All use the same 2k/20k/200k populations, three seeds, 80 synthetic ticks, TTL=40, hypothetical courier routes, 64 kbit/s, 256-byte messages, no Internet gateway, and *no scan filtering*. K4 is compared only to other K4 policies. K2 is compared only to K2. Aggregate bytes appear on each per-category line and MUST NOT be added twice.

### First reproduced numerical results (three seeds, synthetic only)

| Recipient type | Original 1+(1), K4 | Guided 1+(1), K4 | PRoPHET4 | Parallel4 |
|---|---:|---:|---:|---:|
| Control pairs of adjacent campus hubs, 10 buildings | 0% | **100%** | 100% | 100% |
| Control pairs of adjacent campus hubs, 100 buildings | 0% | **100%** | 100% | 100% |
| Random residents in these sparse synthetic contacts | 0% | 0% | 0% | 0% |

**Interpretation:** recipient-aware selection fixes the *naive first-volunteer mistake* for the deliberately constructed adjacent-hub test. It **does not** improve success over PRoPHET4 on that test; all percentages are generated from an artificial graph, not observed smartphone behavior. The K2 guided scheme also achieves 100% for the same control destination pairs, but has a smaller copy budget and should not be called equivalent to K4 in general.

Hand-crafted causal traces demonstrate **both sides**: a previously observed promising carrier can outperform a random neighbor, while a genuinely new chain with **no past recipient history** may be reached by unguided 1+(1) and *missed* by the strict forecast mode. If habitual contacts change, Parallel4 can succeed where the single guided runner becomes stranded. The algorithm must not be presented as globally optimal.

### Acceptance and remaining research

- 33 old/new automated route tests: exact historical K2/K4, strict recipient-only parked copies, max-K enforcement, continued runner movement after saturation, no future leaks, opt-in, TTL, radio budget, old six-policy output preserved, and paired K checks.
- Targeted one-job CI, not a new general Rust test fanout. The original EXP-008 11-policy regression runs separately only when its dependencies change.
- Realistic next step: offline contact datasets with changing human communities; weighted forecast uncertainty, limited exploration fallback, fake-route-resistant consent, encrypted private recipient lookup, durable leases and signed W4 receipts.

No Akula production change, no hardware BLE measurements, and no cryptographic end-to-end delivery guarantee.

