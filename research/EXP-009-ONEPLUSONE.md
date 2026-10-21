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

The code is in `scripts/exp008_recipient_routes.py` with policies `oneplusone2` and `oneplusone4`. The already existing 11 policies retain their decision logic; the model's default paired experiment now compares 13 strategies on identical people, message pairs, time-ordered contacts, BLE scanning events and available airtime. The full matrix adds 240 category rows over the original 1320, for **1560 rows** and **936 algorithm runs** (13 modes × 3 populations × 3 seeds × 2 courier flags × 2 scanner flags × 2 gateway flags).

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