# LABO EXP-018: per-letter event handoff contract for WOW

Date: 2026-10-23. This is an **additive export** of the already accepted EXP-018 comparison. The latest stable baseline is [LABO PR #24](https://github.com/calex794/labo/pull/24) and [run #39972226245](https://github.com/calex794/labo/actions/runs/39972226245). Crypto acceptance is separately represented by [WOW PR #79](https://github.com/calex794/wow/pull/79).

## Motivation

The old `outage-comparison.json` reports 320 aggregate runs, 320 pairwise rows and 80 aggregates. Those counts are not a wire protocol and do **not** reveal when an *individual* letter was stored, uploaded, accepted, or confirmed. WOW cannot replay an aggregate result as a signed recipient W4.

The new `outage-message-events.csv` contains **one row per modeled letter per (source, phase, seed, gateway share, pickup cadence, failure, routing policy)**. The standard matrix has **320 × 24 = 7680 rows**. The original JSON/CSV results, routing logic, and pinned contact archives stay unchanged.

## Columns and semantics

- `source, phase, seed, gateway_percent, pickup_hours, scenario, policy, pair_set_sha256`: experiment parameters. `pair_set_sha256` is **not** a cryptographic identity or receipt.
- `message_ref`: stable 32-char lowercase SHA-256 prefix of a LABO-internal *synthetic* token derived only from experiment source, phase, seed and message index. It contains no raw contact node ID. The same message has the same token across policies, gateway percentages, pickup cadences and failure cases. **NOT** the real W3 `MessageId` and NOT suitable for authorization.
- `message_index`: index within the fixed modeled population for that source/phase/seed.
- `created_tick`, `ttl_ticks`: existing LABO discrete 20-second time bins (not Unix timestamps).
- `custody_copies`: number of recorded gateway storage events, **not** count of distinct physical peers or a proof that their disks persisted in reality.
- `first_gateway_stored_tick`: first modeled custody event, blank if none. Later gateways can rescue after its loss; this field is not authoritative storage after failure.
- `mailbox_uploaded_tick`: earliest modeled upload by any surviving custody copy, blank if none.
- `recipient_stored_tick`: earliest modeled acceptance through observed human contact or hypothetical mailbox polling, blank if none.
- `source_confirmed_tick`: modeled **return-path reachability marker**, blank if none. Never a signature or proof of real W4. May occur after the forward packet TTL.
- `delivery_channel`: model channel string; not transport evidence.
- `claim`: explicitly names the evidence class `measured-human-contact-times-with-synthetic-outages-and-w4-markers`.

No raw `sender`, `recipient`, `gateway_node`, cryptographic keys, contact list or ciphertext is exported. Deterministic pseudonyms are for pairing model outcomes only, not for user anonymity on a production network.

## Required invariants

1. CSV rows exactly equal the sum of `messages` in `outage-comparison.json.rows`. Standard fixed configuration: 7680.
2. Per-run counts of storage, upload, acceptance, and return inferred from the CSV reproduce the corresponding row totals of the unchanged `outage-comparison.json`.
3. A `mailbox_uploaded_tick` requires at least one prior custody event. A `source_confirmed_tick` requires a strictly earlier `recipient_stored_tick`. Receipt may be later than message TTL.
4. `recipient_stored_tick` must lie in `[created_tick, created_tick + ttl_ticks)`. No route reads future contacts or outage schedules.
5. LABO historical baselines (EXP-015/017) must remain byte-for-byte identical; the old EXP-018 `outage-comparison.json` must remain identical to the accepted run.

## Safe WOW consumption

**Do not** turn a CSV `recipient_stored_tick` directly into `Delivery::Recipient` or a signed W4. The replay driver may use the rows to **schedule** a test, but then must use the real WOW code:

1. Author a fresh authentic W3 v3 with independently provisioned test identities and a valid invitation. Preserve the exact ciphertext bytes through all modeled hops.
2. Record actual durable custody using signed W8 offers/ACKs in independent SQLite (one actual K4 plan).
3. On simulated delivery, invoke recipient `accept_private_authenticated_and_queue_receipt` on an isolated SQLite, which signs W4 **only if the receiver truly commits the exact valid W3**.
4. Carry only an opaque `private_return_w4` envelope along the scheduled return path. Verify signature, trust epoch, invitation expiry and exact W3 digest before source Journal becomes `Delivery::Recipient`.
5. If the model schedules no recipient acceptance or return, the source must **not** synthesize it; peer receipts or mailbox custody cannot advance the terminal state. Record discrepancies between actual WOW cryptographic outcomes and model expectations.

This is **not implemented** in the CSV export itself. [WOW PR #79](https://github.com/calex794/wow/pull/79) independently validates the crypto/SQLite boundary on injected gateway failures. An adapter consuming the new per-letter dataset and a genuine two-host test remain separate acceptance gates.

## Test and artifact requirements

```sh
python3 -m unittest discover -s scripts -p 'test_exp018_measured_outages.py' -v
python3 scripts/exp018_measured_outages.py --download \
  --cache results/exp012-source-cache --output results/exp018 \
  --seeds 21021 21022 --gateway-percent 2 10 \
  --pickup-hours 1 2 --letters-per-kind 12 --ttl-hours 4
```

CI must upload `results/exp018/outage-message-events.csv` together with the old EXP-018 files, and verify the population size and causal ordering. Do not merge while new CI is failing. The CSV is a model interface, **not** a privacy-reviewed production log or delivery receipt.
