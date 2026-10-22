# LABO EXP-011 - comparing letter routes on published human contact records

**Scope:** independent experiment only. This does not implement the Akula messenger, operate phone radios, or prove Bluetooth delivery. This follows EXP-008 (parallel K=4) and EXP-010 (adaptive 1+1), whose six hand-constructed dynamic examples were not enough to establish which algorithm is generally better.

## Source, provenance, reuse

We ingest the openly published [SocioPatterns workplace contact dataset](https://sociopatterns.org/datasets/contacts-in-a-workplace/): M. Genois et al., *Network Science* 3, 326 (2015), observations recorded June 24 to July 3, 2013 in an office building in France. **CC0 1.0 public domain**; cite the paper and SocioPatterns. Original study rows: `t i j` for **20-second face-to-face proximity measurement windows**. Neither real BLE signals nor physical contact times for data payload transmission were measured for LABO. The recorded interactions are not a complete list of all possible BLE meetings.

Original dataset downloaded on CI from [SocioPatterns GitHub](https://github.com/SocioPatterns/sociopatterns.github.io/blob/d3fed34de6ca1cdeabe7c21dfc3475a19f46fe8f/assets/data/workplace_InVS_tij.dat.zip) pinned to repository commit `d3fed34de6ca1cdeabe7c21dfc3475a19f46fe8f` and verified against Git blob ID `268390bf5a3ab81b411a03edb02be59f4f172705`. The same archived bytes may be fetched from the SocioPatterns official site as fallback and *must* match the pin. No raw participant events are committed to LABO, and the CI artifact contains derived **aggregated** results, not a republished contact list. Source data uses anonymous identifiers, but inferred social graph information should still be handled carefully.

## Historical changes without invented future paths

1. Original 20-second timestamps retained, sorted and deduplicated on `t, min(i,j), max(i,j)`; each anonymous ID is internally mapped to a dense ID. One modeled contact per measured interval, **20 seconds of assumed transfer opportunity** (an intentionally optimistic upper hypothesis; not a measured BLE connection).
2. Use first sufficiently active day as an **initial social-history / training** period. Then choose an **early** and a **late** active day from recorded dates. For the **same** source/destination pairs, create messages on each evaluation day.
3. Cohorts: truly random *among those present during the first training day*; and a separate, explicitly selected **two-hop past-neighbor** cohort from the training day's contact graph. It is not a population-random estimate. Both cohorts are chosen from prior historical data only, before either delivery window.
4. Measure the observed change in neighbor sets, new/vanished contact edges and their Jaccard similarity for the early and late days. This **post-hoc** diagnostic is never passed to the routing decision.
5. Simulate the actual chronological trace, not a shuffled version and not edges inferred from buildings. No artificial courier, no newly invented bridge, no optional IP gateway. No receiver location oracle.

## Equal-resource comparison

The routing engine is the existing [EXP-008 Python simulator](../scripts/exp008_recipient_routes.py) with two optional parameters *defaulting to its old behavior*: `forecast_decay` and `forecast_all_contacts`. `forecast_all_contacts=True` stores a **bounded 16-entry table per participant of their own previously observed encounters** regardless of which future messages will be sent. This avoids preselecting future addressees to retrospectively populate node history. It still models local histories in a single process, **not a privacy-safe exchange protocol**. The input rate is a hypothesis: `forecast_decay=exp(-ln(2)*20 / (24*3600))` for a one-day half-life; it is **not** the old `0.94` per synthetic tick because real ticks are 20 seconds. Half-life must later be varied and calibrated.

Compare at identical encounter sequence, message list, TTL and shared radio resources:

| Policy | Shared copies | Purpose |
|---|---:|---|
| `direct` | 1 | no relay baseline; not an equal-K comparison |
| `random4` | 4 | baseline random contact selection |
| `spray4` | 4 | budgeted exploration |
| `prophet4` | 4 | older meeting history |
| `sequential4` | 4 | mixed strategies, not simultaneous |
| `parallel4` | 4 | concurrent lanes of **one logical message** |
| `oneplusone_predict4` | 4 | one moving predicted route + parked direct-only copies |

Do **not** include `oneplusone_adaptive4` in this pilot: its existing exploration logic decides that IDs with `node % 2000 == 1` are *special couriers*, a convention from LABO's artificial campus. Real anonymized office IDs do not designate couriers; silently applying that shortcut would bias the comparison. A follow-up must learn candidate bridges only from past contacts before adapting this policy to real traces.

Common simulated parameters: `ttl_hours=8`, 256-byte message, 64-byte framing, hypothetical 64 kbit/s radio goodput, 300-ms setup and 6000-ms radio/device/20-sec tick, **all participants hypothetically consenting** to relay. The original observations do not contain application installation, opt-in, storage availability, scan windows, iOS/Android background restrictions, BLE RSSI, or actual mail transfers. No signed WOW W4 receipt exists in this model. Route success is the simulator's modeled recipient acceptance and not measured delivery.

## Run

```bash
python3 -m unittest discover -s scripts -p 'test_exp011_real_contacts.py' -v
python3 scripts/exp011_real_contacts.py --download --cache results/sociopatterns-raw \
  --output results/exp011 --seeds 21021 21022 21023 --letters-per-kind 12 \
  --ttl-hours 8 --forecast-half-life-hours 24
```

The `--download` option verifies the pinned Git blob before processing. The workflow downloads it for each isolated experiment and preserves only `real-contact-routing.csv`, `real-contact-routing.json`, `report.md`. The raw source must not be committed. Optional local re-run can omit `--download` when cache already contains the same pinned archive.

Number of paired simulations: 3 seeds x 2 measured days x 7 policies = **42 runs**, with 2 separate cohorts per run = **84 category rows**. Each run-level `wire_bytes` is **repeated** in each cohort's row; do not sum them twice. A positive rate in the historical training-neighbor cohort is not evidence of delivery to arbitrary users. Do not compare direct K=1 as though it has the same relay budget as K=4 policies. Delay among delivered messages is shown alongside undelivered counts, and temporal-oracle reachability is a distinct upper bound.

## Acceptance / follow-ups

- [ ] CI downloads original CC0 dataset by pinned commit; Git blob checksum and tabular format verified.
- [ ] 6+ offline tests pass and old EXP-008/010 regressions remain green.
- [ ] Every policy sees the identical message pair set per seed and day; no future-contact lookahead.
- [ ] No exceeded K, 6-second radio time, recipient duplicate acceptance, or BLE delivery beyond time-respecting oracle.
- [ ] Report early vs late contact-partner turnover and paired K4 delivery/byte counts (include zero or negative results).
- [ ] Compare different real contact environments, not just a single office; real anonymized BLE sightings from Haggle are a *separate format* and must be validated independently.
- [ ] Later address private destination identity, sender/storage consent, crash-safe copy budget, signed recipient W4 and genuine phone measurements before Akula integration.

Specification: [LABO-ROUTE-001](https://app.notion.com/p/40032a84beec81768202c3faf8054e83). Parent [EXP-010](https://app.notion.com/p/40132a84beec815d8dffce6e9a014270).
