# EXP-012 — Independent SocioPatterns replication of recipient search

This follows [LABO-ROUTE-001](https://app.notion.com/p/40032a84beec81768202c3faf8054e83) and the [one-office EXP-011](../research/EXP-011-REAL-CONTACTS.md). Unlike the previous six hand-written topology cases or a single office, this study uses two genuinely separate observation environments. **Only temporal proximity records are measured. All forwarding, opt-in, BLE rate, cryptographic acknowledgements, successful message delivery, and device hardware remain hypothetical.**

## Independent pinned CC0 sources

| Source | Context | Original file | Git blob SHA-1 |
|---|---|---|---|
| [SFHH conference (2009)](https://sociopatterns.org/datasets/sfhh-conference-data-set/) | Conference in Nice, 405 recorded attendees over two days; Génois & Barrat, EPJ Data Science 7, 11 (2018) | `SFHH_tij.dat.gz` | `1f323d7ca92ffba0e1b660575a081aa982903f71` |
| [Workplace second deployment (2015)](https://sociopatterns.org/datasets/contacts-in-a-workplace-2/) | Different real office deployment in France; Génois & Barrat, EPJ Data Science 7, 11 (2018) | `workplace_InVS15_tij.dat.gz` | `cd6866d2edcc191c81eece645ae14a9ed98f47bd` |

Both datasets are listed as **CC0 1.0** by SocioPatterns. Download only from the original repository pinned to commit `d3fed34de6ca1cdeabe7c21dfc3475a19f46fe8f`, with official-site fallback allowed only if archive bytes match the *same pinned Git blob*. Original anonymized person-to-person encounter lists are **not committed** to LABO or uploaded as experiment artifacts.

Notably, different school and hospital data on the site are **CC BY-NC-SA**, so they are *not silently bundled* into this possibly product-related research.

## Protocol — chronological, no future knowledge

The shared EXP-011 decoder parses real `t i j` records at 20-second resolution, deduplicates unordered pairs at the same time, converts anonymous IDs to dataset-local dense IDs. The resulting 20-second encounter is treated as a **hypothetical opportunity to transfer** an entire encrypted message; no smartphone BLE air interface was observed.

- **Historical training:** first 25% of unique observed timestamps, independently of routing strategy.
- **Early vs late:** create the *same* chosen source–destination pairs in time windows starting at the ~45th and ~70th percentile of unique recorded timestamps. Require non-overlapping evaluation periods and a full common 4-hour TTL observation horizon on both; fail closed if insufficient.
- Recipient pairs are drawn from **training people only**, with separate random pairs and deliberately historical two-hop neighbors; two-hop is a diagnostic *biased* set, not population random.
- The routing engine's forecast stores up to 16 historical neighbors per node and applies an explicitly assumed 24-hour half-life. It only observes each event **after** decisions during that tick.
- Identical message identities, timing, contacts, radio-time budget, TTL, BLE payload (256+64 bytes), theoretical goodput (64 kbit/s) for all algorithms.
- Compare `direct` (K=1 reference only), `random4`, `spray4`, `prophet4`, and `parallel4` (all four share K=4). No internet gateways or fake physical couriers.
- End-to-end acceptance is modelled; no WOW W4 proof. Failed contact or no time-respecting route is not made successful by the algorithm.

Metrics separately by dataset, time window, recipient cohort: accepted vs unreachable, oracle temporal reachability, delays among accepted, full-run transmitted bytes (not double-counted across cohorts), actual per-message copy cap and per-node radio time. To compare two specific policies, we record **paired discordances for the same individual letters** (`parallel_only` vs `prophet_only`) and a 1200-round deterministic paired letter-level resampling interval.

**Statistical caveat:** fixed historical encounter graphs and letters sharing participants violate the independence assumptions of population-level uncertainty estimates. The interval is **only descriptive finite-cohort sensitivity**. Changing which letters are sampled does not generate independent human social-network observations. Two distinct graphs improve *environmental* coverage but still do not establish universal superiority.

## Reproduce

```bash
python3 -m unittest discover -s scripts -p 'test_exp012_cross_environment.py' -v
python3 scripts/exp012_cross_environment.py --download \
  --cache results/exp012-source-cache --output results/exp012 \
  --seeds 21021 21022 --letters-per-kind 12 --ttl-hours 4
```

Outputs: `independent-contact-routing.csv`, `paired-policy-deltas.csv`, `independent-contact-routing.json`, `report.md`. No raw contact ZIP/GZ artifacts are uploaded. This runs **2 sources × 2 windows × 2 seeds × 5 policies = 40 simulations**, each with separate random and past-two-hop categories, so **80 CSV rows**, and **8 paired (dataset × phase × seed × group)**? Actually 2×2×2×2 = **16** paired rows. The CI verifies row counts, sources, bounds, flags and provenance.

## Limitations and follow-ups

1. Chronological quantile boundaries are chosen retrospectively from the full contact-time distribution (experiment framing), but **are not shared with the algorithms**. Future contact strengths, target activity and optimal routes are never passed to the forwarding decision.
2. At the first/last time slice different participants may be absent, so the empirical bound and zero-delivery cases are important.
3. Default experimental parameters are hypothetical; varying TTL/forecast half-life and *node opt-in rate* is necessary.
4. A physical BLE smartphone benchmark, private recipient tokens, signed W4 acknowledgements, crash-safe distributed copy credits, and integration with Akula are still missing.
5. Natural observed proximity networks are not representative of all Wi-Fi/BLE contacts, buildings or users. Conclusions should be per-dataset and per-source, not a global 200,000-phone success rate.

**Do not claim that a causal routing simulation is a deployed messenger.**