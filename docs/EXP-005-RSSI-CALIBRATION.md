# LABO — calibration of BLE model using measured smartphone RSSI

**Dataset:** Aranda Polo et al., *Frequency-Based Decoupling and Modeling of BLE RSS Measurements for Indoor Positioning* (I2MTC 2025), [Zenodo 14835351](https://zenodo.org/records/14835351), DOI `10.5281/zenodo.14835351`. Recorded 2024-11-28. Individual phone receiver campaigns were collected with other experimental transmitter(s); **do not call these smartphone-to-smartphone transmissions without checking original experiment configuration**.

## Purpose

The first LABO RF study [EXP-005](EXP-005-BLE-RADIO.md) used the same arbitrary transmitter power, antenna gain and log-distance exponent for every simulated device. This follow-up computes per-phone effective *received* RSS at 1 m and a path-loss exponent from real measured RSSI, while preserving legacy/RF synthetic simulations. It does **not** measure transmitter power, actual phone battery use, BLE discovery probability, or delivered messages.

Six small original CSVs are downloaded by the [calibration workflow](../.github/workflows/exp005-rssi-calibration.yml) using published filename + exact MD5. Raw files are ephemeral on CI and **not redistributed in this repository**. Pinned MD5 prevents silent changes; we also record provenance in `profiles.json` artifact. Run again if the source becomes unavailable. All processing uses Python standard library.

## Statistical method

For each phone `d` is the logged ground-truth range in meters, RSS in dBm. For every recorded distance `d_i`, compute the median of the received packets. Fit the least-squares regression

`median_RSS(d) = A - 10*n*log10(d / 1m)`

across the **distinct distances with equal weight**, to prevent ranges with many high-frequency samples from dominating. Output:
- `A = RSS@1m`, effective *measured received strength* and NOT `tx_dbm`.
- `n`, effective propagation exponent only in the measured indoor environment.
- Raw sample residual RMSE and *leave-one-distance-out* RMSE on median RSS; validation does not leak the same distance's packets into train/test.
- Count per measured distance, rejected invalid samples and range limits.

The RSS sample database is **conditioned on receiving advertisements**. Missing, undetected advertisements are not represented, so it cannot calibrate `P(discovery)` or `P(delivery)` without separate packet counters and background scanning measurements. One campaign cannot establish the distribution across arbitrary phone hardware or buildings. Be especially careful with channel mixing, multipath and phone orientation.

The calibrated parameters are not used for extrapolation beyond the maximal source-measured distance. For the pilot, the LABO `--ble-range-cap-m` limit is set accordingly and clearly reported.

## Reproducible numerical findings (first full successful data fetch)

The MD5-pinned source campaigns yielded **32,435 valid RSS observations** at 23 distances, 0.5–11.5 m. Every fitted median-distance path-loss exponent was **1.228–1.423**, which is below the prior arbitrary model minimum 1.5. This was a **scientifically useful falsification of our input range**, not grounds to clip the measurements. Expanded the allowed LABO range to **0.5–6** while keeping validation and the original analytic default n=3.0. Low effective n may result from corridor guidance, multipath and received-packet selection effects; these results do not establish a universal free-space propagation law or phone Tx power.

Measured numerical coefficients are committed as the small derived [pinned CSV](EXP-005-MEASURED-RSSI-COEFFICIENTS.csv). The actual raw measurements remain hosted by the original authors and are downloaded only in CI, where a fresh fit must reproduce the snapshot within numerical rounding tolerance.

## LABO RF implementation

`--ble-physics budget --ble-reference-rssi-at-1m A --ble-path-loss n`

When a reference is provided, received signal is modeled as `A - 10*n*log10(max(d,1m)) - hypothetical wall/floor/exterior losses`, instead of calculating `tx + antenna gains - 40.05dB` at 1 m. This prevents the common error of treating receiver RSS measured in one radio link as the transmitter's actual emitted power. The estimated probability of true user delivery is **not** produced. The receiver threshold remains an explicit independent assumption. The default `None` preserves the previous `budget-v1` calculations and `--ble-physics legacy` preserves EXP-004.

## Reproduce

```bash
python3 -m unittest discover -s scripts -p 'test_exp005_rssi_calibrate.py' -v
python3 scripts/exp005_rssi_calibrate.py --download \
  --input-dir results/raw-rssi --output results/phone-fits
cargo test --all-targets
cargo build --release
python3 scripts/exp005_calibration_compare.py \
  --profiles results/phone-fits/profiles.json \
  --binary target/release/labo \
  --output results/phone-comparison
```

Outputs: `profiles.json`, `profiles.csv`, `report.md` (measured RSS model coefficients) plus separate `comparison.csv`, `comparison.json`, `report.md` (only simulated message delivery, never real measurements). All 6 phone profiles remain in source report even if a fit is outside runtime-valid ranges; they are flagged as unusable, not clipped.

## Next independent validations

1. BLE advertisements and scanning windows (including Android/iOS foreground/background) per real recorded contact duration.
2. Independent time-stamped inter-wing pedestrian contact paths and realistic multi-carrier DTN.
3. Separate radio-band collision/airtime, energy, buffers, acknowledgement checks.
4. Reproduction on hardware with explicit phone models, receiver sensitivity assumptions, antenna orientation and buildings.

Related: [LABO-LIT-002 research](https://app.notion.com/p/40032a84beec812e950ff2304e7435eb), [issue #3](https://github.com/calex794/labo/issues/3), [EXP-004 baseline](EXP-004-CONSTANT-DENSITY.md).

**Never treat numbers labelled `synthetic-not-measured` as physical delivery measurements.**
