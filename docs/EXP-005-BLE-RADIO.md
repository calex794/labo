# LABO EXP-005 — BLE signal strength and paired EXP-004 comparison

**Status:** opt-in mathematical RF link budget for controlled simulation. This is not a measured Bluetooth network, a real smartphone stack or an Akula messenger integration. The separate Akula repository remains untouched.

## Old versus new model

- The default `--ble-physics legacy` preserves EXP-004's radio gate (14 m in plaza, 10 m room/hall, 7 m between different rooms; adjacent floors only on the same staircase). It retains the original contact-probe RNG sequence and JSON output.
- The opt-in `--ble-physics budget` computes received signal in dBm with a logarithmic path-loss model. Paths beyond receiver sensitivity do not connect. An explicit upper distance cap is a **model computational constraint**, not Bluetooth's physical range.
- Both use the same positions, movement, radio ownership, volunteer consent and message sender/recipient pairs for the same seed. There is no random RF noise, discovery window, packet-loss model or time-varying radio contention in v1.
- The RF mode samples spatial-index buckets up to an unobstructed link-budget upper bound; the original `±2`-cell probe range is unchanged in legacy mode. The number of sampled buckets remains limited by `--contact-probes`, so it does *not* guarantee all neighbors are discovered even inside physical range.

## Physical hypothesis (2.4 GHz)

For separation d in meters (min 1), we compute

`FSPL(1 m) ≈ 40.05 dB`

`L(d) = 40.05 + 10 n log10(max(d, 1)) + W * L_wall + F * L_floor + E * L_exterior`

`P_rx(dBm) = P_tx + G_tx + G_rx - L(d)`

A modeled directional contact is accepted when `P_rx >= S_rx` and `d <= range_cap_m`. In this first controlled version `G_tx = G_rx = antenna_gain_db` and all virtual devices share one radio profile. Distance includes 3 m per floor; interior room/hall transitions count as one hypothetical wall, distinct rooms as two. Vertical transitions add one floor penalty per floor, unless both endpoints occupy exactly the same staircase shaft. Different campus wings incur an extra exterior loss; this does not simulate accurate building CAD geometry.

All numbers below are hypotheses for sensitivity testing, **not** measurements of smartphones:

| Parameter | Default | CLI |
|---|---:|---|
| TX | 0 dBm | `--ble-tx-dbm` |
| RX threshold | −95 dBm | `--ble-rx-sensitivity-dbm` |
| Antenna gain (each side) | −3 dB | `--ble-antenna-gain-db` |
| Path-loss exponent | 3.0 | `--ble-path-loss` |
| Loss per wall | 5 dB | `--ble-wall-loss-db` |
| Loss per floor | 15 dB | `--ble-floor-loss-db` |
| Extra loss between wings | 20 dB | `--ble-exterior-loss-db` |
| Model range cap | 200 m | `--ble-range-cap-m` |

For example, for 10 m and no obstacles: `0 − 6 − (40.05 + 30) = −76.05 dBm`. With two hypothetical 5 dB walls and 10 dB extra body blocking (not yet modeled as a separate parameter), reception would fall to approximately −96.05 dBm, below the test threshold. These calculations illustrate why a binary distance cutoff is inadequate.

**Not implemented:** per-device radio heterogeneity, asymmetric profiles, LE Coded bitrates, RSS shadowing, advertising/scanning overlap, Android/iOS background constraints, airborne interference, connection setup, packet airtime, battery cost, delay-tolerant queues, genuine message ACK/WOW W4 signatures, inter-building movement. They are required before treating any simulated delivery rate as a field forecast.

## Run

```bash
cargo test --all-targets
cargo build --release
./target/release/labo --geometry-scale density --devices 2000 --messages 3000 \
  --steps 80 --ttl 40 --map plaza --mode ble --mobility all \
  --outages periodic --seed 21021 --ble-physics legacy

./target/release/labo --geometry-scale density --devices 2000 --messages 3000 \
  --steps 80 --ttl 40 --map plaza --mode ble --mobility all \
  --outages periodic --seed 21021 --ble-physics budget

python3 scripts/exp005_radio_pair.py --devices 2000
python3 scripts/exp005_radio_pair.py --devices 20000
python3 scripts/exp005_radio_pair.py --devices 200000
python3 scripts/exp005_radio_pair.py --combine \
  --source results/exp005 --output results/exp005-summary
```

The comparison script runs 36 actual process invocations: 2 radio models × 2 maps × 3 sizes × 3 seeds, all with the EXP-004 1.5 messages/device load, all-moving scenario, periodic outages, 80 steps and TTL 40. It validates the same initial device fingerprints and sender/recipient pairs in each comparison, conservation of messages, no unintended JSON schema changes in legacy mode, and the published **rounded** EXP-004 baseline percentages. Raw CSV/JSON and the synthesized table are uploaded by [exp005-radio.yml](../.github/workflows/exp005-radio.yml).

**Important:** 3 seeds are a pilot, not a statistical confidence interval. The sampled contact algorithm itself changes in RF mode to cover larger distances, so the resulting delta measures the *combined modeled link and discovery proposal changes*, not an isolated causal effect of antenna power. Physical RSS calibration and an independent discovery-window model must be done separately.

## Supporting information

- [LABO-RF-001 (Notion) — prior sources and model](https://app.notion.com/p/40032a84beec8134b41dcbafe984a67d).
- [EXP-004 baseline report](EXP-004-CONSTANT-DENSITY.md).
- [Bluetooth SIG: Understanding Bluetooth Range](https://www.bluetooth.com/learn-about-bluetooth/key-attributes/range/).
- [Bluetooth Core: LE radio physical layer](https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core_v6.3/out/en/low-energy-controller/radio-physical-layer-specification.html).
- [ITU-R P.1238 — propagation indoors](https://www.itu.int/rec/R-REC-P.1238).
- [Scientific Data: measured BLE links with smartphones](https://www.nature.com/articles/s41597-022-01406-2).

Next independent study: inter-wing carriers, real smartphone RSS calibration, and scanning/contact durations. Do not insert LABO approximations into Akula production code without separate acceptance tests.
