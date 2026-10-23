//! LABO EXP-020: rotating private rendezvous identifiers after 30 days offline.
//!
//! Real HMAC-SHA256/HKDF primitives for the 128-bit tag, but simulated keys,
//! clock faults, permissions, availability and contact events. This is NOT a
//! deployed Akula/WOW protocol, authenticating a peer, an end-to-end message,
//! a Bluetooth experiment, or a proof of unlinkability/security.
//!
//! Each client and permitted custodian have prearranged an independent secret.
//! A matching tag is an *index*, NEVER a capability or delivery receipt.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::env;

type HmacSha256 = Hmac<Sha256>;
type Tag = [u8; 16];

const PEERS: usize = 1_000;
const CLIENTS: usize = 128;
const CANDIDATES: [usize; 4] = [3, 6, 10, 20];
const BAD_PERCENTS: [usize; 7] = [1, 5, 10, 20, 40, 70, 90];
const PERIODS: [i64; 5] = [600, 1_200, 3_600, 21_600, 86_400];
const SKEWS: [i64; 11] = [
    -2_592_000, -86_400, -3_600, -300, -30, 0,
    30, 300, 3_600, 86_400, 2_592_000,
];
const SEEDS: [u64; 3] = [21, 71, 107];
const OFFLINE_DAYS: i64 = 30;
const FIXED_SCOPE: u64 = 42;
const POLICY_EPOCH: u64 = 7;

fn mix(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9e3779b97f4a7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d049bb133111eb);
    x ^ (x >> 31)
}

// Only used to create deterministic laboratory scenarios, not key material
// in a real deployment.
fn keyed(seed: u64, domain: u64, a: u64, b: u64) -> u64 {
    mix(seed ^ mix(domain) ^ mix(a) ^ mix(b.wrapping_add(domain)))
}

/// Derive pair-specific laboratory shared key; 64-bit seed is intentionally
/// NOT a cryptographically secure secret, and must NEVER go into a product.
fn lab_pair_key(seed: u64, client: usize, peer: usize) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(b"AKULA-WOW-RID-EXP020-ONLY"), &seed.to_be_bytes());
    let mut info = Vec::with_capacity(48);
    info.extend_from_slice(b"lab-pair-key/v0");
    info.extend_from_slice(&(client as u32).to_be_bytes());
    info.extend_from_slice(&(peer as u32).to_be_bytes());
    let mut out = [0u8; 32];
    hk.expand(&info, &mut out).expect("HKDF expand 32 bytes");
    out
}

/// Fixed-width, domain-separated encoding, HMAC-SHA256 truncated to 128 bits.
/// This binding has not received an Akula cryptographic review.
fn rotating_tag(secret: &[u8; 32], scope: u64, epoch: u64, bucket: i64) -> Tag {
    let mut mac = HmacSha256::new_from_slice(secret).expect("valid HMAC key");
    mac.update(b"AKULA-WOW-RID\0v0\0");
    mac.update(&scope.to_be_bytes());
    mac.update(&epoch.to_be_bytes());
    mac.update(&bucket.to_be_bytes());
    let full = mac.finalize().into_bytes();
    let mut short = [0u8; 16];
    short.copy_from_slice(&full[..16]);
    short
}

fn bucket(time_seconds: i64, period_seconds: i64) -> i64 {
    time_seconds.div_euclid(period_seconds)
}

fn hex(tag: &Tag) -> String {
    let mut out = String::new();
    for b in tag {
        use std::fmt::Write;
        write!(&mut out, "{b:02x}").expect("hex");
    }
    out
}

#[derive(Clone, Copy, Debug)]
struct Config {
    trials_per_cell: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self { trials_per_cell: 512 }
    }
}

impl Config {
    fn from_args() -> Result<Self, String> {
        let mut cfg = Self::default();
        let mut args = env::args().skip(1);
        while let Some(a) = args.next() {
            if a == "--help" || a == "-h" {
                println!("LABO EXP-020 rotating-ID offline discovery: --trials 512");
                std::process::exit(0);
            }
            let value = args.next().ok_or_else(|| format!("no value for {a}"))?;
            match a.as_str() {
                "--trials" => cfg.trials_per_cell = value.parse()
                    .map_err(|_| "invalid trials".to_string())?,
                _ => return Err(format!("unknown argument {a}")),
            }
        }
        if !(16..=10_000).contains(&cfg.trials_per_cell) {
            return Err("trials outside 16..=10000".to_string());
        }
        Ok(cfg)
    }
}

#[derive(Default, Clone, Copy)]
struct Stats {
    attempts: usize,
    no_honest_in_invitation: usize,
    honest_present_but_not_online: usize,
    any_tag_strict: usize,
    any_tag_adjacent: usize,
    honest_tag_strict: usize,
    honest_tag_adjacent: usize,
    compromised_tag_adjacent: usize,
    client_hmac_calls_strict: usize,
    client_hmac_calls_adjacent: usize,
    service_hmac_calls: usize,
}

#[derive(Clone, Copy)]
struct Encounter {
    honest: bool,
    online: bool,
    strict: bool,
    adjacent: bool,
}

impl Stats {
    fn include(&mut self, encounters: &[Encounter]) {
        self.attempts += 1;
        let honest = encounters.iter().filter(|e| e.honest).count();
        if honest == 0 {
            self.no_honest_in_invitation += 1;
        } else if !encounters.iter().any(|e| e.honest && e.online) {
            self.honest_present_but_not_online += 1;
        }
        if encounters.iter().any(|e| e.online && e.strict) {
            self.any_tag_strict += 1;
        }
        if encounters.iter().any(|e| e.online && e.adjacent) {
            self.any_tag_adjacent += 1;
        }
        if encounters.iter().any(|e| e.online && e.honest && e.strict) {
            self.honest_tag_strict += 1;
        }
        if encounters.iter().any(|e| e.online && e.honest && e.adjacent) {
            self.honest_tag_adjacent += 1;
        }
        if encounters.iter().any(|e| e.online && !e.honest && e.adjacent) {
            self.compromised_tag_adjacent += 1;
        }
        // Model worst-case client computation per known contact.
        // Actual BLE advertisements may require one beacon per PAIR, not per
        // service: group-shared tags vs pairwise tags is unresolved.
        self.client_hmac_calls_strict += encounters.len();
        self.client_hmac_calls_adjacent += 3 * encounters.len();
        self.service_hmac_calls += encounters.len();
    }

    fn write_json(self, seed: u64, percent: usize, candidates: usize,
                  period: i64, skew: i64) {
        println!(
            concat!(
                "{{\"schema\":\"labo-exp020-offline-rid-v1\",",
                "\"claim\":\"synthetic-contact-not-real-network\",",
                "\"seed\":{},\"custodians\":1000,\"bad_percent\":{},",
                "\"candidates\":{},\"rotation_seconds\":{},\"clock_skew_seconds\":{},",
                "\"offline_days\":30,\"trials\":{},",
                "\"no_honest_in_invitation\":{},\"honest_present_but_not_online\":{},",
                "\"any_tag_strict\":{},\"any_tag_adjacent\":{},",
                "\"honest_tag_strict\":{},\"honest_tag_adjacent\":{},",
                "\"compromised_tag_adjacent\":{},",
                "\"client_hmac_calls_strict\":{},\"client_hmac_calls_adjacent\":{},",
                "\"service_hmac_calls\":{},\"tag_is_authorization\":false}}"
            ),
            seed, percent, candidates, period, skew, self.attempts,
            self.no_honest_in_invitation, self.honest_present_but_not_online,
            self.any_tag_strict, self.any_tag_adjacent,
            self.honest_tag_strict, self.honest_tag_adjacent,
            self.compromised_tag_adjacent, self.client_hmac_calls_strict,
            self.client_hmac_calls_adjacent, self.service_hmac_calls,
        );
    }
}

fn selected_peers(seed: u64, trial: usize) -> [usize; 20] {
    let mut values = [usize::MAX; 20];
    let mut used = 0;
    let mut attempt = 0u64;
    while used < values.len() {
        let peer = (keyed(seed, 81, trial as u64, attempt) as usize) % PEERS;
        attempt += 1;
        if !values[..used].contains(&peer) {
            values[used] = peer;
            used += 1;
        }
    }
    values
}

fn compromised_rank(seed: u64) -> Vec<usize> {
    let mut peers: Vec<usize> = (0..PEERS).collect();
    peers.sort_unstable_by_key(|&peer| (keyed(seed, 212, peer as u64, 0), peer));
    let mut rank = vec![0; PEERS];
    for (i, &peer) in peers.iter().enumerate() {
        rank[peer] = i;
    }
    rank
}

/// Offline calculation. Nothing is sent to, or received from, a server here.
/// No physical receiver/router is implemented.
fn simulate(cfg: Config) {
    println!(
        "# LABO EXP-020, RustCrypto HMAC-SHA256/HKDF; model inputs deterministic; \
        separate signature authentication NOT modelled"
    );
    for seed in SEEDS {
        let rank = compromised_rank(seed);
        let pair_keys: Vec<[u8; 32]> = (0..CLIENTS).flat_map(|client| {
            (0..PEERS).map(move |peer| lab_pair_key(seed, client, peer))
        }).collect();
        let candidates_by_trial: Vec<[usize; 20]> = (0..cfg.trials_per_cell)
            .map(|t| selected_peers(seed, t)).collect();

        for period in PERIODS {
            for skew in SKEWS {
                let mut totals =
                    vec![vec![Stats::default(); CANDIDATES.len()]; BAD_PERCENTS.len()];

                for trial in 0..cfg.trials_per_cell {
                    let client = trial % CLIENTS;
                    let peers = &candidates_by_trial[trial];
                    // Encounter happens AFTER 30 days apart. Server has kept
                    // its wall clock; client's clock error is the varied input.
                    let now = 1_800_000_000i64
                        + OFFLINE_DAYS * 86_400
                        + (keyed(seed, 17, trial as u64, 0) % (30 * 86_400)) as i64;
                    let actual_bucket = bucket(now, period);
                    let client_bucket = bucket(now + skew, period);
                    let contacts: Vec<(usize, bool, bool, bool)> = peers.iter()
                        .map(|&peer| {
                            let shared = &pair_keys[client * PEERS + peer];
                            let announced = rotating_tag(
                                shared, FIXED_SCOPE, POLICY_EPOCH, actual_bucket
                            );
                            let strict = rotating_tag(
                                shared, FIXED_SCOPE, POLICY_EPOCH, client_bucket
                            ) == announced;
                            let adjacent = strict
                                || rotating_tag(
                                    shared, FIXED_SCOPE, POLICY_EPOCH, client_bucket - 1
                                ) == announced
                                || rotating_tag(
                                    shared, FIXED_SCOPE, POLICY_EPOCH, client_bucket + 1
                                ) == announced;
                            let online = keyed(seed, 19, trial as u64, peer as u64) % 1000
                                < 950;
                            (peer, online, strict, adjacent)
                        }).collect();

                    for (pi, &bad) in BAD_PERCENTS.iter().enumerate() {
                        for (ci, &count) in CANDIDATES.iter().enumerate() {
                            let encounters: Vec<Encounter> = contacts[..count].iter()
                                .map(|&(peer, online, strict, adjacent)| Encounter {
                                    honest: rank[peer] >= bad * PEERS / 100,
                                    online, strict, adjacent,
                                })
                                .collect();
                            totals[pi][ci].include(&encounters);
                        }
                    }
                }
                for (pi, &bad) in BAD_PERCENTS.iter().enumerate() {
                    for (ci, &count) in CANDIDATES.iter().enumerate() {
                        totals[pi][ci].write_json(seed, bad, count, period, skew);
                    }
                }
            }
        }
    }
}

fn main() {
    let cfg = Config::from_args().unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(2)
    });
    simulate(cfg);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_sha256_fixture_matches_python_standard_library() {
        let key: [u8; 32] = std::array::from_fn(|i| i as u8);
        let got = rotating_tag(&key, 42, 7, 3_000_000);
        assert_eq!(hex(&got), "c0af781a0c066c1b4118895184ee76dc");
        let previous = rotating_tag(&key, 42, 7, 2_999_999);
        assert_eq!(hex(&previous), "f3297d13e7bcfdf1ee7095365a88992c");
    }

    #[test]
    fn same_secret_and_window_matches_offline_after_thirty_days() {
        let k = lab_pair_key(21, 5, 777);
        let thirty_days = 30 * 86_400;
        let t = 1_800_000_000 + thirty_days;
        let b = bucket(t, 600);
        assert_eq!(rotating_tag(&k, 42, 7, b), rotating_tag(&k, 42, 7, b));
        assert_ne!(rotating_tag(&k, 42, 7, b), rotating_tag(&k, 42, 7, b + 1));
    }

    #[test]
    fn scope_epoch_and_pair_separation() {
        let k1 = lab_pair_key(21, 5, 777);
        let k2 = lab_pair_key(21, 6, 777);
        let k3 = lab_pair_key(21, 5, 778);
        let t = rotating_tag(&k1, 42, 7, 1);
        assert_ne!(t, rotating_tag(&k2, 42, 7, 1));
        assert_ne!(t, rotating_tag(&k3, 42, 7, 1));
        assert_ne!(t, rotating_tag(&k1, 43, 7, 1));
        assert_ne!(t, rotating_tag(&k1, 42, 8, 1));
        assert_ne!(t, rotating_tag(&k1, 42, 7, 0));
    }

    #[test]
    fn negative_buckets_use_euclidean_division() {
        assert_eq!(bucket(-1, 600), -1);
        assert_eq!(bucket(-600, 600), -1);
        assert_eq!(bucket(-601, 600), -2);
    }

    #[test]
    fn thirty_day_clock_reset_cannot_be_fixed_by_one_adjacent_window() {
        for period in PERIODS {
            let correct = bucket(1_800_000_000 + 30 * 86_400, period);
            let stale = bucket(1_800_000_000, period);
            assert!((correct - stale).abs() > 1);
        }
    }

    #[test]
    fn all_bad_invitation_cannot_be_authenticated_by_a_matching_tag() {
        let mut x = Stats::default();
        x.include(&[Encounter { honest:false,online:true,strict:true,adjacent:true }; 6]);
        assert_eq!(x.no_honest_in_invitation, 1);
        assert_eq!(x.honest_tag_adjacent, 0);
        assert_eq!(x.any_tag_strict, 1);
        assert_eq!(x.compromised_tag_adjacent, 1);
    }

    #[test]
    fn expected_cost_one_and_three_buckets_for_each_peer() {
        let mut stats = Stats::default();
        stats.include(&[Encounter {honest:true,online:true,strict:true,adjacent:true};20]);
        assert_eq!(stats.client_hmac_calls_strict, 20);
        assert_eq!(stats.client_hmac_calls_adjacent, 60);
        assert_eq!(stats.service_hmac_calls, 20);
    }

    #[test]
    fn compromised_sets_nested_for_same_seed() {
        let rank = compromised_rank(71);
        let mut last = vec![false; PEERS];
        for percent in BAD_PERCENTS {
            let now: Vec<bool> = (0..PEERS).map(|p| rank[p] < PEERS * percent / 100)
                .collect();
            assert_eq!(now.iter().filter(|&&bad| bad).count(), percent * 10);
            assert!(last.iter().zip(&now).all(|(&x, &y)| !x || y));
            last = now;
        }
    }

    #[test]
    fn candidate_prefixes_are_unique_and_deterministic() {
        let first = selected_peers(21, 17);
        let again = selected_peers(21, 17);
        assert_eq!(first, again);
        for (i, p) in first.iter().enumerate() {
            assert!(*p < PEERS && !first[i+1..].contains(p));
        }
    }
}
