//! LABO TIME-03: Byzantine time-witness restoration after offline operation.
//!
//! ISOLATED SYNTHETIC TEST, not Roughtime or a WOW protocol implementation.
//! Ed25519 signatures and verification are real; identities, witnesses, time,
//! RTT, compromise, keys and operator diversity are laboratory assumptions.
//! NEVER treat a valid signed timestamp as proof of correct UTC.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::env;

const OPERATORS: usize = 1_000;
const MAX_KEYS: usize = OPERATORS * 5;
const SEEDS: [u64; 3] = [21, 71, 107];
const BAD_PERCENT: [usize; 7] = [1, 5, 10, 20, 40, 70, 90];
const WITNESSES: [usize; 4] = [1, 2, 3, 5];
const EPOCH: u64 = 7;
const MAX_RTT_MS: u32 = 5_000;
const MAX_RADIUS_S: u32 = 5;
const CONSENSUS_SPREAD_S: u64 = 8;
const SIGN_DOMAIN: &[u8] = b"LABO-TIME03-ONLY-v1\0";
const TRUE_UTC_BASE: i64 = 1_800_000_000 + 30 * 86_400;

fn mix(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9e3779b97f4a7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d049bb133111eb);
    x ^ (x >> 31)
}

fn key(seed: u64, domain: u64, a: u64, b: u64) -> u64 {
    mix(seed ^ mix(domain) ^ mix(a) ^ mix(b.wrapping_add(domain)))
}

fn synthetic_signing_key(seed: u64, endpoint: usize) -> SigningKey {
    // DETERMINISTIC INSECURE LAB KEY; not viable for real public deployments.
    let mut derivation = Vec::with_capacity(40);
    derivation.extend_from_slice(b"LABO-TIME03-TEST-SIGNER");
    derivation.extend_from_slice(&seed.to_be_bytes());
    derivation.extend_from_slice(&(endpoint as u32).to_be_bytes());
    let bytes: [u8; 32] = Sha256::digest(&derivation).into();
    SigningKey::from_bytes(&bytes)
}

fn challenge(seed: u64, scenario: u64, trial: usize, pos: usize) -> [u8; 16] {
    let a = key(seed, 131, scenario ^ (trial as u64), pos as u64);
    let b = key(seed, 132, scenario, (trial as u64).wrapping_mul(8) + pos as u64);
    let mut nonce = [0u8; 16];
    nonce[..8].copy_from_slice(&a.to_be_bytes());
    nonce[8..].copy_from_slice(&b.to_be_bytes());
    nonce
}

#[derive(Clone)]
struct Evidence {
    endpoint: usize,
    nonce: [u8; 16],
    epoch: u64,
    midpoint_utc: i64,
    uncertainty_sec: u32,
    // Measured at client, NOT a claim trusted from the witness.
    measured_roundtrip_ms: u32,
    sig: Signature,
}

fn signed_bytes(
    endpoint: usize, nonce: &[u8; 16], epoch: u64,
    midpoint_utc: i64, uncertainty_sec: u32,
) -> Vec<u8> {
    let mut b = Vec::with_capacity(70);
    b.extend_from_slice(SIGN_DOMAIN);
    b.extend_from_slice(&(endpoint as u32).to_be_bytes());
    b.extend_from_slice(nonce);
    b.extend_from_slice(&epoch.to_be_bytes());
    b.extend_from_slice(&midpoint_utc.to_be_bytes());
    b.extend_from_slice(&uncertainty_sec.to_be_bytes());
    b
}

fn sign_reply(
    key: &SigningKey, endpoint: usize, nonce: [u8; 16],
    utc: i64, uncertainty: u32, rtt_ms: u32,
) -> Evidence {
    let bytes = signed_bytes(endpoint, &nonce, EPOCH, utc, uncertainty);
    Evidence {
        endpoint, nonce, epoch: EPOCH,
        midpoint_utc: utc, uncertainty_sec: uncertainty,
        measured_roundtrip_ms: rtt_ms,
        sig: key.sign(&bytes),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Invalid {
    WrongNonce,
    WrongEpoch,
    BadSignature,
    SlowResponse,
    ExcessUncertainty,
}

fn verify_reply(
    proof: &Evidence, expected_nonce: &[u8; 16], known_key: &SigningKey,
) -> Result<(), Invalid> {
    // In production the key must be pinned, with an externally proven owner.
    if &proof.nonce != expected_nonce { return Err(Invalid::WrongNonce); }
    if proof.epoch != EPOCH { return Err(Invalid::WrongEpoch); }
    let signed = signed_bytes(
        proof.endpoint, &proof.nonce, proof.epoch,
        proof.midpoint_utc, proof.uncertainty_sec,
    );
    known_key.verifying_key().verify(&signed, &proof.sig)
        .map_err(|_| Invalid::BadSignature)?;
    if proof.measured_roundtrip_ms > MAX_RTT_MS {
        return Err(Invalid::SlowResponse);
    }
    if proof.uncertainty_sec > MAX_RADIUS_S {
        return Err(Invalid::ExcessUncertainty);
    }
    Ok(())
}

fn is_conflict(a: &Evidence, b: &Evidence) -> bool {
    // Two visible and individually valid signatures, same signer, request,
    // epoch, but non-overlapping claimed time intervals.
    if a.endpoint != b.endpoint || a.nonce != b.nonce || a.epoch != b.epoch {
        return false;
    }
    a.midpoint_utc.abs_diff(b.midpoint_utc)
        > u64::from(a.uncertainty_sec) + u64::from(b.uncertainty_sec)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Attack {
    FalseTime,
    Replay,
    Slow,
    VisibleFork,
    Sybil,
    Mixed,
}

impl Attack {
    const ALL: [Self; 6] = [
        Self::FalseTime, Self::Replay, Self::Slow,
        Self::VisibleFork, Self::Sybil, Self::Mixed,
    ];
    fn name(self) -> &'static str {
        match self {
            Self::FalseTime => "signed-false-time",
            Self::Replay => "replay",
            Self::Slow => "delayed-response",
            Self::VisibleFork => "visible-split-view",
            Self::Sybil => "sybil-same-operator",
            Self::Mixed => "mixed",
        }
    }
    fn id(self) -> u64 {
        match self {
            Self::FalseTime => 1, Self::Replay => 2,
            Self::Slow => 3, Self::VisibleFork => 4,
            Self::Sybil => 5, Self::Mixed => 6,
        }
    }
}

fn compromise_ranking(seed: u64) -> Vec<usize> {
    let mut owners: Vec<usize> = (0..OPERATORS).collect();
    owners.sort_unstable_by_key(|&owner| (key(seed, 211, owner as u64, 0), owner));
    let mut ranks = vec![0; OPERATORS];
    for (rank, owner) in owners.into_iter().enumerate() {
        ranks[owner] = rank;
    }
    ranks
}

#[derive(Clone, Copy)]
struct Endpoint {
    id: usize,
    operator: usize,
}

fn eligible_endpoints(
    rank: &[usize], bad_count: usize, mode: Attack,
) -> Vec<Endpoint> {
    let mut result = Vec::with_capacity(OPERATORS + 4 * bad_count);
    for (operator, &order) in rank.iter().enumerate() {
        result.push(Endpoint { id: operator * 5, operator });
        if mode == Attack::Sybil && order < bad_count {
            for alias in 1..5 {
                result.push(Endpoint { id: operator * 5 + alias, operator });
            }
        }
    }
    result
}

fn choose_endpoints(
    seed: u64, scenario: u64, trial: usize,
    n: usize, pool: &[Endpoint],
) -> Vec<Endpoint> {
    let mut out = Vec::with_capacity(n);
    let mut index = 0u64;
    while out.len() < n {
        let which = key(
            seed, 89, scenario ^ trial as u64, index,
        ) as usize % pool.len();
        let candidate = pool[which];
        if !out.iter().any(|e: &Endpoint| e.id == candidate.id) {
            out.push(candidate);
        }
        index += 1;
    }
    out
}

fn malicious_profile(mode: Attack, operator: usize) -> Attack {
    match mode {
        Attack::Mixed => match operator % 4 {
            0 => Attack::FalseTime,
            1 => Attack::Replay,
            2 => Attack::Slow,
            _ => Attack::VisibleFork,
        },
        other => other,
    }
}

struct ReplySet {
    main: Evidence,
    second: Option<Evidence>,
}

fn construct_reply(
    k: &SigningKey, selected: Endpoint,
    nonce: [u8; 16], actual_now: i64,
    bad: bool, mode: Attack, seed: u64, trial: usize,
) -> ReplySet {
    let jitter = (key(seed, 51, trial as u64, selected.operator as u64) % 5) as i64 - 2;
    let honest_rtt = (key(seed, 52, trial as u64, selected.id as u64) % 1000) as u32 + 100;
    let effective_attack = if bad {
        malicious_profile(mode, selected.operator)
    } else {
        // This explicit branch prevents honest actors being scored maliciously.
        Attack::Replay
    };
    if !bad {
        return ReplySet {
            main: sign_reply(k, selected.id, nonce, actual_now + jitter, 3, honest_rtt),
            second: None,
        };
    }
    match effective_attack {
        Attack::Replay => {
            let mut previous = nonce;
            previous[0] ^= 1;
            ReplySet {
                main: sign_reply(k, selected.id, previous, actual_now - 3600, 3, honest_rtt),
                second: None,
            }
        }
        Attack::Slow => ReplySet {
            main: sign_reply(k, selected.id, nonce, actual_now - 3600, 3, 30_000),
            second: None,
        },
        Attack::VisibleFork => ReplySet {
            main: sign_reply(k, selected.id, nonce, actual_now + 3600, 3, honest_rtt),
            second: Some(sign_reply(
                k, selected.id, nonce, actual_now - 3600, 3, honest_rtt,
            )),
        },
        Attack::FalseTime | Attack::Sybil | Attack::Mixed => ReplySet {
            main: sign_reply(k, selected.id, nonce, actual_now + 3600, 3, honest_rtt),
            second: None,
        },
    }
}

#[derive(Clone, Copy)]
struct VerifiedSample {
    operator: usize,
    utc: i64,
}

#[derive(Default, Clone)]
struct AttemptCounters {
    queries: u64,
    proofs_signed: u64,
    proofs_verified: u64,
    bad_selected: u64,
    replay_rejected: u64,
    delay_rejected: u64,
    forks_observed: u64,
    duplicate_operators: u64,
    naive_good: u64,
    naive_false: u64,
    naive_unknown: u64,
    guarded_good: u64,
    guarded_false: u64,
    guarded_unknown: u64,
}

fn median_utc(values: &[i64]) -> i64 {
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    sorted[sorted.len() / 2]
}

fn naive_accept(samples: &[VerifiedSample]) -> Option<i64> {
    if samples.is_empty() {
        None
    } else {
        Some(median_utc(
            &samples.iter().map(|s| s.utc).collect::<Vec<_>>(),
        ))
    }
}

fn independent_samples(samples: &[VerifiedSample]) -> (Vec<VerifiedSample>, usize) {
    let mut owners = HashSet::new();
    let filtered = samples.iter().copied().filter(|s| owners.insert(s.operator))
        .collect::<Vec<_>>();
    (filtered, samples.len() - owners.len())
}

fn guarded_accept(samples: &[VerifiedSample], requested: usize) -> Option<i64> {
    // Deliberately conservative test policy, NOT Roughtime or a proven BFT
    // protocol. One/two signed sources never authorize changing absolute UTC.
    let quorum = match requested {
        3 => 3,
        5 => 4,
        _ => return None,
    };
    if samples.len() < quorum { return None; }

    let mut supported: Vec<i64> = Vec::new();
    for sample in samples {
        let agreement = samples.iter().filter(|candidate| {
            candidate.utc.abs_diff(sample.utc) <= CONSENSUS_SPREAD_S
        }).count();
        if agreement >= quorum {
            supported.push(sample.utc);
        }
    }
    if supported.len() < quorum { return None; }
    let tentative = median_utc(&supported);
    let supporters = samples.iter().filter(|s| {
        s.utc.abs_diff(tentative) <= CONSENSUS_SPREAD_S
    }).count();
    (supporters >= quorum).then_some(tentative)
}

fn score_recovered(estimate: Option<i64>, actual_utc: i64, good: &mut u64,
                   bad: &mut u64, unknown: &mut u64) {
    match estimate {
        Some(t) if t.abs_diff(actual_utc) <= 15 => *good += 1,
        Some(_) => *bad += 1,
        None => *unknown += 1,
    }
}

fn experiment_round(
    seed: u64, mode: Attack, percent: usize, requested: usize,
    trial: usize, endpoints: &[Endpoint], rank: &[usize],
    keyring: &[SigningKey],
    counters: &mut AttemptCounters,
) {
    let scenario = mode.id() * 100_000 + (percent as u64) * 100 + requested as u64;
    let selected = choose_endpoints(seed, scenario, trial, requested, endpoints);
    let true_utc = TRUE_UTC_BASE + (key(seed, 18, trial as u64, 0) % 86_400) as i64;
    let mut accepted: Vec<VerifiedSample> = Vec::new();
    for (pos, endpoint) in selected.iter().enumerate() {
        let bad = rank[endpoint.operator] < percent * OPERATORS / 100;
        counters.bad_selected += u64::from(bad);
        counters.queries += 1;
        let nonce = challenge(seed, scenario, trial, pos);
        let replies = construct_reply(
            &keyring[endpoint.id], *endpoint, nonce, true_utc,
            bad, mode, seed, trial,
        );
        counters.proofs_signed += 1 + u64::from(replies.second.is_some());

        let first = verify_reply(&replies.main, &nonce, &keyring[endpoint.id]);
        if let Err(reason) = first {
            match reason {
                Invalid::WrongNonce => counters.replay_rejected += 1,
                Invalid::SlowResponse => counters.delay_rejected += 1,
                _ => {}
            }
            continue;
        }
        counters.proofs_verified += 1;
        if let Some(second) = replies.second {
            if verify_reply(&second, &nonce, &keyring[endpoint.id]).is_ok() {
                counters.proofs_verified += 1;
                if is_conflict(&replies.main, &second) {
                    counters.forks_observed += 1;
                    continue;
                }
            }
        }
        accepted.push(VerifiedSample {
            operator: endpoint.operator, utc: replies.main.midpoint_utc,
        });
    }
    let naive = naive_accept(&accepted);
    let (distinct, duplicates) = independent_samples(&accepted);
    counters.duplicate_operators += duplicates as u64;
    let guarded = guarded_accept(&distinct, requested);
    score_recovered(
        naive, true_utc, &mut counters.naive_good,
        &mut counters.naive_false, &mut counters.naive_unknown,
    );
    score_recovered(
        guarded, true_utc, &mut counters.guarded_good,
        &mut counters.guarded_false, &mut counters.guarded_unknown,
    );
}

fn emit_summary(
    seed: u64, mode: Attack, percent: usize, requested: usize,
    trials: usize, v: &AttemptCounters,
) {
    println!(
        concat!(
            "{{\"schema\":\"labo-time03-byzantine-clock-v1\",",
            "\"claim\":\"synthetic-not-a-time-service\",",
            "\"cryptography\":\"ed25519-dalek-verified-lab-signatures\",",
            "\"operator_diversity\":\"trusted-registry-model-assumption\",",
            "\"seed\":{},\"scenario\":\"{}\",\"bad_percent\":{},",
            "\"known_operators\":1000,\"requested_witnesses\":{},",
            "\"trials\":{},\"queries\":{},\"proofs_signed\":{},",
            "\"proofs_verified\":{},\"bad_selected\":{},",
            "\"replay_rejected\":{},\"delay_rejected\":{},",
            "\"forks_observed\":{},\"duplicate_operators\":{},",
            "\"naive_good\":{},\"naive_false\":{},\"naive_unknown\":{},",
            "\"guarded_good\":{},\"guarded_false\":{},",
            "\"guarded_unknown\":{},\"utc_from_tag\":false}}"
        ),
        seed, mode.name(), percent, requested,
        trials, v.queries, v.proofs_signed, v.proofs_verified,
        v.bad_selected, v.replay_rejected, v.delay_rejected,
        v.forks_observed, v.duplicate_operators,
        v.naive_good, v.naive_false, v.naive_unknown,
        v.guarded_good, v.guarded_false, v.guarded_unknown,
    );
}

fn run(trials: usize) {
    for seed in SEEDS {
        let rank = compromise_ranking(seed);
        let keyring: Vec<_> = (0..MAX_KEYS)
            .map(|index| synthetic_signing_key(seed, index))
            .collect();
        for percent in BAD_PERCENT {
            for mode in Attack::ALL {
                let pool = eligible_endpoints(
                    &rank, percent * OPERATORS / 100, mode,
                );
                for requested in WITNESSES {
                    let mut counters = AttemptCounters::default();
                    for trial in 0..trials {
                        experiment_round(
                            seed, mode, percent, requested, trial, &pool,
                            &rank, &keyring, &mut counters,
                        );
                    }
                    assert_eq!(
                        counters.guarded_good + counters.guarded_false
                            + counters.guarded_unknown, trials as u64,
                    );
                    assert_eq!(
                        counters.naive_good + counters.naive_false
                            + counters.naive_unknown, trials as u64,
                    );
                    emit_summary(seed, mode, percent, requested, trials, &counters);
                }
            }
        }
    }
}

fn main() {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args == ["--help"] {
        println!("LABO TIME-03 synthetic: [--trials 256]");
        return;
    }
    let trials = if args.is_empty() {
        256
    } else if args.len() == 2 && args[0] == "--trials" {
        args[1].parse::<usize>().unwrap_or(0)
    } else {
        0
    };
    if !(16..=10_000).contains(&trials) {
        eprintln!("trials must be in [16,10000]");
        std::process::exit(2);
    }
    run(trials);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn single() -> (SigningKey, [u8; 16], Evidence) {
        let key = synthetic_signing_key(21, 42);
        let nonce = challenge(21, 123, 7, 2);
        let proof = sign_reply(&key, 42, nonce, 2_000_000_000, 3, 500);
        (key, nonce, proof)
    }

    #[test]
    fn ed25519_proof_verifies_and_modified_time_fails() {
        let (key, nonce, mut proof) = single();
        assert_eq!(verify_reply(&proof, &nonce, &key), Ok(()));
        proof.midpoint_utc += 1000;
        assert_eq!(
            verify_reply(&proof, &nonce, &key), Err(Invalid::BadSignature),
        );
    }

    #[test]
    fn nonce_replay_and_cross_key_impostor_rejected() {
        let (key, nonce, proof) = single();
        let different = synthetic_signing_key(21, 43);
        assert_eq!(
            verify_reply(&proof, &[0; 16], &key), Err(Invalid::WrongNonce),
        );
        assert_eq!(
            verify_reply(&proof, &nonce, &different), Err(Invalid::BadSignature),
        );
    }

    #[test]
    fn old_epoch_and_long_rtt_are_rejected() {
        let (key, nonce, mut proof) = single();
        proof.epoch -= 1;
        assert_eq!(verify_reply(&proof, &nonce, &key), Err(Invalid::WrongEpoch));
        proof.epoch = EPOCH;
        proof.measured_roundtrip_ms = 20_000;
        assert_eq!(verify_reply(&proof, &nonce, &key), Err(Invalid::SlowResponse));
    }

    #[test]
    fn two_visible_signed_forks_produce_observed_evidence() {
        let (key, nonce, first) = single();
        let second = sign_reply(&key, 42, nonce, first.midpoint_utc + 3600, 3, 500);
        assert_eq!(verify_reply(&first, &nonce, &key), Ok(()));
        assert_eq!(verify_reply(&second, &nonce, &key), Ok(()));
        assert!(is_conflict(&first, &second));
        // A fork that is hidden from the same verifier is *not* detected here.
    }

    #[test]
    fn no_absolute_time_set_with_one_or_two_sources() {
        let samples = [
            VerifiedSample {operator:1, utc:2_000_000_000},
            VerifiedSample {operator:2, utc:2_000_000_001},
        ];
        assert_eq!(guarded_accept(&samples[..1], 1), None);
        assert_eq!(guarded_accept(&samples, 2), None);
        assert!(naive_accept(&samples).is_some());
    }

    #[test]
    fn three_source_unanimity_and_five_source_quorum() {
        let good = [
            VerifiedSample {operator:1, utc:500},
            VerifiedSample {operator:2, utc:501},
            VerifiedSample {operator:3, utc:499},
            VerifiedSample {operator:4, utc:502},
        ];
        let bad = VerifiedSample {operator:5, utc:4100};
        assert_eq!(guarded_accept(&good[..3], 3), Some(500));
        assert_eq!(
            guarded_accept(&[good[0], good[1], bad], 3), None,
        );
        assert_eq!(
            guarded_accept(&[good[0], good[1], good[2], good[3], bad], 5),
            Some(501),
        );
    }

    #[test]
    fn signed_liars_can_force_false_time_without_anchor() {
        let liar = [
            VerifiedSample {operator:1, utc:4100},
            VerifiedSample {operator:2, utc:4100},
            VerifiedSample {operator:3, utc:4100},
        ];
        assert_eq!(guarded_accept(&liar, 3), Some(4100));
        // This result is malicious but indistinguishable from an honest group
        // if there is no independent trustworthy time bound.
    }

    #[test]
    fn cloned_operator_identities_are_not_independent() {
        let samples = [
            VerifiedSample {operator:42, utc:4100},
            VerifiedSample {operator:42, utc:4100},
            VerifiedSample {operator:42, utc:4100},
        ];
        let (distinct, ignored) = independent_samples(&samples);
        assert_eq!(distinct.len(), 1);
        assert_eq!(ignored, 2);
        assert_eq!(guarded_accept(&distinct, 3), None);
        assert_eq!(naive_accept(&samples), Some(4100));
    }

    #[test]
    fn nested_compromise_fractions_and_sybil_pool() {
        let rank = compromise_ranking(21);
        let mut previous = vec![false; OPERATORS];
        for percent in BAD_PERCENT {
            let marked = (0..OPERATORS)
                .map(|owner| rank[owner] < percent * 10)
                .collect::<Vec<_>>();
            assert_eq!(marked.iter().filter(|&&b| b).count(), percent * 10);
            assert!(
                previous.iter().zip(&marked).all(|(&a, &b)| !a || b),
            );
            previous = marked;
            let pool = eligible_endpoints(&rank, percent * 10, Attack::Sybil);
            assert_eq!(pool.len(), OPERATORS + percent * 40);
        }
    }

    #[test]
    fn full_scenario_repeatability_and_invalid_inputs() {
        let rank = compromise_ranking(21);
        let pool = eligible_endpoints(&rank, 200, Attack::Mixed);
        let keys = (0..MAX_KEYS)
            .map(|i| synthetic_signing_key(21, i))
            .collect::<Vec<_>>();
        let f = || {
            let mut counters = AttemptCounters::default();
            for trial in 0..20 {
                experiment_round(
                    21, Attack::Mixed, 20, 5, trial, &pool, &rank, &keys,
                    &mut counters,
                );
            }
            (counters.naive_false, counters.guarded_false,
             counters.guarded_unknown, counters.forks_observed)
        };
        assert_eq!(f(), f());
    }

    #[test]
    fn rtc_watermark_is_not_absolute_utc_after_power_loss() {
        // Mathematical lower bound can remain valid; it cannot by itself
        // tell how long power was absent. Zero elapsed is *not* a justified
        // upper bound.
        let last_trusted_lower = 1_800_000_000i64;
        let real_elapsed = 30 * 86_400;
        assert_eq!(last_trusted_lower + real_elapsed, 1_802_592_000);
        assert_ne!(last_trusted_lower, 1_802_592_000);
    }
}
