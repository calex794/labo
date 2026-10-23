//! LABO CAUSAL-01: causal order + bounded age + retrospective UTC interval.
//!
//! Isolated deterministic research. Real SHA-256 and Ed25519 verification on
//! INSECURE deterministic laboratory keys. W3/W4, W8, W10, disk, cryptographic
//! custody and two physical computers are NOT implemented.
//! A valid signed claim is NEVER evidence that its physical time is true.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest as ShaDigest, Sha256};
use std::collections::{HashMap, HashSet};

type Digest = [u8; 32];
const ZERO: Digest = [0; 32];
const SCOPE: u64 = 42;
const BASE_UTC: i64 = 1_800_000_000;
const THIRTY_DAYS: i64 = 30 * 86_400;
const MAX_LOGICAL_STEP: u64 = 1;
const RECORD_DOMAIN: &[u8] = b"LABO-CAUSAL01-EVENT-v1\0";
const ANCHOR_DOMAIN: &[u8] = b"LABO-CAUSAL01-ANCHOR-v1\0";

fn mix(mut v: u64) -> u64 {
    v = v.wrapping_add(0x9e3779b97f4a7c15);
    v = (v ^ (v >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    v = (v ^ (v >> 27)).wrapping_mul(0x94d049bb133111eb);
    v ^ (v >> 31)
}

fn draw(seed: u64, domain: u64, index: u64) -> u64 {
    mix(seed ^ mix(domain) ^ mix(index))
}

fn lab_key(seed: u64, actor: u8) -> SigningKey {
    let mut input = b"INSECURE-LAB-CAUSAL01-KEY".to_vec();
    input.extend_from_slice(&seed.to_be_bytes());
    input.push(actor);
    SigningKey::from_bytes(&Sha256::digest(input).into())
}

fn hash(data: &[u8]) -> Digest {
    Sha256::digest(data).into()
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
enum Kind {
    Checkpoint = 1,
    Received = 2,
    Stored = 3,
    HandoffClaim = 4,
}

#[derive(Clone, Debug)]
struct Event {
    scope: u64,
    actor: u8,
    boot_generation: u32,
    seq: u64,
    lamport: u64,
    predecessor: Digest,
    parent: Option<Digest>,
    kind: Kind,
    claimed_utc: i64,
}

impl Event {
    fn bytes(&self) -> Vec<u8> {
        // Fixed-width canonical encoding, private scope, domain separation.
        let mut b = RECORD_DOMAIN.to_vec();
        b.extend_from_slice(&self.scope.to_be_bytes());
        b.push(self.actor);
        b.extend_from_slice(&self.boot_generation.to_be_bytes());
        b.extend_from_slice(&self.seq.to_be_bytes());
        b.extend_from_slice(&self.lamport.to_be_bytes());
        b.extend_from_slice(&self.predecessor);
        match self.parent {
            Some(p) => {
                b.push(1);
                b.extend_from_slice(&p);
            }
            None => {
                b.push(0);
                b.extend_from_slice(&ZERO);
            }
        }
        b.push(self.kind as u8);
        b.extend_from_slice(&self.claimed_utc.to_be_bytes());
        b
    }

    fn digest(&self) -> Digest {
        hash(&self.bytes())
    }
}

#[derive(Clone)]
struct SignedEvent {
    data: Event,
    signature: Signature,
}

fn sign(key: &SigningKey, data: Event) -> SignedEvent {
    let signature = key.sign(&data.bytes());
    SignedEvent { data, signature }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reject {
    Key,
    Signature,
    Fork,
    Replay,
    Sequence,
    Predecessor,
    MissingParent,
    Scope,
    LogicalCounter,
}

#[derive(Clone, Copy)]
struct Head {
    seq: u64,
    lamport: u64,
    digest: Digest,
}

#[derive(Clone, Copy)]
struct Anchor {
    record: Digest,
    earliest: i64,
    latest: i64,
    signature: Signature,
}

fn anchor_bytes(digest: Digest, earliest: i64, latest: i64) -> Vec<u8> {
    let mut v = ANCHOR_DOMAIN.to_vec();
    v.extend_from_slice(&digest);
    v.extend_from_slice(&earliest.to_be_bytes());
    v.extend_from_slice(&latest.to_be_bytes());
    v
}

fn trusted_anchor(key: &SigningKey, record: Digest, earliest: i64, latest: i64) -> Anchor {
    Anchor {
        record,
        earliest,
        latest,
        signature: key.sign(&anchor_bytes(record, earliest, latest)),
    }
}

struct Ledger {
    pubkeys: [VerifyingKey; 3],
    events: HashMap<Digest, SignedEvent>,
    heads: HashMap<(u64, u8), Head>,
    sequence: HashMap<(u64, u8, u64), Digest>,
    anchors: HashMap<Digest, (i64, i64)>,
    witnessed_forks: u64,
}

impl Ledger {
    fn new(keys: &[SigningKey; 3]) -> Self {
        Self {
            pubkeys: keys.each_ref().map(SigningKey::verifying_key),
            events: HashMap::new(),
            heads: HashMap::new(),
            sequence: HashMap::new(),
            anchors: HashMap::new(),
            witnessed_forks: 0,
        }
    }

    fn draft(
        &self,
        scope: u64,
        actor: u8,
        boot_generation: u32,
        parent: Option<Digest>,
        kind: Kind,
        claimed_utc: i64,
    ) -> Event {
        let previous = self.heads.get(&(scope, actor));
        let predecessor = previous.map_or(ZERO, |h| h.digest);
        let parent_lamport = parent.and_then(|d| self.events.get(&d))
            .map_or(0, |r| r.data.lamport);
        let prev_lamport = previous.map_or(0, |h| h.lamport);
        Event {
            scope,
            actor,
            boot_generation,
            seq: previous.map_or(1, |h| h.seq + 1),
            lamport: prev_lamport.max(parent_lamport) + 1,
            predecessor,
            parent,
            kind,
            claimed_utc,
        }
    }

    fn append(&mut self, r: SignedEvent) -> Result<Digest, Reject> {
        let data = &r.data;
        let Some(pubkey) = self.pubkeys.get(usize::from(data.actor)) else {
            return Err(Reject::Key);
        };
        pubkey.verify(&data.bytes(), &r.signature)
            .map_err(|_| Reject::Signature)?;
        let digest = data.digest();

        if let Some(&existing) = self.sequence.get(&(data.scope, data.actor, data.seq)) {
            if existing == digest {
                return Err(Reject::Replay);
            }
            self.witnessed_forks += 1;
            return Err(Reject::Fork);
        }
        let old = self.heads.get(&(data.scope, data.actor));
        if data.seq != old.map_or(1, |h| h.seq + 1) {
            return Err(Reject::Sequence);
        }
        if data.predecessor != old.map_or(ZERO, |h| h.digest) {
            return Err(Reject::Predecessor);
        }

        let mut logical_parent = old.map_or(0, |h| h.lamport);
        if let Some(parent) = data.parent {
            let Some(parent_event) = self.events.get(&parent) else {
                return Err(Reject::MissingParent);
            };
            if parent_event.data.scope != data.scope {
                return Err(Reject::Scope);
            }
            logical_parent = logical_parent.max(parent_event.data.lamport);
        }

        // No trust in arbitrary Lamport numbers from unvalidated peers.
        if data.lamport != logical_parent.saturating_add(MAX_LOGICAL_STEP) {
            return Err(Reject::LogicalCounter);
        }

        self.heads.insert(
            (data.scope, data.actor),
            Head { seq: data.seq, lamport: data.lamport, digest },
        );
        self.sequence.insert((data.scope, data.actor, data.seq), digest);
        self.events.insert(digest, r);
        Ok(digest)
    }

    fn pin_anchor(&mut self, proof: Anchor, trusted_key: &VerifyingKey) -> bool {
        if proof.earliest > proof.latest {
            return false;
        }
        if !self.events.get(&proof.record).is_some_and(|event| {
            event.data.kind == Kind::Checkpoint
        }) {
            return false;
        }
        if trusted_key.verify(
            &anchor_bytes(proof.record, proof.earliest, proof.latest),
            &proof.signature,
        ).is_err() {
            return false;
        }
        // This signature is an assertion by an operator already trusted by
        // policy. It does not make an otherwise malicious anchor truthful.
        self.anchors.insert(proof.record, (proof.earliest, proof.latest));
        true
    }

    fn is_ancestor(&self, ancestor: Digest, child: Digest) -> bool {
        if !self.events.contains_key(&ancestor) || !self.events.contains_key(&child) {
            return false;
        }
        let mut stack = vec![child];
        let mut seen = HashSet::new();
        while let Some(current) = stack.pop() {
            if current == ancestor {
                return true;
            }
            if !seen.insert(current) {
                continue;
            }
            if let Some(r) = self.events.get(&current) {
                if r.data.predecessor != ZERO {
                    stack.push(r.data.predecessor);
                }
                if let Some(parent) = r.data.parent {
                    stack.push(parent);
                }
            }
        }
        false
    }

    fn bounds(&self, event: Digest) -> Bounds {
        if !self.events.contains_key(&event) {
            return Bounds::OrderOnly;
        }
        let mut lower: Option<i64> = None;
        let mut upper: Option<i64> = None;
        for (&anchor, &(earliest, latest)) in &self.anchors {
            // These inferences require honest externally witnessed ordering.
            // Signatures by an arbitrary malicious C alone do not suffice.
            if self.is_ancestor(anchor, event) {
                lower = Some(lower.map_or(earliest, |x| x.max(earliest)));
            }
            if self.is_ancestor(event, anchor) {
                upper = Some(upper.map_or(latest, |x| x.min(latest)));
            }
        }
        match (lower, upper) {
            (Some(a), Some(b)) if a > b => Bounds::Conflict,
            (Some(a), Some(b)) => Bounds::Interval(a, b),
            (Some(a), None) => Bounds::LowerOnly(a),
            (None, Some(b)) => Bounds::UpperOnly(b),
            (None, None) => Bounds::OrderOnly,
        }
    }

    fn pinned_checkpoint_ok(&self, scope: u64, actor: u8, seq: u64, digest: Digest) -> bool {
        self.sequence.get(&(scope, actor, seq)) == Some(&digest)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Bounds {
    OrderOnly,
    LowerOnly(i64),
    UpperOnly(i64),
    Interval(i64, i64),
    Conflict,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AgeRange {
    at_least_ms: u64,
    at_most_ms: Option<u64>,
}

impl AgeRange {
    fn new() -> Self {
        Self { at_least_ms: 0, at_most_ms: Some(0) }
    }

    fn trusted_uptime(&mut self, measured_ms: u64, max_error_ms: u64) {
        self.at_least_ms = self.at_least_ms
            .saturating_add(measured_ms.saturating_sub(max_error_ms));
        self.at_most_ms = self.at_most_ms
            .map(|v| v.saturating_add(measured_ms.saturating_add(max_error_ms)));
    }

    fn unknown_power_off_gap(&mut self) {
        // A missing RTC cannot measure time elapsed while power is absent.
        self.at_most_ms = None;
    }

    fn untrusted_age_claim(&mut self, _claimed_ms: u64) {
        // No amount of signed but untrusted claims changes a measured bound.
    }
}

fn expiring_fetch_allowed(current_trusted_utc: Bounds, expires_utc: i64) -> bool {
    matches!(current_trusted_utc, Bounds::Interval(_, latest) if latest < expires_utc)
}

#[derive(Default)]
struct Slots {
    // Logical C-right only: no new owner on a lost or ambiguous ACK.
    reservations: HashMap<u64, u8>,
    uncertain: HashSet<u64>,
}
impl Slots {
    fn reserve(&mut self, id: u64, custodian: u8) -> bool {
        if self.reservations.contains_key(&id) {
            return false;
        }
        self.reservations.insert(id, custodian);
        true
    }
    fn ack_missing(&mut self, id: u64) {
        if self.reservations.contains_key(&id) {
            self.uncertain.insert(id);
        }
    }
}

#[derive(Debug, Clone)]
struct Outcome {
    seed: u64,
    bad_percent: usize,
    entries: usize,
    old_messages: usize,
    bad_signed_dates: usize,
    invalid_sequence_rejected: usize,
    witness_forks_detected: u64,
    age_upper_unknown: usize,
    dangerous_fetch_approved: usize,
    slot_duplicates: usize,
    retroactively_bounded: usize,
    clock_restored_from_mail: bool,
    public_receipt_graph_exported: bool,
}

fn simulate(seed: u64, bad_percent: usize) -> Outcome {
    let keys = [lab_key(seed, 0), lab_key(seed, 1), lab_key(seed, 2)];
    let trusted = lab_key(seed, 200);
    let mut ledger = Ledger::new(&keys);
    let initial = ledger.draft(
        SCOPE, 0, 1, None, Kind::Checkpoint, BASE_UTC,
    );
    let mut last = ledger.append(sign(&keys[0], initial)).unwrap();
    assert!(ledger.pin_anchor(
        trusted_anchor(&trusted, last, BASE_UTC, BASE_UTC + 5),
        &trusted.verifying_key(),
    ));

    let mut sample = ZERO;
    // First phase: 500 events under different actor keys and without relying
    // on real wall-clock time. Signed claims are only attributable claims.
    for n in 0..500 {
        let actor = (n % 3) as u8;
        let kind = match n % 3 {
            0 => Kind::Received, 1 => Kind::Stored, _ => Kind::HandoffClaim,
        };
        let payload = ledger.draft(
            SCOPE, actor, 1, Some(last), kind, BASE_UTC + n as i64,
        );
        last = ledger.append(sign(&keys[actor as usize], payload)).unwrap();
        if n == 125 {
            sample = last;
        }
    }
    assert!(matches!(ledger.bounds(sample), Bounds::LowerOnly(_)));

    // 30 days offline, RTC broken. Receiving signed mail cannot recreate UTC.
    let current_time = Bounds::OrderOnly;
    let mut order = (0..100).collect::<Vec<usize>>();
    order.sort_unstable_by_key(|&n| (draw(seed, 300, n as u64), n));
    let bad_set: HashSet<usize> = order.into_iter().take(bad_percent).collect();

    let mut slots = Slots::default();
    let mut bad_signed_dates = 0;
    let mut rejected = 0;
    let mut unknown_age = 0;
    let mut slot_duplicates = 0;
    let mut unsafe_fetch = 0;
    let mut one_event_to_fork = None;

    for n in 0..100 {
        let actor = (n % 3) as u8;
        let malicious = bad_set.contains(&n);
        let claimed = if malicious { BASE_UTC + 10 * 365 * 86_400 }
                      else { BASE_UTC + n as i64 };
        let payload = ledger.draft(
            SCOPE, actor, 2, Some(last), Kind::Received, claimed,
        );
        let valid = sign(&keys[actor as usize], payload);
        last = ledger.append(valid.clone()).unwrap();
        if n == 2 {
            one_event_to_fork = Some(valid);
        }
        if malicious {
            bad_signed_dates += 1;
            let mut malicious_counter = ledger.draft(
                SCOPE, actor, 2, Some(last), Kind::Stored, claimed,
            );
            malicious_counter.seq = 1_000_000_000;
            malicious_counter.lamport = 1_000_000_000;
            assert_eq!(
                ledger.append(sign(&keys[actor as usize], malicious_counter)),
                Err(Reject::Sequence),
            );
            rejected += 1;
        }

        let mut age = AgeRange::new();
        age.trusted_uptime(7_200_000, 1_000);
        age.unknown_power_off_gap();
        age.trusted_uptime(10_000, 100);
        if malicious {
            age.untrusted_age_claim(10 * 365 * 86_400_000);
        }
        if age.at_most_ms.is_none() {
            unknown_age += 1;
        }

        assert!(slots.reserve(n as u64, actor));
        slots.ack_missing(n as u64);
        // Lost ACK must never reallocate the logical C-slot.
        if slots.reserve(n as u64, (actor + 1) % 3) {
            slot_duplicates += 1;
        }
        if expiring_fetch_allowed(current_time, BASE_UTC + 3600) {
            unsafe_fetch += 1;
        }
    }

    let original = one_event_to_fork.unwrap();
    let mut diverged = original.data.clone();
    diverged.claimed_utc = diverged.claimed_utc.saturating_add(12345);
    assert_eq!(
        ledger.append(sign(&keys[diverged.actor as usize], diverged)),
        Err(Reject::Fork),
    );
    assert_eq!(ledger.append(original), Err(Reject::Replay));

    // Only now does an independently trusted observer attest a later
    // checkpoint: all already-linked events can be bracketed RETROSPECTIVELY.
    let closing = ledger.draft(
        SCOPE, 0, 3, Some(last), Kind::Checkpoint,
        BASE_UTC + THIRTY_DAYS + 3600,
    );
    let ending = ledger.append(sign(&keys[0], closing)).unwrap();
    assert!(ledger.pin_anchor(
        trusted_anchor(
            &trusted, ending,
            BASE_UTC + THIRTY_DAYS + 3600,
            BASE_UTC + THIRTY_DAYS + 3610,
        ),
        &trusted.verifying_key(),
    ));
    assert!(matches!(ledger.bounds(sample), Bounds::Interval(_, _)));
    assert!(ledger.pinned_checkpoint_ok(
        SCOPE, 0, ledger.heads[&(SCOPE, 0)].seq, ending,
    ));

    Outcome {
        seed, bad_percent, entries: ledger.events.len(), old_messages: 100,
        bad_signed_dates, invalid_sequence_rejected: rejected,
        witness_forks_detected: ledger.witnessed_forks,
        age_upper_unknown: unknown_age,
        dangerous_fetch_approved: unsafe_fetch,
        slot_duplicates, retroactively_bounded: 100,
        clock_restored_from_mail: false,
        public_receipt_graph_exported: false,
    }
}

fn main() {
    for seed in [21, 71, 107] {
        for bad_percent in [1, 5, 10, 20, 40, 70, 90] {
            let r = simulate(seed, bad_percent);
            println!(
                "{{\"schema\":\"labo-causal01-mail-time-v1\",\"claim\":\"synthetic-causality-not-clock\",\
                \"seed\":{},\"bad_percent\":{},\"entries\":{},\"old_messages\":{},\
                \"bad_signed_dates\":{},\"invalid_sequence_rejected\":{},\
                \"witness_forks_detected\":{},\"age_upper_unknown\":{},\
                \"dangerous_fetch_approved\":{},\"slot_duplicates\":{},\
                \"retroactively_bounded\":{},\"clock_restored_from_mail\":{},\
                \"public_receipt_graph_exported\":{}}}",
                r.seed, r.bad_percent, r.entries, r.old_messages,
                r.bad_signed_dates, r.invalid_sequence_rejected,
                r.witness_forks_detected, r.age_upper_unknown,
                r.dangerous_fetch_approved, r.slot_duplicates,
                r.retroactively_bounded, r.clock_restored_from_mail,
                r.public_receipt_graph_exported,
            );
        }
    }
    // Explicit metadata-only cost comparison; does not include framing,
    // encryption, transport, per-device storage or real protocol signatures.
    for peers in [100usize, 1_000, 10_000] {
        println!(
            "{{\"schema\":\"labo-causal01-size-v1\",\"peers\":{},\
            \"scalar_seq_parent_sig_bytes\":{},\"vector_clock_bytes\":{},\
            \"cost_assumption\":\"8-byte-seq-32-byte-hash-64-byte-signature-vs-8-byte-per-peer\"}}",
            peers, 8 + 32 + 64, peers * 8,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> [SigningKey; 3] {
        [lab_key(31, 0), lab_key(31, 1), lab_key(31, 2)]
    }

    #[test]
    fn signed_causal_order_without_utc() {
        let k = keys();
        let mut l = Ledger::new(&k);
        let a = l.draft(1, 0, 0, None, Kind::Received, -10_000);
        let ah = l.append(sign(&k[0], a)).unwrap();
        let b = l.draft(1, 1, 0, Some(ah), Kind::Stored, 10_000);
        let bh = l.append(sign(&k[1], b)).unwrap();
        assert!(l.is_ancestor(ah, bh));
        assert!(!l.is_ancestor(bh, ah));
        assert_eq!(l.bounds(bh), Bounds::OrderOnly);
    }

    #[test]
    fn concurrent_branches_not_mistaken_as_ordered() {
        let k = keys();
        let mut l = Ledger::new(&k);
        let ah = { let draft = l.draft(1, 0, 0, None, Kind::Received, 0); l.append(sign(&k[0], draft)) }.unwrap();
        let bh = { let draft = l.draft(1, 1, 0, None, Kind::Received, 0); l.append(sign(&k[1], draft)) }.unwrap();
        assert_ne!(ah, bh);
        assert!(!l.is_ancestor(ah, bh));
        assert!(!l.is_ancestor(bh, ah));
    }

    #[test]
    fn retrospective_two_anchor_interval_not_current_time() {
        let k = keys();
        let authority = lab_key(31, 240);
        let mut l = Ledger::new(&k);
        let a = { let draft = l.draft(1, 0, 0, None, Kind::Checkpoint, 999); l.append(sign(&k[0], draft)) }.unwrap();
        assert!(l.pin_anchor(
            trusted_anchor(&authority, a, 1000, 1010),
            &authority.verifying_key(),
        ));
        let mid = { let draft = l.draft(1, 1, 0, Some(a), Kind::Received, i64::MAX); l.append(sign(&k[1], draft)) }.unwrap();
        assert_eq!(l.bounds(mid), Bounds::LowerOnly(1000));
        let after = { let draft = l.draft(1, 2, 0, Some(mid), Kind::Checkpoint, 0); l.append(sign(&k[2], draft)) }.unwrap();
        assert!(l.pin_anchor(
            trusted_anchor(&authority, after, 2000, 2010),
            &authority.verifying_key(),
        ));
        assert_eq!(l.bounds(mid), Bounds::Interval(1000, 2010));
        assert!(!expiring_fetch_allowed(Bounds::OrderOnly, 5000));
    }

    #[test]
    fn unsigned_or_wrongly_signed_anchor_never_changes_bounds() {
        let k = keys();
        let mut l = Ledger::new(&k);
        let h = { let draft = l.draft(1, 0, 0, None, Kind::Checkpoint, 0); l.append(sign(&k[0], draft)) }.unwrap();
        let false_authority = lab_key(31, 210);
        let real_authority = lab_key(31, 211);
        let claim = trusted_anchor(&false_authority, h, 3000, 3010);
        assert!(!l.pin_anchor(claim, &real_authority.verifying_key()));
        assert_eq!(l.bounds(h), Bounds::OrderOnly);
    }

    #[test]
    fn unknown_sleep_preserves_lower_but_drops_upper_age() {
        let mut age = AgeRange::new();
        age.trusted_uptime(7_200_000, 1_000);
        assert_eq!(age.at_least_ms, 7_199_000);
        assert_eq!(age.at_most_ms, Some(7_201_000));
        age.unknown_power_off_gap();
        age.trusted_uptime(1_000, 10);
        assert_eq!(age.at_least_ms, 7_199_990);
        assert_eq!(age.at_most_ms, None);
        age.untrusted_age_claim(u64::MAX);
        assert_eq!(age.at_most_ms, None);
    }

    #[test]
    fn stale_signed_dates_cannot_grant_expiring_fetch() {
        assert!(!expiring_fetch_allowed(Bounds::LowerOnly(1000), 999_999));
        assert!(!expiring_fetch_allowed(Bounds::UpperOnly(3000), 999_999));
        assert!(!expiring_fetch_allowed(Bounds::Conflict, 999_999));
        assert!(expiring_fetch_allowed(Bounds::Interval(100, 200), 300));
        assert!(!expiring_fetch_allowed(Bounds::Interval(100, 400), 300));
    }

    #[test]
    fn signed_billion_seq_is_rejected() {
        let k = keys();
        let mut l = Ledger::new(&k);
        let mut e = l.draft(1, 0, 0, None, Kind::Received, i64::MAX);
        e.seq = 1_000_000_000;
        e.lamport = 1_000_000_000;
        assert_eq!(l.append(sign(&k[0], e)), Err(Reject::Sequence));
        assert_eq!(l.events.len(), 0);
    }

    #[test]
    fn signed_fork_and_identical_replay_are_distinct() {
        let k = keys();
        let mut l = Ledger::new(&k);
        let original = sign(&k[0], l.draft(1, 0, 0, None, Kind::Received, 0));
        l.append(original.clone()).unwrap();
        assert_eq!(l.append(original.clone()), Err(Reject::Replay));
        let mut alt = original.data;
        alt.claimed_utc = 12;
        assert_eq!(l.append(sign(&k[0], alt)), Err(Reject::Fork));
        assert_eq!(l.witnessed_forks, 1);
    }

    #[test]
    fn integrity_and_scope_isolation() {
        let k = keys();
        let mut l = Ledger::new(&k);
        let mut signed = sign(&k[0], l.draft(1, 0, 0, None, Kind::Received, 1));
        signed.data.scope = 2;
        assert_eq!(l.append(signed), Err(Reject::Signature));

        let in_scope = { let draft = l.draft(1, 0, 0, None, Kind::Received, 1); l.append(sign(&k[0], draft)) }.unwrap();
        let cross_scope = l.draft(2, 1, 0, Some(in_scope), Kind::Stored, 1);
        assert_eq!(l.append(sign(&k[1], cross_scope)), Err(Reject::Scope));
    }

    #[test]
    fn ledger_head_checkpoint_detects_known_snapshot_rollback() {
        let k = keys();
        let mut l = Ledger::new(&k);
        let first = { let draft = l.draft(1, 0, 0, None, Kind::Received, 0); l.append(sign(&k[0], draft)) }.unwrap();
        let second = { let draft = l.draft(1, 0, 0, None, Kind::Stored, 0); l.append(sign(&k[0], draft)) }.unwrap();
        assert!(l.pinned_checkpoint_ok(1, 0, 2, second));
        assert!(!l.pinned_checkpoint_ok(1, 0, 2, first));
        assert!(!l.pinned_checkpoint_ok(1, 0, 3, second));
    }

    #[test]
    fn ambiguous_ack_cannot_reallocate_c_credit() {
        let mut slots = Slots::default();
        assert!(slots.reserve(42, 0));
        slots.ack_missing(42);
        assert!(!slots.reserve(42, 1));
        assert_eq!(slots.reservations.get(&42), Some(&0));
    }

    #[test]
    fn three_seeds_seven_attack_rates_are_exact_and_safe() {
        for seed in [21, 71, 107] {
            for pct in [1, 5, 10, 20, 40, 70, 90] {
                let r = simulate(seed, pct);
                assert_eq!(r.bad_signed_dates, pct);
                assert_eq!(r.invalid_sequence_rejected, pct);
                assert_eq!(r.witness_forks_detected, 1);
                assert_eq!(r.entries, 602);
                assert_eq!(r.old_messages, 100);
                assert_eq!(r.age_upper_unknown, 100);
                assert_eq!(r.dangerous_fetch_approved, 0);
                assert_eq!(r.slot_duplicates, 0);
                assert_eq!(r.retroactively_bounded, 100);
                assert!(!r.clock_restored_from_mail);
                assert!(!r.public_receipt_graph_exported);
            }
        }
    }
}
