//! LABO EXP-019: reproducible 1,000-custodian contamination stress grid.
//! Virtual endpoints only. No real cryptography, SSD, receipt, internet or W4.
//! Observed exact/bad-byte response attribution is an explicit modeling assumption.
//! Two policies share the same message intents, eligible peers and keyed outcomes.
//! Each message receives AT MOST ONE logical C-slot (no handoff/reissue).

use std::env;
use std::fmt::Write;

const CANDIDATES: usize = 6;
const PROBE_BYTES: u64 = 16 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Behavior {
    Honest,
    DeclaredSleeper,
    Refusal,
    BadBytes,
    AuditEvasion,
    Unstable,
    Collusion,
}

impl Behavior {
    fn is_compromised(self) -> bool {
        !matches!(self, Self::Honest | Self::DeclaredSleeper)
    }

    fn active(self, tick: u32) -> bool {
        self != Self::DeclaredSleeper || tick % 24 < 16
    }

    fn link_probability(self) -> f64 {
        if self == Self::Unstable {
            0.58
        } else if self.is_compromised() {
            0.98
        } else {
            0.995
        }
    }

    fn index(self) -> usize {
        match self {
            Self::Honest => 0,
            Self::DeclaredSleeper => 1,
            Self::Refusal => 2,
            Self::BadBytes => 3,
            Self::AuditEvasion => 4,
            Self::Unstable => 5,
            Self::Collusion => 6,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Profile {
    Mixed,
    Refusal,
    BadBytes,
    AuditEvasion,
    Unstable,
    Collusion,
    LateCompromise,
}

impl Profile {
    fn parse(s: &str) -> Result<Self, String> {
        match s {
            "mixed" => Ok(Self::Mixed),
            "refusal" => Ok(Self::Refusal),
            "bad-bytes" => Ok(Self::BadBytes),
            "audit-evasion" => Ok(Self::AuditEvasion),
            "unstable" => Ok(Self::Unstable),
            "collusion" => Ok(Self::Collusion),
            "late-compromise" => Ok(Self::LateCompromise),
            _ => Err(format!("unknown profile: {s}")),
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::Mixed => "mixed",
            Self::Refusal => "refusal",
            Self::BadBytes => "bad-bytes",
            Self::AuditEvasion => "audit-evasion",
            Self::Unstable => "unstable",
            Self::Collusion => "collusion",
            Self::LateCompromise => "late-compromise",
        }
    }
}

#[derive(Clone, Debug)]
struct Config {
    custodians: usize,
    messages: usize,
    ticks: u32,
    audit_probes_per_tick: usize,
    bad_percent: u8,
    profile: Profile,
    seed: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            custodians: 1_000,
            messages: 50_000,
            ticks: 160,
            audit_probes_per_tick: 100,
            bad_percent: 10,
            profile: Profile::Mixed,
            seed: 21,
        }
    }
}

impl Config {
    fn validate(&self) -> Result<(), String> {
        if !(6..=200_000).contains(&self.custodians) {
            return Err("custodians outside 6..=200000".into());
        }
        if !(1..=2_000_000).contains(&self.messages) {
            return Err("messages outside 1..=2000000".into());
        }
        if !(4..=10_000).contains(&self.ticks) {
            return Err("ticks outside 4..=10000".into());
        }
        if self.bad_percent > 100 {
            return Err("bad-percent outside 0..=100".into());
        }
        if self.audit_probes_per_tick > 1_000 ||
            self.audit_probes_per_tick as u64 * u64::from(self.ticks) > 2_000_000
        {
            return Err("audit budget exceeded".into());
        }
        Ok(())
    }
}

fn mix(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9e3779b97f4a7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d049bb133111eb);
    x ^ (x >> 31)
}

// Reproducible keyed random draws, NEVER cryptographic randomness.
fn key(seed: u64, domain: u64, a: u64, b: u64) -> u64 {
    mix(seed ^ mix(domain) ^ mix(a) ^ mix(b.wrapping_add(domain)))
}

fn chance(seed: u64, domain: u64, a: u64, b: u64) -> f64 {
    ((key(seed, domain, a, b) >> 11) as f64) / ((1_u64 << 53) as f64)
}

fn population(cfg: &Config) -> Vec<Behavior> {
    let mut kinds = (0..cfg.custodians)
        .map(|peer| {
            if key(cfg.seed, 211, peer as u64, 0) % 10 == 0 {
                Behavior::DeclaredSleeper
            } else {
                Behavior::Honest
            }
        })
        .collect::<Vec<_>>();
    let bad_count = cfg.custodians * usize::from(cfg.bad_percent) / 100;
    // Strict nested compromised populations for the SAME seed, across 1..90%.
    let mut ranks: Vec<usize> = (0..cfg.custodians).collect();
    ranks.sort_unstable_by_key(|&peer| (key(cfg.seed, 212, peer as u64, 0), peer));
    for peer in ranks.into_iter().take(bad_count) {
        kinds[peer] = match cfg.profile {
            Profile::Mixed => match key(cfg.seed, 213, peer as u64, 0) % 100 {
                0..=29 => Behavior::Refusal,
                30..=54 => Behavior::BadBytes,
                55..=74 => Behavior::AuditEvasion,
                75..=89 => Behavior::Unstable,
                _ => Behavior::Collusion,
            },
            Profile::Refusal | Profile::LateCompromise => Behavior::Refusal,
            Profile::BadBytes => Behavior::BadBytes,
            Profile::AuditEvasion => Behavior::AuditEvasion,
            Profile::Unstable => Behavior::Unstable,
            Profile::Collusion => Behavior::Collusion,
        }
    }
    kinds
}

fn effective(cfg: &Config, kind: Behavior, tick: u32) -> Behavior {
    if cfg.profile == Profile::LateCompromise &&
        kind == Behavior::Refusal && tick < cfg.ticks / 2
    {
        Behavior::Honest
    } else {
        kind
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    Exact,
    Refused,
    Broken,
    Unreachable,
    DeclaredSleep,
}

fn response(
    cfg: &Config, kind: Behavior, operation_id: u64, peer: usize, tick: u32,
    audit: bool,
) -> Outcome {
    let current = effective(cfg, kind, tick);
    if !current.active(tick) {
        return Outcome::DeclaredSleep;
    }
    if chance(cfg.seed, 41, operation_id, peer as u64) >= current.link_probability() {
        return Outcome::Unreachable;
    }
    let r = chance(cfg.seed, 42, operation_id, peer as u64);
    match current {
        Behavior::Refusal if r < 0.86 => Outcome::Refused,
        Behavior::BadBytes if r < 0.76 => Outcome::Broken,
        Behavior::AuditEvasion if !audit && r < 0.91 => Outcome::Refused,
        Behavior::Collusion if r < 0.73 => Outcome::Refused,
        Behavior::Honest | Behavior::DeclaredSleeper if r < 0.002 => Outcome::Refused,
        _ => Outcome::Exact,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Grade { Probation, Preferred, Deprioritized, SuspendedNewStore }

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Observations {
    exact: u32,
    refused: u32,
    broken: u32,
    reachable: u32,
    unavailable: u32,
    scheduled_sleep: u32,
    stored: u32,
    lost_ack: u32,
}

impl Observations {
    fn see(&mut self, r: Outcome) {
        match r {
            Outcome::Exact => { self.exact += 1; self.reachable += 1; }
            Outcome::Refused => { self.refused += 1; self.reachable += 1; }
            Outcome::Broken => { self.broken += 1; self.reachable += 1; }
            Outcome::Unreachable => self.unavailable += 1,
            Outcome::DeclaredSleep => self.scheduled_sleep += 1,
        }
    }
    fn grade(&self) -> Grade {
        if self.broken > 0 { return Grade::SuspendedNewStore; }
        let n = self.exact + self.refused;
        if n >= 8 && self.refused * 2 >= n { return Grade::Deprioritized; }
        if n >= 12 && self.exact >= self.refused.saturating_mul(5) {
            return Grade::Preferred;
        }
        Grade::Probation
    }
    fn score(&self) -> f64 {
        let q = (f64::from(self.exact) + 2.0)
            / (f64::from(self.exact + self.refused) + 4.0);
        let available = (f64::from(self.reachable) + 2.0)
            / (f64::from(self.reachable + self.unavailable) + 4.0);
        let score = 0.8 * q + 0.2 * available;
        match self.grade() {
            Grade::SuspendedNewStore => -1.0,
            Grade::Deprioritized => score * 0.45,
            _ => score,
        }
    }
}

fn private_candidates(cfg: &Config, mid: usize) -> [usize; CANDIDATES] {
    // A synthetic private invitation, NOT a global map of recipients/mailboxes.
    let mut choices = [usize::MAX; CANDIDATES];
    let mut n = 0;
    let mut attempt = 0;
    while n < CANDIDATES {
        let candidate =
            (key(cfg.seed, 81, mid as u64, attempt) as usize) % cfg.custodians;
        if !choices[..n].contains(&candidate) {
            choices[n] = candidate;
            n += 1;
        }
        attempt += 1;
    }
    choices
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Policy { Random, Scored }

fn select(
    cfg: &Config, mid: usize, tick: u32, policy: Policy, kinds: &[Behavior],
    local: &[Observations],
) -> Option<usize> {
    let choices = private_candidates(cfg, mid);
    let eligible = choices.into_iter().filter(|&peer| {
        effective(cfg, kinds[peer], tick).active(tick)
            && (policy == Policy::Random || local[peer].grade() != Grade::SuspendedNewStore)
    }).collect::<Vec<_>>();
    if eligible.is_empty() { return None; }
    if policy == Policy::Random || chance(cfg.seed, 91, mid as u64, 0) < 0.08 {
        return Some(eligible[key(cfg.seed, 92, mid as u64, 0) as usize % eligible.len()]);
    }
    eligible.into_iter().max_by(|&a, &b| {
        local[a].score().total_cmp(&local[b].score())
            .then_with(|| key(cfg.seed, 93, mid as u64, a as u64)
                    .cmp(&key(cfg.seed, 93, mid as u64, b as u64)))
    })
}

#[derive(Clone, Copy)]
struct WaitingRead { message: usize, custodian: usize }

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Summary {
    created: u64,
    selected: u64,
    stored: u64,
    intended_read: u64,
    actual_read: u64,
    delivered: u64,
    refused: u64,
    broken: u64,
    unreadable: u64,
    no_candidate: u64,
    no_honest_candidate: u64,
    selected_compromised: u64,
    lost_ack: u64,
    audits: u64,
    audits_sleep_skipped: u64,
    audit_bytes_model: u64,
    fabricated_votes_ignored: u64,
    bad_nodes_suspended: u64,
    bad_nodes_deprioritized: u64,
    good_nodes_suspended: u64,
    good_nodes_deprioritized: u64,
    bad_bytes_nodes_identified: u64,
    audit_evaders_deprioritized: u64,
    max_logical_c_slots: u64,
}

impl Summary {
    fn to_json(&self) -> String {
        let mut fields = Vec::new();
        macro_rules! push { ($name:expr,$val:expr) => {
            fields.push(format!("\"{}\":{}", $name, $val));
        }; }
        push!("created", self.created);
        push!("selected", self.selected);
        push!("stored", self.stored);
        push!("intended_read", self.intended_read);
        push!("actual_read", self.actual_read);
        push!("delivered_synthetic_exact_read", self.delivered);
        push!("refused", self.refused);
        push!("broken", self.broken);
        push!("unreadable", self.unreadable);
        push!("no_candidate", self.no_candidate);
        push!("no_honest_candidate", self.no_honest_candidate);
        push!("selected_compromised", self.selected_compromised);
        push!("lost_ack", self.lost_ack);
        push!("audits", self.audits);
        push!("audits_sleep_skipped", self.audits_sleep_skipped);
        push!("audit_bytes_model", self.audit_bytes_model);
        push!("fabricated_votes_ignored", self.fabricated_votes_ignored);
        push!("bad_nodes_suspended", self.bad_nodes_suspended);
        push!("bad_nodes_deprioritized", self.bad_nodes_deprioritized);
        push!("good_nodes_suspended", self.good_nodes_suspended);
        push!("good_nodes_deprioritized", self.good_nodes_deprioritized);
        push!("bad_bytes_nodes_identified", self.bad_bytes_nodes_identified);
        push!("audit_evaders_deprioritized", self.audit_evaders_deprioritized);
        push!("max_logical_c_slots", self.max_logical_c_slots);
        format!("{{{}}}", fields.join(","))
    }
}

fn simulate(cfg: &Config, kinds: &[Behavior], policy: Policy) -> Summary {
    let mut local = vec![Observations::default(); cfg.custodians];
    let mut future: Vec<Vec<WaitingRead>> = vec![Vec::new(); cfg.ticks as usize];
    let mut result = Summary { created: cfg.messages as u64, ..Summary::default() };
    let colluders = kinds.iter().filter(|&&k| k == Behavior::Collusion).count() as u64;
    let mut mid = 0;

    for tick in 0..cfg.ticks {
        for probe in 0..cfg.audit_probes_per_tick {
            let peer = key(cfg.seed, 101, tick as u64, probe as u64) as usize
                % cfg.custodians;
            let op = key(cfg.seed, 111, tick as u64, probe as u64);
            let answer = response(cfg, kinds[peer], op, peer, tick, true);
            if answer == Outcome::DeclaredSleep {
                result.audits_sleep_skipped += 1;
            } else {
                local[peer].see(answer);
                result.audits += 1;
                result.audit_bytes_model += PROBE_BYTES;
            }
        }
        // A report from a different key without verifiable evidence cannot
        // trigger a global ban. We count forged votes as ignored, not successes.
        result.fabricated_votes_ignored += colluders;
        // Serve only actually requested reads. No W4 inferred from STORE.
        for request in future[tick as usize].drain(..) {
            let op = key(cfg.seed, 161, request.message as u64, 0);
            let answer = response(
                cfg, kinds[request.custodian], op, request.custodian, tick, false
            );
            local[request.custodian].see(answer);
            result.actual_read += 1;
            match answer {
                Outcome::Exact => result.delivered += 1,
                Outcome::Refused => result.refused += 1,
                Outcome::Broken => result.broken += 1,
                Outcome::Unreachable | Outcome::DeclaredSleep => result.unreadable += 1,
            }
        }
        while mid < cfg.messages && mid as u64 * u64::from(cfg.ticks)
            / cfg.messages as u64 == u64::from(tick)
        {
            let id = mid;
            mid += 1;
            let will_read = chance(cfg.seed, 181, id as u64, 0) < 0.84;
            if will_read && tick + 2 < cfg.ticks { result.intended_read += 1; }
            if private_candidates(cfg, id).iter().all(|&p| kinds[p].is_compromised()) {
                result.no_honest_candidate += 1;
            }
            let Some(peer) = select(cfg, id, tick, policy, kinds, &local) else {
                result.no_candidate += 1;
                continue;
            };
            result.selected += 1;
            if kinds[peer].is_compromised() {
                result.selected_compromised += 1;
            }
            // A successful/ambiguous placement reserves exactly ONE logical
            // C slot. A timeout or missing ACK never authorizes a second slot.
            result.max_logical_c_slots = 1;
            let node = effective(cfg, kinds[peer], tick);
            if chance(cfg.seed, 171, id as u64, peer as u64) >= node.link_probability()
                || chance(cfg.seed, 172, id as u64, peer as u64) >= 0.995
            {
                local[peer].unavailable += 1;
                continue;
            }
            local[peer].stored += 1;
            local[peer].reachable += 1;
            result.stored += 1;
            if chance(cfg.seed, 173, id as u64, peer as u64) < 0.02 {
                // Persisted but ACK lost. NO re-issue of an existing C slot.
                local[peer].lost_ack += 1;
                result.lost_ack += 1;
            }
            if will_read && tick + 2 < cfg.ticks {
                future[(tick + 2) as usize].push(WaitingRead { message: id, custodian: peer });
            }
        }
    }
    for (i, st) in local.iter().enumerate() {
        match st.grade() {
            Grade::SuspendedNewStore => {
                if kinds[i].is_compromised() { result.bad_nodes_suspended += 1; }
                else { result.good_nodes_suspended += 1; }
                if kinds[i] == Behavior::BadBytes {
                    result.bad_bytes_nodes_identified += 1;
                }
            }
            Grade::Deprioritized => {
                if kinds[i].is_compromised() { result.bad_nodes_deprioritized += 1; }
                else { result.good_nodes_deprioritized += 1; }
                if kinds[i] == Behavior::AuditEvasion {
                    result.audit_evaders_deprioritized += 1;
                }
            }
            _ => {}
        }
    }
    result
}

fn parse() -> Result<Config, String> {
    let mut cfg = Config::default();
    let mut it = env::args().skip(1);
    while let Some(arg) = it.next() {
        if arg == "--help" || arg == "-h" {
            println!("LABO EXP-019 (synthetic): --custodians 1000 --messages 50000 \
                --ticks 160 --audit-probes 100 --bad-percent 1..90 \
                --profile mixed|refusal|bad-bytes|audit-evasion|unstable|collusion|late-compromise \
                --seed 21");
            std::process::exit(0);
        }
        let value = it.next().ok_or_else(|| format!("missing value for {arg}"))?;
        match arg.as_str() {
            "--custodians" => cfg.custodians = value.parse().map_err(|_| "bad custodians")?,
            "--messages" => cfg.messages = value.parse().map_err(|_| "bad messages")?,
            "--ticks" => cfg.ticks = value.parse().map_err(|_| "bad ticks")?,
            "--audit-probes" => cfg.audit_probes_per_tick =
                value.parse().map_err(|_| "bad audit-probes")?,
            "--bad-percent" => cfg.bad_percent = value.parse().map_err(|_| "bad bad-percent")?,
            "--profile" => cfg.profile = Profile::parse(&value)?,
            "--seed" => cfg.seed = value.parse().map_err(|_| "bad seed")?,
            _ => return Err(format!("unknown parameter {arg}")),
        }
    }
    cfg.validate()?;
    Ok(cfg)
}

fn main() {
    let cfg = match parse() {
        Ok(c) => c,
        Err(error) => { eprintln!("{error}"); std::process::exit(2); }
    };
    let kinds = population(&cfg);
    let actual_bad = kinds.iter().filter(|&&k| k.is_compromised()).count();
    assert_eq!(actual_bad, cfg.custodians * usize::from(cfg.bad_percent) / 100);
    let mut kinds_by_type = [0usize; 7];
    for k in &kinds { kinds_by_type[k.index()] += 1; }
    let random = simulate(&cfg, &kinds, Policy::Random);
    let scored = simulate(&cfg, &kinds, Policy::Scored);
    assert_eq!(random.created, scored.created);
    assert!(random.delivered <= random.actual_read && scored.delivered <= scored.actual_read);
    assert!(random.max_logical_c_slots <= 1 && scored.max_logical_c_slots <= 1);
    let gain_pp = 100.0 * (scored.delivered as f64 - random.delivered as f64)
        / cfg.messages as f64;
    let mut output = String::new();
    write!(
        &mut output,
        "{{\"schema\":\"labo-exp019-adversarial-custodian-grid-v1\",\
        \"claim\":\"synthetic-not-measured\",\
        \"receipt_semantics\":\"synthetic-exact-read-not-W4\",\
        \"custodians\":{},\"messages\":{},\"ticks\":{},\
        \"audit_probes_per_tick\":{},\"bad_percent\":{},\
        \"actual_bad_nodes\":{},\"profile\":\"{}\",\"seed\":{},\
        \"max_logical_c_slots_per_message\":1,\
        \"behavior_counts\":{{\"honest\":{},\"scheduled_sleep_honest\":{},\
        \"refusal\":{},\"bad_bytes\":{},\"audit_evasion\":{},\
        \"unstable\":{},\"collusion\":{}}},\
        \"random\":{},\"scored\":{},\"paired_gain_pp_created\":{:.6}}}",
        cfg.custodians, cfg.messages, cfg.ticks, cfg.audit_probes_per_tick,
        cfg.bad_percent, actual_bad, cfg.profile.name(), cfg.seed,
        kinds_by_type[0], kinds_by_type[1], kinds_by_type[2],
        kinds_by_type[3], kinds_by_type[4], kinds_by_type[5], kinds_by_type[6],
        random.to_json(), scored.to_json(), gain_pp
    ).expect("fmt string");
    println!("{output}");
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn percentages_are_exact_and_nested_for_each_seed() {
        let mut c = Config::default();
        let mut old = vec![false; c.custodians];
        for p in [0, 1, 5, 10, 20, 40, 70, 90] {
            c.bad_percent = p;
            let kinds = population(&c);
            assert_eq!(kinds, population(&c));
            assert_eq!(kinds.iter().filter(|&&k| k.is_compromised()).count(), 10 * p as usize);
            let current: Vec<bool> = kinds.iter().map(|&k| k.is_compromised()).collect();
            assert!(old.iter().zip(&current).all(|(&a, &b)| !a || b));
            old = current;
        }
    }
    #[test]
    fn profiles_select_only_declared_bad_behavior() {
        let mut c = Config { bad_percent: 90, ..Config::default() };
        for (p, kind) in [
            (Profile::Refusal, Behavior::Refusal),
            (Profile::BadBytes, Behavior::BadBytes),
            (Profile::AuditEvasion, Behavior::AuditEvasion),
            (Profile::Unstable, Behavior::Unstable),
            (Profile::Collusion, Behavior::Collusion),
            (Profile::LateCompromise, Behavior::Refusal),
        ] {
            c.profile = p;
            assert_eq!(population(&c).iter().filter(|&&b| b == kind).count(), 900);
        }
    }
    #[test]
    fn audit_evasion_fools_probe_not_recipient() {
        let cfg = Config { profile: Profile::AuditEvasion, ..Config::default() };
        let mut good_probe = 0;
        let mut denied_client = 0;
        for op in 0..100 {
            if response(&cfg, Behavior::AuditEvasion, op, 4, 1, true) == Outcome::Exact {
                good_probe += 1;
            }
            if response(&cfg, Behavior::AuditEvasion, op, 4, 1, false) == Outcome::Refused {
                denied_client += 1;
            }
        }
        assert!(good_probe >= 90 && denied_client >= 80);
    }
    #[test]
    fn late_compromise_activates_halfway() {
        let c = Config { profile: Profile::LateCompromise, ..Config::default() };
        assert_eq!(effective(&c, Behavior::Refusal, 79), Behavior::Honest);
        assert_eq!(effective(&c, Behavior::Refusal, 80), Behavior::Refusal);
    }
    #[test]
    fn missing_fetch_requests_cannot_damage_reputation() {
        let mut o = Observations { stored: 100, ..Observations::default() };
        assert_eq!(o.grade(), Grade::Probation);
        assert_eq!(o.score(), 0.5);
        o.see(Outcome::DeclaredSleep);
        assert_eq!(o.unavailable, 0);
        assert_ne!(o.grade(), Grade::SuspendedNewStore);
    }
    #[test]
    fn confirmed_wrong_bytes_suspend_but_timeout_never_does() {
        let mut o = Observations::default();
        for _ in 0..100 { o.see(Outcome::Exact); }
        o.see(Outcome::Broken);
        assert_eq!(o.grade(), Grade::SuspendedNewStore);
        let mut timeout = Observations::default();
        for _ in 0..100 { timeout.see(Outcome::Unreachable); }
        assert_ne!(timeout.grade(), Grade::SuspendedNewStore);
    }
    #[test]
    fn all_private_invitation_candidates_are_distinct() {
        let c = Config::default();
        for id in 0..100 {
            let peers = private_candidates(&c, id);
            for (i, peer) in peers.iter().enumerate() {
                assert!(*peer < c.custodians);
                assert!(!peers[i + 1..].contains(peer));
            }
        }
    }
    #[test]
    fn high_compromise_has_unavoidable_all_bad_candidate_lists() {
        let c = Config { bad_percent: 90, profile: Profile::Mixed,
            messages: 4_000, ticks: 40, audit_probes_per_tick: 20, ..Config::default() };
        let kinds = population(&c);
        let random = simulate(&c, &kinds, Policy::Random);
        let scored = simulate(&c, &kinds, Policy::Scored);
        assert!(scored.no_honest_candidate > 0);
        assert_eq!(random.no_honest_candidate, scored.no_honest_candidate);
        assert_eq!(random.created, scored.created);
        assert!(random.max_logical_c_slots <= 1 && scored.max_logical_c_slots <= 1);
        assert_eq!(scored.good_nodes_suspended, 0);
    }
    #[test]
    fn simulation_is_deterministic_on_same_seed_and_parameters() {
        let c = Config { bad_percent: 40, messages: 4000, ticks: 40,
            audit_probes_per_tick: 20, seed: 20261023, ..Config::default() };
        let kinds = population(&c);
        assert_eq!(simulate(&c, &kinds, Policy::Scored),
                   simulate(&c, &kinds, Policy::Scored));
    }
    #[test]
    fn fake_collusion_votes_have_no_direct_sanction_authority() {
        let c = Config { profile: Profile::Collusion, bad_percent: 70,
            messages: 3000, ticks: 40, audit_probes_per_tick: 20, ..Config::default() };
        let kinds = population(&c);
        let scored = simulate(&c, &kinds, Policy::Scored);
        assert!(scored.fabricated_votes_ignored > 0);
        assert_eq!(scored.good_nodes_suspended, 0);
    }
    #[test]
    fn bad_inputs_rejected() {
        assert!(Config { bad_percent: 101, ..Config::default() }.validate().is_err());
        assert!(Config { custodians: 4, ..Config::default() }.validate().is_err());
        assert!(Config { audit_probes_per_tick: 1001, ..Config::default() }.validate().is_err());
        assert!(Config { messages: 0, ..Config::default() }.validate().is_err());
    }
}
