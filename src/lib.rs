//! Labo: reproducible, bounded-cost network/contact experiments.
//!
//! A virtual node is NOT a Docker container, a phone radio or an Akula client.
//! No file, network, real clock or crypto operations are performed by this crate.
//! Geography, radio contacts and routing are parametrized hypotheses.

use std::collections::HashMap;

pub const WIFI: u8 = 1;
pub const CELL: u8 = 2;
pub const BLE: u8 = 4;
const CELL_METERS: i16 = 10;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MapKind { Building, Plaza }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RadioMode { Wifi, Hybrid, Ble, Exclusive }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mobility { Static, Quarter, All }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outages { Never, One, Periodic }

impl MapKind {
    pub fn name(self) -> &'static str {
        match self { Self::Building => "building", Self::Plaza => "plaza" }
    }
}
impl RadioMode {
    pub fn name(self) -> &'static str {
        match self {
            Self::Wifi => "wifi", Self::Hybrid => "hybrid",
            Self::Ble => "ble", Self::Exclusive => "exclusive",
        }
    }
}
impl Mobility {
    pub fn name(self) -> &'static str {
        match self { Self::Static => "static", Self::Quarter => "quarter", Self::All => "all" }
    }
}
impl Outages {
    pub fn name(self) -> &'static str {
        match self { Self::Never => "never", Self::One => "once", Self::Periodic => "periodic" }
    }
}

#[derive(Clone, Debug)]
pub struct Config {
    pub devices: usize,
    pub messages: usize,
    pub steps: u32,
    pub seed: u64,
    pub map: MapKind,
    pub mode: RadioMode,
    pub mobility: Mobility,
    pub outages: Outages,
    pub ttl_steps: u32,
    pub contact_probes: usize,
    pub ip_interconnect: bool,
    pub relay_percent: u8,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            devices: 2_000, messages: 2_000, steps: 120, seed: 21,
            map: MapKind::Building, mode: RadioMode::Hybrid,
            mobility: Mobility::Quarter, outages: Outages::Periodic,
            ttl_steps: 60, contact_probes: 8, ip_interconnect: false,
            relay_percent: 20,
        }
    }
}
impl Config {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.devices < 2 || self.devices > 1_000_000 { return Err("devices must be 2..=1000000"); }
        if self.messages > 2_000_000 { return Err("messages must be <=2000000"); }
        if self.steps == 0 || self.steps > 100_000 { return Err("steps must be 1..=100000"); }
        if self.contact_probes == 0 || self.contact_probes > 64 {
            return Err("contact-probes must be 1..=64");
        }
        if self.ttl_steps == 0 { return Err("ttl-steps must be positive"); }
        if self.relay_percent > 100 { return Err("relay-percent must be 0..=100"); }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Zone { Room, Hall, Stair(u8), Plaza }
#[derive(Clone, Copy, Debug)]
struct Position { x: i16, y: i16, floor: u8, zone: Zone }
#[derive(Clone, Debug)]
struct Device {
    p: Position,
    radios: u8,
    mobile: bool,
    volunteer: bool,
}
#[derive(Clone, Debug)]
struct Message {
    from: usize,
    to: usize,
    carrier: usize,
    previous_carrier: usize,
    created: u32,
    delivered: Option<u32>,
    hops: u8,
    forwarded: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Report {
    pub map: &'static str,
    pub mode: &'static str,
    pub mobility: &'static str,
    pub outages: &'static str,
    pub seed: u64,
    pub devices: usize,
    pub messages_created: usize,
    pub delivered: usize,
    pub expired: usize,
    pub pending: usize,
    pub relayed_messages: usize,
    pub relay_transfers: u64,
    pub contact_probes: u64,
    pub blocked_by_offline: u64,
    pub p50_steps: Option<u32>,
    pub p95_steps: Option<u32>,
}
impl Report {
    pub fn as_json(&self) -> String {
        // Every user-configurable string is an enum-controlled ASCII literal.
        let number_or_null = |n: Option<u32>| {
            n.map(|x| x.to_string()).unwrap_or_else(|| "null".to_string())
        };
        let rate = if self.messages_created == 0 { 0.0 } else {
            self.delivered as f64 / self.messages_created as f64
        };
        format!(
            concat!(
                "{{\"schema\":\"labo-sim-v0\",\"claim\":\"synthetic-not-measured\",",
                "\"map\":\"{}\",\"mode\":\"{}\",\"mobility\":\"{}\",",
                "\"outages\":\"{}\",\"seed\":{},\"devices\":{},",
                "\"created\":{},\"delivered\":{},\"delivery_ratio\":{:.8},",
                "\"expired\":{},\"pending\":{},\"messages_using_relays\":{},",
                "\"relay_transfers\":{},\"contact_probes\":{},",
                "\"offline_blocked_attempts\":{},\"p50_steps\":{},\"p95_steps\":{}}}"
            ),
            self.map, self.mode, self.mobility, self.outages,
            self.seed, self.devices, self.messages_created, self.delivered,
            rate, self.expired, self.pending, self.relayed_messages,
            self.relay_transfers, self.contact_probes, self.blocked_by_offline,
            number_or_null(self.p50_steps), number_or_null(self.p95_steps),
        )
    }
}

/// SplitMix64: simple deterministic, non-cryptographic RNG. No shared global clock.
#[derive(Clone)]
struct Rng { s: u64 }
impl Rng {
    fn new(seed: u64) -> Self { Self { s: seed } }
    fn next(&mut self) -> u64 {
        self.s = self.s.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.s;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
    fn usize(&mut self, ceiling: usize) -> usize {
        debug_assert!(ceiling > 0);
        (self.next() % ceiling as u64) as usize
    }
    fn chance(&mut self, percent: usize) -> bool { self.usize(100) < percent }
}
type Cell = (u8, i16, i16);

fn cell(p: Position) -> Cell {
    (p.floor, p.x.div_euclid(CELL_METERS), p.y.div_euclid(CELL_METERS))
}
fn stair_x(stair: u8) -> i16 { ((stair as i16) + 1) * 58 }
fn radio_choice(mode: RadioMode, rng: &mut Rng) -> u8 {
    match mode {
        RadioMode::Wifi => WIFI,
        RadioMode::Ble => BLE,
        RadioMode::Hybrid => {
            let r = rng.usize(100);
            if r < 30 { BLE } else if r < 60 { BLE | WIFI } else { WIFI }
        }
        RadioMode::Exclusive => match rng.usize(3) {
            0 => WIFI, 1 => CELL, _ => BLE,
        },
    }
}
fn online(id: usize, t: u32, cfg: &Config) -> bool {
    match cfg.outages {
        Outages::Never => true,
        Outages::One => {
            // A deliberately correlated temporary interruption of 1/5 of nodes.
            !(id % 5 == 0 && t >= cfg.steps / 3 && t < cfg.steps * 2 / 3)
        }
        Outages::Periodic => ((t / 5 + (id % 19) as u32) % 9) != 0,
    }
}
fn ip_path(a: &Device, b: &Device, interconnect: bool) -> bool {
    let shared = a.radios & b.radios & (WIFI | CELL);
    shared != 0
        || (interconnect
            && ((a.radios & WIFI != 0 && b.radios & CELL != 0)
                || (a.radios & CELL != 0 && b.radios & WIFI != 0)))
}
fn ble_path(a: &Device, b: &Device, map: MapKind) -> bool {
    if a.radios & BLE == 0 || b.radios & BLE == 0 { return false; }
    if a.p.floor != b.p.floor {
        return matches!((a.p.zone, b.p.zone),
            (Zone::Stair(s), Zone::Stair(t)) if s == t
               && a.p.floor.abs_diff(b.p.floor) == 1);
    }
    let dx = i32::from(a.p.x) - i32::from(b.p.x);
    let dy = i32::from(a.p.y) - i32::from(b.p.y);
    let mut r = 14i32;
    if map == MapKind::Building {
        // Idealized extra loss across room doors and walls. NOT measured.
        if matches!(a.p.zone, Zone::Room) != matches!(b.p.zone, Zone::Room) { r -= 4; }
        if a.p.zone == Zone::Room && b.p.zone == Zone::Room
            && (a.p.x != b.p.x || a.p.y != b.p.y) { r -= 7; }
    }
    dx * dx + dy * dy <= r * r
}

/// O(N) spatial hashing per virtual tick, O(messages * bounded probes)
/// for local candidate selection. No dense N x N neighbor matrix.
pub struct Simulation {
    cfg: Config,
    devices: Vec<Device>,
    messages: Vec<Message>,
    rng: Rng,
}
impl Simulation {
    pub fn new(cfg: Config) -> Result<Self, &'static str> {
        cfg.validate()?;
        let mut rng = Rng::new(cfg.seed);
        let mut devices = Vec::with_capacity(cfg.devices);
        for i in 0..cfg.devices {
            let p = match cfg.map {
                MapKind::Building => {
                    let floor = ((i / 400) % 5) as u8;
                    let room = (i % 70) as i16;
                    Position {
                        x: room / 2 * 10 + 5, y: if room % 2 == 0 { -7 } else { 7 },
                        floor, zone: Zone::Room,
                    }
                }
                MapKind::Plaza => Position {
                    x: rng.usize(500) as i16, y: rng.usize(500) as i16,
                    floor: 0, zone: Zone::Plaza,
                },
            };
            devices.push(Device {
                p, radios: radio_choice(cfg.mode, &mut rng),
                mobile: match cfg.mobility {
                    Mobility::Static => false,
                    Mobility::Quarter => rng.chance(25),
                    Mobility::All => true,
                },
                volunteer: rng.chance(cfg.relay_percent as usize),
            });
        }
        let mut messages = Vec::with_capacity(cfg.messages);
        for _ in 0..cfg.messages {
            let from = rng.usize(cfg.devices);
            let mut to = rng.usize(cfg.devices - 1);
            if to >= from { to += 1; }
            // Spread creation over the first half of the observation horizon.
            let created = rng.usize((cfg.steps / 2).max(1) as usize) as u32;
            messages.push(Message {
                from, to, carrier: from, previous_carrier: from, created,
                delivered: None, hops: 0, forwarded: false,
            });
        }
        Ok(Self { cfg, devices, messages, rng })
    }

    fn move_devices(&mut self) {
        for d in &mut self.devices {
            if !d.mobile || !self.rng.chance(30) { continue; }
            match self.cfg.map {
                MapKind::Plaza => {
                    let dx = self.rng.usize(11) as i16 - 5;
                    let dy = self.rng.usize(11) as i16 - 5;
                    d.p.x = (d.p.x + dx).clamp(0, 499);
                    d.p.y = (d.p.y + dy).clamp(0, 499);
                }
                MapKind::Building => match d.p.zone {
                    Zone::Room => {
                        d.p.zone = Zone::Hall;
                        d.p.y = 0;
                    }
                    Zone::Hall => {
                        let dx = self.rng.usize(17) as i16 - 8;
                        d.p.x = (d.p.x + dx).clamp(0, 350);
                        let nearest = (0..5u8).min_by_key(|s| (d.p.x - stair_x(*s)).abs()).unwrap();
                        if (d.p.x - stair_x(nearest)).abs() <= 7 && self.rng.chance(18) {
                            d.p.x = stair_x(nearest);
                            d.p.zone = Zone::Stair(nearest);
                        } else if self.rng.chance(20) {
                            d.p.zone = Zone::Room;
                            d.p.y = if self.rng.chance(50) { -7 } else { 7 };
                        }
                    }
                    Zone::Stair(_) => {
                        if self.rng.chance(65) {
                            let direction = if self.rng.chance(50) { 1i16 } else { -1i16 };
                            d.p.floor = (i16::from(d.p.floor) + direction).clamp(0, 4) as u8;
                        }
                        if self.rng.chance(55) { d.p.zone = Zone::Hall; }
                    }
                    Zone::Plaza => unreachable!(),
                },
            }
        }
    }

    fn build_index(&self) -> HashMap<Cell, Vec<usize>> {
        let mut index: HashMap<Cell, Vec<usize>> = HashMap::with_capacity(self.devices.len() / 30);
        for (i, device) in self.devices.iter().enumerate() {
            index.entry(cell(device.p)).or_default().push(i);
        }
        index
    }

    fn choose_relay(
        &mut self, carrier: usize, previous: usize, t: u32,
        index: &HashMap<Cell, Vec<usize>>, bridges: &[usize],
        probes: &mut u64,
    ) -> Option<usize> {
        let origin = &self.devices[carrier];
        if !online(carrier, t, &self.cfg) { return None; }
        let (_, cx, cy) = cell(origin.p);
        for _ in 0..self.cfg.contact_probes {
            *probes += 1;
            let dx = self.rng.usize(5) as i16 - 2;
            let dy = self.rng.usize(5) as i16 - 2;
            let step_floor = if matches!(origin.p.zone, Zone::Stair(_)) {
                self.rng.usize(3) as i16 - 1
            } else { 0 };
            let floor = i16::from(origin.p.floor) + step_floor;
            if !(0..=4).contains(&floor) && self.cfg.map == MapKind::Building { continue; }
            let candidate = index.get(&(floor as u8, cx + dx, cy + dy))
                .filter(|bucket| !bucket.is_empty())
                .map(|bucket| bucket[self.rng.usize(bucket.len())]);
            if let Some(other) = candidate {
                if other == carrier || other == previous
                    || !self.devices[other].volunteer
                    || !online(other, t, &self.cfg) { continue; }
                if ble_path(origin, &self.devices[other], self.cfg.map) {
                    return Some(other);
                }
            }
        }
        // A Wi-Fi peer can hand its encrypted packet to a consenting
        // dual-interface participant over *the same local Wi-Fi*. This is
        // an explicit idealized AP contact, not a hidden BLE<->IP bridge.
        if origin.radios & WIFI != 0 && !bridges.is_empty() {
            for _ in 0..self.cfg.contact_probes.min(4) {
                *probes += 1;
                let other = bridges[self.rng.usize(bridges.len())];
                if other != carrier && other != previous
                    && online(other, t, &self.cfg)
                    && ip_path(origin, &self.devices[other], self.cfg.ip_interconnect) {
                    return Some(other);
                }
            }
        }
        None
    }

    pub fn run(&mut self) -> Report {
        let mut relay_transfers = 0u64;
        let mut probes = 0u64;
        let mut offline_blocked = 0u64;
        let mut deliveries = Vec::new();
        let bridges: Vec<usize> = self.devices.iter().enumerate()
            .filter(|(_, d)| d.volunteer && d.radios & (WIFI | BLE) == (WIFI | BLE))
            .map(|(i, _)| i).collect();
        for t in 0..self.cfg.steps {
            if t > 0 { self.move_devices(); }
            let grid = self.build_index();
            for msg_idx in 0..self.messages.len() {
                let msg = &self.messages[msg_idx];
                if t < msg.created || msg.delivered.is_some()
                    || t.saturating_sub(msg.created) >= self.cfg.ttl_steps { continue; }
                let carrier = msg.carrier;
                let target = msg.to;
                if !online(carrier, t, &self.cfg) {
                    offline_blocked += 1;
                    continue;
                }
                if !online(target, t, &self.cfg) {
                    offline_blocked += 1;
                } else if ip_path(&self.devices[carrier], &self.devices[target],
                                  self.cfg.ip_interconnect)
                    || ble_path(&self.devices[carrier], &self.devices[target], self.cfg.map) {
                    self.messages[msg_idx].delivered = Some(t);
                    deliveries.push(t - self.messages[msg_idx].created);
                    continue;
                }
                if self.messages[msg_idx].hops >= 16 { continue; }
                let old = self.messages[msg_idx].previous_carrier;
                if let Some(relay) = self.choose_relay(carrier, old, t, &grid, &bridges, &mut probes) {
                    self.messages[msg_idx].carrier = relay;
                    self.messages[msg_idx].previous_carrier = carrier;
                    self.messages[msg_idx].hops += 1;
                    self.messages[msg_idx].forwarded = true;
                    relay_transfers += 1;
                }
            }
        }
        let created = self.messages.iter().filter(|m| m.created < self.cfg.steps).count();
        let delivered = deliveries.len();
        let expired = self.messages.iter().filter(|m| {
            m.delivered.is_none()
                && self.cfg.steps.saturating_sub(m.created) >= self.cfg.ttl_steps
        }).count();
        let forwarded = self.messages.iter().filter(|m| m.forwarded).count();
        deliveries.sort_unstable();
        let quantile = |numerator: usize| {
            if deliveries.is_empty() { return None; }
            let i = ((deliveries.len() - 1) * numerator) / 100;
            deliveries.get(i).copied()
        };
        Report {
            map: self.cfg.map.name(), mode: self.cfg.mode.name(),
            mobility: self.cfg.mobility.name(), outages: self.cfg.outages.name(),
            seed: self.cfg.seed, devices: self.devices.len(), messages_created: created,
            delivered, expired, pending: created - delivered - expired,
            relayed_messages: forwarded, relay_transfers, contact_probes: probes,
            blocked_by_offline: offline_blocked, p50_steps: quantile(50),
            p95_steps: quantile(95),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_seed_gives_identical_result() {
        let c = Config { devices: 280, messages: 300, steps: 30, ..Config::default() };
        let a = Simulation::new(c.clone()).unwrap().run();
        let b = Simulation::new(c).unwrap().run();
        assert_eq!(a, b);
        assert_eq!(a.messages_created, a.delivered + a.expired + a.pending);
    }

    #[test]
    fn all_wifi_delivers_on_shared_local_network() {
        let c = Config {
            mode: RadioMode::Wifi, mobility: Mobility::Static,
            outages: Outages::Never, devices: 600, messages: 500,
            steps: 15, ..Config::default()
        };
        let report = Simulation::new(c).unwrap().run();
        assert_eq!(report.delivered, 500);
        assert_eq!(report.relay_transfers, 0);
    }

    #[test]
    fn exclusive_interfaces_never_create_hidden_ble_ip_bridge() {
        let a = Device { p: Position { x: 0, y: 0, floor: 0, zone: Zone::Plaza },
                         radios: BLE, mobile: true, volunteer: true };
        let b = Device { p: a.p, radios: WIFI, mobile: true, volunteer: true };
        assert!(!ip_path(&a, &b, true));
        assert!(!ble_path(&a, &b, MapKind::Plaza));
        let c = Config { devices: 100, messages: 100, steps: 10,
                         mode: RadioMode::Exclusive, ..Config::default() };
        let s = Simulation::new(c).unwrap();
        assert!(s.devices.iter().all(|d| d.radios.count_ones() == 1));
    }

    #[test]
    fn stairs_only_join_neighbouring_floors_in_ble_model() {
        let a = Device { p: Position {x: 58, y: 0, floor: 1, zone: Zone::Stair(0)},
                         radios: BLE, mobile: false, volunteer: true };
        let mut b = a.clone();
        b.p.floor = 2;
        assert!(ble_path(&a, &b, MapKind::Building));
        b.p.floor = 4;
        assert!(!ble_path(&a, &b, MapKind::Building));
        b.p.floor = 2;
        b.p.zone = Zone::Stair(3);
        assert!(!ble_path(&a, &b, MapKind::Building));
    }

    #[test]
    fn offline_recipient_later_accepts_pending_wifi_message() {
        let c = Config { devices: 10, messages: 1, steps: 40,
                         outages: Outages::One, mode: RadioMode::Wifi,
                         ttl_steps: 35, ..Config::default() };
        let mut s = Simulation::new(c).unwrap();
        s.messages[0].from = 1;
        s.messages[0].carrier = 1;
        s.messages[0].previous_carrier = 1;
        s.messages[0].to = 0; // 0 is offline during the correlated outage
        s.messages[0].created = 16; // outage begins at t=13, ends at t=26
        let r = s.run();
        assert_eq!(r.delivered, 1);
        assert_eq!(r.p50_steps, Some(10));
        assert!(r.blocked_by_offline > 0);
    }

    #[test]
    fn scale_case_is_linear_in_device_count_for_index_formation() {
        let c = Config { devices: 200_000, messages: 60, steps: 2,
                         map: MapKind::Plaza, mode: RadioMode::Ble,
                         ..Config::default() };
        let report = Simulation::new(c).unwrap().run();
        assert_eq!(report.devices, 200_000);
        assert_eq!(report.messages_created, 60);
        assert_eq!(report.created_balance(), 60);
    }

    #[test]
    fn invalid_parameters_are_rejected() {
        assert!(Simulation::new(Config { devices: 1, ..Config::default() }).is_err());
        assert!(Simulation::new(Config { contact_probes: 0, ..Config::default() }).is_err());
        assert!(Simulation::new(Config { relay_percent: 101, ..Config::default() }).is_err());
    }

    #[test]
    fn movement_cannot_leave_building_or_plaza() {
        for map in [MapKind::Building, MapKind::Plaza] {
            let c = Config { devices: 500, steps: 20,
                             messages: 0, map, mobility: Mobility::All, ..Config::default() };
            let mut s = Simulation::new(c).unwrap();
            for _ in 0..20 { s.move_devices(); }
            for d in &s.devices {
                assert!((0..=4).contains(&d.p.floor));
                match map {
                    MapKind::Building => { assert!((0..=350).contains(&d.p.x)); }
                    MapKind::Plaza => {
                        assert!((0..500).contains(&d.p.x));
                        assert!((0..500).contains(&d.p.y));
                    }
                }
            }
        }
    }
}

impl Report {
    pub fn created_balance(&self) -> usize {
        self.delivered + self.expired + self.pending
    }
}
