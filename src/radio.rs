//! Opt-in link-budget model for BLE. Synthetic hypotheses, NOT radio measurements.
//! The legacy contact rule in lib.rs is intentionally left untouched.

use super::{building_origin, Config, Device, MapKind, Position, Zone, BLE};

const FSPL_AT_ONE_METRE_DB: f64 = 40.05; // Approximate free-space loss at 2.4 GHz.
const FLOOR_HEIGHT_M: f64 = 3.0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlePhysics {
    Legacy,
    Budget,
}

impl BlePhysics {
    pub fn name(self) -> &'static str {
        match self {
            Self::Legacy => "legacy",
            Self::Budget => "budget-v1",
        }
    }
}

/// Homogeneous radio parameters, deliberately kept separate from real hardware.
/// Antenna gain is applied once at each end. Positive losses weaken reception.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RfBudget {
    pub tx_dbm: f64,
    pub rx_sensitivity_dbm: f64,
    pub antenna_gain_db: f64,
    pub path_loss_exponent: f64,
    /// Measured received signal at 1 m, combined Tx/antenna/Rx campaign effect.
    /// Not a physical transmitter power. None retains the analytic FSPL model.
    pub reference_rssi_at_1m_dbm: Option<f64>,
    pub wall_loss_db: f64,
    pub floor_loss_db: f64,
    pub exterior_loss_db: f64,
    /// Computational/modeling cap, not a Bluetooth protocol distance limit.
    pub range_cap_m: u16,
}

impl Default for RfBudget {
    fn default() -> Self {
        Self {
            tx_dbm: 0.0,
            rx_sensitivity_dbm: -95.0,
            antenna_gain_db: -3.0,
            path_loss_exponent: 3.0,
            reference_rssi_at_1m_dbm: None,
            wall_loss_db: 5.0,
            floor_loss_db: 15.0,
            exterior_loss_db: 20.0,
            range_cap_m: 200,
        }
    }
}

impl RfBudget {
    pub fn validate(self) -> Result<(), &'static str> {
        if !self.tx_dbm.is_finite() || !(-20.0..=20.0).contains(&self.tx_dbm) {
            return Err("ble-tx-dbm must be finite and in -20..=20");
        }
        if !self.rx_sensitivity_dbm.is_finite()
            || !(-125.0..=-40.0).contains(&self.rx_sensitivity_dbm)
        {
            return Err("ble-rx-sensitivity-dbm must be finite and in -125..=-40");
        }
        if !self.antenna_gain_db.is_finite()
            || !(-20.0..=20.0).contains(&self.antenna_gain_db)
        {
            return Err("ble-antenna-gain-db must be finite and in -20..=20");
        }
        if !self.path_loss_exponent.is_finite()
            || !(1.5..=6.0).contains(&self.path_loss_exponent)
        {
            return Err("ble-path-loss must be finite and in 1.5..=6");
        }
        if let Some(reference) = self.reference_rssi_at_1m_dbm {
            if !reference.is_finite() || !(-120.0..=-10.0).contains(&reference) {
                return Err("ble-reference-rssi-at-1m must be finite and in -120..=-10");
            }
        }
        for loss in [self.wall_loss_db, self.floor_loss_db, self.exterior_loss_db] {
            if !loss.is_finite() || !(0.0..=90.0).contains(&loss) {
                return Err("ble losses must be finite and in 0..=90 dB");
            }
        }
        if !(1..=2000).contains(&self.range_cap_m) {
            return Err("ble-range-cap-m must be in 1..=2000");
        }
        Ok(())
    }

    /// Maximum distance that can pass the receiver threshold *without* any
    /// obstruction. Used as a conservative upper bound for spatial lookup.
    pub fn unobstructed_reach_m(self) -> f64 {
        let one_metre_dbm = self.reference_rssi_at_1m_dbm
            .unwrap_or(self.tx_dbm + 2.0 * self.antenna_gain_db - FSPL_AT_ONE_METRE_DB);
        let budget_db = one_metre_dbm - self.rx_sensitivity_dbm;
        10.0f64.powf(budget_db / (10.0 * self.path_loss_exponent))
            .min(f64::from(self.range_cap_m))
            .max(1.0)
    }

    /// The extra cell accounts for rounding / a transmitter near a cell edge.
    pub fn search_span_cells(self) -> i16 {
        (self.unobstructed_reach_m() / 10.0).ceil() as i16 + 1
    }

    fn received_dbm(self, a: Position, b: Position, cfg: &Config) -> f64 {
        let dx = f64::from(i32::from(a.x) - i32::from(b.x));
        let dy = f64::from(i32::from(a.y) - i32::from(b.y));
        let floors = a.floor.abs_diff(b.floor);
        let d = (dx * dx + dy * dy
            + (f64::from(floors) * FLOOR_HEIGHT_M).powi(2)).sqrt().max(1.0);
        let path_loss = FSPL_AT_ONE_METRE_DB
            + 10.0 * self.path_loss_exponent * d.log10();

        let mut obstruction_loss = 0.0;
        if cfg.map == MapKind::Building {
            let walls = match (a.zone, b.zone) {
                (Zone::Room, Zone::Room) if a.x != b.x || a.y != b.y => 2,
                (Zone::Room, Zone::Room) => 0,
                (Zone::Room, _) | (_, Zone::Room) => 1,
                _ => 0,
            };
            obstruction_loss += self.wall_loss_db * f64::from(walls);
            let common_stairwell = match (a.zone, b.zone) {
                (Zone::Stair(x), Zone::Stair(y)) => {
                    x == y && a.x == b.x && a.y == b.y
                }
                _ => false,
            };
            if !common_stairwell {
                obstruction_loss += self.floor_loss_db * f64::from(floors);
            }
            if building_origin(a, cfg) != building_origin(b, cfg) {
                obstruction_loss += self.exterior_loss_db;
            }
        }
        match self.reference_rssi_at_1m_dbm {
            Some(measured_one_metre) => {
                measured_one_metre - 10.0 * self.path_loss_exponent * d.log10()
                    - obstruction_loss
            }
            None => self.tx_dbm + 2.0 * self.antenna_gain_db - path_loss - obstruction_loss,
        }
    }
}

/// Unidirectional modeled data reception, NOT discovery or a delivered message.
/// The same radio profile is used for each device in this first controlled study.
pub(super) fn ble_budget_path(a: &Device, b: &Device, cfg: &Config) -> bool {
    if a.radios & b.radios & BLE == 0 {
        return false;
    }
    let dx = f64::from(i32::from(a.p.x) - i32::from(b.p.x));
    let dy = f64::from(i32::from(a.p.y) - i32::from(b.p.y));
    let floors = f64::from(a.p.floor.abs_diff(b.p.floor)) * FLOOR_HEIGHT_M;
    let distance = (dx * dx + dy * dy + floors * floors).sqrt();
    if distance > f64::from(cfg.rf.range_cap_m)
        || distance > cfg.rf.unobstructed_reach_m()
    {
        return false;
    }
    cfg.rf.received_dbm(a.p, b.p, cfg) >= cfg.rf.rx_sensitivity_dbm
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(x: i16, y: i16, floor: u8, zone: Zone) -> Device {
        Device {
            p: Position { x, y, floor, zone },
            radios: BLE,
            mobile: false,
            volunteer: true,
        }
    }

    fn cfg(map: MapKind) -> Config {
        Config {
            map,
            ble_physics: BlePhysics::Budget,
            ..Config::default()
        }
    }

    #[test]
    fn radio_power_follows_log_distance_in_free_space() {
        let mut c = cfg(MapKind::Plaza);
        c.rf.path_loss_exponent = 2.0;
        c.rf.antenna_gain_db = 0.0;
        let a = d(0, 0, 0, Zone::Plaza);
        let ten = d(10, 0, 0, Zone::Plaza);
        let hundred = d(100, 0, 0, Zone::Plaza);
        let p10 = c.rf.received_dbm(a.p, ten.p, &c);
        let p100 = c.rf.received_dbm(a.p, hundred.p, &c);
        assert!((p10 + 60.05).abs() < 0.001, "{p10}");
        assert!((p10 - p100 - 20.0).abs() < 0.001);
        assert!(ble_budget_path(&a, &hundred, &c));
    }

    #[test]
    fn wall_and_floor_losses_reduce_reach() {
        let mut c = cfg(MapKind::Building);
        c.rf.antenna_gain_db = 0.0;
        c.rf.rx_sensitivity_dbm = -72.0;
        let hallway = d(0, 0, 0, Zone::Hall);
        let near = d(10, 0, 0, Zone::Hall);
        let walled = d(10, 0, 0, Zone::Room);
        assert!(ble_budget_path(&hallway, &near, &c));
        assert!(!ble_budget_path(&hallway, &walled, &c));

        let upstairs = d(0, 0, 1, Zone::Hall);
        c.rf.rx_sensitivity_dbm = -60.0;
        assert!(!ble_budget_path(&hallway, &upstairs, &c));
        let stair = d(58, 0, 0, Zone::Stair(0));
        let next_stair = d(58, 0, 1, Zone::Stair(0));
        assert!(ble_budget_path(&stair, &next_stair, &c));
    }

    #[test]
    fn changing_power_and_receiver_threshold_changes_link() {
        let mut c = cfg(MapKind::Plaza);
        let a = d(0, 0, 0, Zone::Plaza);
        let far = d(70, 0, 0, Zone::Plaza);
        assert!(!ble_budget_path(&a, &far, &c));
        let before = c.rf.search_span_cells();
        c.rf.tx_dbm = 8.0;
        assert!(ble_budget_path(&a, &far, &c));
        assert!(c.rf.search_span_cells() > before);
        c.rf.range_cap_m = 40;
        assert!(!ble_budget_path(&a, &far, &c));
    }

    #[test]
    fn observed_one_metre_rssi_is_not_confused_with_tx_power() {
        let mut c = cfg(MapKind::Plaza);
        c.rf.reference_rssi_at_1m_dbm = Some(-55.0);
        c.rf.path_loss_exponent = 2.0;
        c.rf.rx_sensitivity_dbm = -76.0;
        let source = d(0, 0, 0, Zone::Plaza);
        let at_one = d(1, 0, 0, Zone::Plaza);
        let at_ten = d(10, 0, 0, Zone::Plaza);
        let at_twenty = d(20, 0, 0, Zone::Plaza);
        assert!((c.rf.received_dbm(source.p, at_one.p, &c) + 55.0).abs() < 1e-5);
        assert!((c.rf.received_dbm(source.p, at_ten.p, &c) + 75.0).abs() < 1e-5);
        assert!(ble_budget_path(&source, &at_ten, &c));
        assert!(!ble_budget_path(&source, &at_twenty, &c));
        c.rf.tx_dbm = 12.0; // empirical intercept overrides this unknown RF factor
        assert!((c.rf.received_dbm(source.p, at_ten.p, &c) + 75.0).abs() < 1e-5);
        assert!(c.rf.search_span_cells() >= 2);
        c.rf.reference_rssi_at_1m_dbm = Some(f64::NAN);
        assert!(c.validate().is_err());
    }

    #[test]
    fn neither_profile_invents_ble_to_ip_bridges() {
        let c = cfg(MapKind::Plaza);
        let ble = d(0, 0, 0, Zone::Plaza);
        let mut wifi = ble.clone();
        wifi.radios = super::super::WIFI;
        assert!(!ble_budget_path(&ble, &wifi, &c));
    }

    #[test]
    fn invalid_parameters_are_rejected() {
        let mut c = cfg(MapKind::Plaza);
        c.rf.path_loss_exponent = f64::NAN;
        assert!(c.validate().is_err());
        c.rf = RfBudget::default();
        c.rf.range_cap_m = 2001;
        assert!(c.validate().is_err());
    }
}
