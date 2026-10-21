use labo::{BlePhysics, Config, GeometryScale, MapKind, Mobility, Outages, RadioMode, Simulation};

fn usage() -> &'static str {
    "Labo: synthetic, reproducible Akula network laboratory

Usage: cargo run --release -- [flags]
  --map building|plaza           Geometry (default building)
  --geometry-scale fixed|density Fixed geography or proportional area/wings
  --mode wifi|hybrid|ble|exclusive
  --ble-physics legacy|budget     Opt-in link budget (legacy is EXP-004 default)
  --ble-tx-dbm N                  BLE Tx power in dBm (budget default 0)
  --ble-rx-sensitivity-dbm N      Receiver threshold in dBm (default -95)
  --ble-antenna-gain-db N         Gain per antenna (default -3 dB)
  --ble-path-loss N               Distance exponent (default 3)
  --ble-wall-loss-db N            Building wall penalty per wall (default 5)
  --ble-floor-loss-db N           Floor penetration penalty (default 15)
  --ble-exterior-loss-db N        Additional inter-wing loss (default 20)
  --ble-range-cap-m N             Computational distance cap (default 200 m)
  --mobility static|quarter|all
  --outages never|once|periodic
  --devices N                    Logical devices (max 1,000,000)
  --messages N                   Messages (max 2,000,000)
  --steps N                      Virtual time steps
  --ttl N                        Message lifetime in virtual steps
  --contact-probes N             Bounded local contact proposals per message/step
  --relay-percent N              Volunteers able to store/forward [0,100]
  --seed N                       Deterministic run seed
  --ip-interconnect              Idealized routable Wi-Fi<->cellular path
  --matrix                       Run all 4 x 3 x 3 = 36 model families sequentially
  --help                         This help

Output: one JSON object per scenario; synthetic model, NOT RF measurement.
Do not run 200,000 Docker containers: every simulated device is in-memory.
"
}

fn next_arg(it: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    it.next().ok_or_else(|| format!("missing value for {flag}"))
}

fn config_from_args() -> Result<(Config, bool), String> {
    let mut cfg = Config::default();
    let mut matrix = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                print!("{}", usage());
                std::process::exit(0);
            }
            "--map" => {
                cfg.map = match next_arg(&mut args, &arg)?.as_str() {
                    "building" => MapKind::Building,
                    "plaza" => MapKind::Plaza,
                    s => return Err(format!("unknown map '{s}'")),
                };
            }
            "--geometry-scale" => {
                cfg.geometry_scale = match next_arg(&mut args, &arg)?.as_str() {
                    "fixed" => GeometryScale::Fixed,
                    "density" => GeometryScale::ConstantDensity,
                    s => return Err(format!("unknown geometry scale '{s}'")),
                };
            }
            "--mode" => {
                cfg.mode = match next_arg(&mut args, &arg)?.as_str() {
                    "wifi" => RadioMode::Wifi,
                    "hybrid" => RadioMode::Hybrid,
                    "ble" => RadioMode::Ble,
                    "exclusive" => RadioMode::Exclusive,
                    s => return Err(format!("unknown mode '{s}'")),
                };
            }
            "--ble-physics" => {
                cfg.ble_physics = match next_arg(&mut args, &arg)?.as_str() {
                    "legacy" => BlePhysics::Legacy,
                    "budget" => BlePhysics::Budget,
                    s => return Err(format!("unknown BLE physics '{s}'")),
                };
            }
            "--ble-tx-dbm" => cfg.rf.tx_dbm = next_arg(&mut args, &arg)?.parse()
                .map_err(|_| "invalid --ble-tx-dbm".to_string())?,
            "--ble-rx-sensitivity-dbm" => cfg.rf.rx_sensitivity_dbm =
                next_arg(&mut args, &arg)?.parse()
                .map_err(|_| "invalid --ble-rx-sensitivity-dbm".to_string())?,
            "--ble-antenna-gain-db" => cfg.rf.antenna_gain_db =
                next_arg(&mut args, &arg)?.parse()
                .map_err(|_| "invalid --ble-antenna-gain-db".to_string())?,
            "--ble-path-loss" => cfg.rf.path_loss_exponent =
                next_arg(&mut args, &arg)?.parse()
                .map_err(|_| "invalid --ble-path-loss".to_string())?,
            "--ble-wall-loss-db" => cfg.rf.wall_loss_db =
                next_arg(&mut args, &arg)?.parse()
                .map_err(|_| "invalid --ble-wall-loss-db".to_string())?,
            "--ble-floor-loss-db" => cfg.rf.floor_loss_db =
                next_arg(&mut args, &arg)?.parse()
                .map_err(|_| "invalid --ble-floor-loss-db".to_string())?,
            "--ble-exterior-loss-db" => cfg.rf.exterior_loss_db =
                next_arg(&mut args, &arg)?.parse()
                .map_err(|_| "invalid --ble-exterior-loss-db".to_string())?,
            "--ble-range-cap-m" => cfg.rf.range_cap_m =
                next_arg(&mut args, &arg)?.parse()
                .map_err(|_| "invalid --ble-range-cap-m".to_string())?,
            "--mobility" => {
                cfg.mobility = match next_arg(&mut args, &arg)?.as_str() {
                    "static" => Mobility::Static,
                    "quarter" => Mobility::Quarter,
                    "all" => Mobility::All,
                    s => return Err(format!("unknown mobility '{s}'")),
                };
            }
            "--outages" => {
                cfg.outages = match next_arg(&mut args, &arg)?.as_str() {
                    "never" => Outages::Never,
                    "once" => Outages::One,
                    "periodic" => Outages::Periodic,
                    s => return Err(format!("unknown outages '{s}'")),
                };
            }
            "--devices" => cfg.devices = next_arg(&mut args, &arg)?.parse()
                .map_err(|_| "invalid --devices".to_string())?,
            "--messages" => cfg.messages = next_arg(&mut args, &arg)?.parse()
                .map_err(|_| "invalid --messages".to_string())?,
            "--steps" => cfg.steps = next_arg(&mut args, &arg)?.parse()
                .map_err(|_| "invalid --steps".to_string())?,
            "--ttl" => cfg.ttl_steps = next_arg(&mut args, &arg)?.parse()
                .map_err(|_| "invalid --ttl".to_string())?,
            "--contact-probes" => cfg.contact_probes = next_arg(&mut args, &arg)?.parse()
                .map_err(|_| "invalid --contact-probes".to_string())?,
            "--relay-percent" => cfg.relay_percent = next_arg(&mut args, &arg)?.parse()
                .map_err(|_| "invalid --relay-percent".to_string())?,
            "--seed" => cfg.seed = next_arg(&mut args, &arg)?.parse()
                .map_err(|_| "invalid --seed".to_string())?,
            "--ip-interconnect" => cfg.ip_interconnect = true,
            "--matrix" => matrix = true,
            s => return Err(format!("unknown argument '{s}'")),
        }
    }
    cfg.validate().map_err(|s| s.to_string())?;
    Ok((cfg, matrix))
}

fn run(cfg: Config) -> Result<(), String> {
    let mut sim = Simulation::new(cfg).map_err(|s| s.to_string())?;
    let report = sim.run();
    println!("{}", report.as_json());
    Ok(())
}

fn main() {
    let result = (|| {
        let (cfg, matrix) = config_from_args()?;
        if !matrix { return run(cfg); }
        for mode in [RadioMode::Wifi, RadioMode::Hybrid, RadioMode::Ble, RadioMode::Exclusive] {
            for mobility in [Mobility::Static, Mobility::Quarter, Mobility::All] {
                for outages in [Outages::Never, Outages::One, Outages::Periodic] {
                    let mut c = cfg.clone();
                    c.mode = mode;
                    c.mobility = mobility;
                    c.outages = outages;
                    run(c)?;
                }
            }
        }
        Ok::<(), String>(())
    })();
    if let Err(e) = result {
        eprintln!("labo error: {e}\n\n{}", usage());
        std::process::exit(2);
    }
}
