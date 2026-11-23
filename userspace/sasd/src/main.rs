//! CBRS SAS client for the Titan 4000, in place of the vendor `cbrs_fsm`.
//!
//! `run` is the client. It listens where the vendor client listened for
//! radio events from `rcinit`, talks to the SAS, and opens or closes
//! customer traffic. It sleeps until its next deadline, so an idle unit
//! costs one HTTPS call per heartbeat interval and nothing between.
//!
//! `shadow` changes nothing. It reads the vendor client's log and records
//! what this client would have done with the same radio events.
//!
//! `gate-close` closes customer traffic. The supervisor runs it whenever
//! `run` exits, so a dead client never leaves traffic open.
//!
//! `hand-back` returns control to the vendor: it asks `rcinit` to rebuild its
//! own no-grant rule and start the vendor client, then removes our rules.
//!
//! Exit status 78 from `run` means this client cannot serve the unit (no
//! usable SAS address or setting, unusable certificate files, or no CBSD ID
//! and no complete registration data) and the vendor client should run
//! instead: the supervisor then runs `hand-back`.
//!
//! Settings, all optional, for moving to another SAS (`docs/sas-client.md`
//! section 10): `WITCHER_SAS_CA_FILE`, `WITCHER_SAS_CA_SOURCE`,
//! `WITCHER_SAS_IP`, `WITCHER_SAS_URL_EXACT`, `WITCHER_SAS_BATCH`,
//! `WITCHER_SAS_MEAS_FIELD`, `WITCHER_SAS_GROUP` and `WITCHER_SAS_CPI_FILE`.
use std::collections::BTreeMap;
use std::fs;
use std::io::{ErrorKind, Read, Seek, SeekFrom};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

use serde_json::json;
use witcher_sas_model::band::{self, Range};
use witcher_sas_model::engine::{Action, Engine, Gate, Input, Policy, RadioCommand};
use witcher_sas_model::ipc;
use witcher_sas_model::mock::{Fault, Sim};
use witcher_sas_model::proto::Kind;
use witcher_sas_model::registration::{self, MeasField, Options, Stored};
use witcher_sas_model::vendor_log::{self, Event, Outcome};

mod host;
mod transport;

const UNSERVICEABLE: i32 = 78;

fn main() {
    let mut args = std::env::args().skip(1);
    let code = match args.next().as_deref() {
        Some("run") => run(),
        Some("shadow") => shadow(),
        Some("gate-close") => {
            host::close_gate();
            0
        }
        Some("hand-back") => {
            host::hand_back();
            0
        }
        Some("status") => {
            let path = directory("WITCHER_SAS_RUNTIME", "/tmp/witcher-sasd").join("status.json");
            println!("{}", fs::read_to_string(path).unwrap_or_default());
            0
        }
        _ => {
            eprintln!("usage: witcher-sasd run|shadow|gate-close|hand-back|status");
            64
        }
    };
    std::process::exit(code);
}

fn directory(variable: &str, default: &str) -> PathBuf {
    PathBuf::from(host::tool(variable, default))
}

fn private_directory(path: &PathBuf) -> bool {
    fs::create_dir_all(path).is_ok()
        && fs::set_permissions(path, fs::Permissions::from_mode(0o700)).is_ok()
}

/// `3620-3640,3660-3680` in megahertz.
fn parse_ranges(text: &str) -> Vec<Range> {
    text.split(',')
        .filter_map(|entry| {
            let (low, high) = entry.trim().split_once('-')?;
            Range::mhz(low.trim().parse().ok()?, high.trim().parse().ok()?)
        })
        .collect()
}

fn environment(variable: &str) -> Option<String> {
    std::env::var(variable).ok()
}

fn policy() -> Policy {
    policy_from(environment)
}

fn policy_from(get: impl Fn(&str) -> Option<String>) -> Policy {
    let mut policy = Policy::default();
    let number = |variable: &str| get(variable).and_then(|text| text.trim().parse::<u64>().ok());
    if let Some(text) = get("WITCHER_SAS_STANDBY") {
        policy.standby = parse_ranges(&text);
    }
    if let Some(seconds) = number("WITCHER_SAS_RETAIN") {
        policy.retain_idle = seconds;
    }
    if let Some(seconds) = number("WITCHER_SAS_HANDSHAKE_LIMIT") {
        policy.handshake_limit = seconds;
    }
    if get("WITCHER_SAS_BATCH").is_some_and(|text| text.trim() == "0") {
        policy.batch = false;
    }
    policy
}

/// Registration settings an operator may set. Errors name the setting.
fn options_from(get: impl Fn(&str) -> Option<String>) -> Result<Options, String> {
    let meas = MeasField::parse(&get("WITCHER_SAS_MEAS_FIELD").unwrap_or_default())?;
    let grouping = registration::parse_grouping(&get("WITCHER_SAS_GROUP").unwrap_or_default())
        .map_err(|why| format!("WITCHER_SAS_GROUP: {why}"))?;
    Ok(Options { meas, grouping })
}

/// What the unit stores for its registration. Nothing here is logged.
fn stored_unit() -> Stored {
    let cpi = host::tool("WITCHER_SAS_CPI_FILE", "/mnt/cbrs_cpi_file");
    Stored {
        user_id: host::nvram_get_slot(host::SAS_SLOT, "cbrs_userId"),
        fcc_id: host::nvram_get("cbrs_fccId"),
        serial: host::nvram_get("sqns_identity_serialNumber"),
        single_step: host::nvram_get_slot(host::SAS_SLOT, "cbrs_isSingleReg"),
        category: host::nvram_get("cbrs_category"),
        cpi_file: host::read_small(&cpi, 16 * 1024),
    }
}

/// Monotonic seconds. It starts above zero so no deadline is ever "at 0".
struct Clock(Instant);

impl Clock {
    fn now(&self) -> u64 {
        1000 + self.0.elapsed().as_secs()
    }
}

struct Daemon {
    engine: Engine,
    socket: UnixDatagram,
    credentials: transport::Credentials,
    endpoint: transport::Endpoint,
    runtime: PathBuf,
    state: PathBuf,
    log: host::Log,
    clock: Clock,
    call: Option<transport::Call>,
    gate: Gate,
    gate_checked: u64,
    exit: Option<i32>,
}

fn run() -> i32 {
    let runtime = directory("WITCHER_SAS_RUNTIME", "/tmp/witcher-sasd");
    let state = directory("WITCHER_SAS_STATE", "/mnt/titan-api/sas");
    if !private_directory(&runtime) {
        eprintln!("witcher-sasd: cannot make {}", runtime.display());
        return 1;
    }
    let log = host::Log::new(&runtime);
    // Closed until a heartbeat says otherwise.
    host::close_gate();
    let exact = environment("WITCHER_SAS_URL_EXACT").is_some_and(|text| text.trim() == "1");
    let configured = host::nvram_get_slot(host::SAS_SLOT, "cbrs_sasurl");
    let Some(base) = transport::base_url(&configured, exact) else {
        log.line("no usable SAS address in cbrs_sasurl");
        return UNSERVICEABLE;
    };
    let family = match transport::Family::parse(&environment("WITCHER_SAS_IP").unwrap_or_default())
    {
        Ok(family) => family,
        Err(why) => {
            log.line(&why);
            return UNSERVICEABLE;
        }
    };
    let options = match options_from(environment) {
        Ok(options) => options,
        Err(why) => {
            log.line(&why);
            return UNSERVICEABLE;
        }
    };
    let ca = transport::ca_source(
        environment("WITCHER_SAS_CA_FILE").as_deref(),
        environment("WITCHER_SAS_CA_SOURCE").as_deref(),
    );
    let credentials = match transport::Credentials::prepare(&runtime, &ca) {
        Ok(credentials) => credentials,
        Err(why) => {
            log.line(&why);
            return UNSERVICEABLE;
        }
    };
    let stored = stored_unit();
    // Built only from what the unit stores. Anything missing leaves the
    // client unable to register; the log names what, never a value.
    let registration = match registration::build(&stored, &options) {
        Ok(request) => {
            let mode = if request.get("cpiSignatureData").is_some() {
                "single-step with the installer's signed data"
            } else {
                "multi-step"
            };
            log.line(&format!("registration request ready: {mode}"));
            Some(request)
        }
        Err(missing) => {
            log.line(&format!(
                "no registration request: missing {}",
                missing.join("; ")
            ));
            None
        }
    };
    // The vendor client's CBSD ID may come from another SAS. The engine uses
    // it only until this SAS shows it does not know it.
    let adopted = Some(host::nvram_get("cbrs_cbsdId"))
        .filter(|id| !id.is_empty() && host::nvram_get("cbrs_registration_status") == "1");
    let clock = Clock(Instant::now());
    let mut engine = Engine::new(policy(), registration, adopted);
    // Saved grants belong to one SAS address and account.
    engine.bind(&base, &stored.user_id);
    if let Ok(saved) = fs::read_to_string(state.join("state.json")) {
        match engine.restore(&saved, clock.now()) {
            Ok(count) => log.line(&format!(
                "restored {count} saved grant(s); each needs a heartbeat"
            )),
            Err(why) => log.line(&format!("saved state not used: {why}")),
        }
    }
    let _ = fs::remove_file(ipc::SOCKET);
    let socket = match UnixDatagram::bind(ipc::SOCKET) {
        Ok(socket) => socket,
        Err(err) => {
            log.line(&format!("cannot listen on {}: {err}", ipc::SOCKET));
            return 1;
        }
    };
    let _ = private_directory(&state);
    let mut daemon = Daemon {
        engine,
        socket,
        credentials,
        endpoint: transport::Endpoint { base, family },
        runtime,
        state,
        log,
        clock,
        call: None,
        gate: Gate::Closed,
        gate_checked: 0,
        exit: None,
    };
    daemon.log.line("started");
    // `rcinit` reports changes. The state at start has to be read.
    match host::carriers() {
        Some((primary, uplink)) if host::attached() => {
            daemon.feed(Input::Online { primary, uplink })
        }
        _ => daemon.feed(Input::Offline),
    }
    loop {
        if let Some(code) = daemon.exit {
            host::close_gate();
            daemon.log.line(&format!("exit {code}"));
            return code;
        }
        daemon.turn();
    }
}

impl Daemon {
    fn feed(&mut self, input: Input) {
        let now = self.clock.now();
        let actions = self.engine.step(now, host::wall(), input);
        let changed = !actions.is_empty();
        for action in actions {
            self.act(action);
        }
        if changed {
            let status = self.engine.status(now).to_string();
            host::write_atomic(&self.runtime.join("status.json"), &status);
        }
    }

    fn act(&mut self, action: Action) {
        match action {
            Action::Send(request) => {
                let kind = request.kind;
                match transport::start(&self.credentials, &self.endpoint, &self.runtime, request) {
                    Ok(call) => self.call = Some(call),
                    // The engine counts a call it never hears back from as lost.
                    Err(why) => self.log.line(&format!("{} not sent: {why}", kind.method())),
                }
            }
            Action::Gate(gate) => {
                self.gate = gate;
                match gate {
                    Gate::Closed => host::close_gate(),
                    Gate::Open { max_eirp } => host::open_gate(max_eirp),
                }
            }
            Action::Radio(RadioCommand::LeavePrimary) => host::leave_primary(),
            Action::Radio(RadioCommand::DropUplink) => {
                if !host::drop_uplink() {
                    host::leave_primary();
                }
            }
            Action::Radio(RadioCommand::Rejoin) => host::rejoin(),
            Action::Persist(text) => {
                if !host::write_atomic(&self.state.join("state.json"), &text) {
                    self.log.line("could not save the grant state");
                }
            }
            Action::Log(line) => self.log.line(&line),
            Action::CannotRegister => self.exit = Some(UNSERVICEABLE),
            Action::Stopped => self.exit = Some(0),
        }
    }

    fn turn(&mut self) {
        let finished = self
            .call
            .as_mut()
            .and_then(|call| call.poll().map(|result| (call.id, result)));
        if let Some((id, result)) = finished {
            self.call = None;
            self.feed(Input::Reply { id, result });
        }
        let now = self.clock.now();
        let online = !self.engine.in_use().is_empty();
        // The vendor rebuilds its firewall on radio events and would drop
        // our rules. Only a closed gate has rules to lose, so only then is
        // there anything to check.
        let guarding = self.gate == Gate::Closed && online;
        if guarding && now >= self.gate_checked + 5 {
            self.gate_checked = now;
            if !host::gate_holds() {
                host::close_gate();
                self.log
                    .line("customer traffic gate put back after a firewall rebuild");
            }
        }
        let mut wait = self.engine.next_wake(now).saturating_sub(now).clamp(1, 600);
        if self.call.is_some() {
            wait = 1;
        } else if guarding {
            wait = wait.min(5);
        }
        let _ = self
            .socket
            .set_read_timeout(Some(Duration::from_secs(wait)));
        let mut datagram = [0_u8; 256];
        match self.socket.recv(&mut datagram) {
            Ok(length) => match ipc::parse_device(&datagram[..length]) {
                Some(device) if device.connected => {
                    let (primary, uplink) =
                        host::carriers().unwrap_or_else(|| from_mask(device.mask));
                    self.gate_checked = 0;
                    self.feed(Input::Online { primary, uplink });
                }
                Some(_) => self.feed(Input::Offline),
                None => self.feed(Input::Tick),
            },
            Err(err) if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                self.feed(Input::Tick);
            }
            Err(err) => {
                self.log.line(&format!("socket error: {err}"));
                thread::sleep(Duration::from_secs(1));
                self.feed(Input::Tick);
            }
        }
    }
}

/// Carriers from the vendor mask alone, when nvram does not name them: the
/// lowest range is taken as the main carrier.
fn from_mask(mask: u32) -> (Range, Option<Range>) {
    let ranges = band::from_mask(mask);
    let whole = Range {
        low: band::BAND_LOW,
        high: band::BAND_HIGH,
    };
    (
        ranges.first().copied().unwrap_or(whole),
        ranges.get(1).copied(),
    )
}

/// Read what the vendor log gained since `offset`.
fn read_new(path: &str, offset: &mut u64) -> String {
    let Ok(mut file) = fs::File::open(path) else {
        return String::new();
    };
    let length = file.metadata().map(|meta| meta.len()).unwrap_or(0);
    if length < *offset {
        // The vendor rotated the log.
        *offset = 0;
    }
    let mut text = String::new();
    if file.seek(SeekFrom::Start(*offset)).is_ok() {
        let mut bytes = Vec::new();
        if file.read_to_end(&mut bytes).is_ok() {
            *offset += bytes.len() as u64;
            text = String::from_utf8_lossy(&bytes).into_owned();
        }
    }
    text
}

/// Shadow mode: read-only. The engine runs against a pretend SAS that is
/// given the trouble the vendor client met, and both sides are counted.
fn shadow() -> i32 {
    let runtime = directory("WITCHER_SAS_RUNTIME", "/tmp/witcher-sasd");
    if !private_directory(&runtime) {
        eprintln!("witcher-sasd: cannot make {}", runtime.display());
        return 1;
    }
    let log = host::Log::new(&runtime);
    let path = host::tool("WITCHER_SAS_VENDOR_LOG", "/mnt/cbrslog0.txt");
    let mut offset = fs::metadata(&path).map(|meta| meta.len()).unwrap_or(0);
    let mut sim = Sim::registered(policy());
    let mut vendor: BTreeMap<String, u64> = BTreeMap::new();
    let mut stamp = 0_u64;
    let mut vendor_closed_at: Option<u64> = None;
    let mut shown = 0;
    let mut last = Instant::now();
    log.line("shadow started: read-only, nothing is sent to the SAS or the modem");
    loop {
        thread::sleep(Duration::from_secs(20));
        let elapsed = last.elapsed().as_secs();
        last += Duration::from_secs(elapsed);
        for line in read_new(&path, &mut offset).lines() {
            if let Some(time) = vendor_log::parse_stamp(line) {
                stamp = time;
                continue;
            }
            let Some(event) = vendor_log::parse_line(line) else {
                continue;
            };
            let mut count =
                |name: &str, by: u64| *vendor.entry(name.to_string()).or_insert(0) += by;
            match event {
                Event::Online(mask) => {
                    count("radioOnline", 1);
                    vendor_closed_at.get_or_insert(stamp);
                    let (primary, uplink) = host::carriers()
                        .filter(|(primary, _)| {
                            band::from_mask(mask)
                                .iter()
                                .any(|range| range.contains(*primary))
                        })
                        .unwrap_or_else(|| from_mask(mask));
                    sim.online(primary, uplink);
                }
                Event::Offline => {
                    count("radioOffline", 1);
                    sim.offline();
                }
                Event::Traffic(true) => {
                    if let Some(since) = vendor_closed_at.take() {
                        count("closedSeconds", stamp.saturating_sub(since));
                    }
                }
                Event::Traffic(false) => {
                    vendor_closed_at.get_or_insert(stamp);
                }
                Event::Call(kind, outcome) => {
                    count(kind.method(), 1);
                    match outcome {
                        Outcome::NoAnswer => {
                            count("noAnswer", 1);
                            if kind == Kind::Grant {
                                sim.sas.fault(Kind::Grant, Fault::Swallow);
                            }
                        }
                        Outcome::Code(501) => {
                            count("suspended", 1);
                            for carrier in sim.engine.in_use() {
                                sim.sas.suspend(carrier, 1, "seen by the vendor client");
                            }
                        }
                        Outcome::Code(401) => count("conflicts", 1),
                        Outcome::Code(_) => {}
                    }
                }
            }
        }
        sim.run(elapsed);
        for line in &sim.log[shown..] {
            log.line(&format!("would: {line}"));
        }
        shown = sim.log.len();
        let ours: BTreeMap<&str, usize> = [
            Kind::Registration,
            Kind::SpectrumInquiry,
            Kind::Grant,
            Kind::Heartbeat,
            Kind::Relinquishment,
            Kind::Deregistration,
        ]
        .into_iter()
        .map(|kind| (kind.method(), sim.count(kind)))
        .collect();
        let summary = json!({
            "note": "our side assumes a SAS that answers, except where the vendor log showed trouble",
            "vendor": vendor,
            "ours": ours,
            "ourClosedSeconds": sim.closed_seconds,
            "ourRadioCommands": sim.radio_commands.len(),
            "violations": sim.violations.len(),
            "status": sim.engine.status(sim.now),
        });
        host::write_atomic(&runtime.join("shadow.json"), &summary.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standby_ranges_parse_from_megahertz() {
        assert_eq!(
            parse_ranges("3620-3640, 3660-3680"),
            vec![
                Range::mhz(3620, 3640).unwrap(),
                Range::mhz(3660, 3680).unwrap()
            ]
        );
        assert!(parse_ranges("3500-3520,junk").is_empty());
    }

    fn settings(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let pairs: Vec<(String, String)> = pairs
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect();
        move |variable: &str| {
            pairs
                .iter()
                .find(|(key, _)| key == variable)
                .map(|(_, value)| value.clone())
        }
    }

    #[test]
    fn batching_is_on_unless_the_operator_turns_it_off() {
        assert!(policy_from(settings(&[])).batch);
        assert!(policy_from(settings(&[("WITCHER_SAS_BATCH", "1")])).batch);
        assert!(!policy_from(settings(&[("WITCHER_SAS_BATCH", "0")])).batch);
    }

    #[test]
    fn registration_settings_parse_or_fail_closed() {
        let options = options_from(settings(&[])).unwrap();
        assert_eq!(options.meas, MeasField::Omit);
        assert!(options.grouping.is_empty());
        let options = options_from(settings(&[
            ("WITCHER_SAS_MEAS_FIELD", "empty"),
            ("WITCHER_SAS_GROUP", "INTERFERENCE_COORDINATION:g1"),
        ]))
        .unwrap();
        assert_eq!(options.meas, MeasField::Empty);
        assert_eq!(options.grouping.len(), 1);
        assert!(options_from(settings(&[("WITCHER_SAS_MEAS_FIELD", "all")])).is_err());
        assert!(options_from(settings(&[("WITCHER_SAS_GROUP", "x")])).is_err());
    }

    #[test]
    fn a_mask_alone_still_names_the_carriers() {
        let (primary, uplink) = from_mask(0x3C00_003C);
        assert_eq!(primary, Range::mhz(3560, 3580).unwrap());
        assert_eq!(uplink, Range::mhz(3680, 3700));
    }
}
