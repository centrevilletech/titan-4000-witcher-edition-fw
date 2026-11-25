//! The passthrough bridge fast path: the `titan_k1fp` kernel module (v2.3).
//!
//! At 130+ Mbps in IP passthrough, softirq saturates the CPU and adds queueing
//! delay. `titan_k1fp` short-circuits steady-state unicast IPv4 and IPv6
//! TCP/UDP flows between `lte0pdn2` and `eth0` straight from the bridge port RX
//! handler to `dev_queue_xmit` after proving every flow on the stock path. See
//! `docs/fast-path.md`.
//!
//! Like the download clamp, the image has no room for it, so an operator stages
//! the module per unit in `/mnt/titan-api/fastpath/` with a `config`. The
//! keeper:
//! - loads it only when `config` asks for a mode other than 0, only in IP
//!   passthrough with the exact bridge shape (`eth0` and `lte0pdn2` in `br0`),
//!   once both have stayed up for `SETTLE_SECS`, and after the download clamp
//!   if both are configured;
//! - loads only bytes that match the digest built into the keeper
//!   (`device/fastpath/SHA256SUMS`), from a private copy in RAM;
//! - refuses to load beside any other module with `k1fp` in its name or a
//!   different version string;
//! - checks `ports_ok=1`, `lan_hooked=1`, and `wan_hooked=1` in `/proc/k1fp`
//!   before enabling any mode other than 0;
//! - drives the module's SAS grant lease from the keeper's own CBRS gate state
//!   (renewing once a second while held, writing `grant 0` first on close, and
//!   never writing a lease while `cbrs_mode_grant` is not 1);
//! - tracks watchdog trips (`wd_trips`, `wd_reason`) and unexpected mode drops,
//!   re-arming automatically at most once per boot before holding at mode 0 in
//!   `state=tripped` until the config changes or the unit reboots;
//! - treats a lost bridge device as a pause, not a trip. A modem re-attach
//!   makes the vendor scripts recreate `br0` and `lte0pdn2`; the module drops
//!   to mode 0, counts `dev_gone`, and takes the new devices by itself. The
//!   keeper writes the configured mode again once the bridge is ready, and
//!   that does not use the re-arm budget.

use crate::cbrs_gate::{Gate, Step as GateStep};

/// The first line of `/proc/k1fp` for the allowed build.
/// 2.3 accepts the receive window titan_qctrl v0.4's upload clamp lowers on downlink ACKs
/// in its stock-path proofs (2.2 counted it as modified and tripped its watchdog).
pub const VERSION_LINE: &str = "titan_k1fp v2.3";
/// The module's name in `/proc/modules`.
pub const MODULE: &str = "titan_k1fp";
/// The file in the staging directory and in the manifest.
pub const FILE: &str = "titan_k1fp.ko";
/// Bridge LAN port expected by `titan_k1fp`.
pub const LAN: &str = "eth0";
/// Bridge WAN (customer bearer) port expected by `titan_k1fp`.
pub const WAN: &str = "lte0pdn2";
/// Allowed operating modes: 0 off, 1 observe, 2 downlink, 3 both directions.
pub const MODES: [u32; 4] = [0, 1, 2, 3];
/// Seconds `eth0` and the customer bearer must stay up before a load.
pub const SETTLE_SECS: u64 = 30;
/// Seconds between config and `/proc/k1fp` checks.
pub const CHECK_EVERY: u64 = 15;
/// Validity in seconds written to `/proc/k1fp` once per second while a SAS
/// grant is held. A crashed keeper leaves the lease to expire on its own.
pub const GRANT_LEASE_SECS: u32 = 5;
/// Maximum automatic re-arms per boot after a watchdog trip or mode drop.
pub const MAX_AUTO_REARMS: u32 = 1;

/// `/mnt/titan-api/fastpath/config`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Config {
    pub mode: u32,
    /// Lines that were not used, as written.
    pub refused: Vec<String>,
}

fn plain(text: &str) -> Option<u32> {
    if text.is_empty() || text.len() > 5 || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// `mode=0|1|2|3`, plain decimal, `#` comments. The last `mode=` line wins. A
/// bad `mode=` line leaves the fast path off (`mode=0`).
pub fn parse_config(text: &str) -> Config {
    let mut config = Config::default();
    for raw in text.lines() {
        let line: String = raw
            .split('#')
            .next()
            .unwrap_or("")
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            config.refused.push(raw.trim().to_owned());
            continue;
        };
        let value = plain(value);
        let ok = match (key, value) {
            ("mode", Some(mode)) if MODES.contains(&mode) => {
                config.mode = mode;
                true
            }
            ("mode", _) => {
                config.mode = 0;
                false
            }
            _ => false,
        };
        if !ok {
            config.refused.push(raw.trim().to_owned());
        }
    }
    config
}

/// What `/proc/k1fp` shows.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Proc {
    /// The first line matches `VERSION_LINE` exactly.
    pub ours: bool,
    pub mode: Option<u32>,
    pub lan: Option<String>,
    pub lan_hooked: Option<bool>,
    pub wan: Option<String>,
    pub wan_hooked: Option<bool>,
    pub br: Option<String>,
    pub br_ports: Option<i32>,
    pub ports_ok: Option<bool>,
    pub require_grant: Option<bool>,
    pub grant_left_ms: Option<u32>,
    pub gate_open: Option<bool>,
    pub qctrl_present: Option<bool>,
    pub wd_armed: Option<bool>,
    pub wd_trips: Option<u32>,
    pub wd_reason: Option<String>,
    pub gate_closed: Option<u32>,
    /// Times the module lost `eth0`, `lte0pdn2` or the bridge
    /// (`NETDEV_UNREGISTER`). Each loss sets mode 0 without a watchdog trip.
    pub dev_gone: Option<u32>,
    /// Times the module took recreated devices again.
    pub reacq: Option<u32>,
}

impl Proc {
    /// True only when the module reports both bridge ports hooked and the
    /// bridge has exactly the expected two ports.
    pub fn bridge_ready(&self) -> bool {
        self.ports_ok == Some(true)
            && self.lan_hooked == Some(true)
            && self.wan_hooked == Some(true)
    }

    /// Human-readable reason why `bridge_ready()` is false.
    pub fn bridge_issue(&self) -> String {
        let bit = |v: Option<bool>| match v {
            Some(true) => "1",
            Some(false) => "0",
            None => "?",
        };
        let ports = self
            .br_ports
            .map_or_else(|| "?".to_owned(), |n| n.to_string());
        format!(
            "ports_ok={} lan_hooked={} wan_hooked={} br_ports={ports}",
            bit(self.ports_ok),
            bit(self.lan_hooked),
            bit(self.wan_hooked)
        )
    }
}

fn parse_bool01(s: &str) -> Option<bool> {
    match s {
        "1" => Some(true),
        "0" => Some(false),
        _ => None,
    }
}

pub fn parse_proc(text: &str) -> Proc {
    let mut proc = Proc {
        ours: text
            .lines()
            .next()
            .is_some_and(|line| line.trim() == VERSION_LINE),
        ..Proc::default()
    };
    for word in text.split_whitespace() {
        if let Some(v) = word.strip_prefix("mode=") {
            proc.mode = proc.mode.or_else(|| v.parse().ok());
        } else if let Some(v) = word.strip_prefix("lan=") {
            if proc.lan.is_none() {
                proc.lan = Some(v.to_owned());
            }
        } else if let Some(v) = word.strip_prefix("lan_hooked=") {
            proc.lan_hooked = proc.lan_hooked.or_else(|| parse_bool01(v));
        } else if let Some(v) = word.strip_prefix("wan=") {
            if proc.wan.is_none() {
                proc.wan = Some(v.to_owned());
            }
        } else if let Some(v) = word.strip_prefix("wan_hooked=") {
            proc.wan_hooked = proc.wan_hooked.or_else(|| parse_bool01(v));
        } else if let Some(v) = word.strip_prefix("br=") {
            if proc.br.is_none() {
                proc.br = Some(v.to_owned());
            }
        } else if let Some(v) = word.strip_prefix("br_ports=") {
            proc.br_ports = proc.br_ports.or_else(|| v.parse().ok());
        } else if let Some(v) = word.strip_prefix("ports_ok=") {
            proc.ports_ok = proc.ports_ok.or_else(|| parse_bool01(v));
        } else if let Some(v) = word.strip_prefix("require_grant=") {
            proc.require_grant = proc.require_grant.or_else(|| parse_bool01(v));
        } else if let Some(v) = word.strip_prefix("grant_left_ms=") {
            proc.grant_left_ms = proc.grant_left_ms.or_else(|| v.parse().ok());
        } else if let Some(v) = word.strip_prefix("gate=") {
            proc.gate_open = proc.gate_open.or_else(|| match v {
                "open" => Some(true),
                "closed" => Some(false),
                _ => None,
            });
        } else if let Some(v) = word.strip_prefix("qctrl_present=") {
            proc.qctrl_present = proc.qctrl_present.or_else(|| parse_bool01(v));
        } else if let Some(v) = word.strip_prefix("wd_armed=") {
            proc.wd_armed = proc.wd_armed.or_else(|| parse_bool01(v));
        } else if let Some(v) = word.strip_prefix("wd_trips=") {
            proc.wd_trips = proc.wd_trips.or_else(|| v.parse().ok());
        } else if let Some(v) = word.strip_prefix("wd_reason=") {
            if proc.wd_reason.is_none() {
                proc.wd_reason = Some(v.to_owned());
            }
        } else if let Some(v) = word.strip_prefix("gate_closed=") {
            proc.gate_closed = proc.gate_closed.or_else(|| v.parse().ok());
        } else if let Some(v) = word.strip_prefix("dev_gone=") {
            proc.dev_gone = proc.dev_gone.or_else(|| v.parse().ok());
        } else if let Some(v) = word.strip_prefix("reacq=") {
            proc.reacq = proc.reacq.or_else(|| v.parse().ok());
        }
    }
    proc
}

/// `/proc/k1fp` shows the expected build and the configured mode.
pub fn matches(config: &Config, proc: &Proc) -> bool {
    proc.ours && proc.mode == Some(config.mode)
}

/// True when `br0` holds exactly the two ports `titan_k1fp` expects: `eth0`
/// and `lte0pdn2`.
pub fn bridge_shape_ok<'a>(ports: impl IntoIterator<Item = &'a str>) -> bool {
    let mut list: Vec<&str> = ports.into_iter().collect();
    list.sort_unstable();
    list == [LAN, WAN]
}

/// Human-readable description of a bridge port list that failed `bridge_shape_ok`.
pub fn describe_bridge(ports: &[String]) -> String {
    let mut sorted = ports.to_vec();
    sorted.sort();
    format!("br0 has ports [{}], expected [{LAN}, {WAN}]", sorted.join(", "))
}

/// Which fast path module is loaded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Loaded {
    None,
    /// `titan_k1fp` with the allowed version line.
    Ours,
    /// Any other module with `k1fp` in its name, or a `titan_k1fp` that shows
    /// another version string. The keeper never loads beside it.
    Other(String),
}

/// From `/proc/modules` and `/proc/k1fp` (empty when absent).
pub fn loaded(modules: &str, proc_text: &str) -> Loaded {
    let names: Vec<&str> = modules
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|name| name.contains("k1fp"))
        .collect();
    let ours = parse_proc(proc_text).ours;
    if let Some(other) = names.iter().find(|name| **name != MODULE) {
        return Loaded::Other((*other).to_owned());
    }
    match (names.is_empty(), proc_text.trim().is_empty()) {
        (true, true) => Loaded::None,
        (false, _) if ours => Loaded::Ours,
        (true, false) if ours => Loaded::Other("a /proc/k1fp with no module".into()),
        _ => {
            let first = proc_text.lines().next().unwrap_or("").trim();
            let shown = if first.is_empty() {
                "no /proc/k1fp".to_owned()
            } else {
                first.to_owned()
            };
            Loaded::Other(format!("{MODULE} ({shown})"))
        }
    }
}

/// `eth0` and the customer bearer have been up long enough in IP passthrough.
pub fn settled(up_since: Option<u64>, now: u64) -> bool {
    up_since.is_some_and(|since| now.saturating_sub(since) >= SETTLE_SECS)
}

/// Whether this keeper has written a grant lease to `/proc/k1fp`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum LeaseState {
    /// Initial state on startup: a prior keeper process may have left a lease
    /// open, so the first closed gate must still send `grant 0`.
    #[default]
    Unknown,
    /// A non-zero lease was written; must revoke with `grant 0` on close.
    Open,
    /// `grant 0` has been written (or the module was freshly loaded closed).
    Revoked,
}

/// What the keeper writes to `/proc/k1fp` on one SAS gate tick.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaseAction {
    /// Do not write `/proc/k1fp` on this tick.
    Hold,
    /// Write `grant <secs>\n`.
    Renew(u32),
    /// Write `grant 0\n` immediately before anything else in the tick.
    Revoke,
}

/// Decide the `/proc/k1fp` grant write for one CBRS gate observation.
///
/// - Renews ONLY when `gate` is `Gate::Open` (which requires `cbrs_mode_grant=1`
///   and `cbrs_grant_state=2`) and `active` is true.
/// - Immediately returns `Revoke` on a clear gate loss (`clear == true`) or
///   whenever `cbrs_gate::Watch` returns `GateStep::Close` (including after the
///   confirm window when CBRS keys are absent).
/// - Never renews on an unclear/torn read (`Gate::Closed { clear: false }`).
pub fn lease_decision(
    gate: &Gate,
    step: GateStep,
    state: LeaseState,
    active: bool,
) -> LeaseAction {
    match gate {
        Gate::Open(_) if active => LeaseAction::Renew(GRANT_LEASE_SECS),
        Gate::Open(_) => {
            if state != LeaseState::Revoked {
                LeaseAction::Revoke
            } else {
                LeaseAction::Hold
            }
        }
        Gate::Closed { clear: true, .. } => {
            if state != LeaseState::Revoked {
                LeaseAction::Revoke
            } else {
                LeaseAction::Hold
            }
        }
        Gate::Closed { clear: false, .. } => {
            if step == GateStep::Close && state != LeaseState::Revoked {
                LeaseAction::Revoke
            } else {
                LeaseAction::Hold
            }
        }
    }
}

/// Command string for `/proc/k1fp` for a lease action.
pub fn lease_command(action: LeaseAction) -> Option<String> {
    match action {
        LeaseAction::Hold => None,
        LeaseAction::Renew(secs) => Some(format!("grant {secs}\n")),
        LeaseAction::Revoke => Some("grant 0\n".to_owned()),
    }
}

/// Tracks applied mode and watchdog trips / unexpected drops for one boot.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TripWatch {
    /// True after the first `/proc/k1fp` observation in this keeper process.
    observed: bool,
    /// Mode last confirmed in `/proc/k1fp` (only when > 0).
    applied_mode: Option<u32>,
    /// Automatic re-arms used this boot (capped at `MAX_AUTO_REARMS`).
    rearms: u32,
    /// Last observed `wd_trips` count from `/proc/k1fp`.
    last_wd_trips: u32,
    /// Config held in `state=tripped` until config changes or reboot.
    tripped_for: Option<Config>,
    /// Reason recorded when entering `state=tripped`.
    tripped_reason: Option<String>,
    /// Last observed `dev_gone` count from `/proc/k1fp`.
    last_dev_gone: Option<u32>,
    /// A device loss was seen and not yet reported with `take_device_event`.
    device_event: bool,
}

/// Mode action decided from config and `/proc/k1fp`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TripAction {
    /// `/proc/k1fp` already matches config.
    Normal,
    /// Initial apply or config change: write `config.mode`.
    Apply,
    /// Unexpected drop / watchdog trip, first time this boot: log reason and
    /// re-arm `config.mode` once.
    Rearm { reason: String },
    /// Re-arm budget spent: hold at mode 0 with `state=tripped` until config
    /// changes or reboot.
    Tripped { reason: String, first_notice: bool },
}

fn describe_trip(proc: &Proc, prev_wd_trips: u32, want_mode: u32) -> String {
    let got = proc
        .mode
        .map_or_else(|| "unknown".to_owned(), |m| m.to_string());
    let trips = proc.wd_trips.unwrap_or(0);
    let wd_reason = proc.wd_reason.as_deref().unwrap_or("unknown");
    if trips > prev_wd_trips || (trips > 0 && wd_reason != "none") {
        format!("watchdog tripped (reason={wd_reason}, wd_trips={trips}, mode {want_mode} -> {got})")
    } else {
        format!("mode changed unexpectedly ({want_mode} -> {got}, wd_trips={trips}, wd_reason={wd_reason})")
    }
}

impl TripWatch {
    pub fn evaluate(&mut self, config: &Config, proc: &Proc) -> TripAction {
        let first_observation = !self.observed;
        self.observed = true;

        // The module lost a bridge device since the last look (a modem
        // re-attach recreates `br0` and `lte0pdn2`) and set mode 0 itself.
        // That is a pause, not a trip: forget the applied mode so the
        // configured mode is written again without using the re-arm budget.
        // A unit already held in `state=tripped` stays there.
        if let Some(count) = proc.dev_gone {
            if self.last_dev_gone.is_some_and(|prev| prev != count) {
                self.device_event = true;
                // A watchdog trip in the same interval still counts.
                if proc.wd_trips.unwrap_or(0) <= self.last_wd_trips {
                    self.applied_mode = None;
                }
            }
            self.last_dev_gone = Some(count);
        }

        if config.mode == 0 {
            self.applied_mode = None;
            self.tripped_for = None;
            self.tripped_reason = None;
            if let Some(t) = proc.wd_trips {
                self.last_wd_trips = t;
            }
            return if proc.mode == Some(0) {
                TripAction::Normal
            } else {
                TripAction::Apply
            };
        }

        if let Some(ref tripped_cfg) = self.tripped_for {
            if tripped_cfg == config {
                if let Some(t) = proc.wd_trips {
                    self.last_wd_trips = t;
                }
                let reason = self
                    .tripped_reason
                    .clone()
                    .unwrap_or_else(|| describe_trip(proc, self.last_wd_trips, config.mode));
                return TripAction::Tripped {
                    reason,
                    first_notice: false,
                };
            }
            // Config changed: clear tripped hold, keep boot re-arm count.
            self.tripped_for = None;
            self.tripped_reason = None;
            self.applied_mode = None;
        }

        if self.applied_mode == Some(config.mode) {
            if proc.mode == Some(config.mode) {
                if let Some(t) = proc.wd_trips {
                    self.last_wd_trips = t;
                }
                return TripAction::Normal;
            }
            let reason = describe_trip(proc, self.last_wd_trips, config.mode);
            if let Some(t) = proc.wd_trips {
                self.last_wd_trips = t;
            }
            if self.rearms < MAX_AUTO_REARMS {
                self.rearms += 1;
                return TripAction::Rearm { reason };
            }
            self.applied_mode = None;
            self.tripped_for = Some(config.clone());
            self.tripped_reason = Some(reason.clone());
            return TripAction::Tripped {
                reason,
                first_notice: true,
            };
        }

        // First observation (e.g. keeper restarted after a watchdog trip).
        if first_observation
            && self.applied_mode.is_none()
            && proc.mode == Some(0)
            && proc.wd_trips.unwrap_or(0) > 0
        {
            let trips = proc.wd_trips.unwrap_or(0);
            let reason = describe_trip(proc, self.last_wd_trips, config.mode);
            self.last_wd_trips = trips;
            if trips > MAX_AUTO_REARMS || self.rearms >= MAX_AUTO_REARMS {
                self.tripped_for = Some(config.clone());
                self.tripped_reason = Some(reason.clone());
                return TripAction::Tripped {
                    reason,
                    first_notice: true,
                };
            }
            self.rearms += 1;
            return TripAction::Rearm { reason };
        }

        if let Some(t) = proc.wd_trips {
            self.last_wd_trips = t;
        }
        if proc.mode == Some(config.mode) {
            self.applied_mode = Some(config.mode);
            TripAction::Normal
        } else {
            TripAction::Apply
        }
    }

    /// Record that `mode` was written and read back from `/proc/k1fp`.
    pub fn note_applied(&mut self, mode: u32, proc: &Proc) {
        self.applied_mode = (mode > 0).then_some(mode);
        if let Some(t) = proc.wd_trips {
            self.last_wd_trips = t;
        }
    }

    /// Clear `applied_mode` when paused (unloaded, left passthrough, or bridge
    /// not ready) so resuming later is not counted as a watchdog trip.
    pub fn note_paused(&mut self) {
        self.applied_mode = None;
    }

    /// True once after the module reported a lost bridge device.
    pub fn take_device_event(&mut self) -> bool {
        std::mem::take(&mut self.device_event)
    }

    pub fn rearms(&self) -> u32 {
        self.rearms
    }

    pub fn is_tripped(&self) -> bool {
        self.tripped_for.is_some()
    }
}

/// Fields written to `/var/run/witcher-fastpath.status`.
pub struct StatusView<'a> {
    pub state: &'a str,
    pub detail: &'a str,
    pub config: &'a Config,
    pub active_mode: Option<u32>,
    pub gate_open: Option<bool>,
    pub qctrl_present: Option<bool>,
    pub wd_trips: u32,
    pub wd_reason: &'a str,
    pub now: u64,
}

/// Stable body of `/var/run/witcher-fastpath.status` (without `updated=`) for
/// change detection across state, detail, config mode, active mode, gate,
/// `qctrl_present`, `wd_trips` and `wd_reason`.
pub fn status_body(view: &StatusView<'_>) -> String {
    let active = view
        .active_mode
        .map_or_else(|| "none".to_owned(), |m| m.to_string());
    let gate = match view.gate_open {
        Some(true) => "open",
        Some(false) => "closed",
        None => "unknown",
    };
    let qctrl = match view.qctrl_present {
        Some(true) => "1",
        Some(false) => "0",
        None => "unknown",
    };
    format!(
        "state={}\ndetail={}\nmode={}\nactive_mode={active}\ngate={gate}\nqctrl_present={qctrl}\nwd_trips={}\nwd_reason={}\n",
        view.state,
        view.detail,
        view.config.mode,
        view.wd_trips,
        view.wd_reason,
    )
}

/// Format `/var/run/witcher-fastpath.status`.
pub fn status(view: &StatusView<'_>) -> String {
    format!("{}updated={}\n", status_body(view), view.now)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbrs_gate;

    // Real `/proc/k1fp` output captured on the bench unit (mode 2, download running).
    const BENCH_PROC: &str = "\
titan_k1fp v2.3
mode=2 lan=eth0 lan_hooked=1 wan=lte0pdn2 wan_hooked=1 br=br0 br_ports=2 ports_ok=1
devices: dev_gone=0 reacq=0
require_grant=1 grant_left_ms=4290 gate=open v4=1 v6=1 lease_ms=60 sample_ms=20
qctrl: qctrl_present=1 qctrl_dl_calls=242513 qctrl_dl_drop=0 qctrl_dl_stolen=0 qctrl_ul_stock=0
watchdog: wd_armed=1 wd_trips=0 wd_reason=none wd_mod=20 wd_mismatch=64 wd_stall_ms=500 wd_ringfull_ms=500
safety: txirq=0 txdrain=0 dlbypass=0 pins=0 modref=0 err_tx=0
vendor: netifq_enabled=1 net_mode=2 host_mac_learned=1 host_mac=00:11:22:33:44:55 external_dev_set=0
brhook: external_dev_stop=0 list_nr=0 in_hold=0 held=0 holds=0
fast_dl=242513 fast_ul=0 fast_dl_KiB=230594 fast_ul_KiB=0 would_fast=0 gate_closed=0 xmit_err=0
";

    const MODULES: &str =
        "titan_k1fp 32768 0 - Live 0x7f0c0000\ntitan_qctrl 47104 0 - Live 0x7f0b4000\n";

    #[test]
    fn config_accepts_only_valid_modes_and_defaults_to_off() {
        assert_eq!(parse_config(""), Config { mode: 0, refused: vec![] });
        assert_eq!(
            parse_config("# fast path\nmode = 2 # downlink\n"),
            Config { mode: 2, refused: vec![] }
        );
        for mode in MODES {
            let cfg = parse_config(&format!("mode={mode}\n"));
            assert_eq!(cfg.mode, mode);
            assert!(cfg.refused.is_empty());
        }
        // Last mode line wins.
        assert_eq!(parse_config("mode=1\nmode=3\n").mode, 3);
        // Bad mode resets to 0 and records the line.
        for bad in ["mode=4", "mode=99", "mode=-1", "mode=0x2", "mode=two", "mode="] {
            let cfg = parse_config(&format!("mode=2\n{bad}\n"));
            assert_eq!(cfg.mode, 0, "{bad}");
            assert_eq!(cfg.refused, vec![bad.to_owned()]);
        }
        // Unknown keys and malformed lines are refused without clearing a valid mode.
        let cfg = parse_config("mode=2\ntxirq=1\nnonsense\n");
        assert_eq!(cfg.mode, 2);
        assert_eq!(cfg.refused, vec!["txirq=1", "nonsense"]);
    }

    #[test]
    fn proc_parses_real_bench_output_and_checks_bridge_and_version() {
        let proc = parse_proc(BENCH_PROC);
        assert_eq!(
            proc,
            Proc {
                ours: true,
                mode: Some(2),
                lan: Some("eth0".into()),
                lan_hooked: Some(true),
                wan: Some("lte0pdn2".into()),
                wan_hooked: Some(true),
                br: Some("br0".into()),
                br_ports: Some(2),
                ports_ok: Some(true),
                require_grant: Some(true),
                grant_left_ms: Some(4290),
                gate_open: Some(true),
                qctrl_present: Some(true),
                wd_armed: Some(true),
                wd_trips: Some(0),
                wd_reason: Some("none".into()),
                gate_closed: Some(0),
                dev_gone: Some(0),
                reacq: Some(0),
            }
        );
        assert!(proc.bridge_ready());
        assert!(matches(&parse_config("mode=2\n"), &proc));
        assert!(!matches(&parse_config("mode=3\n"), &proc));

        // Bridge anomalies fail bridge_ready and report why.
        let bad_ports = parse_proc(&BENCH_PROC.replace("br_ports=2 ports_ok=1", "br_ports=3 ports_ok=0"));
        assert!(!bad_ports.bridge_ready());
        assert!(bad_ports.bridge_issue().contains("ports_ok=0"));
        assert!(bad_ports.bridge_issue().contains("br_ports=3"));

        let unhooked_lan = parse_proc(&BENCH_PROC.replace("lan_hooked=1", "lan_hooked=0"));
        assert!(!unhooked_lan.bridge_ready());
        assert!(unhooked_lan.bridge_issue().contains("lan_hooked=0"));

        let unhooked_wan = parse_proc(&BENCH_PROC.replace("wan_hooked=1", "wan_hooked=0"));
        assert!(!unhooked_wan.bridge_ready());
        assert!(unhooked_wan.bridge_issue().contains("wan_hooked=0"));

        // Different version string is rejected.
        let v1 = parse_proc(&BENCH_PROC.replace("titan_k1fp v2.3", "titan_k1fp v1.2"));
        assert!(!v1.ours);
        assert!(!matches(&parse_config("mode=2\n"), &v1));
        let dev = parse_proc(&BENCH_PROC.replace("titan_k1fp v2.3", "titan_k1fp v2.3-dev"));
        assert!(!dev.ours);
        assert!(!parse_proc("").ours);
    }

    #[test]
    fn refuses_other_k1fp_modules_or_wrong_version() {
        assert_eq!(loaded("titan_qctrl 47104 0 - Live 0x7f0b4000\n", ""), Loaded::None);
        assert_eq!(loaded("", ""), Loaded::None);
        assert_eq!(loaded(MODULES, BENCH_PROC), Loaded::Ours);
        assert_eq!(
            loaded(MODULES, &BENCH_PROC.replace("titan_k1fp v2.3", "titan_k1fp v2.2")),
            Loaded::Other("titan_k1fp (titan_k1fp v2.2)".into())
        );
        assert_eq!(
            loaded(MODULES, ""),
            Loaded::Other("titan_k1fp (no /proc/k1fp)".into())
        );
        assert_eq!(
            loaded("titan_k1fp_v1 20000 0 - Live 0x7f0c0000\n", ""),
            Loaded::Other("titan_k1fp_v1".into())
        );
        assert_eq!(
            loaded(&format!("{MODULES}k1fp_test 100 0 - Live 0x0\n"), BENCH_PROC),
            Loaded::Other("k1fp_test".into())
        );
        assert!(matches!(loaded("", BENCH_PROC), Loaded::Other(_)));
    }

    #[test]
    fn bridge_shape_requires_exactly_eth0_and_lte0pdn2() {
        assert!(bridge_shape_ok(["eth0", "lte0pdn2"]));
        assert!(bridge_shape_ok(["lte0pdn2", "eth0"]));
        assert!(!bridge_shape_ok(["eth0"]));
        assert!(!bridge_shape_ok(["eth0", "lte0pdn1"]));
        assert!(!bridge_shape_ok(["eth0", "lte0pdn2", "wlan0"]));
        assert!(!bridge_shape_ok(std::iter::empty()));
        assert_eq!(
            describe_bridge(&["wlan0".into(), "eth0".into()]),
            "br0 has ports [eth0, wlan0], expected [eth0, lte0pdn2]"
        );
    }

    #[test]
    fn loading_waits_for_a_settled_link() {
        assert!(!settled(None, 1000));
        assert!(!settled(Some(100), 100 + SETTLE_SECS - 1));
        assert!(settled(Some(100), 100 + SETTLE_SECS));
        assert!(!settled(Some(200), 100));
    }

    #[test]
    fn lease_policy_renews_only_with_grant_and_revokes_in_same_tick_on_close() {
        let mut watch = cbrs_gate::Watch::default();
        let held = b"cbrs_mode_grant=1\0cbrs_grant_state=2\0";
        let lost_state = b"cbrs_mode_grant=1\0cbrs_grant_state=1\0";
        let lost_mode = b"cbrs_mode_grant=0\0cbrs_grant_state=2\0";

        // Held: renew every second.
        let gate = cbrs_gate::decide(Some(held));
        let (step, _) = watch.observe(10, &gate);
        assert_eq!(
            lease_decision(&gate, step, LeaseState::Revoked, true),
            LeaseAction::Renew(GRANT_LEASE_SECS)
        );
        assert_eq!(
            lease_command(LeaseAction::Renew(GRANT_LEASE_SECS)).as_deref(),
            Some("grant 5\n")
        );

        // Clear loss (grant_state drops to 1): immediate Revoke in the SAME tick.
        let gate = cbrs_gate::decide(Some(lost_state));
        let (step, _) = watch.observe(11, &gate);
        assert_eq!(step, GateStep::Close);
        assert_eq!(
            lease_decision(&gate, step, LeaseState::Open, true),
            LeaseAction::Revoke
        );
        assert_eq!(lease_command(LeaseAction::Revoke).as_deref(), Some("grant 0\n"));

        // Once revoked, subsequent closed ticks hold (no redundant writes, no renew).
        let gate = cbrs_gate::decide(Some(lost_mode));
        let (step, _) = watch.observe(12, &gate);
        assert_eq!(
            lease_decision(&gate, step, LeaseState::Revoked, true),
            LeaseAction::Hold
        );

        // Startup with unknown lease state and closed gate still revokes once.
        assert_eq!(
            lease_decision(&gate, step, LeaseState::Unknown, true),
            LeaseAction::Revoke
        );

        // Inactive fastpath (mode=0 or tripped): never renews even when grant is held,
        // and revokes an open lease once.
        let gate = cbrs_gate::decide(Some(held));
        let (step, _) = watch.observe(13, &gate);
        assert_eq!(
            lease_decision(&gate, step, LeaseState::Open, false),
            LeaseAction::Revoke
        );
        assert_eq!(
            lease_decision(&gate, step, LeaseState::Revoked, false),
            LeaseAction::Hold
        );
    }

    #[test]
    fn lease_policy_never_renews_without_cbrs_mode_grant_or_on_torn_read() {
        // Unit with no CBRS keys at all: fails closed like cbrs_gate and never writes a lease.
        let mut watch = cbrs_gate::Watch::default();
        let no_cbrs = b"router_disable=1\0sqns_radio_band=4\0";
        let mut state = LeaseState::Unknown;

        let gate0 = cbrs_gate::decide(Some(no_cbrs));
        let (step0, _) = watch.observe(0, &gate0);
        assert_eq!(step0, GateStep::Hold);
        assert_eq!(lease_decision(&gate0, step0, state, true), LeaseAction::Hold);

        let gate1 = cbrs_gate::decide(Some(no_cbrs));
        let (step1, _) = watch.observe(1, &gate1);
        assert_eq!(step1, GateStep::Hold);
        assert_eq!(lease_decision(&gate1, step1, state, true), LeaseAction::Hold);

        // After CONFIRM (2 s), gate closes and revokes any prior lease; still never renews.
        let gate2 = cbrs_gate::decide(Some(no_cbrs));
        let (step2, _) = watch.observe(2, &gate2);
        assert_eq!(step2, GateStep::Close);
        assert_eq!(lease_decision(&gate2, step2, state, true), LeaseAction::Revoke);
        state = LeaseState::Revoked;

        for t in 3..10 {
            let g = cbrs_gate::decide(Some(no_cbrs));
            let (s, _) = watch.observe(t, &g);
            assert_eq!(lease_decision(&g, s, state, true), LeaseAction::Hold);
        }

        // Single torn read between valid grants: never renews during the torn read,
        // does not falsely revoke until CONFIRM expires.
        let mut w2 = cbrs_gate::Watch::default();
        let held = b"cbrs_mode_grant=1\0cbrs_grant_state=2\0";
        let g = cbrs_gate::decide(Some(held));
        let (s, _) = w2.observe(10, &g);
        assert_eq!(lease_decision(&g, s, LeaseState::Revoked, true), LeaseAction::Renew(GRANT_LEASE_SECS));

        let torn = cbrs_gate::decide(None);
        let (s, _) = w2.observe(11, &torn);
        assert_eq!(s, GateStep::Hold);
        assert_eq!(lease_decision(&torn, s, LeaseState::Open, true), LeaseAction::Hold);

        // Next tick readable again: resumes renewing.
        let g = cbrs_gate::decide(Some(held));
        let (s, _) = w2.observe(12, &g);
        assert_eq!(lease_decision(&g, s, LeaseState::Open, true), LeaseAction::Renew(GRANT_LEASE_SECS));
    }

    #[test]
    fn trip_policy_rearms_at_most_once_per_boot_then_stays_tripped_until_config_change() {
        let cfg2 = parse_config("mode=2\n");
        let cfg3 = parse_config("mode=3\n");
        let cfg0 = parse_config("mode=0\n");
        let proc0 = parse_proc(&BENCH_PROC.replace("mode=2 ", "mode=0 "));
        let proc2 = parse_proc(BENCH_PROC);

        let mut tw = TripWatch::default();
        // Initial load starts at mode 0 -> Apply.
        assert_eq!(tw.evaluate(&cfg2, &proc0), TripAction::Apply);
        tw.note_applied(2, &proc2);
        assert_eq!(tw.evaluate(&cfg2, &proc2), TripAction::Normal);
        assert_eq!(tw.rearms(), 0);

        // Watchdog trip #1 -> Rearm once with reason.
        let trip1 = parse_proc(
            &BENCH_PROC
                .replace("mode=2 ", "mode=0 ")
                .replace("wd_trips=0 wd_reason=none", "wd_trips=1 wd_reason=tx_stall"),
        );
        match tw.evaluate(&cfg2, &trip1) {
            TripAction::Rearm { reason } => {
                assert!(reason.contains("tx_stall"), "{reason}");
                assert!(reason.contains("wd_trips=1"), "{reason}");
            }
            other => panic!("expected Rearm, got {other:?}"),
        }
        assert_eq!(tw.rearms(), 1);
        let rearmed = parse_proc(
            &BENCH_PROC.replace("wd_trips=0 wd_reason=none", "wd_trips=1 wd_reason=tx_stall"),
        );
        tw.note_applied(2, &rearmed);
        assert_eq!(tw.evaluate(&cfg2, &rearmed), TripAction::Normal);

        // Watchdog trip #2 -> Tripped, no second automatic re-arm.
        let trip2 = parse_proc(
            &BENCH_PROC
                .replace("mode=2 ", "mode=0 ")
                .replace("wd_trips=0 wd_reason=none", "wd_trips=2 wd_reason=ring_full"),
        );
        let first_reason = match tw.evaluate(&cfg2, &trip2) {
            TripAction::Tripped { reason, first_notice } => {
                assert!(first_notice);
                assert!(reason.contains("ring_full"), "{reason}");
                assert!(reason.contains("wd_trips=2"), "{reason}");
                reason
            }
            other => panic!("expected Tripped, got {other:?}"),
        };
        assert!(tw.is_tripped());

        // Subsequent poll stays Tripped with identical reason and first_notice=false.
        assert_eq!(
            tw.evaluate(&cfg2, &trip2),
            TripAction::Tripped {
                reason: first_reason,
                first_notice: false,
            }
        );

        // Changing config clears tripped hold, applies new mode, but keeps boot re-arm count.
        assert_eq!(tw.evaluate(&cfg3, &trip2), TripAction::Apply);
        assert!(!tw.is_tripped());
        let proc3 = parse_proc(
            &BENCH_PROC
                .replace("mode=2 ", "mode=3 ")
                .replace("wd_trips=0 wd_reason=none", "wd_trips=2 wd_reason=ring_full"),
        );
        tw.note_applied(3, &proc3);

        // Another drop on the new config goes straight to Tripped (already re-armed once this boot).
        let trip3 = parse_proc(
            &BENCH_PROC
                .replace("mode=2 ", "mode=0 ")
                .replace("wd_trips=0 wd_reason=none", "wd_trips=3 wd_reason=modified"),
        );
        assert!(matches!(
            tw.evaluate(&cfg3, &trip3),
            TripAction::Tripped { first_notice: true, .. }
        ));

        // Config rollback to mode=0 clears tripped state.
        assert_eq!(tw.evaluate(&cfg0, &trip3), TripAction::Normal);
        assert!(!tw.is_tripped());
    }

    #[test]
    fn trip_policy_handles_manual_mode_drop_and_pause_and_restart() {
        let cfg2 = parse_config("mode=2\n");
        let proc0 = parse_proc(&BENCH_PROC.replace("mode=2 ", "mode=0 "));
        let proc2 = parse_proc(BENCH_PROC);

        // Manual mode 0 write (wd_trips stays 0): re-arms once, then trips on second drop.
        let mut tw = TripWatch::default();
        assert_eq!(tw.evaluate(&cfg2, &proc0), TripAction::Apply);
        tw.note_applied(2, &proc2);
        assert!(matches!(tw.evaluate(&cfg2, &proc0), TripAction::Rearm { .. }));
        tw.note_applied(2, &proc2);
        assert!(matches!(
            tw.evaluate(&cfg2, &proc0),
            TripAction::Tripped { first_notice: true, .. }
        ));

        // Pause (e.g., bridge unready) and resume is NOT a trip.
        let mut tw2 = TripWatch::default();
        assert_eq!(tw2.evaluate(&cfg2, &proc0), TripAction::Apply);
        tw2.note_applied(2, &proc2);
        tw2.note_paused();
        assert_eq!(tw2.evaluate(&cfg2, &proc0), TripAction::Apply);
        assert_eq!(tw2.rearms(), 0);

        // Keeper restart seeing wd_trips >= 2 and mode=0 stays tripped without re-arming.
        let mut tw3 = TripWatch::default();
        let already_tripped = parse_proc(
            &BENCH_PROC
                .replace("mode=2 ", "mode=0 ")
                .replace("wd_trips=0 wd_reason=none", "wd_trips=2 wd_reason=bad_ring"),
        );
        assert!(matches!(
            tw3.evaluate(&cfg2, &already_tripped),
            TripAction::Tripped { first_notice: true, .. }
        ));
        // Operator clears tripped state by setting mode=0 then re-enabling mode=2.
        let cfg0 = parse_config("mode=0\n");
        assert_eq!(tw3.evaluate(&cfg0, &already_tripped), TripAction::Normal);
        assert_eq!(tw3.evaluate(&cfg2, &already_tripped), TripAction::Apply);

        // Adopting an already-loaded module running at mode=2 records applied_mode so
        // any later drop is detected.
        let mut tw4 = TripWatch::default();
        assert_eq!(tw4.evaluate(&cfg2, &proc2), TripAction::Normal);
        assert!(matches!(tw4.evaluate(&cfg2, &proc0), TripAction::Rearm { .. }));
    }

    #[test]
    fn device_loss_is_a_pause_and_never_spends_the_rearm_budget() {
        let cfg = Config { mode: 2, refused: vec![] };
        let mut at = parse_proc(BENCH_PROC);
        assert_eq!((at.dev_gone, at.reacq), (Some(0), Some(0)));
        let mut watch = TripWatch::default();
        assert_eq!(watch.evaluate(&cfg, &at), TripAction::Normal);
        assert!(!watch.take_device_event());

        // Ten re-attaches in a row. Each time the module has already taken the
        // new devices by the next look: mode 0, bridge ready, counters up,
        // watchdog untouched. The keeper writes the mode again every time.
        for n in 1..=10u32 {
            at.mode = Some(0);
            at.dev_gone = Some(2 * n);
            at.reacq = Some(n);
            assert!(at.bridge_ready());
            assert_eq!(watch.evaluate(&cfg, &at), TripAction::Apply, "re-attach {n}");
            assert!(watch.take_device_event());
            assert!(!watch.take_device_event());
            at.mode = Some(2);
            watch.note_applied(2, &at);
            assert_eq!(watch.evaluate(&cfg, &at), TripAction::Normal);
            assert_eq!(watch.rearms(), 0);
            assert!(!watch.is_tripped());
        }

        // A real watchdog trip afterwards still gets its one re-arm, then holds.
        at.mode = Some(0);
        at.wd_trips = Some(1);
        at.wd_reason = Some("modified".into());
        assert!(matches!(watch.evaluate(&cfg, &at), TripAction::Rearm { .. }));
        at.mode = Some(2);
        watch.note_applied(2, &at);
        at.mode = Some(0);
        at.wd_trips = Some(2);
        assert!(matches!(
            watch.evaluate(&cfg, &at),
            TripAction::Tripped { first_notice: true, .. }
        ));
        // A device loss does not release a tripped unit.
        at.dev_gone = Some(99);
        assert!(matches!(
            watch.evaluate(&cfg, &at),
            TripAction::Tripped { first_notice: false, .. }
        ));
        assert!(watch.is_tripped());

        // A keeper that starts after a device loss sees no watchdog trip and
        // simply applies the mode.
        let mut fresh = TripWatch::default();
        let mut after = parse_proc(BENCH_PROC);
        after.mode = Some(0);
        after.dev_gone = Some(4);
        after.reacq = Some(2);
        assert_eq!(fresh.evaluate(&cfg, &after), TripAction::Apply);
        assert_eq!(fresh.rearms(), 0);

        // A trip and a device loss in the same interval: the trip still counts
        // on the next drop, because the watchdog counter moved.
        let mut both = TripWatch::default();
        let mut p = parse_proc(BENCH_PROC);
        assert_eq!(both.evaluate(&cfg, &p), TripAction::Normal);
        p.mode = Some(0);
        p.dev_gone = Some(1);
        p.wd_trips = Some(1);
        p.wd_reason = Some("tx_stall".into());
        assert!(matches!(both.evaluate(&cfg, &p), TripAction::Rearm { .. }));
    }

    #[test]
    fn status_formats_all_fields() {
        let cfg = parse_config("mode=2\n");
        let base = StatusView {
            state: "applied",
            detail: "mode 2 read back from /proc/k1fp",
            config: &cfg,
            active_mode: Some(2),
            gate_open: Some(true),
            qctrl_present: Some(true),
            wd_trips: 0,
            wd_reason: "none",
            now: 95,
        };
        let text = status(&base);
        assert_eq!(
            text,
            "state=applied\ndetail=mode 2 read back from /proc/k1fp\nmode=2\nactive_mode=2\ngate=open\nqctrl_present=1\nwd_trips=0\nwd_reason=none\nupdated=95\n"
        );
        // Changing only `now` leaves status_body identical; changing gate,
        // active_mode, qctrl_present, or wd_trips changes status_body.
        let later = StatusView { now: 200, ..base };
        assert_eq!(status_body(&base), status_body(&later));
        assert_ne!(
            status_body(&base),
            status_body(&StatusView {
                gate_open: Some(false),
                ..base
            })
        );
        assert_ne!(
            status_body(&base),
            status_body(&StatusView {
                active_mode: Some(0),
                ..base
            })
        );
        assert_ne!(
            status_body(&base),
            status_body(&StatusView {
                qctrl_present: Some(false),
                ..base
            })
        );
        assert_ne!(
            status_body(&base),
            status_body(&StatusView {
                wd_trips: 1,
                wd_reason: "tx_stall",
                ..base
            })
        );
    }
}
