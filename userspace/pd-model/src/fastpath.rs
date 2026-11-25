//! The passthrough bridge fast path: the `titan_k1fp` kernel module (v2.2.1).
//!
//! At 130+ Mbps in IP passthrough, softirq saturates the CPU and adds queueing
//! delay. `titan_k1fp` short-circuits steady-state unicast IPv4 and IPv6
//! TCP/UDP flows between `lte0pdn2` and `eth0` straight from the bridge port RX
//! handler to `dev_queue_xmit` after proving every flow on the stock path. See
//! `docs/fast-path.md`.
//!
//! Since v1.0.17 the module is in the firmware image and on by default, in
//! `DEFAULT_MODE`. An operator's `/mnt/titan-api/fastpath/config` sets
//! another mode, and `fastpath=off` in the latency switches turns it off
//! (`effective`). The keeper:
//! - loads it only when the effective mode is not 0, only in IP
//!   passthrough with the exact bridge shape (`eth0` and `lte0pdn2` in `br0`),
//!   once both have stayed up for `SETTLE_SECS`, and after the download clamp
//!   if both are configured;
//! - loads only bytes that match the digest built into the keeper
//!   (`device/fastpath/SHA256SUMS`): a copy staged in
//!   `/mnt/titan-api/fastpath/` when there is one, else the image's, from a
//!   private copy in RAM;
//! - refuses to load beside any other module with `k1fp` in its name or a
//!   different version string;
//! - checks `ports_ok=1`, `lan_hooked=1`, and `wan_hooked=1` in `/proc/k1fp`
//!   before enabling any mode other than 0;
//! - drives the module's SAS grant lease from the keeper's own CBRS gate state
//!   (renewing once a second while held, writing `grant 0` first on close, and
//!   never writing a lease while `cbrs_mode_grant` is not 1);
//! - tracks watchdog trips (`wd_trips`, `wd_reason`) and unexpected mode drops.
//!   After each drop it holds mode 0 in `state=tripped` for a wait that
//!   doubles with each drop in a row (`retry::MODULES`: 1 min up to 1 h),
//!   then writes the mode again, for as long as it takes. An hour at the mode
//!   without a drop (`CLEAN_SECS`) forgets the earlier ones, and a config
//!   change or the switch turned off and on re-arms at once;
//! - treats a lost bridge device as a pause, not a trip. A modem re-attach
//!   makes the vendor scripts recreate `br0` and `lte0pdn2`; the module drops
//!   to mode 0, counts `dev_gone`, and takes the new devices by itself. The
//!   keeper writes the configured mode again once the bridge is ready, and
//!   that is not a drop.

use crate::cbrs_gate::{Gate, Step as GateStep};
use crate::retry::{Backoff, Policy};
use crate::switches::Source;

/// The first line of `/proc/k1fp` for the allowed build.
pub const VERSION_LINE: &str = "titan_k1fp v2.2.1";
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
/// The mode of a unit with no `fastpath/config`: the downlink fast path, which
/// the bench has run for days. It must be one of `MODES`.
pub const DEFAULT_MODE: u32 = 2;
/// Seconds `eth0` and the customer bearer must stay up before a load.
pub const SETTLE_SECS: u64 = 30;
/// Seconds between config and `/proc/k1fp` checks.
pub const CHECK_EVERY: u64 = 15;
/// Validity in seconds written to `/proc/k1fp` once per second while a SAS
/// grant is held. A crashed keeper leaves the lease to expire on its own.
pub const GRANT_LEASE_SECS: u32 = 5;
/// Seconds at the configured mode without a drop after which earlier drops
/// are forgotten, so the next one waits the shortest time again.
pub const CLEAN_SECS: u64 = 3600;

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

/// The settings the keeper keeps, and where they came from: mode 0 while
/// `fastpath=off` is in the latency switches, the operator's
/// `fastpath/config` (`staged`) when there is one, else `DEFAULT_MODE`.
pub fn effective(switch_on: bool, staged: Option<&str>) -> (Config, Source) {
    match (switch_on, staged) {
        (false, _) => (Config::default(), Source::Off),
        (true, Some(text)) => (parse_config(text), Source::Operator),
        (true, None) => (Config { mode: DEFAULT_MODE, refused: Vec::new() }, Source::Default),
    }
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

/// Tracks the applied mode and watchdog trips or unexpected drops for one
/// keeper process. Nothing here is kept across a restart or a reboot.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TripWatch {
    /// True after the first `/proc/k1fp` observation in this keeper process.
    observed: bool,
    /// Mode last confirmed in `/proc/k1fp` (only when > 0).
    applied_mode: Option<u32>,
    /// When that mode was written or adopted (monotonic seconds).
    applied_at: Option<u64>,
    /// Last observed `wd_trips` count from `/proc/k1fp`.
    last_wd_trips: u32,
    /// Held at mode 0 after a drop, until `rearm` is ready.
    held: Option<Held>,
    /// Drops in a row and when the next re-arm is due.
    rearm: Backoff,
    /// Last observed `dev_gone` count from `/proc/k1fp`.
    last_dev_gone: Option<u32>,
    /// A device loss was seen and not yet reported with `take_device_event`.
    device_event: bool,
}

/// A drop the fast path is waiting out.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Held {
    /// The config it happened under. Another config is applied at once.
    config: Config,
    reason: String,
    /// The wait chosen at the drop, in seconds.
    wait: u64,
}

/// Mode action decided from config and `/proc/k1fp`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TripAction {
    /// `/proc/k1fp` already matches config.
    Normal,
    /// Initial apply or config change: write `config.mode`.
    Apply,
    /// The wait after a drop is over: write `config.mode` again. `drops` is
    /// the number of drops in a row, this one included.
    Rearm { reason: String, drops: u32 },
    /// After a drop: hold at mode 0 with `state=tripped` for `wait` seconds.
    /// `first_notice` is true on the look that saw the drop.
    Tripped { reason: String, first_notice: bool, wait: u64 },
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
    /// One look at `/proc/k1fp` at `now` (monotonic seconds). `policy` sets
    /// the waits after drops (`retry::MODULES`, shortened in tests).
    pub fn evaluate(&mut self, config: &Config, proc: &Proc, policy: Policy, now: u64) -> TripAction {
        let first_observation = !self.observed;
        self.observed = true;

        // The module lost a bridge device since the last look (a modem
        // re-attach recreates `br0` and `lte0pdn2`) and set mode 0 itself.
        // That is a pause, not a drop: forget the applied mode so the
        // configured mode is written again at once. A fast path waiting out
        // a drop keeps waiting.
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
            // Off, by config or by the switch: turning it on again starts afresh.
            self.applied_mode = None;
            self.held = None;
            self.rearm.reset();
            self.seen_trips(proc);
            return if proc.mode == Some(0) {
                TripAction::Normal
            } else {
                TripAction::Apply
            };
        }

        if let Some(held) = self.held.take() {
            if &held.config == config {
                self.seen_trips(proc);
                if !self.rearm.ready(now) {
                    let action = TripAction::Tripped {
                        reason: held.reason.clone(),
                        first_notice: false,
                        wait: held.wait,
                    };
                    self.held = Some(held);
                    return action;
                }
                return TripAction::Rearm {
                    reason: held.reason,
                    drops: self.rearm.failures(),
                };
            }
            // Config changed: apply it at once, with no drops counted.
            self.rearm.reset();
            self.applied_mode = None;
        }

        if self.applied_mode == Some(config.mode) {
            if proc.mode == Some(config.mode) {
                self.seen_trips(proc);
                if self
                    .applied_at
                    .is_some_and(|at| now.saturating_sub(at) >= CLEAN_SECS)
                {
                    self.rearm.reset();
                }
                return TripAction::Normal;
            }
            let reason = describe_trip(proc, self.last_wd_trips, config.mode);
            self.seen_trips(proc);
            return self.hold(config, reason, policy, now);
        }

        // First observation (e.g. keeper restarted after a watchdog trip):
        // wait as after a drop, then write the mode again.
        if first_observation
            && self.applied_mode.is_none()
            && proc.mode == Some(0)
            && proc.wd_trips.unwrap_or(0) > 0
        {
            let reason = describe_trip(proc, self.last_wd_trips, config.mode);
            self.seen_trips(proc);
            return self.hold(config, reason, policy, now);
        }

        self.seen_trips(proc);
        if proc.mode == Some(config.mode) {
            // Adopted at the configured mode.
            self.applied_mode = Some(config.mode);
            self.applied_at = Some(now);
            TripAction::Normal
        } else {
            TripAction::Apply
        }
    }

    fn seen_trips(&mut self, proc: &Proc) {
        if let Some(t) = proc.wd_trips {
            self.last_wd_trips = t;
        }
    }

    /// A drop at `now`: hold mode 0 for the next wait in `policy`.
    fn hold(&mut self, config: &Config, reason: String, policy: Policy, now: u64) -> TripAction {
        self.applied_mode = None;
        let wait = self.rearm.failed(now, policy);
        self.held = Some(Held {
            config: config.clone(),
            reason: reason.clone(),
            wait,
        });
        TripAction::Tripped {
            reason,
            first_notice: true,
            wait,
        }
    }

    /// Record that `mode` was written and read back from `/proc/k1fp` at `now`.
    pub fn note_applied(&mut self, mode: u32, proc: &Proc, now: u64) {
        self.applied_mode = (mode > 0).then_some(mode);
        self.applied_at = Some(now);
        self.seen_trips(proc);
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

    /// Drops in a row (forgotten after `CLEAN_SECS` at the mode).
    pub fn drops(&self) -> u32 {
        self.rearm.failures()
    }

    /// Holding mode 0 after a drop.
    pub fn is_tripped(&self) -> bool {
        self.held.is_some()
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
titan_k1fp v2.2.1
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
    fn on_by_default_in_mode_2_unless_switched_off_or_configured() {
        assert!(MODES.contains(&DEFAULT_MODE));
        assert_eq!(effective(true, None), (Config { mode: 2, refused: Vec::new() }, Source::Default));
        assert_eq!(effective(false, Some("mode=3\n")), (Config::default(), Source::Off));
        assert_eq!(effective(true, Some("mode=3\n")).0.mode, 3);
        assert_eq!(effective(true, Some("mode=0\n")), (Config::default(), Source::Operator));
        assert_eq!(effective(true, Some("")).0.mode, 0, "an empty file is the operator's: off");
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
        let v1 = parse_proc(&BENCH_PROC.replace(VERSION_LINE, "titan_k1fp v1.2"));
        assert!(!v1.ours);
        assert!(!matches(&parse_config("mode=2\n"), &v1));
        let dev = parse_proc(&BENCH_PROC.replace(VERSION_LINE, "titan_k1fp v2.2.1-dev"));
        assert!(!dev.ours);
        assert!(!parse_proc("").ours);
    }

    #[test]
    fn refuses_other_k1fp_modules_or_wrong_version() {
        assert_eq!(loaded("titan_qctrl 47104 0 - Live 0x7f0b4000\n", ""), Loaded::None);
        assert_eq!(loaded("", ""), Loaded::None);
        assert_eq!(loaded(MODULES, BENCH_PROC), Loaded::Ours);
        assert_eq!(
            loaded(MODULES, &BENCH_PROC.replace(VERSION_LINE, "titan_k1fp v2.2")),
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

    /// `/proc/k1fp` after a watchdog trip: mode 0, `wd_trips` = `trips`.
    fn tripped(trips: u32, reason: &str) -> Proc {
        parse_proc(&BENCH_PROC.replace("mode=2 ", "mode=0 ").replace(
            "wd_trips=0 wd_reason=none",
            &format!("wd_trips={trips} wd_reason={reason}"),
        ))
    }

    /// `/proc/k1fp` running `mode` after `trips` earlier trips.
    fn running(mode: u32, trips: u32, reason: &str) -> Proc {
        let mut proc = tripped(trips, reason);
        proc.mode = Some(mode);
        proc
    }

    const P: Policy = crate::retry::MODULES;

    #[test]
    fn every_drop_waits_its_turn_then_rearms_for_as_long_as_it_takes() {
        let cfg2 = parse_config("mode=2\n");
        let mut tw = TripWatch::default();
        // Initial load starts at mode 0 -> Apply.
        assert_eq!(tw.evaluate(&cfg2, &tripped(0, "none"), P, 0), TripAction::Apply);
        tw.note_applied(2, &running(2, 0, "none"), 0);
        assert_eq!(tw.evaluate(&cfg2, &running(2, 0, "none"), P, 15), TripAction::Normal);
        assert_eq!(tw.drops(), 0);

        // Trip 1: hold mode 0 for a minute, then re-arm.
        let reason = match tw.evaluate(&cfg2, &tripped(1, "tx_stall"), P, 100) {
            TripAction::Tripped { reason, first_notice: true, wait: 60 } => reason,
            other => panic!("expected a 60 s hold, got {other:?}"),
        };
        assert!(reason.contains("tx_stall") && reason.contains("wd_trips=1"), "{reason}");
        assert!(tw.is_tripped());
        for now in [115, 130, 159] {
            assert_eq!(
                tw.evaluate(&cfg2, &tripped(1, "tx_stall"), P, now),
                TripAction::Tripped { reason: reason.clone(), first_notice: false, wait: 60 },
                "still waiting at {now}"
            );
        }
        assert_eq!(
            tw.evaluate(&cfg2, &tripped(1, "tx_stall"), P, 160),
            TripAction::Rearm { reason: reason.clone(), drops: 1 }
        );
        assert!(!tw.is_tripped());
        tw.note_applied(2, &running(2, 1, "tx_stall"), 160);
        assert_eq!(tw.evaluate(&cfg2, &running(2, 1, "tx_stall"), P, 175), TripAction::Normal);

        // Every further drop in a row waits twice as long, up to an hour, and
        // is always re-armed: there is no budget to spend. (v1.0.17 held the
        // second one at mode 0 until the config changed or the unit rebooted.)
        let mut now = 200;
        for drop in 2..=12u32 {
            let want = P.wait(drop);
            match tw.evaluate(&cfg2, &tripped(drop, "ring_full"), P, now) {
                TripAction::Tripped { first_notice: true, wait, .. } => assert_eq!(wait, want, "drop {drop}"),
                other => panic!("drop {drop}: expected a hold, got {other:?}"),
            }
            assert!(matches!(
                tw.evaluate(&cfg2, &tripped(drop, "ring_full"), P, now + want - 1),
                TripAction::Tripped { first_notice: false, .. }
            ));
            assert_eq!(
                tw.evaluate(&cfg2, &tripped(drop, "ring_full"), P, now + want),
                TripAction::Rearm {
                    reason: "watchdog tripped (reason=ring_full, wd_trips=".to_owned()
                        + &drop.to_string()
                        + ", mode 2 -> 0)",
                    drops: drop
                }
            );
            now += want;
            tw.note_applied(2, &running(2, drop, "ring_full"), now);
            now += 30;
        }
        assert_eq!(P.wait(12), 3600, "the wait stops growing at an hour");

        // An hour at the mode with no drop forgets them: the next waits a minute.
        assert_eq!(tw.evaluate(&cfg2, &running(2, 12, "ring_full"), P, now + CLEAN_SECS), TripAction::Normal);
        assert_eq!(tw.drops(), 0);
        assert!(matches!(
            tw.evaluate(&cfg2, &tripped(13, "modified"), P, now + CLEAN_SECS + 15),
            TripAction::Tripped { first_notice: true, wait: 60, .. }
        ));
    }

    #[test]
    fn a_new_config_or_the_switch_turned_off_and_on_rearms_at_once() {
        let cfg2 = parse_config("mode=2\n");
        let cfg3 = parse_config("mode=3\n");
        let off = Config::default();
        let mut tw = TripWatch::default();
        tw.note_applied(2, &running(2, 0, "none"), 0);
        assert!(matches!(tw.evaluate(&cfg2, &tripped(1, "tx_stall"), P, 10), TripAction::Tripped { wait: 60, .. }));
        tw.evaluate(&cfg2, &tripped(1, "tx_stall"), P, 70);
        tw.note_applied(2, &running(2, 1, "tx_stall"), 70);
        assert!(matches!(tw.evaluate(&cfg2, &tripped(2, "tx_stall"), P, 80), TripAction::Tripped { wait: 120, .. }));

        // A new config while waiting: applied at once, with no drops counted.
        assert_eq!(tw.evaluate(&cfg3, &tripped(2, "tx_stall"), P, 90), TripAction::Apply);
        assert!(!tw.is_tripped());
        assert_eq!(tw.drops(), 0);
        tw.note_applied(3, &running(3, 2, "tx_stall"), 90);
        assert!(matches!(tw.evaluate(&cfg3, &tripped(3, "modified"), P, 100), TripAction::Tripped { wait: 60, .. }));

        // The web switch: fastpath=off (mode 0) and on again. Off ends the
        // hold; on applies at once and the next drop waits a minute.
        assert_eq!(tw.evaluate(&off, &tripped(3, "modified"), P, 105), TripAction::Normal);
        assert!(!tw.is_tripped());
        assert_eq!(tw.evaluate(&cfg3, &tripped(3, "modified"), P, 110), TripAction::Apply);
        tw.note_applied(3, &running(3, 3, "modified"), 110);
        assert!(matches!(tw.evaluate(&cfg3, &tripped(4, "modified"), P, 120), TripAction::Tripped { wait: 60, .. }));
    }

    #[test]
    fn trip_policy_handles_manual_mode_drop_and_pause_and_restart() {
        let cfg2 = parse_config("mode=2\n");
        let proc0 = tripped(0, "none");
        let proc2 = running(2, 0, "none");

        // A hand-written mode 0 (wd_trips stays 0) is a drop too: wait, then re-arm.
        let mut tw = TripWatch::default();
        assert_eq!(tw.evaluate(&cfg2, &proc0, P, 0), TripAction::Apply);
        tw.note_applied(2, &proc2, 0);
        match tw.evaluate(&cfg2, &proc0, P, 15) {
            TripAction::Tripped { reason, first_notice: true, wait: 60 } => {
                assert!(reason.contains("mode changed unexpectedly"), "{reason}")
            }
            other => panic!("expected a hold, got {other:?}"),
        }
        assert!(matches!(tw.evaluate(&cfg2, &proc0, P, 75), TripAction::Rearm { drops: 1, .. }));

        // Pause (e.g., bridge unready) and resume is NOT a drop.
        let mut tw2 = TripWatch::default();
        assert_eq!(tw2.evaluate(&cfg2, &proc0, P, 0), TripAction::Apply);
        tw2.note_applied(2, &proc2, 0);
        tw2.note_paused();
        assert_eq!(tw2.evaluate(&cfg2, &proc0, P, 15), TripAction::Apply);
        assert_eq!(tw2.drops(), 0);

        // A keeper that restarts and finds the module at mode 0 after trips
        // waits a minute, then writes the mode again. (v1.0.17 held it at mode
        // 0 for the rest of the boot once wd_trips was 2 or more.)
        let mut tw3 = TripWatch::default();
        assert!(matches!(
            tw3.evaluate(&cfg2, &tripped(2, "bad_ring"), P, 500),
            TripAction::Tripped { first_notice: true, wait: 60, .. }
        ));
        assert!(matches!(tw3.evaluate(&cfg2, &tripped(2, "bad_ring"), P, 559), TripAction::Tripped { .. }));
        assert!(matches!(tw3.evaluate(&cfg2, &tripped(2, "bad_ring"), P, 560), TripAction::Rearm { .. }));

        // Adopting an already-loaded module running at mode=2 records applied_mode so
        // any later drop is detected.
        let mut tw4 = TripWatch::default();
        assert_eq!(tw4.evaluate(&cfg2, &proc2, P, 0), TripAction::Normal);
        assert!(matches!(tw4.evaluate(&cfg2, &proc0, P, 15), TripAction::Tripped { first_notice: true, .. }));
    }

    #[test]
    fn device_loss_is_a_pause_and_never_counts_as_a_drop() {
        let cfg = Config { mode: 2, refused: vec![] };
        let mut at = parse_proc(BENCH_PROC);
        assert_eq!((at.dev_gone, at.reacq), (Some(0), Some(0)));
        let mut watch = TripWatch::default();
        assert_eq!(watch.evaluate(&cfg, &at, P, 0), TripAction::Normal);
        assert!(!watch.take_device_event());

        // Ten re-attaches in a row. Each time the module has already taken the
        // new devices by the next look: mode 0, bridge ready, counters up,
        // watchdog untouched. The keeper writes the mode again every time.
        let mut now = 0;
        for n in 1..=10u32 {
            now += 15;
            at.mode = Some(0);
            at.dev_gone = Some(2 * n);
            at.reacq = Some(n);
            assert!(at.bridge_ready());
            assert_eq!(watch.evaluate(&cfg, &at, P, now), TripAction::Apply, "re-attach {n}");
            assert!(watch.take_device_event());
            assert!(!watch.take_device_event());
            at.mode = Some(2);
            watch.note_applied(2, &at, now);
            assert_eq!(watch.evaluate(&cfg, &at, P, now + 1), TripAction::Normal);
            assert_eq!(watch.drops(), 0);
            assert!(!watch.is_tripped());
        }

        // A real watchdog trip afterwards waits its minute.
        at.mode = Some(0);
        at.wd_trips = Some(1);
        at.wd_reason = Some("modified".into());
        assert!(matches!(
            watch.evaluate(&cfg, &at, P, 200),
            TripAction::Tripped { first_notice: true, wait: 60, .. }
        ));
        // A device loss while waiting neither ends nor restarts the wait.
        at.dev_gone = Some(99);
        assert!(matches!(
            watch.evaluate(&cfg, &at, P, 230),
            TripAction::Tripped { first_notice: false, wait: 60, .. }
        ));
        assert!(watch.is_tripped());
        assert!(matches!(watch.evaluate(&cfg, &at, P, 260), TripAction::Rearm { drops: 1, .. }));

        // A keeper that starts after a device loss sees no watchdog trip and
        // simply applies the mode.
        let mut fresh = TripWatch::default();
        let mut after = parse_proc(BENCH_PROC);
        after.mode = Some(0);
        after.dev_gone = Some(4);
        after.reacq = Some(2);
        assert_eq!(fresh.evaluate(&cfg, &after, P, 0), TripAction::Apply);
        assert_eq!(fresh.drops(), 0);

        // A trip and a device loss in the same interval: the trip still counts,
        // because the watchdog counter moved.
        let mut both = TripWatch::default();
        let mut p = parse_proc(BENCH_PROC);
        assert_eq!(both.evaluate(&cfg, &p, P, 0), TripAction::Normal);
        p.mode = Some(0);
        p.dev_gone = Some(1);
        p.wd_trips = Some(1);
        p.wd_reason = Some("tx_stall".into());
        assert!(matches!(both.evaluate(&cfg, &p, P, 15), TripAction::Tripped { first_notice: true, .. }));
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
