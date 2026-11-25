//! The deaf watchdog: reboot a unit that stays attached but hears nothing
//! through the core, and keep the vendor's own ping watchdog off while it
//! runs. See `titan_pd_model::deaf`.

use std::fs;
use std::net::IpAddr;
use std::process::{Child, Command, Stdio};

use titan_pd_model::deaf::{self, Action as DeafAction};
use titan_pd_model::mgmt;

use crate::{log, nvram};
use crate::files::read_file;
use crate::paths::{env_or, state_dir};

use super::Keeper;

/// A plain `reboot` that has not ended this process after this long is forced.
const REBOOT_FORCE_AFTER: u64 = 45;
/// After the forced attempt also fails, go back to watching.
const REBOOT_GIVE_UP_AFTER: u64 = 120;

/// One ping to each target, collected on later ticks so the wire loop keeps
/// running. The deaf watchdog and the tk boot confirm each run one.
pub(super) struct PingRound {
    children: Vec<Child>,
    started: u64,
}

impl PingRound {
    /// Start a round, or `None` when no ping could start.
    pub(super) fn start(targets: &[IpAddr], now: u64) -> Option<Self> {
        let children = spawn_pings(targets);
        (!children.is_empty()).then_some(Self {
            children,
            started: now,
        })
    }

    /// Whether a target answered: once one has, once every ping has ended,
    /// or `timeout` seconds after the start. `None` while the round is open.
    /// An answered round's pings are stopped and reaped.
    pub(super) fn poll(&mut self, now: u64, timeout: u64) -> Option<bool> {
        let mut heard = false;
        let mut running = false;
        for child in &mut self.children {
            match child.try_wait() {
                Ok(Some(status)) => heard |= status.success(),
                Ok(None) => running = true,
                Err(_) => {}
            }
        }
        if !heard && running && now.saturating_sub(self.started) < timeout {
            return None;
        }
        for child in &mut self.children {
            let _ = child.kill();
            let _ = child.wait();
        }
        Some(heard)
    }
}

impl Keeper {
    /// Reboot a unit that stays attached but hears nothing through the core.
    /// Runs in NAT and in passthrough. See `titan_pd_model::deaf`.
    pub(super) fn maintain_deaf_watchdog(&mut self) {
        if let Some(asked) = self.reboot_asked_at {
            let waited = self.now.saturating_sub(asked);
            if !self.reboot_forced && waited >= REBOOT_FORCE_AFTER {
                self.reboot_forced = true;
                log("watchdog reboot did not happen; forcing it");
                let _ = Command::new(reboot_program()).arg("-f").status();
            } else if self.reboot_forced && waited >= REBOOT_GIVE_UP_AFTER {
                self.reboot_asked_at = None;
                self.reboot_forced = false;
                self.deaf_watch = deaf::Watch::default();
                log("the forced watchdog reboot did not happen either; watching again");
            }
            return;
        }
        if let Some(mut probe) = self.deaf_probe.take() {
            match probe.poll(self.now, deaf::PROBE_TIMEOUT) {
                None => self.deaf_probe = Some(probe),
                Some(heard) => self.deaf_round(Some(heard)),
            }
            return;
        }
        if !self.last_deaf_round.ready(self.now, deaf::PROBE_EVERY) {
            return;
        }
        let settings = deaf::parse_settings(&read_file(state_dir().join("watchdog.conf")));
        self.deaf_secs = settings.deaf_secs;
        self.maintain_vendor_watchdog(&settings);
        if !settings.enabled {
            self.deaf_round(None);
            return;
        }
        let bearer_dns = if settings.targets.is_empty() {
            self.nvram_get_cached("wan_get_dns")
        } else {
            String::new()
        };
        let targets = deaf::targets(&settings, &bearer_dns);
        match PingRound::start(&targets, self.now) {
            Some(round) => self.deaf_probe = Some(round),
            None => self.deaf_round(None),
        }
    }

    /// Run one watchdog, not two. The vendor's (`ucid`, nvram `detection_enable`)
    /// reboots after about 110 s without its ping target and has no backoff, so
    /// two setting saves in a row can reboot the unit. `ucid` reads the flag from
    /// the RAM cache every 15 s, so clearing it there is enough and nothing is
    /// committed to flash. An operator who turns this watchdog off keeps the
    /// vendor setting as saved.
    fn maintain_vendor_watchdog(&mut self, settings: &deaf::Settings) {
        let value = self
            .read_nvram_cache()
            .and_then(|cache| nvram::field(cache, "detection_enable"))
            .map(str::to_owned);
        if !deaf::vendor_watchdog_must_stop(settings, value.as_deref()) {
            return;
        }
        let was = value.as_deref().unwrap_or("").trim().to_owned();
        let done = crate::nvram::set("detection_enable", "0").is_ok();
        // Something that keeps turning it back on must not fill the flash log.
        if !self.vendor_watchdog_logged.ready(self.now, 3600) {
            return;
        }
        if done {
            self.note(&format!(
                "vendor ping watchdog: turned off in RAM for this boot (detection_enable was {was}); the keeper's deaf watchdog covers this unit"
            ));
        } else {
            self.note("vendor ping watchdog: could not turn it off; two watchdogs may reboot this unit");
        }
    }

    fn deaf_round(&mut self, heard: Option<bool>) {
        // A guarded radio cycle deliberately interrupts the management bearer.
        if crate::radio::transition_in_progress(self.now) {
            self.deaf_watch = deaf::Watch::default();
            return;
        }
        let attached = deaf::attached(&self.nvram_get_cached("sqns_connection_mediaState"));
        let path = state_dir().join("watchdog-strikes.txt");
        let strikes = deaf::parse_strikes(&read_file(&path));
        match self
            .deaf_watch
            .observe(self.now, attached, heard, self.deaf_secs, strikes)
        {
            DeafAction::Hold => {}
            DeafAction::Armed => self.note(&format!(
                "deaf watchdog armed: a target answered through the core; {} s of silence while attached will reboot the unit",
                deaf::required_silence(self.deaf_secs, strikes)
            )),
            DeafAction::Silent => {
                self.note("deaf watchdog: attached, but no target answered this round");
                if self.passthrough {
                    // The known cause of a deaf passthrough unit needs no reboot.
                    self.note(
                        "deaf watchdog: trying the passthrough repair first (external device and management MAC)",
                    );
                    self.repair_external_dev(mgmt::MGMT_DEV);
                }
            }
            DeafAction::Recovered { silent_for } => self.note(&format!(
                "deaf watchdog: answers are back after {silent_for} s of silence"
            )),
            DeafAction::ClearStrikes => {
                if store_strikes(&path, 0) {
                    self.note("deaf watchdog: an hour of answers; earlier reboots are forgotten");
                } else {
                    // Ask again next round rather than keep the old count all boot.
                    self.deaf_watch.clear_failed();
                }
            }
            DeafAction::Reboot { silent_for } => {
                store_strikes(&path, strikes.saturating_add(1));
                self.note(&format!(
                    "deaf watchdog: attached but nothing heard through the core for {silent_for} s; rebooting (reboot {} in a row)",
                    strikes.saturating_add(1)
                ));
                self.request_reboot();
            }
        }
    }

    /// A watchdog reboot. `maintain_deaf_watchdog` forces it if it does not
    /// happen.
    pub(super) fn request_reboot(&mut self) {
        titan_sys::kernel::sync();
        self.reboot_asked_at = Some(self.now);
        self.reboot_forced = false;
        let _ = Command::new(reboot_program())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
    }
}

fn reboot_program() -> String {
    env_or("TITAN_REBOOT", "reboot")
}

/// One ping to each target.
fn spawn_pings(targets: &[IpAddr]) -> Vec<Child> {
    targets
        .iter()
        .filter_map(|target| {
            let program = if target.is_ipv6() { "ping6" } else { "ping" };
            let address = target.to_string();
            Command::new(env_or("TITAN_PING", program))
                .args(["-c", "1", "-W", "4", address.as_str()])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .ok()
        })
        .collect()
}

/// Write the strike count through a temporary file, so a power cut cannot
/// leave a torn record.
fn store_strikes(path: &std::path::Path, strikes: u32) -> bool {
    let temp = path.with_extension("tmp");
    fs::write(&temp, deaf::format_strikes(strikes)).is_ok() && fs::rename(&temp, path).is_ok()
}
