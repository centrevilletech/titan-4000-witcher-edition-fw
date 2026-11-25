//! The deaf watchdog: reboot a unit that stays attached but hears nothing
//! through the core, and keep the vendor's own ping watchdog off while it
//! runs. See `titan_pd_model::deaf`. Its reboot passes the keeper's reboot
//! gate (`super::reboot`): never in the SAS CPAS window, never with the
//! clock unset, and within the keeper's daily cap (v1.0.17).

use std::net::{IpAddr, UdpSocket};
use std::process::{Child, Command, Stdio};

use titan_pd_model::deaf::{self, Action as DeafAction};
use titan_pd_model::dns_probe;
use titan_pd_model::mgmt;

use crate::{log, nvram};
use crate::files::read_file;
use crate::paths::{env_or, state_dir};

use super::Keeper;
use super::reboot::Kind;

/// A plain `reboot` that has not ended this process after this long is forced.
const REBOOT_FORCE_AFTER: u64 = 45;
/// After the forced attempt also fails, go back to watching.
const REBOOT_GIVE_UP_AFTER: u64 = 120;

/// One ping to each target, collected on later ticks so the wire loop keeps
/// running. The deaf watchdog and the tk boot confirm each run one; the boot
/// confirm's also asks each target a DNS question (`dns_probe`), because a
/// carrier's DNS servers often ignore ping.
pub(super) struct PingRound {
    children: Vec<Child>,
    questions: Vec<(UdpSocket, u16)>,
    started: u64,
}

impl PingRound {
    /// Start a round of pings, or `None` when no ping could start.
    pub(super) fn start(targets: &[IpAddr], now: u64) -> Option<Self> {
        Self::open(targets, now, false)
    }

    /// Pings and a DNS question to each target, or `None` when neither could
    /// start.
    pub(super) fn start_with_dns(targets: &[IpAddr], now: u64) -> Option<Self> {
        Self::open(targets, now, true)
    }

    fn open(targets: &[IpAddr], now: u64, dns: bool) -> Option<Self> {
        let children = spawn_pings(targets);
        let questions = if dns { ask_dns(targets, now) } else { Vec::new() };
        (!children.is_empty() || !questions.is_empty()).then_some(Self {
            children,
            questions,
            started: now,
        })
    }

    /// Whether a target answered: once one has, once every ping has ended
    /// (and no DNS question is open), or `timeout` seconds after the start.
    /// `None` while the round is open. An answered round's pings are stopped
    /// and reaped.
    pub(super) fn poll(&mut self, now: u64, timeout: u64) -> Option<bool> {
        let mut heard = self.questions.iter().any(|(socket, id)| dns_answered(socket, *id));
        let mut running = !self.questions.is_empty();
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
        // Stopped and reaped without waiting on one that does not die.
        for child in self.children.drain(..) {
            crate::command::stop(child, "ping");
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
                let _ = crate::command::output(Command::new(reboot_program()).arg("-f"));
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

    /// Keep the vendor's ping watchdog (`ucid`, nvram `detection_enable`) off,
    /// with this watchdog on or off. It reboots after about 110 s without its
    /// ping target, with no backoff and at any hour, CPAS included, so two
    /// setting saves in a row can reboot the unit. `ucid` reads the flag from
    /// the RAM cache every 15 s, so clearing it there is enough and nothing is
    /// committed to flash: a unit flashed back to stock keeps its setting.
    fn maintain_vendor_watchdog(&mut self, settings: &deaf::Settings) {
        let value = self
            .read_nvram_cache()
            .and_then(|cache| nvram::field(cache, "detection_enable"))
            .map(str::to_owned);
        if !deaf::vendor_watchdog_must_stop(value.as_deref()) {
            return;
        }
        let was = value.as_deref().unwrap_or("").trim().to_owned();
        let done = crate::nvram::set("detection_enable", "0").is_ok();
        // Something that keeps turning it back on must not fill the flash log.
        if !self.vendor_watchdog_logged.ready(self.now, 3600) {
            return;
        }
        if done {
            let covered = if settings.enabled {
                "the keeper's deaf watchdog covers this unit"
            } else {
                "it reboots with no backoff and in the SAS CPAS window, so it stays off although the keeper's deaf watchdog is off too"
            };
            self.note(&format!(
                "vendor ping watchdog: turned off in RAM for this boot (detection_enable was {was}); {covered}"
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
        if heard == Some(true) {
            self.heard_through_core();
            self.deaf_reboot_held = None;
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
                // The gate holds it in the CPAS window, without a set clock,
                // or at the keeper's daily cap; the watch asks again after
                // the next stretch of silence.
                if let Some(why) = self.reboot_blocked(Kind::Deaf) {
                    if self.deaf_reboot_held.as_deref() != Some(why.as_str()) {
                        self.note(&format!(
                            "deaf watchdog: attached but nothing heard through the core for {silent_for} s; the reboot waits: {why}"
                        ));
                        self.deaf_reboot_held = Some(why);
                    }
                    return;
                }
                self.deaf_reboot_held = None;
                store_strikes(&path, strikes.saturating_add(1));
                self.note(&format!(
                    "deaf watchdog: attached but nothing heard through the core for {silent_for} s; rebooting (reboot {} in a row)",
                    strikes.saturating_add(1)
                ));
                self.keeper_reboot(Kind::Deaf);
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

/// One DNS question to each target (`dns_probe::query`) from its own
/// connected, non-blocking socket, so only that target's reply arrives on
/// it. The id changes from round to round. A target that cannot be asked
/// (no route) is left to its ping.
fn ask_dns(targets: &[IpAddr], now: u64) -> Vec<(UdpSocket, u16)> {
    targets
        .iter()
        .enumerate()
        .filter_map(|(i, target)| {
            let id = (now as u16).wrapping_mul(31).wrapping_add(i as u16) ^ 0x5a5a;
            let any = if target.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
            let socket = UdpSocket::bind(any).ok()?;
            socket.set_nonblocking(true).ok()?;
            socket.connect((*target, 53)).ok()?;
            socket.send(&dns_probe::query(id)).ok()?;
            Some((socket, id))
        })
        .collect()
}

/// A reply to question `id` has arrived on `socket`.
fn dns_answered(socket: &UdpSocket, id: u16) -> bool {
    let mut reply = [0u8; 512];
    while let Ok(n) = socket.recv(&mut reply) {
        if dns_probe::answers(id, &reply[..n]) {
            return true;
        }
    }
    false
}

/// Write the strike count durably, so a power cut cannot leave a torn record.
fn store_strikes(path: &std::path::Path, strikes: u32) -> bool {
    crate::files::write_durably(path, &path.with_extension("tmp"), deaf::format_strikes(strikes).as_bytes())
        .is_ok()
}
