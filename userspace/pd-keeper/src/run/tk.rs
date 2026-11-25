//! A staged modem firmware image's boot confirm, or the way back to stock
//! firmware (see `titan_pd_model::tk_boot`), and after the confirm the modem
//! feature flags `tk/config` lists (see `titan_pd_model::tk_flags`): the
//! default image's or an operator's. `modem=off` in the latency switches
//! rolls them all back to their off values.
//!
//! Only time with a cell in view counts against an image; no cell is
//! waiting for the network. A rollback of the default image is a comparison
//! with stock firmware: the next stock boot judges whether the image or the
//! network failed (see `titan_pd_model::tk_verdict`), and a network verdict
//! goes straight back onto the image. A modem crash while the default image
//! runs is judged the same way, on the same boot. The clocks pause while the
//! radio guard cycles the radio on purpose. Every reboot here passes the
//! keeper's reboot gate (`super::reboot`).

use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use titan_pd_model::deaf;
use titan_pd_model::tk_boot::{self, Action as TkAction, Why};
use titan_pd_model::tk_default;
use titan_pd_model::tk_flags;
use titan_pd_model::tk_verdict::{GENUINE_LIMIT, Judgement, Verdict};

use crate::tk_flags_io;
use crate::files::{read_file, write_durably};
use crate::nvram;
use crate::paths::{env_or, firmware_id, state_dir, tk_dir};

use super::Keeper;
use super::mgmt_v6::mgmt_address_up;
use super::reboot::Kind;
use super::watchdog::PingRound;

/// Seconds between reads of `tk/config` for flag changes.
const TK_FLAGS_CONFIG_EVERY: u64 = 15;
/// The default image's rollback record in `tk/` (`titan_pd_model::tk_verdict`).
const VERDICT: &str = "verdict";

impl Keeper {
    /// Runs in NAT and in passthrough. See `titan_pd_model::tk_boot`. Nothing
    /// arms unless the boot hook staged a modem firmware image this boot, or
    /// a stock boot has a rollback of the default image to judge.
    pub(super) fn maintain_tk_confirm(&mut self) {
        if !self.tk_checked {
            self.tk_checked = true;
            self.tk_start();
        }
        // The kernel log was read earlier this tick; the flag writer takes the
        // signal after this.
        if self.modem_restart_seen {
            self.tk_modem_reloaded();
        }
        self.maintain_tk_healthy();
        if self.reboot_asked_at.is_none() {
            self.maintain_tk_owed_reboots();
        }
        if self.tk_confirm.is_none() || self.reboot_asked_at.is_some() {
            return;
        }
        if let Some(mut probe) = self.tk_probe.take() {
            match probe.poll(self.now, tk_boot::PROBE_TIMEOUT) {
                None => self.tk_probe = Some(probe),
                Some(heard) => self.tk_round(Some(heard)),
            }
            return;
        }
        if !self.tk_last_round.ready(self.now, self.tk_timing.probe_every) {
            return;
        }
        let targets = self.tk_targets();
        match PingRound::start_with_dns(&targets, self.now) {
            Some(round) => self.tk_probe = Some(round),
            None => self.tk_round(None),
        }
    }

    /// Once per keeper process: read what the hook did this boot and arm the
    /// image's confirm, or a stock boot's judging watch.
    fn tk_start(&mut self) {
        self.tk_timing = tk_boot::Timing::with(|name| std::env::var(name).ok());
        self.tk_firmware = firmware_id();
        let status = tk_boot::parse_status(&read_file(tk_status_path()));
        if let Some(line) = tk_boot::describe(&status) {
            self.note(&line);
        }
        let result = read_file(tk_result_path());
        let decided = fs::metadata(tk_result_path()).is_ok();
        let verdict = tk_dir().map(|dir| Verdict::parse(&read_file(dir.join(VERDICT)))).unwrap_or_default();
        // The image waits for the network when its last verdict was the
        // network's: it is not compared again until it confirms.
        let waiting = status
            .staged
            .as_deref()
            .is_some_and(|sha| verdict.waits_for_network(sha, &self.tk_firmware));
        self.tk_confirm = tk_boot::Confirm::arm(&status, self.now, decided, self.tk_timing, waiting);
        // A stock boot after a rollback of the default image judges it: the
        // same watch tells whether stock firmware fares any better.
        if let (None, Some(dir)) = (&status.staged, tk_dir()) {
            let mut verdict = verdict.clone();
            if let Some(recorded) = self.tk_record_stopped(&dir, &verdict) {
                verdict = recorded;
            }
            if verdict.pending && tk_boot::valid_sha(&verdict.gzip) {
                self.tk_confirm = Some(tk_boot::Confirm::watch(&verdict.gzip, status.loaded_at, self.now, self.tk_timing));
            }
        }
        // A reboot an earlier keeper process decided on and did not finish.
        let result = result.trim();
        if let (Some(sha), Some(dir)) = (result.strip_prefix("rollback="), tk_dir()) {
            // Owed only once the record makes the hook refuse the image.
            self.tk_away_owed = status.staged.as_deref() == Some(sha)
                && tk_boot::refused(
                    tk_boot::parse_strikes(&read_file(dir.join("strikes"))),
                    &tk_boot::parse_quarantine(&read_file(dir.join("quarantine"))),
                    sha,
                );
        }
        if let Some(sha) = result.strip_prefix("back=") {
            self.tk_back_owed = Some(sha.to_owned());
        }
        // An earlier keeper process saw the default image's modem crash this
        // boot: stock firmware runs now, so judge the crash, never confirm.
        if let (Some(sha), Some(_)) = (result.strip_prefix("crashed="), tk_dir()) {
            self.tk_crashed = true;
            self.tk_confirm = None;
            if verdict.pending && verdict.crash && verdict.gzip == sha {
                self.tk_confirm = Some(tk_boot::Confirm::watch(sha, None, self.now, self.tk_timing));
            }
        }
        self.tk_status = status.clone();
        // A keeper that restarts after the confirm takes the flags over.
        match tk_flags::armed_sha(&status, &read_file(tk_result_path())) {
            Some(sha) => self.arm_tk_flags(&sha),
            None => {
                let reason = if status.staged.is_some() {
                    "waiting for the boot confirm"
                } else {
                    "stock modem firmware: no flag writes"
                };
                let _ = fs::write(tk_flags_status_path(), tk_flags::idle_status(reason, self.now));
            }
        }
        let timing = self.tk_timing;
        let line = self.tk_confirm.as_ref().map(|confirm| {
            let short = tk_boot::short(&confirm.sha);
            if confirm.judging() {
                format!(
                    "tk boot verdict armed: stock modem firmware after a rollback of modem firmware {short}; an answer through the core within {} s of the modem load says the image failed, none says the network did",
                    timing.confirm
                )
            } else if confirm.waiting {
                format!(
                    "tk boot confirm armed: modem firmware {short} waits for the network (its last rollback was the network's); it is not compared with stock modem firmware again until it answers, or after {} s",
                    timing.recheck
                )
            } else {
                format!(
                    "tk boot confirm armed: modem firmware {short} is compared with stock modem firmware after {} s with a cell in view and no answer through the core, or {} s in a row with no cell; time with no cell is waiting, not failure",
                    timing.confirm, timing.search
                )
            }
        });
        if let Some(line) = line {
            self.note(&line);
        }
    }

    /// Reboots decided on earlier: the way back onto the image after a
    /// verdict, and a recorded rollback whose reboot did not happen.
    fn maintain_tk_owed_reboots(&mut self) {
        if let Some(sha) = self.tk_back_owed.clone() {
            let short = tk_boot::short(&sha).to_owned();
            match self.reboot_blocked(Kind::Back) {
                Some(why) => self.note_tk_hold(&format!(
                    "tk boot verdict: the reboot back onto modem firmware {short} waits: {why}. Any boot from now on loads it"
                )),
                None => {
                    self.tk_back_owed = None;
                    self.tk_hold_noted = None;
                    self.note(&format!("tk boot verdict: rebooting back onto modem firmware {short}"));
                    self.keeper_reboot(Kind::Back);
                }
            }
        } else if self.tk_away_owed {
            match self.reboot_held() {
                Some(why) => self.note_tk_hold(&format!(
                    "tk boot confirm: the recorded reboot onto stock modem firmware waits: {why}"
                )),
                None => {
                    self.tk_away_owed = false;
                    self.tk_hold_noted = None;
                    self.note("tk boot confirm: rebooting onto stock modem firmware, as recorded");
                    self.request_reboot();
                }
            }
        }
    }

    /// A line about a reboot that waits, once per reason.
    fn note_tk_hold(&mut self, line: &str) {
        if self.tk_hold_noted.as_deref() != Some(line) {
            self.note(line);
            self.tk_hold_noted = Some(line.to_owned());
        }
    }

    fn tk_round(&mut self, heard: Option<bool>) {
        if heard == Some(true) {
            self.heard_through_core();
        }
        let Some(mut confirm) = self.tk_confirm.take() else {
            return;
        };
        // The radio guard cycles the radio on purpose (a picker hold, an
        // enforcement re-attach): no clock runs meanwhile, as for the deaf
        // watchdog.
        if crate::radio::transition_in_progress(self.now) {
            confirm.pause(self.now);
            self.tk_confirm = Some(confirm);
            return;
        }
        let cell = self.cell_seen();
        let action = confirm.observe(self.now, mgmt_address_up(), heard, cell);
        match (action, confirm.judging()) {
            (TkAction::Hold, _) => self.tk_confirm = Some(confirm),
            (TkAction::Confirmed, false) => self.tk_confirmed(&confirm.sha),
            (TkAction::Rollback(why), false) => {
                // Still watching while the reboot must wait: an answer
                // meanwhile confirms the image instead.
                let sha = confirm.sha.clone();
                if !self.tk_rollback(&sha, why) {
                    self.tk_confirm = Some(confirm);
                }
            }
            (TkAction::Confirmed, true) => self.tk_judged(&confirm.sha, true),
            (TkAction::Rollback(_), true) => self.tk_judged(&confirm.sha, false),
        }
    }

    /// The modem sees a cell (`tk_boot::cell_seen`), from the vendor's cache.
    fn cell_seen(&mut self) -> bool {
        let media = self.nvram_get_cached("sqns_connection_mediaState");
        let rsrp = self
            .read_nvram_cache()
            .and_then(|cache| nvram::field(cache, "sqns_radio_RSRP"))
            .map(str::to_owned)
            .unwrap_or_default();
        tk_boot::cell_seen(&media, &rsrp)
    }

    /// Boots of the default image that ended before their confirm decided
    /// anything left the strikes at the limit and no rollback: record them as
    /// one rollback for this stock boot to judge (`Verdict::stopped`). The
    /// verdict goes first, so an interrupted write leaves a rollback to judge,
    /// never a quarantine nothing judges.
    fn tk_record_stopped(&mut self, dir: &Path, verdict: &Verdict) -> Option<Verdict> {
        let sha = tk_default::default_sha(&read_file(dir.join("config")))?;
        // A strikes file that cannot be read (a flash error, a hand edit)
        // counts as the limit: judged and repaired here, never stock for good.
        let path = dir.join("strikes");
        let at_limit = match tk_boot::parse_strikes(&read_file(&path)) {
            Some(n) => n >= tk_boot::STRIKE_LIMIT,
            None => fs::symlink_metadata(&path).is_ok(),
        };
        let path = dir.join("quarantine");
        let quarantine = read_file(&path);
        let quarantined = tk_boot::parse_quarantine(&quarantine).contains(&sha);
        let next = verdict.stopped(&sha, &self.tk_firmware, at_limit, quarantined)?;
        if !write_atomic(&dir.join(VERDICT), next.render().as_bytes()) {
            return None;
        }
        let _ = write_atomic(&path, tk_boot::add_quarantine(&quarantine, &sha).as_bytes());
        self.note(&format!(
            "tk boot verdict: {} boots of modem firmware {} ended before their boot confirm decided (a power cut, a crash or a reboot); this stock boot judges them as one rollback",
            tk_boot::STRIKE_LIMIT,
            tk_boot::short(&sha)
        ));
        Some(next)
    }

    /// A stock boot's verdict on the default image's last rollback (see
    /// `titan_pd_model::tk_verdict`). `answered`: stock firmware got an answer
    /// through the core within the confirm window. Either way but a stuck
    /// quarantine, the image comes out of quarantine first and the keeper
    /// then reboots back onto it, so any boot from then on loads it.
    fn tk_judged(&mut self, sha: &str, answered: bool) {
        let Some(dir) = tk_dir() else {
            return;
        };
        let short = tk_boot::short(sha).to_owned();
        let verdict = Verdict::parse(&read_file(dir.join(VERDICT)));
        if !verdict.pending || verdict.gzip != sha {
            // Retried or replaced meanwhile.
            return;
        }
        let (next, judgement) = verdict.judge(answered);
        if judgement.back_to_image() {
            // Out of quarantine first: an interrupted write leaves the rollback
            // pending for the next stock boot, never a good image stuck.
            let (quarantine, strikes) = (dir.join("quarantine"), dir.join("strikes"));
            let _ = write_atomic(&quarantine, tk_boot::remove_quarantine(&read_file(&quarantine), sha).as_bytes());
            let _ = write_atomic(&strikes, tk_boot::format_strikes(0, &self.tk_firmware).as_bytes());
            let blocked = tk_boot::refused(
                tk_boot::parse_strikes(&read_file(&strikes)),
                &tk_boot::parse_quarantine(&read_file(&quarantine)),
                sha,
            );
            if blocked {
                self.note(&format!(
                    "tk boot verdict: modem firmware {short} could not be taken out of quarantine; the next stock boot judges it again"
                ));
                return;
            }
        }
        // The way back only on a record that reads back: an unwritten one
        // would make the next stock boot judge the same rollback again.
        let recorded = write_atomic(&dir.join(VERDICT), next.render().as_bytes())
            && Verdict::parse(&read_file(dir.join(VERDICT))) == next;
        self.note(&match judgement {
            Judgement::Network => format!(
                "tk boot verdict: stock modem firmware got no answer through the core either, so the rollback of modem firmware {short} was the network's ({} so far); it is out of quarantine, and the unit goes back onto it, where it waits for the network",
                next.network
            ),
            Judgement::Genuine { count, sticks: false } => format!(
                "tk boot verdict: stock modem firmware answered where modem firmware {short} did not: failure {count} of {GENUINE_LIMIT}; it is out of quarantine and the network is up, so the unit tries it again at once"
            ),
            Judgement::Genuine { count, sticks: true } => format!(
                "tk boot verdict: stock modem firmware answered where modem firmware {short} did not: failure {count} of {GENUINE_LIMIT} in a row; it stays quarantined until Retry under Network -> Latency, or a new firmware"
            ),
            Judgement::Crash { count, sticks: false } => format!(
                "tk boot verdict: stock modem firmware answered after modem firmware {short} crashed: crash {count} of {GENUINE_LIMIT}; it is out of quarantine, so the unit goes straight back onto it"
            ),
            Judgement::Crash { count, sticks: true } => format!(
                "tk boot verdict: stock modem firmware answered after modem firmware {short} crashed: crash {count} of {GENUINE_LIMIT} in a row; it stays quarantined until Retry under Network -> Latency, or a new firmware"
            ),
        });
        if judgement.back_to_image() {
            if recorded {
                let _ = fs::write(tk_result_path(), format!("back={sha}\n"));
                self.tk_back_owed = Some(sha.to_owned());
            } else {
                self.note(&format!(
                    "tk boot verdict: the record could not be written, so no reboot now; the next boot loads modem firmware {short}"
                ));
            }
        }
    }

    /// The modem driver loaded firmware again (`modem_restart_seen`). On a
    /// boot that loaded the default image, stock firmware from NAND runs now:
    /// the image crashed. Never confirm it after that; record the crash and
    /// judge it like a rollback, by watching stock firmware on this boot
    /// (`Verdict::crashed`). A second load while judging is stock firmware
    /// crashing too: not the image's fault, so the judgement goes to the
    /// network and the unit back onto the image. An operator's image keeps
    /// its old rule (stock until the next boot).
    fn tk_modem_reloaded(&mut self) {
        let Some(sha) = self.tk_status.staged.clone() else {
            return;
        };
        let short = tk_boot::short(&sha).to_owned();
        if self.tk_crashed {
            if self.tk_confirm.as_ref().is_some_and(|c| c.judging()) {
                self.note(&format!(
                    "tk boot verdict: stock modem firmware restarted as well, so the crash of modem firmware {short} was not the image's"
                ));
                self.tk_confirm = None;
                self.tk_probe = None;
                self.tk_judged(&sha, false);
            }
            return;
        }
        let Some(dir) = tk_dir() else {
            return;
        };
        if tk_default::default_sha(&read_file(dir.join("config"))).as_deref() != Some(sha.as_str()) {
            return;
        }
        self.tk_crashed = true;
        self.tk_confirm = None;
        self.tk_probe = None;
        let _ = fs::write(tk_result_path(), format!("crashed={sha}\n"));
        // The record first, as for a rollback; the quarantine keeps a boot
        // before the judgement on stock firmware.
        let next = Verdict::parse(&read_file(dir.join(VERDICT))).crashed(&sha, &self.tk_firmware);
        let written = write_atomic(&dir.join(VERDICT), next.render().as_bytes())
            && Verdict::parse(&read_file(dir.join(VERDICT))) == next;
        if !written {
            self.note(&format!(
                "tk boot: modem firmware {short} crashed and stock firmware runs now, but the crash could not be recorded; the next boot loads the image again"
            ));
            return;
        }
        let quarantine = dir.join("quarantine");
        let _ = write_atomic(&quarantine, tk_boot::add_quarantine(&read_file(&quarantine), &sha).as_bytes());
        let _ = write_atomic(
            &dir.join("strikes"),
            tk_boot::format_strikes(tk_boot::STRIKE_LIMIT, &self.tk_firmware).as_bytes(),
        );
        self.note(&format!(
            "tk boot: modem firmware {short} crashed and the modem reloaded stock firmware; this boot judges the crash by watching stock firmware for {} s",
            self.tk_timing.confirm
        ));
        self.tk_confirm = Some(tk_boot::Confirm::watch(&sha, Some(self.now), self.now, self.tk_timing));
    }

    /// The default image ran a day on this boot after its confirm, without a
    /// modem crash: its crash count is history (`Verdict::healthy`).
    fn maintain_tk_healthy(&mut self) {
        let Some(since) = self.tk_confirmed_at else {
            return;
        };
        if self.tk_crashed || self.now.saturating_sub(since) < tk_boot::CRASH_CLEAR_SECS {
            return;
        }
        self.tk_confirmed_at = None;
        let (Some(sha), Some(dir)) = (self.tk_status.staged.clone(), tk_dir()) else {
            return;
        };
        let verdict = Verdict::parse(&read_file(dir.join(VERDICT)));
        let next = verdict.healthy(&sha);
        if next != verdict && write_atomic(&dir.join(VERDICT), next.render().as_bytes()) {
            self.note(&format!(
                "tk boot: modem firmware {} ran a day without a modem crash; its crash count is cleared",
                tk_boot::short(&sha)
            ));
        }
    }

    fn tk_confirmed(&mut self, sha: &str) {
        self.tk_confirmed_at = Some(self.now);
        self.tk_confirmed_record(sha);
        // Only now, and only for the image the hook staged, may flags be written.
        if let Some(armed) = tk_flags::armed_sha(&self.tk_status, &format!("confirmed={sha}\n")) {
            self.arm_tk_flags(&armed);
        }
    }

    fn tk_confirmed_record(&mut self, sha: &str) {
        let _ = fs::write(tk_result_path(), format!("confirmed={sha}\n"));
        let short = tk_boot::short(sha);
        let Some(dir) = tk_dir() else {
            self.note(&format!(
                "tk boot confirmed: modem firmware {short} answered through the core, but the persistent volume is not mounted; its strike stays counted"
            ));
            return;
        };
        let cleared = write_atomic(&dir.join("strikes"), tk_boot::format_strikes(0, &self.tk_firmware).as_bytes());
        let _ = write_atomic(&dir.join("confirmed"), format!("sha256={sha}\n").as_bytes());
        // A confirmed boot ends any wait and clears the image's failure count
        // (`Verdict::confirmed`); the file is rewritten only when that changes.
        let verdict = Verdict::parse(&read_file(dir.join(VERDICT)));
        let next = verdict.confirmed(sha);
        if next != verdict {
            let _ = write_atomic(&dir.join(VERDICT), next.render().as_bytes());
        }
        if cleared {
            self.note(&format!(
                "tk boot confirmed: modem firmware {short} answered through the core; strikes cleared"
            ));
        } else {
            self.note(&format!(
                "tk boot confirmed: modem firmware {short} answered through the core, but the strike count could not be cleared"
            ));
        }
    }

    /// Compare the image with stock firmware: quarantine it and reboot onto
    /// stock firmware, but only when the reboot gate lets the reboot go now
    /// and a read-back shows the boot hook will refuse the image (a reboot
    /// without that record could load the same image again). Returns false
    /// while the reboot must wait: nothing is recorded, and the watch goes on.
    fn tk_rollback(&mut self, sha: &str, why: Why) -> bool {
        let short = tk_boot::short(sha).to_owned();
        let reason = match why {
            Why::Blind => format!(
                "a cell in view for {} s without a management answer through the core from modem firmware {short}",
                self.tk_timing.confirm
            ),
            Why::Search => format!(
                "no cell in view for {} s in a row with modem firmware {short}",
                self.tk_timing.search
            ),
        };
        let Some(dir) = tk_dir() else {
            self.note(&format!(
                "tk boot confirm: {reason}, but the persistent volume is not mounted; not rebooting"
            ));
            return true;
        };
        if let Some(hold) = self.reboot_blocked(Kind::Away) {
            self.note_tk_hold(&format!(
                "tk boot confirm: {reason}; the comparison with stock modem firmware waits: {hold}. Nothing is recorded, and an answer meanwhile still confirms the image"
            ));
            return false;
        }
        // The default image's comparison is recorded first: without its
        // verdict the quarantine would be a leftover the hook clears, and a
        // bad image could come back at every boot. If it cannot be written,
        // nothing is, and the watch goes on.
        let default = tk_default::default_sha(&read_file(dir.join("config"))).as_deref() == Some(sha);
        if default {
            let next = Verdict::parse(&read_file(dir.join(VERDICT))).rolled_back(sha, &self.tk_firmware);
            let written = write_atomic(&dir.join(VERDICT), next.render().as_bytes())
                && Verdict::parse(&read_file(dir.join(VERDICT))) == next;
            if !written {
                self.note_tk_hold(&format!(
                    "tk boot confirm: {reason}, but the rollback record could not be written; not rebooting, and the watch goes on"
                ));
                return false;
            }
        }
        let _ = fs::write(tk_result_path(), format!("rollback={sha}\n"));
        let quarantine = dir.join("quarantine");
        let strikes = dir.join("strikes");
        let listed = tk_boot::add_quarantine(&read_file(&quarantine), sha);
        let _ = write_atomic(&quarantine, listed.as_bytes());
        let _ = write_atomic(
            &strikes,
            tk_boot::format_strikes(tk_boot::STRIKE_LIMIT, &self.tk_firmware).as_bytes(),
        );
        let recorded = tk_boot::refused(
            tk_boot::parse_strikes(&read_file(&strikes)),
            &tk_boot::parse_quarantine(&read_file(&quarantine)),
            sha,
        );
        if !recorded {
            self.note(&format!(
                "tk boot confirm: {reason}, and the quarantine could not be recorded; not rebooting"
            ));
            return true;
        }
        // The default image's quarantine is provisional: the next stock boot
        // judges whether the image or the network failed. An operator's
        // image stays quarantined as before.
        let quarantined = if default {
            "quarantined it for now (the next stock boot tells whether the image or the network failed)"
        } else {
            "quarantined it"
        };
        self.tk_hold_noted = None;
        self.note(&format!(
            "tk boot confirm: {reason}; {quarantined}, rebooting onto stock modem firmware"
        ));
        self.keeper_reboot(Kind::Away);
        true
    }

    /// Start the flag writes for a confirmed staged boot. The words and values
    /// come from `wm=` lines in `tk/config`.
    fn arm_tk_flags(&mut self, sha: &str) {
        if self.tk_flags.is_some() {
            return;
        }
        let short = tk_boot::short(sha).to_owned();
        let Some(dir) = tk_dir() else {
            self.note(&format!(
                "tk flags: modem firmware {short} confirmed, but the persistent volume is not mounted; no flag writes"
            ));
            let _ = fs::write(
                tk_flags_status_path(),
                tk_flags::idle_status("the persistent volume is not mounted", self.now),
            );
            return;
        };
        let text = read_file(dir.join("config"));
        let parsed = tk_flags::parse_writes(&text);
        self.note_tk_flags_refused(&parsed);
        self.tk_flags_config_hands_off = parsed.hands_off;
        let wanted = tk_flags::wanted(self.words_config(&text), &[]);
        let mut control = tk_flags::Control::new_with_ack(wanted.clone(), parsed.hold_ack, self.now);
        let hands_off = self.tk_flags_hands_off_reason();
        if let Some(reason) = hands_off.as_deref() {
            let (_, line) = control.set_hands_off(Some(reason), self.now);
            if let Some(line) = line {
                self.note(&line);
            }
            let _ = fs::write(tk_flags_status_path(), control.status(self.now));
        } else if wanted.is_empty() {
            let _ = fs::write(tk_flags_status_path(), tk_flags::idle_status(self.no_words_reason(), self.now));
        } else {
            self.note(&format!(
                "tk flags: modem firmware {short} confirmed; writing {} once the patch magic shows",
                tk_flags::list(&wanted)
            ));
            let _ = fs::write(tk_flags_status_path(), control.status(self.now));
        }
        self.tk_flags = Some(control);
        self.tk_flags_config_at.mark(self.now);
    }

    /// The config text the words come from: none while `modem=off` is in the
    /// latency switches, which rolls every managed word back.
    fn words_config<'a>(&self, text: &'a str) -> &'a str {
        if self.switches.now.modem { text } else { "" }
    }

    fn no_words_reason(&self) -> &'static str {
        if self.switches.now.modem {
            "no wm= lines in tk/config"
        } else {
            "modem=off in latency/config"
        }
    }

    fn tk_flags_hands_off_reason(&self) -> Option<String> {
        if self.tk_flags_config_hands_off {
            return Some("manage=off in tk/config".into());
        }
        let marker = tk_flags_hands_off_path();
        if Path::new(&marker).exists() {
            return Some(marker);
        }
        None
    }

    fn note_tk_flags_refused(&mut self, parsed: &tk_flags::Parsed) {
        if parsed.refused == self.tk_flags_refused {
            return;
        }
        for (line, reason) in &parsed.refused_reasons {
            self.note(&format!(
                "tk flags: ignored {line:?} in tk/config: {reason}"
            ));
        }
        self.tk_flags_refused = parsed.refused.clone();
    }

    /// Run the DM sessions for the flags, one at a time, on their own thread.
    /// Nothing runs unless `arm_tk_flags` made a `Control`.
    pub(super) fn maintain_tk_flags(&mut self) {
        let mut lines: Vec<String> = Vec::new();
        let mut changed = false;
        if self
            .tk_flags_job
            .as_ref()
            .is_some_and(|(job, _)| job.is_finished())
        {
            if let Some((job, plan)) = self.tk_flags_job.take() {
                let (outcome, sent) = job.join().unwrap_or((tk_flags::Outcome::NoReply, false));
                if let Some(control) = self.tk_flags.as_mut() {
                    lines.extend(control.finished(self.now, &plan, &outcome, sent));
                    changed = true;
                }
            }
        }
        let restarted = std::mem::take(&mut self.modem_restart_seen);
        if self.tk_flags.is_none() {
            return;
        }
        // The operator may change tk/config: read it again now and then. A
        // missing file means off; a read error changes nothing.
        let mut config_text = None;
        if self.tk_flags_config_at.ready(self.now, TK_FLAGS_CONFIG_EVERY) {
            if let Some(dir) = tk_dir() {
                config_text = match fs::read_to_string(dir.join("config")) {
                    Ok(text) => Some(text),
                    Err(err) if err.kind() == ErrorKind::NotFound => Some(String::new()),
                    Err(_) => None,
                };
            }
        }
        let parsed_config = config_text.as_deref().map(tk_flags::parse_writes);
        if let Some(parsed) = &parsed_config {
            self.note_tk_flags_refused(parsed);
            self.tk_flags_config_hands_off = parsed.hands_off;
        }
        let hands_off = self.tk_flags_hands_off_reason();
        let busy = self.tk_flags_job.is_some() || self.reboot_asked_at.is_some();
        let mut spawned = None;
        if let Some(control) = self.tk_flags.as_mut() {
            let (ho_changed, ho_line) = control.set_hands_off(hands_off.as_deref(), self.now);
            if ho_changed {
                changed = true;
            }
            lines.extend(ho_line);
            if restarted {
                lines.push(control.modem_restarted(self.now));
                changed = true;
            }
            if let (Some(text), Some(parsed)) = (&config_text, &parsed_config) {
                let words = if self.switches.now.modem { text.as_str() } else { "" };
                let wanted = tk_flags::wanted(words, control.wanted());
                if let Some(line) = control.set_wanted_with_ack(wanted, parsed.hold_ack, self.now) {
                    lines.push(line);
                    changed = true;
                }
            }
            if !busy {
                if let Some(plan) = control.due(self.now) {
                    match tk_flags_io::spawn(plan.clone()) {
                        Some(job) => spawned = Some((job, plan)),
                        None => {
                            let outcome = tk_flags::Outcome::NoReply;
                            lines.extend(control.finished(self.now, &plan, &outcome, false));
                            changed = true;
                        }
                    }
                }
            }
        }
        if spawned.is_some() {
            self.tk_flags_job = spawned;
        }
        let idle = self.no_words_reason();
        let status = if changed {
            self.tk_flags.as_ref().map(|control| {
                if control.state() == tk_flags::State::HandsOff {
                    control.status(self.now)
                } else if control.wanted().is_empty() {
                    tk_flags::idle_status(idle, self.now)
                } else {
                    control.status(self.now)
                }
            })
        } else {
            None
        };
        for line in lines {
            self.note(&line);
        }
        if let Some(status) = status {
            let _ = fs::write(tk_flags_status_path(), status);
        }
    }

    /// The tk config's own targets, else the deaf watchdog's.
    fn tk_targets(&mut self) -> Vec<std::net::IpAddr> {
        let config = tk_dir()
            .map(|dir| read_file(dir.join("config")))
            .unwrap_or_default();
        let own = tk_boot::parse_targets(&config);
        if !own.is_empty() {
            return own;
        }
        let settings = deaf::parse_settings(&read_file(state_dir().join("watchdog.conf")));
        let bearer_dns = if settings.targets.is_empty() {
            self.nvram_get_cached("wan_get_dns")
        } else {
            String::new()
        };
        deaf::targets(&settings, &bearer_dns)
    }
}

fn tk_status_path() -> String {
    env_or("TITAN_TK_STATUS", "/var/run/witcher-tk.status")
}

/// Written once a keeper process confirmed or rolled back this boot.
fn tk_result_path() -> String {
    env_or("TITAN_TK_RESULT", "/var/run/witcher-tk.result")
}

/// The flag writes' status, in RAM.
fn tk_flags_status_path() -> String {
    env_or("TITAN_TK_FLAGS", "/var/run/witcher-tk.flags")
}

/// Optional bench/maintenance marker file that pauses all modem console
/// sessions until removed.
fn tk_flags_hands_off_path() -> String {
    env_or("TITAN_TK_HANDS_OFF", "/var/run/witcher-tk.hands-off")
}

/// Write through a synced temporary file, then sync the directory, so a power
/// cut leaves the old record or the new one.
fn write_atomic(path: &Path, bytes: &[u8]) -> bool {
    write_durably(path, &path.with_extension("tmp"), bytes).is_ok()
}
