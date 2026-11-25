//! A staged modem firmware image's boot confirm, or the way back to stock
//! firmware (see `titan_pd_model::tk_boot`), and after the confirm the
//! operator's modem feature flags (see `titan_pd_model::tk_flags`).

use std::fs;
use std::io::ErrorKind;
use std::path::PathBuf;

use titan_pd_model::deaf;
use titan_pd_model::tk_boot::{self, Action as TkAction};
use titan_pd_model::tk_flags;

use crate::tk_flags_io;
use crate::files::{read_file, write_durably};
use crate::paths::{env_or, state_dir, volume_dir};

use super::Keeper;
use super::mgmt_v6::mgmt_address_up;
use super::watchdog::PingRound;

/// Seconds between reads of `tk/config` for flag changes.
const TK_FLAGS_CONFIG_EVERY: u64 = 15;

impl Keeper {
    /// Runs in NAT and in passthrough. See `titan_pd_model::tk_boot`. Nothing
    /// arms unless the boot hook staged a modem firmware image this boot.
    pub(super) fn maintain_tk_confirm(&mut self) {
        if !self.tk_checked {
            self.tk_checked = true;
            let status = tk_boot::parse_status(&read_file(&tk_status_path()));
            if let Some(line) = tk_boot::describe(&status) {
                self.note(&line);
            }
            let decided = fs::metadata(tk_result_path()).is_ok();
            self.tk_confirm = tk_boot::Confirm::arm(&status, self.now, decided);
            self.tk_status = status.clone();
            // A keeper that restarts after the confirm takes the flags over.
            match tk_flags::armed_sha(&status, &read_file(&tk_result_path())) {
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
            let left = self
                .tk_confirm
                .as_ref()
                .map(|confirm| confirm.deadline.saturating_sub(self.now));
            if let Some(left) = left {
                self.note(&format!(
                    "tk boot confirm armed: without a management answer through the core in {left} s the keeper quarantines this image and reboots onto stock modem firmware"
                ));
            }
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
        if self
            .tk_last_round
            .is_some_and(|last| self.now.saturating_sub(last) < tk_boot::PROBE_EVERY)
        {
            return;
        }
        self.tk_last_round = Some(self.now);
        let targets = self.tk_targets();
        match PingRound::start(&targets, self.now) {
            Some(round) => self.tk_probe = Some(round),
            None => self.tk_round(None),
        }
    }

    fn tk_round(&mut self, heard: Option<bool>) {
        let Some(mut confirm) = self.tk_confirm.take() else {
            return;
        };
        match confirm.observe(self.now, mgmt_address_up(), heard) {
            TkAction::Hold => self.tk_confirm = Some(confirm),
            TkAction::Confirmed => self.tk_confirmed(&confirm.sha),
            TkAction::Rollback => self.tk_rollback(&confirm.sha),
        }
    }

    fn tk_confirmed(&mut self, sha: &str) {
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
        let cleared = write_atomic(&dir.join("strikes"), tk_boot::format_strikes(0).as_bytes());
        let _ = write_atomic(&dir.join("confirmed"), format!("sha256={sha}\n").as_bytes());
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

    /// Quarantine the image and reboot onto stock firmware, but only once a
    /// read-back shows the boot hook will refuse it: a reboot without that
    /// record could load the same image again.
    fn tk_rollback(&mut self, sha: &str) {
        let _ = fs::write(tk_result_path(), format!("rollback={sha}\n"));
        let short = tk_boot::short(sha);
        let secs = tk_boot::CONFIRM_SECS;
        let Some(dir) = tk_dir() else {
            self.note(&format!(
                "tk boot confirm: no management answer within {secs} s of loading modem firmware {short}, but the persistent volume is not mounted; not rebooting"
            ));
            return;
        };
        let quarantine = dir.join("quarantine");
        let strikes = dir.join("strikes");
        let listed = tk_boot::add_quarantine(&read_file(&quarantine), sha);
        let _ = write_atomic(&quarantine, listed.as_bytes());
        let _ = write_atomic(&strikes, tk_boot::format_strikes(tk_boot::STRIKE_LIMIT).as_bytes());
        let recorded = tk_boot::refused(
            tk_boot::parse_strikes(&read_file(&strikes)),
            &tk_boot::parse_quarantine(&read_file(&quarantine)),
            sha,
        );
        if !recorded {
            self.note(&format!(
                "tk boot confirm: no management answer within {secs} s of loading modem firmware {short}, and the quarantine could not be recorded; not rebooting"
            ));
            return;
        }
        self.note(&format!(
            "tk boot confirm: no management answer within {secs} s of loading modem firmware {short}; quarantined it, rebooting onto stock modem firmware"
        ));
        self.request_reboot();
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
        let wanted = tk_flags::wanted(&text, &[]);
        let mut control = tk_flags::Control::new_with_ack(wanted.clone(), parsed.hold_ack, self.now);
        let hands_off = self.tk_flags_hands_off_reason();
        if let Some(reason) = hands_off.as_deref() {
            let (_, line) = control.set_hands_off(Some(reason), self.now);
            if let Some(line) = line {
                self.note(&line);
            }
            let _ = fs::write(tk_flags_status_path(), control.status(self.now));
        } else if wanted.is_empty() {
            let _ = fs::write(
                tk_flags_status_path(),
                tk_flags::idle_status("no wm= lines in tk/config", self.now),
            );
        } else {
            self.note(&format!(
                "tk flags: modem firmware {short} confirmed; writing {} once the patch magic shows",
                tk_flags::list(&wanted)
            ));
            let _ = fs::write(tk_flags_status_path(), control.status(self.now));
        }
        self.tk_flags = Some(control);
        self.tk_flags_config_at = Some(self.now);
    }

    fn tk_flags_hands_off_reason(&self) -> Option<String> {
        if self.tk_flags_config_hands_off {
            return Some("manage=off in tk/config".into());
        }
        let marker = tk_flags_hands_off_path();
        if std::path::Path::new(&marker).exists() {
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
        if self
            .tk_flags_config_at
            .is_none_or(|at| self.now.saturating_sub(at) >= TK_FLAGS_CONFIG_EVERY)
        {
            self.tk_flags_config_at = Some(self.now);
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
                let wanted = tk_flags::wanted(text, control.wanted());
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
        let status = if changed {
            self.tk_flags.as_ref().map(|control| {
                if control.state() == tk_flags::State::HandsOff {
                    control.status(self.now)
                } else if control.wanted().is_empty() {
                    tk_flags::idle_status("no wm= lines in tk/config", self.now)
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

/// The boot hook's files on the persistent volume, only while it is mounted.
fn tk_dir() -> Option<PathBuf> {
    volume_dir("TITAN_TK_DIR", "tk")
}

/// Write through a synced temporary file, then sync the directory, so a power
/// cut leaves the old record or the new one.
fn write_atomic(path: &std::path::Path, bytes: &[u8]) -> bool {
    write_durably(path, &path.with_extension("tmp"), bytes).is_ok()
}
