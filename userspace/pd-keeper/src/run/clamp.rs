//! The staged clamp module (download and upload). See `titan_pd_model::qctrl`.

use titan_pd_model::pace::Pace;
use titan_pd_model::qctrl::{self, Loaded as QctrlLoaded};

use crate::{qctrl_io, staged};
use crate::files::read_file;
use crate::netdev::carrier_up;
use crate::status_file::StatusFile;

use super::{CUSTOMER, Keeper};
use super::mgmt_v6::mgmt_address_up;

/// The download clamp's progress this boot.
#[derive(Default)]
pub(super) struct QctrlWatch {
    checked_at: Pace,
    /// The customer port and the management bearer were both up since then.
    up_since: Option<u64>,
    /// The last status, so the file and the log change only on news.
    status: StatusFile,
    /// True while configured with a non-zero mode and still waiting to load.
    pub(super) waiting: bool,
    /// A load failed for this config. It is not retried until the config changes.
    failed_for: Option<qctrl::Config>,
    refused_logged: Vec<String>,
}

impl Keeper {
    /// Load the staged download clamp once the customer port and LTE are up,
    /// and keep its mode as `qctrl/config` says. Runs in every mode.
    pub(super) fn maintain_qctrl(&mut self) {
        if !self.qctrl.checked_at.ready(self.now, qctrl::CHECK_EVERY) {
            return;
        }
        let Some(dir) = qctrl_io::MODULE.staged_dir() else {
            self.qctrl_status("off", "the persistent volume is not mounted", &qctrl::Config::default());
            return;
        };
        let config = qctrl::parse_config(&read_file(dir.join("config")));
        if config.refused != self.qctrl.refused_logged {
            for line in &config.refused {
                self.note(&format!(
                    "download clamp: ignored {line:?} in qctrl/config (allowed: mode=0|2|3|6 plus 16 for the upload clamp, trough_ms=0..40, target_ms=4..80, ack_adapt=0|1, ctrl_v3=0|1, ack_ms=1..10, ack_segs=2..32, ack_min_kbps=0..100000, ul_target_ms=0..40)"
                ));
            }
            self.qctrl.refused_logged = config.refused.clone();
        }
        let up = carrier_up(CUSTOMER) && (config.mode == 0 || mgmt_address_up());
        if !up {
            self.qctrl.up_since = None;
        } else if self.qctrl.up_since.is_none() {
            self.qctrl.up_since = Some(self.now);
        }
        let proc_text = read_file(&qctrl_io::proc_path());
        let mut proc_fresh = true;
        match qctrl::loaded(&read_file(staged::modules_path()), &proc_text) {
            QctrlLoaded::Other(name) => {
                let (state, detail) = if config.mode == 0 {
                    ("off", format!("mode 0; another clamp module is loaded ({name})"))
                } else {
                    ("failed", format!("another clamp module is loaded ({name}); not loading {}", qctrl::MODULE))
                };
                self.qctrl_status(state, &detail, &config);
                return;
            }
            QctrlLoaded::None => {
                if config.mode == 0 {
                    self.qctrl_status("off", "mode 0 or no qctrl/config", &config);
                    return;
                }
                if !qctrl::settled(self.qctrl.up_since, self.now) {
                    self.qctrl_status(
                        "waiting",
                        &format!("for the customer port and LTE to stay up {} s", qctrl::SETTLE_SECS),
                        &config,
                    );
                    return;
                }
                if self.qctrl.failed_for.as_ref() == Some(&config) {
                    return;
                }
                if let Err(err) = qctrl_io::MODULE.load(&dir) {
                    self.qctrl.failed_for = Some(config.clone());
                    self.qctrl_status("failed", &format!("not loaded: {err}"), &config);
                    return;
                }
                self.note(&format!("download clamp: loaded {} from the staged copy", qctrl::VERSION_LINE));
                proc_fresh = false;
            }
            QctrlLoaded::Ours => {}
        }
        let mut proc = if proc_fresh {
            qctrl::parse_proc(&proc_text)
        } else {
            qctrl::parse_proc(&read_file(&qctrl_io::proc_path()))
        };
        if !proc.ours {
            self.qctrl.failed_for = Some(config.clone());
            self.qctrl_status(
                "failed",
                &format!("/proc/titan_qctrl does not show {}", qctrl::VERSION_LINE),
                &config,
            );
            return;
        }
        if !qctrl::matches(&config, &proc) {
            if let Err(err) = qctrl_io::write_proc(&qctrl::proc_writes(&config)) {
                self.qctrl_status("failed", &err, &config);
                return;
            }
            proc = qctrl::parse_proc(&read_file(&qctrl_io::proc_path()));
        }
        if !qctrl::matches(&config, &proc) {
            let shown = proc.mode.map_or_else(|| "nothing".to_owned(), |m| m.to_string());
            self.qctrl_status(
                "failed",
                &format!("mode {} did not read back (shows {shown})", config.mode),
                &config,
            );
            return;
        }
        let state = if config.mode == 0 { "off" } else { "applied" };
        let detail = format!(
            "mode {} read back from /proc/titan_qctrl{}{}{}{}{}{}{}{}",
            config.mode,
            config.trough_ms.map_or_else(String::new, |ms| format!(", trough_ms {ms}")),
            config.target_ms.map_or_else(String::new, |ms| format!(", target_ms {ms}")),
            config.ack_adapt.map_or_else(String::new, |v| format!(", ack_adapt {v}")),
            config.ctrl_v3.map_or_else(String::new, |v| format!(", ctrl_v3 {v}")),
            config.ack_ms.map_or_else(String::new, |ms| format!(", ack_ms {ms}")),
            config.ack_segs.map_or_else(String::new, |s| format!(", ack_segs {s}")),
            config.ack_min_kbps.map_or_else(String::new, |k| format!(", ack_min_kbps {k}")),
            config.ul_target_ms.map_or_else(String::new, |ms| format!(", ul_target_ms {ms}"))
        );
        self.qctrl_status(state, &detail, &config);
    }

    /// Write the clamp status file and log the change. A unit that never
    /// staged a clamp logs nothing.
    fn qctrl_status(&mut self, state: &str, detail: &str, config: &qctrl::Config) {
        self.qctrl.waiting = state == "waiting";
        let quiet = state == "off" && self.qctrl.status.is_blank();
        let now = self.now;
        let key = format!("{state}: {detail}");
        let render = |_: &str| qctrl::status(state, detail, config, now);
        if !self.qctrl.status.update(qctrl_io::status_path(), key, false, render) {
            return;
        }
        if !quiet {
            self.note(&format!("download clamp {state}: {detail}"));
        }
    }
}
