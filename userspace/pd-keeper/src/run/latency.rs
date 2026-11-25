//! The latency switches (`titan_pd_model::switches`): `/mnt/titan-api/
//! latency/config`, written by the web service's Latency screen or by hand.
//! Read every few seconds; a change is logged once and the modem words, the
//! download clamp and the fast path act on it at their next tick.

use std::fs;
use std::io::ErrorKind;

use titan_pd_model::pace::Pace;
use titan_pd_model::switches::{self, Switches};

use crate::paths::volume_dir;

use super::Keeper;

/// Seconds between reads. A toggle acts within this and one tick.
const READ_EVERY: u64 = 5;

#[derive(Default)]
pub(super) struct SwitchWatch {
    read_at: Pace,
    /// The switches in force: all on until the file says otherwise.
    pub(super) now: Switches,
    /// Unreadable lines already logged.
    refused: Vec<String>,
}

/// The file's text: `Some("")` when it or the volume is missing (every
/// feature on), `None` when it exists but cannot be read (keep what is in
/// force rather than flip a feature on).
fn read() -> Option<String> {
    let Some(dir) = volume_dir("TITAN_LATENCY_DIR", switches::DIR) else {
        return Some(String::new());
    };
    match fs::read_to_string(dir.join("config")) {
        Ok(text) => Some(text),
        Err(err) if err.kind() == ErrorKind::NotFound => Some(String::new()),
        Err(_) => None,
    }
}

impl Keeper {
    pub(super) fn maintain_switches(&mut self) {
        if !self.switches.read_at.ready(self.now, READ_EVERY) {
            return;
        }
        let Some(text) = read() else {
            return;
        };
        let next = switches::parse(&text);
        if next.refused != self.switches.refused {
            for line in &next.refused {
                self.note(&format!(
                    "latency switches: {line:?} in latency/config is not modem=, clamp= or fastpath= with on or off; a feature it names is off"
                ));
            }
            self.switches.refused = next.refused.clone();
        }
        // Starting with everything on, a unit that never turned a feature
        // off logs nothing here.
        if next.same_as(&self.switches.now) {
            return;
        }
        self.note(&format!("latency switches: {} (latency/config)", next.describe()));
        self.switches.now = next;
        // Act now, not at each part's next scheduled check.
        self.qctrl.recheck();
        self.fastpath.recheck();
        self.tk_flags_config_at.reset();
    }
}
