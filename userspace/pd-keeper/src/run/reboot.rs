//! The gate every reboot the keeper starts goes through (v1.0.17): the boot
//! confirm's comparison with stock firmware, the verdict's way back onto the
//! image, and the deaf watchdog's.
//!
//! - None while the SAS CPAS window is open, and none with the clock unset on
//!   a boot that heard an answer through the core
//!   (`titan_pd_model::tk_boot::reboot_hold`).
//! - At most `reboots::CAP` in a day (`titan_pd_model::reboots`), with the
//!   last slot kept for a reboot back onto the image.

use std::fs;
use std::path::PathBuf;

use titan_pd_model::carrier_watch::QuietWindow;
use titan_pd_model::{reboots, tk_boot};

use crate::clock::{monotonic, unix_now};
use crate::files::{read_file, write_durably};
use crate::paths::{runtime_dir, state_dir};

use super::Keeper;

/// What a reboot does, for the gate and the log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    /// Onto stock modem firmware, to compare the image with it.
    Away,
    /// Back onto the image: after a network verdict, or to try it again
    /// after stock firmware answered.
    Back,
    /// The deaf watchdog's.
    Deaf,
}

impl Kind {
    fn slots(self) -> usize {
        match self {
            Kind::Back => reboots::SLOTS_BACK,
            Kind::Away | Kind::Deaf => reboots::SLOTS_AWAY,
        }
    }

    fn word(self) -> &'static str {
        match self {
            Kind::Away => "away",
            Kind::Back => "back",
            Kind::Deaf => "deaf",
        }
    }
}

impl Keeper {
    /// Something answered through the core this boot. Kept in RAM as well,
    /// so a keeper that restarts still knows; a reboot clears it.
    pub(super) fn heard_through_core(&mut self) {
        if !self.heard_this_boot {
            self.heard_this_boot = true;
            let _ = fs::write(heard_marker(), b"1\n");
        }
    }

    fn heard_since_boot(&self) -> bool {
        self.heard_this_boot || heard_marker().exists()
    }

    /// Why a reboot of `kind` must wait now, or `None` when it may go.
    pub(super) fn reboot_blocked(&mut self, kind: Kind) -> Option<String> {
        if let Some(why) = self.reboot_held() {
            return Some(why.to_owned());
        }
        let wall = unix_now();
        let entries = reboot_log(wall);
        if reboots::allows(&entries, wall, kind.slots()) {
            return None;
        }
        Some(format!(
            "{} keeper reboots in the last day reach its cap of {}",
            reboots::recent(&entries, wall),
            reboots::CAP
        ))
    }

    /// The CPAS window and clock part of the gate only: for a reboot already
    /// counted against the cap, which an earlier keeper process asked for.
    pub(super) fn reboot_held(&self) -> Option<&'static str> {
        tk_boot::reboot_hold(cpas_window(), unix_now(), self.heard_since_boot())
    }

    /// Count a reboot of `kind` and start it. The caller asked
    /// `reboot_blocked` first.
    pub(super) fn keeper_reboot(&mut self, kind: Kind) {
        let wall = unix_now();
        let entries = reboot_log(wall);
        let path = reboot_log_path();
        let _ = write_durably(
            &path,
            &path.with_extension("tmp"),
            reboots::record(&entries, wall, kind.word()).as_bytes(),
        );
        self.request_reboot();
    }
}

/// The SAS CPAS window every keeper reboot waits out (`TITAN_TK_QUIET_UTC` in
/// tests: `HH:MM-HH:MM`, or empty for none).
pub(super) fn cpas_window() -> Option<QuietWindow> {
    tk_boot::quiet_window(std::env::var("TITAN_TK_QUIET_UTC").ok().as_deref())
}

/// The reboot log as this boot can judge it (`reboots::settle`); it is
/// rewritten only when settling changed it.
fn reboot_log(wall: u64) -> Vec<reboots::Entry> {
    let path = reboot_log_path();
    let entries = reboots::parse(&read_file(&path));
    let settled = reboots::settle(&entries, wall, wall.saturating_sub(monotonic()));
    if settled != entries {
        let _ = write_durably(&path, &path.with_extension("tmp"), reboots::render(&settled).as_bytes());
    }
    settled
}

fn reboot_log_path() -> PathBuf {
    state_dir().join("keeper-reboots")
}

fn heard_marker() -> PathBuf {
    runtime_dir().join("heard-through-core")
}
