//! The radio profile guard's last resort (v1.0.17). When its stock restore
//! has failed for `radio_guard::RESTORE_RESTART_SECS`, the guard leaves
//! `radio::REBOOT_REQUEST` in the keeper's RAM directory and keeps trying the
//! restore. The keeper restarts the unit through its reboot gate: never in
//! the SAS CPAS window, never with the clock unset, and within the daily cap.
//! A restore that works meanwhile takes the request back. Before v1.0.17 the
//! guard rebooted by itself at once, at any hour, after wiping the operator's
//! saved profile.

use crate::paths::runtime_dir;

use super::Keeper;
use super::reboot::Kind;

impl Keeper {
    pub(super) fn maintain_radio_reboot(&mut self) {
        if self.reboot_asked_at.is_some() || !runtime_dir().join(crate::radio::REBOOT_REQUEST).exists() {
            self.radio_reboot_held = None;
            return;
        }
        if let Some(why) = self.reboot_blocked(Kind::Radio) {
            if self.radio_reboot_held.as_deref() != Some(why.as_str()) {
                self.note(&format!(
                    "radio profile: stock settings will not go back; the restart waits: {why}"
                ));
                self.radio_reboot_held = Some(why);
            }
            return;
        }
        self.radio_reboot_held = None;
        self.note("radio profile: stock settings will not go back; restarting the unit");
        self.keeper_reboot(Kind::Radio);
    }
}
