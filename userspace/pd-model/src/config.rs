//! Saved choice and the keeper's live report.
//!
//! A missing file is not Off. Off is an explicit choice that makes the customer
//! bearer IPv4-only. An upgrade that has never saved the setting must leave the
//! bearer family alone.

use crate::prefix::{Block, parse_pinned};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Where the keeper and the web service keep the setting.
///
/// An explicit `TITAN_PD_STATE` wins. Otherwise the persistent volume is used
/// only when it is actually mounted. Writing into `/mnt/titan-api` before that
/// mount would leave files on the vendor volume and the mount would then refuse
/// to cover them.
pub fn default_state_dir() -> PathBuf {
    if let Ok(path) = std::env::var("TITAN_PD_STATE") {
        return PathBuf::from(path);
    }
    if persistent_volume_mounted() {
        PathBuf::from("/mnt/titan-api/pd")
    } else {
        PathBuf::from("/tmp/titan-pd-state")
    }
}

pub fn persistent_volume_mounted() -> bool {
    fs::read_to_string("/proc/mounts")
        .unwrap_or_default()
        .lines()
        .any(|line| {
            let mut parts = line.split_whitespace();
            let _device = parts.next();
            let point = parts.next();
            let kind = parts.next();
            point == Some("/mnt/titan-api") && kind == Some("ubifs")
        })
}

/// A setting change that re-attaches LTE. The guard reverts it if management
/// does not return. If that guard dies with the unit, the keeper reverts it on
/// the next start once `not_before` has passed and no guard process is left.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pending {
    pub token: String,
    pub ip_proto: String,
    pub absent: bool,
    pub not_before: u64,
}

/// The web service writes `pending.json` with `not_before` 15 s ahead, then
/// starts the guard. A keeper that starts in that gap must not revert. A same-boot
/// wait longer than this can only come from a clock step, so it is not honoured.
pub const PENDING_ARM_SECS: u64 = 60;

/// What a starting keeper does with a `pending.json` left behind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recovery {
    /// A guard owns it, or is about to.
    Wait,
    /// Management came back before the guard was lost. Keep the new setting,
    /// as the guard would have.
    Keep,
    /// Put the previous IP family back.
    Revert,
}

/// Decide without trusting the wall clock across a reboot. The Titan has no
/// battery clock: it boots at 2013-06-20 and NTP corrects it about a minute
/// later, after the keeper has started. `not_before` is wall time from the web
/// service, so after a reboot it always looks far in the future.
///
/// - No guard survives a reboot, so on the keeper's first start in a boot the
///   change is reverted (unless it was confirmed) whatever the clock says.
/// - On a later start in the same boot, `not_before` still covers the short gap
///   before the guard starts, but never more than `PENDING_ARM_SECS`.
pub fn recovery(
    guard_running: bool,
    confirmed: bool,
    first_start_this_boot: bool,
    wall_now: u64,
    not_before: u64,
) -> Recovery {
    if guard_running {
        return Recovery::Wait;
    }
    if confirmed {
        return Recovery::Keep;
    }
    if first_start_this_boot {
        return Recovery::Revert;
    }
    match not_before.checked_sub(wall_now) {
        Some(ahead) if ahead > 0 && ahead <= PENDING_ARM_SECS => Recovery::Wait,
        _ => Recovery::Revert,
    }
}

/// `marker` is what the keeper left in its RAM directory on an earlier start
/// (gone after a reboot), and `boot_id` is `/proc/sys/kernel/random/boot_id`.
/// A marker from another boot (a RAM directory that somehow survived) does not
/// count. An unreadable boot id falls back to the marker alone.
pub fn first_start(marker: Option<&str>, boot_id: &str) -> bool {
    match marker {
        None => true,
        Some(seen) => !boot_id.trim().is_empty() && seen.trim() != boot_id.trim(),
    }
}

/// `confirm-<token>` holds the token once management came back and held.
pub fn confirmed(token: &str, confirm_file: &str) -> bool {
    !token.is_empty() && confirm_file.trim() == token
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub enabled: bool,
    #[serde(default)]
    pub pinned: Option<String>,
    /// "entered" when an operator typed it, "learned" when the first attach supplied it.
    #[serde(default)]
    pub pin_source: String,
}

impl Config {
    pub fn pinned_block(&self) -> Result<Option<Block>, String> {
        self.pinned.as_deref().map(parse_pinned).transpose()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    pub bearer_prefix: String,
    pub delegated_prefix: String,
    pub router_mac: String,
    pub healthy: bool,
    pub detail: String,
    pub last_action: String,
    pub last_action_at: String,
    pub serving: bool,
    pub mismatch: String,
}

impl Default for Report {
    fn default() -> Self {
        Self {
            bearer_prefix: String::new(),
            delegated_prefix: String::new(),
            router_mac: String::new(),
            healthy: false,
            detail: "Keeper has not reported yet".into(),
            last_action: String::new(),
            last_action_at: String::new(),
            serving: false,
            mismatch: String::new(),
        }
    }
}

pub fn load_config(path: &Path) -> io::Result<Option<Config>> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

pub fn store_config(path: &Path, config: &Config) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(config).map_err(io::Error::other)?;
    replace(path, &bytes)
}

pub fn load_report(path: &Path) -> Option<Report> {
    let bytes = fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

pub fn store_report(path: &Path, report: &Report) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(report).map_err(io::Error::other)?;
    replace(path, &bytes)
}

pub fn load_pending(path: &Path) -> io::Result<Option<Pending>> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

pub fn store_pending(path: &Path, pending: &Pending) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(pending).map_err(io::Error::other)?;
    replace(path, &bytes)
}

fn replace(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, bytes)?;
    fs::rename(&tmp, path)
}

/// Select value shown on the operating-mode page.
pub fn shown_choice(saved: Option<&Config>) -> &'static str {
    match saved {
        None => "unset",
        Some(config) if config.enabled => "1",
        Some(_) => "0",
    }
}

pub fn saved_label(saved: Result<Option<&Config>, &str>) -> String {
    match saved {
        Ok(None) => "Not set. The IP family above is unchanged until you save Off or On.".into(),
        Ok(Some(config)) if config.enabled => match config.pinned.as_deref() {
            Some(prefix) => format!(
                "On. Pinned {prefix} ({})",
                if config.pin_source.is_empty() {
                    "source not recorded"
                } else {
                    config.pin_source.as_str()
                }
            ),
            None => "On. The block will be learned from the first attach and then pinned.".into(),
        },
        Ok(Some(_)) => "Off. The customer bearer is IPv4-only.".into(),
        Err(_) => "The saved setting could not be read. It was not changed.".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn dir() -> std::path::PathBuf {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("titan-pd-config-{n}"))
    }

    #[test]
    fn a_missing_file_is_not_off() {
        let path = dir().join("config.json");
        assert_eq!(load_config(&path).unwrap(), None);
        assert_eq!(shown_choice(None), "unset");
        assert!(saved_label(Ok(None)).contains("Not set"));
    }

    #[test]
    fn off_and_on_round_trip_and_a_corrupt_file_is_not_read_as_off() {
        let path = dir().join("config.json");
        store_config(
            &path,
            &Config {
                enabled: true,
                pinned: Some("2001:db8:f0:1200::/56".into()),
                pin_source: "entered".into(),
            },
        )
        .unwrap();
        let loaded = load_config(&path).unwrap().unwrap();
        assert!(loaded.enabled);
        assert_eq!(
            loaded.pinned_block().unwrap().unwrap().to_string(),
            "2001:db8:f0:1200::/56"
        );
        assert_eq!(shown_choice(Some(&loaded)), "1");
        fs::write(&path, b"{").unwrap();
        assert!(load_config(&path).is_err());
    }

    // Wall times from a bench log: the keeper starts at 2013-06-20 and NTP
    // corrects the clock about a minute later.
    const BOOT_CLOCK: u64 = 1_371_736_806;
    const REAL_CLOCK: u64 = 1_795_195_592;

    #[test]
    fn a_cold_boot_reverts_although_the_clock_reads_2013() {
        // The change was saved just before the reboot, so not_before is 2026.
        let not_before = REAL_CLOCK + 15;
        assert_eq!(
            recovery(false, false, true, BOOT_CLOCK, not_before),
            Recovery::Revert
        );
        // The old wall-clock test skipped it: 2013 < 2026.
        assert!(BOOT_CLOCK < not_before);
    }

    #[test]
    fn a_confirmed_change_is_kept_after_a_reboot() {
        assert_eq!(
            recovery(false, true, true, BOOT_CLOCK, REAL_CLOCK + 15),
            Recovery::Keep
        );
        assert!(confirmed("abc123", "abc123\n"));
        assert!(!confirmed("abc123", ""));
        assert!(!confirmed("abc123", "abc124"));
        assert!(!confirmed("", ""));
    }

    #[test]
    fn a_running_guard_always_wins() {
        for first in [true, false] {
            assert_eq!(
                recovery(true, false, first, BOOT_CLOCK, REAL_CLOCK),
                Recovery::Wait
            );
        }
    }

    #[test]
    fn a_restart_in_the_same_boot_honours_only_the_short_arming_gap() {
        let now = REAL_CLOCK;
        // Inside the 15 s gap before the guard starts.
        assert_eq!(recovery(false, false, false, now, now + 15), Recovery::Wait);
        assert_eq!(recovery(false, false, false, now, now + 1), Recovery::Wait);
        // Past it.
        assert_eq!(recovery(false, false, false, now, now), Recovery::Revert);
        assert_eq!(recovery(false, false, false, now + 400, now), Recovery::Revert);
        // A backward clock step cannot stretch the wait.
        assert_eq!(
            recovery(false, false, false, now, now + PENDING_ARM_SECS + 1),
            Recovery::Revert
        );
        assert_eq!(
            recovery(false, false, false, BOOT_CLOCK, REAL_CLOCK),
            Recovery::Revert
        );
    }

    #[test]
    fn the_boot_marker_tells_a_first_start() {
        let id = "3f1c2b8e-0d4a-4c55-9e61-1a2b3c4d5e6f\n";
        assert!(first_start(None, id));
        assert!(!first_start(Some(id.trim()), id));
        assert!(first_start(Some("another-boot"), id));
        // Without a boot id the marker alone decides.
        assert!(!first_start(Some("seen"), ""));
        assert!(first_start(None, ""));
    }
}
