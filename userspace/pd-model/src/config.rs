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
}
