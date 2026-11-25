//! The vendor's configuration store: its RAM cache `/tmp/nvram.cfg`, the
//! `titan-nvram` tool that changes it, and the `rcinit` signal that applies a
//! change.

use std::env;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

use titan_sys::process::Signal;

/// The vendor's RAM configuration cache.
pub fn cache_path() -> PathBuf {
    std::env::var_os("TITAN_NVRAM_CACHE").map_or_else(|| PathBuf::from("/tmp/nvram.cfg"), PathBuf::from)
}

/// Read one key from a NUL- or newline-delimited NVRAM cache snapshot,
/// formatted the same way as `nvram_get 0 <key>`.
pub fn get_from_cache(cache: &[u8], key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    for record in cache.split(|&b| b == 0 || b == b'\n') {
        let Some(rest) = record.strip_prefix(prefix.as_bytes()) else {
            continue;
        };
        let value = String::from_utf8_lossy(rest);
        return Some(format!("nvram_get success: {value}\n"));
    }
    None
}

/// The vendor's `titan-nvram` tool (`TITAN_NVRAM` in tests).
fn tool() -> PathBuf {
    env::var("TITAN_NVRAM").map_or_else(
        |_| PathBuf::from("/usr/lib/titan-api/titan-nvram"),
        PathBuf::from,
    )
}

/// `titan-nvram set 0 <key>`, with the value on stdin.
pub fn set(key: &str, value: &str) -> Result<(), ()> {
    let mut child = Command::new(tool())
        .args(["set", "0", key])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .map_err(|_| ())?;
    child
        .stdin
        .take()
        .ok_or(())?
        .write_all(value.as_bytes())
        .map_err(|_| ())?;
    child
        .wait()
        .ok()
        .filter(|status| status.success())
        .map(|_| ())
        .ok_or(())
}

/// `titan-nvram commit 0`: the RAM settings go to flash.
pub fn commit() -> Result<(), ()> {
    Command::new(tool())
        .args(["commit", "0"])
        .status()
        .ok()
        .filter(|status| status.success())
        .map(|_| ())
        .ok_or(())
}

/// `SIGUSR1` to `rcinit`, which applies the settings.
pub fn signal_rcinit() -> Result<(), ()> {
    let entries = fs::read_dir("/proc").map_err(|_| ())?;
    for entry in entries.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        if fs::read_to_string(entry.path().join("comm")).is_ok_and(|name| name.trim() == "rcinit") {
            return titan_sys::process::kill(pid, Signal::User1).map_err(drop);
        }
    }
    Err(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nvram_cache_lookup_handles_nul_and_newline_formats() {
        let nul = b"router_disable=1\0pdn_data_ipaddr=172.20.64.152\0wan_get_dns=192.0.2.53\0";
        assert_eq!(
            get_from_cache(nul, "router_disable").as_deref(),
            Some("nvram_get success: 1\n")
        );
        assert_eq!(
            get_from_cache(nul, "pdn_data_ipaddr").as_deref(),
            Some("nvram_get success: 172.20.64.152\n")
        );
        assert_eq!(get_from_cache(nul, "missing"), None);

        let lines = b"detection_enable=1\nsqns_connection_mediaState=ATTACHED\n";
        assert_eq!(
            get_from_cache(lines, "sqns_connection_mediaState").as_deref(),
            Some("nvram_get success: ATTACHED\n")
        );
    }
}
