//! Staging, loading and `/proc` control for `titan_pd_model::qctrl`.
//!
//! The rootfs has no room for the module, so an operator stages
//! `titan_qctrl.ko` from the repository's `device/qctrl/payload` in
//! `/mnt/titan-api/qctrl` (see `crate::staged`).
use std::fs::OpenOptions;
use std::io::Write as _;

use titan_pd_model::qctrl;

use crate::paths::env_or;
use crate::staged::Staged;

/// The staged clamp module.
pub const MODULE: Staged = Staged {
    file: qctrl::FILE,
    manifest: include_str!("../../../device/qctrl/SHA256SUMS"),
    dir: "qctrl",
    dir_env: "TITAN_QCTRL_DIR",
};

pub fn proc_path() -> String {
    env_or("TITAN_QCTRL_PROC", "/proc/titan_qctrl")
}

pub fn status_path() -> String {
    env_or("TITAN_QCTRL_STATUS", "/var/run/witcher-qctrl.status")
}

/// One write per line, as `echo 'mode 2' > /proc/titan_qctrl` does.
pub fn write_proc(lines: &[String]) -> Result<(), String> {
    let path = proc_path();
    for line in lines {
        OpenOptions::new()
            .write(true)
            .open(&path)
            .and_then(|mut file| file.write_all(line.as_bytes()))
            .map_err(|e| format!("cannot write {:?} to {path}: {e}", line.trim()))?;
    }
    Ok(())
}
