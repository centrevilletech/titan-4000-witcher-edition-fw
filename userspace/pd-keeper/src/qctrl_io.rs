//! Loading and `/proc` control for `titan_pd_model::qctrl`.
//!
//! The firmware image carries `titan_qctrl.ko` from the repository's
//! `device/qctrl/payload`. A copy staged in `/mnt/titan-api/qctrl` overrides
//! it only when it is the same pinned module (see `crate::staged`).
use std::fs::OpenOptions;
use std::io::Write as _;
use std::thread;
use std::time::Duration;

use titan_pd_model::qctrl;

use crate::files::read_file;
use crate::paths::env_or;
use crate::staged::Staged;

/// The clamp module.
pub const MODULE: Staged = Staged {
    file: qctrl::FILE,
    manifest: include_str!("../../../device/qctrl/SHA256SUMS"),
    dir: "qctrl",
    dir_env: "TITAN_QCTRL_DIR",
};

pub fn proc_path() -> String {
    env_or("TITAN_QCTRL_PROC", "/proc/titan_qctrl")
}

/// Separate write target only when tests point it at a control pipe. On a
/// real unit this is `/proc/titan_qctrl`.
fn proc_write_path() -> String {
    std::env::var("TITAN_QCTRL_PROC_WRITE").unwrap_or_else(|_| proc_path())
}

pub fn status_path() -> String {
    env_or("TITAN_QCTRL_STATUS", "/var/run/witcher-qctrl.status")
}

/// One write per line, as `echo 'mode 2' > /proc/titan_qctrl` does.
pub fn write_proc(lines: &[String]) -> Result<(), String> {
    let path = proc_write_path();
    for line in lines {
        OpenOptions::new()
            .write(true)
            .open(&path)
            .and_then(|mut file| file.write_all(line.as_bytes()))
            .map_err(|e| format!("cannot write {:?} to {path}: {e}", line.trim()))?;
    }
    Ok(())
}

/// `/proc/titan_qctrl` once it shows `config`. A real kernel updates it
/// synchronously, so the first read shows it; one brief retry covers a test
/// control pipe updating a stand-in file.
pub fn read_back(config: &qctrl::Config) -> qctrl::Proc {
    let proc = qctrl::parse_proc(&read_file(proc_path()));
    if qctrl::matches(config, &proc) {
        return proc;
    }
    thread::sleep(Duration::from_millis(50));
    qctrl::parse_proc(&read_file(proc_path()))
}
