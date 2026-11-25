//! Staging, loading and `/proc` control for `titan_pd_model::qctrl`.
//!
//! The rootfs has no room for the module, so an operator stages
//! `titan_qctrl.ko` from the repository's `device/qctrl/payload` in
//! `/mnt/titan-api/qctrl`. Only bytes that match the digest built into the
//! keeper are copied into its private RAM directory and loaded from there.
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use titan_pd_model::{config, qctrl, sha256};

const MANIFEST: &str = include_str!("../../../device/qctrl/SHA256SUMS");

/// The staged module and its config, only while the volume is mounted.
pub fn staged_dir() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("TITAN_QCTRL_DIR") {
        return Some(PathBuf::from(path));
    }
    config::persistent_volume_mounted().then(|| PathBuf::from("/mnt/titan-api/qctrl"))
}

pub fn proc_path() -> String {
    std::env::var("TITAN_QCTRL_PROC").unwrap_or_else(|_| "/proc/titan_qctrl".into())
}

pub fn modules_path() -> String {
    std::env::var("TITAN_PROC_MODULES").unwrap_or_else(|_| "/proc/modules".into())
}

pub fn status_path() -> String {
    std::env::var("TITAN_QCTRL_STATUS").unwrap_or_else(|_| "/var/run/witcher-qctrl.status".into())
}

fn insmod_program() -> String {
    std::env::var("TITAN_INSMOD").unwrap_or_else(|_| "insmod".into())
}

/// The digest built into this keeper.
pub fn pinned() -> Option<&'static str> {
    sha256::pinned(MANIFEST, qctrl::FILE)
}

fn short(sha: &str) -> &str {
    sha.get(..12).unwrap_or(sha)
}

/// Copy the staged module into RAM once its bytes match the pinned digest,
/// check the copy again, and return its path.
pub fn stage(dir: &Path) -> Result<PathBuf, String> {
    let want = pinned().ok_or("the keeper's qctrl manifest has no titan_qctrl.ko line")?;
    let source = dir.join(qctrl::FILE);
    let bytes =
        fs::read(&source).map_err(|e| format!("{} is not staged: {e}", source.display()))?;
    let got = sha256::hex(&sha256::digest(&bytes));
    if got != want {
        return Err(format!(
            "{} has SHA-256 {}, not the pinned {}",
            source.display(),
            short(&got),
            short(want)
        ));
    }
    let run = crate::paths::runtime_dir().join("qctrl");
    if !run.is_dir() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&run)
            .map_err(|e| format!("cannot create {}: {e}", run.display()))?;
    }
    let dest = run.join(qctrl::FILE);
    let tmp = run.join(format!(".{}.{}", qctrl::FILE, std::process::id()));
    let _ = fs::remove_file(&tmp);
    let written = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .and_then(|mut file| {
            file.write_all(&bytes)?;
            file.sync_all()
        })
        .and_then(|()| fs::rename(&tmp, &dest));
    if let Err(e) = written {
        let _ = fs::remove_file(&tmp);
        return Err(format!("cannot copy the module into RAM: {e}"));
    }
    let copy = fs::read(&dest).map_err(|e| format!("cannot read the RAM copy: {e}"))?;
    if sha256::hex(&sha256::digest(&copy)) != want {
        let _ = fs::remove_file(&dest);
        return Err("the RAM copy does not match the pinned digest".into());
    }
    Ok(dest)
}

pub fn insmod(path: &Path) -> Result<(), String> {
    let out = Command::new(insmod_program())
        .arg(path)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("insmod did not run: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    let why = String::from_utf8_lossy(&out.stderr).trim().to_owned();
    Err(if why.is_empty() {
        format!("insmod failed ({})", out.status)
    } else {
        format!("insmod failed: {why}")
    })
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
