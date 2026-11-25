//! Kernel modules the keeper loads by pinned digest: the firmware image's
//! copy (`/usr/lib/titan-api/modules`, since v1.0.17), or a copy an operator
//! staged on the persistent volume, which overrides it only when its bytes
//! match the same digest. The keeper loads only bytes whose SHA-256 matches
//! the digest built into it, from a copy in its private RAM directory.
//!
//! A load that fails is tried again after `retry_policy()`'s wait, for as
//! long as it fails; a unit without the volume loads the image's copy.

use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use titan_pd_model::retry::{self, Policy};
use titan_pd_model::sha256;

use crate::paths;

/// One stageable module.
pub struct Staged {
    /// The module file, for example `titan_qctrl.ko`.
    pub file: &'static str,
    /// The `SHA256SUMS` built into the keeper that pins it.
    pub manifest: &'static str,
    /// Its directory, on the volume and in the keeper's RAM directory.
    pub dir: &'static str,
    /// The variable that points tests at another staging directory.
    pub dir_env: &'static str,
}

impl Staged {
    /// Where the module and its config are staged, while the volume is mounted.
    pub fn staged_dir(&self) -> Option<PathBuf> {
        paths::volume_dir(self.dir_env, self.dir)
    }

    /// The digest built into this keeper.
    pub fn pinned(&self) -> Option<&'static str> {
        sha256::pinned(self.manifest, self.file)
    }

    /// Load the module and say where it came from: the copy staged in `dir`
    /// (`staged_dir()`, none without the volume) when there is one and it
    /// is the pinned module, else the firmware image's copy. Bytes that are
    /// not the pinned module never load.
    pub fn load_any(&self, dir: Option<&Path>) -> Result<&'static str, String> {
        let refused = match dir {
            Some(dir) if dir.join(self.file).exists() => match self.stage(dir) {
                Ok(path) => return insmod(&path).map(|()| "the staged copy"),
                Err(why) => Some(why),
            },
            _ => None,
        };
        let image = self.stage(&image_dir()).and_then(|path| insmod(&path));
        match (image, refused) {
            (Ok(()), None) => Ok("the firmware image"),
            (Ok(()), Some(_)) => Ok("the firmware image (the staged copy is not the pinned module)"),
            (Err(err), None) => Err(err),
            (Err(err), Some(why)) => Err(format!("{why}; {err}")),
        }
    }

    /// Copy the staged module into RAM once its bytes match the pinned digest,
    /// check the copy again, and return its path.
    fn stage(&self, dir: &Path) -> Result<PathBuf, String> {
        let want = self
            .pinned()
            .ok_or_else(|| format!("the keeper's {} manifest has no {} line", self.dir, self.file))?;
        let source = dir.join(self.file);
        let bytes =
            fs::read(&source).map_err(|e| format!("cannot read {}: {e}", source.display()))?;
        let got = sha256::hex(&sha256::digest(&bytes));
        if got != want {
            return Err(format!(
                "{} has SHA-256 {}, not the pinned {}",
                source.display(),
                short(&got),
                short(want)
            ));
        }
        let run = paths::runtime_dir().join(self.dir);
        if !run.is_dir() {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&run)
                .map_err(|e| format!("cannot create {}: {e}", run.display()))?;
        }
        let dest = run.join(self.file);
        let tmp = run.join(format!(".{}.{}", self.file, std::process::id()));
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
}

/// The operator's `config` in a staging directory, or `None` when there is
/// none, so the firmware default applies. A file that exists but cannot be
/// read counts as empty, which turns the feature off.
pub fn operator_config(dir: &Path) -> Option<String> {
    match fs::read_to_string(dir.join("config")) {
        Ok(text) => Some(text),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => Some(String::new()),
    }
}

/// Where the firmware image keeps the modules (`TITAN_MODULES_DIR` in tests).
pub fn image_dir() -> PathBuf {
    paths::env_path_or("TITAN_MODULES_DIR", "/usr/lib/titan-api/modules")
}

/// The kernel's module list (`TITAN_PROC_MODULES` in tests).
pub fn modules_path() -> String {
    paths::env_or("TITAN_PROC_MODULES", "/proc/modules")
}

/// The waits before a failed module load, or the fast path after a watchdog
/// trip, is tried again (`retry::MODULES`). Tests shorten the first one with
/// `TITAN_RETRY_SECS`.
pub fn retry_policy() -> Policy {
    retry::MODULES.with_first(std::env::var("TITAN_RETRY_SECS").ok().as_deref())
}

fn short(sha: &str) -> &str {
    sha.get(..12).unwrap_or(sha)
}

fn insmod_program() -> String {
    paths::env_or("TITAN_INSMOD", "insmod")
}

fn insmod(path: &Path) -> Result<(), String> {
    let out = crate::command::output(Command::new(insmod_program()).arg(path))
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
