//! Kernel modules an operator stages on the persistent volume, because the
//! rootfs has no room for them. The keeper loads only bytes whose SHA-256
//! matches the digest built into it, from a copy in its private RAM
//! directory.

use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

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

    /// Stage the module from `dir` and load it.
    pub fn load(&self, dir: &Path) -> Result<(), String> {
        self.stage(dir).and_then(|path| insmod(&path))
    }

    /// Copy the staged module into RAM once its bytes match the pinned digest,
    /// check the copy again, and return its path.
    fn stage(&self, dir: &Path) -> Result<PathBuf, String> {
        let want = self
            .pinned()
            .ok_or_else(|| format!("the keeper's {} manifest has no {} line", self.dir, self.file))?;
        let source = dir.join(self.file);
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

/// The kernel's module list (`TITAN_PROC_MODULES` in tests).
pub fn modules_path() -> String {
    paths::env_or("TITAN_PROC_MODULES", "/proc/modules")
}

fn short(sha: &str) -> &str {
    sha.get(..12).unwrap_or(sha)
}

fn insmod_program() -> String {
    paths::env_or("TITAN_INSMOD", "insmod")
}

fn insmod(path: &Path) -> Result<(), String> {
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
