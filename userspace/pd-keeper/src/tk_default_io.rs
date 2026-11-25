//! `titan-pd-keeper tk-build boot`: the default modem image, at boot
//! (`titan_pd_model::tk_default`, docs/tk-boot-loader.md).
//!
//! Only `witcher-tk-stage pre` runs it, under a time limit, with
//! `TITAN_TK_DIR` set to `tk/` on its own mount of the Witcher volume. That
//! is before the vendor mounts the volume and before anyone can log in, so
//! no other writer exists: what an earlier run left is ours.
//!
//! The hook runs it twice at most. First on the read-only mount, which only
//! decides; it writes nothing. Only when a build is due does the hook
//! remount read-write and run it again with `--write`, which builds. So a
//! unit that opted out, or one that cannot use the image, is only read.
//!
//! It prints one line for the hook and exits:
//! - `operator`, 0: an operator owns `tk/`; the hook's usual checks decide.
//! - `cached` or `built`, 0: the release image and its default config are in
//!   place; the hook's usual checks then load them.
//! - `build`, 2 (without `--write`): a build is due.
//! - `reason=<word>`, 1: keep stock firmware for that reason.
//!
//! Anything else (a crash, the time limit) also keeps stock firmware. The
//! details go to stderr, which the hook keeps in RAM.

use std::fs::{self, DirBuilder};
use std::io;
use std::os::unix::fs::DirBuilderExt;
use std::path::Path;

use titan_pd_model::tk_build;
use titan_pd_model::tk_default::{self, Inputs, Owner, Plan, Record};
use witcher_tk_patch::manifest::Manifest;
use witcher_tk_patch::manifests;

use crate::files::write_durably;
use crate::paths::{env_path_or, tk_dir};
use crate::tk_build_io::{self, TMP_CONFIG, TMP_IMAGE};

/// The build record (`tk_default::Record`) and its temporary file.
const RECORD: &str = "default";
const TMP_RECORD: &str = ".default.tk-build";

/// What the hook reads on stdout.
enum Outcome {
    /// Go on with the hook's usual checks.
    Go(&'static str),
    /// A build is due; run again with `--write` on a read-write mount.
    Build,
    /// Keep stock modem firmware, for this reason.
    Stock(&'static str),
}

pub fn main(args: &[String]) -> i32 {
    let write = match args {
        [] => false,
        [flag] if flag == "--write" => true,
        _ => {
            eprintln!("usage: titan-pd-keeper tk-build boot [--write]");
            return 64;
        }
    };
    match boot(write) {
        Outcome::Go(word) => {
            println!("{word}");
            0
        }
        Outcome::Build => {
            println!("build");
            2
        }
        Outcome::Stock(reason) => {
            println!("reason={reason}");
            1
        }
    }
}

fn read(dir: &Path, name: &str) -> Option<String> {
    fs::read_to_string(dir.join(name)).ok()
}

fn boot(write: bool) -> Outcome {
    let Some(dir) = tk_dir() else {
        eprintln!("tk-build boot: TITAN_TK_DIR names no tk directory");
        return Outcome::Stock("build");
    };
    let m = match Manifest::parse(manifests::RELEASE) {
        Ok(m) => m,
        Err(err) => {
            eprintln!("tk-build boot: the built-in manifest: {err}");
            return Outcome::Stock("build");
        }
    };
    let release = m.gzip.sha256.to_string();
    let config = read(&dir, "config");
    let record = read(&dir, RECORD);
    let image = dir.join("active.gz");
    let has_image = fs::symlink_metadata(&image).is_ok();
    if tk_default::owner(config.as_deref(), has_image, record.as_deref(), &release) == Owner::Operator {
        return Outcome::Go("operator");
    }
    let default_for = config.as_deref().and_then(tk_default::default_sha);
    let cached = default_for.as_deref() == Some(release.as_str()) && is_release_image(&image, &m);
    let cmdline = fs::read_to_string(env_path_or("TITAN_TK_PROC_CMDLINE", "/proc/cmdline")).unwrap_or_default();
    let bank = tk_build::active_bank(&cmdline);
    let (strikes, quarantine) = (read(&dir, "strikes"), read(&dir, "quarantine"));
    let inputs = Inputs {
        strikes: strikes.as_deref(),
        quarantine: quarantine.as_deref(),
        record: record.as_deref(),
        release: &release,
        cached,
        bank,
    };
    match (tk_default::plan(&inputs), bank) {
        (Plan::Ready, _) => Outcome::Go("cached"),
        (Plan::Stock(reason), _) => Outcome::Stock(reason),
        (Plan::Build, None) => Outcome::Stock("bank-unknown"),
        (Plan::Build, Some(_)) if !write => Outcome::Build,
        (Plan::Build, Some(bank)) => build(&dir, &m, bank, record.as_deref()),
    }
}

/// `active.gz` is a plain file holding exactly the release image.
fn is_release_image(path: &Path, m: &Manifest) -> bool {
    let plain = fs::symlink_metadata(path).is_ok_and(|meta| meta.is_file() && meta.len() == m.gzip.size);
    plain && tk_build_io::sha256_file(path).is_ok_and(|sha| sha == m.gzip.sha256)
}

/// The tk directory, created like stage-latency.sh does (mode 0700), without
/// what an earlier run left and without the stale default image: the
/// firmware owns `tk/` here, and a stale image would only fill the volume.
fn prepare(dir: &Path) -> io::Result<()> {
    match fs::symlink_metadata(dir) {
        Ok(meta) if meta.is_dir() => {}
        Ok(_) => return Err(io::Error::other("is not a directory")),
        Err(e) if e.kind() == io::ErrorKind::NotFound => DirBuilder::new().mode(0o700).create(dir)?,
        Err(e) => return Err(e),
    }
    for name in [TMP_IMAGE, TMP_CONFIG, TMP_RECORD, "active.gz"] {
        match fs::remove_file(dir.join(name)) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
    }
    Ok(())
}

fn save(dir: &Path, record: &Record) -> io::Result<()> {
    write_durably(&dir.join(RECORD), &dir.join(TMP_RECORD), record.render().as_bytes())
}

/// Record how the build ended, then hand the hook its answer.
fn finish(dir: &Path, record: Record, result: &str, outcome: Outcome) -> Outcome {
    if let Err(err) = save(dir, &record.finish(result)) {
        eprintln!("tk-build boot: recording the result: {err}");
    }
    outcome
}

/// Build the release image from `bank` into `dir`, then write its default
/// config. The build is recorded before it starts, so one that is killed
/// still counts; any failure leaves no image and no default config behind.
fn build(dir: &Path, m: &Manifest, bank: &str, record: Option<&str>) -> Outcome {
    if let Err(err) = prepare(dir) {
        eprintln!("tk-build boot: {}: {err}", dir.display());
        return Outcome::Stock("build");
    }
    let release = m.gzip.sha256.to_string();
    let record = Record::start(record.unwrap_or(""), &release);
    if let Err(err) = save(dir, &record) {
        // Unrecorded, a build that dies could repeat at every boot.
        eprintln!("tk-build boot: recording the build: {err}");
        return Outcome::Stock("build");
    }
    let proc_mtd = fs::read_to_string(env_path_or("TITAN_TK_PROC_MTD", "/proc/mtd")).unwrap_or_default();
    let Some(part) = tk_build::find_mtd(&proc_mtd, bank) else {
        eprintln!("tk-build boot: /proc/mtd has no {bank} partition");
        return finish(dir, record, "failed", Outcome::Stock("bank-unknown"));
    };
    let (built, skipped) = match tk_build_io::build(m, &part, Some(dir)) {
        Ok(done) => done,
        Err(failure) => {
            eprintln!("tk-build boot: {bank} (mtd{}): {}", part.index, failure.text);
            return if failure.stock {
                finish(dir, record, "stock-mismatch", Outcome::Stock("stock-mismatch"))
            } else {
                finish(dir, record, "failed", Outcome::Stock("build"))
            };
        }
    };
    let config = tk_default::config_text(m.name, &release);
    let placed = tk_build_io::place_image(dir, &built).and_then(|()| {
        write_durably(&dir.join("config"), &dir.join(TMP_CONFIG), config.as_bytes()).map_err(|e| {
            // An image with no config would read as an operator's next boot.
            let _ = fs::remove_file(dir.join("active.gz"));
            let _ = fs::remove_file(dir.join(TMP_CONFIG));
            format!("writing the config: {e}")
        })
    });
    if let Err(why) = placed {
        eprintln!("tk-build boot: {why}");
        return finish(dir, record, "failed", Outcome::Stock("build"));
    }
    eprintln!(
        "tk-build boot: built {} from {bank} (mtd{}, {skipped} bad blocks skipped): gzip {} ({} bytes)",
        m.name, part.index, built.gzip, built.gzip_size
    );
    finish(dir, record, "built", Outcome::Go("built"))
}
