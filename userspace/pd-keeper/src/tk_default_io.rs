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
//! - `cached`, `updated`, `cleared` or `built`, 0: the release image and its
//!   default config are in place; the hook's usual checks then load them.
//!   `updated` means a default config an earlier firmware wrote for this
//!   same image was rewritten with this firmware's words, without a
//!   rebuild. `cleared` means a quarantine, strikes or a rollback record that
//!   another firmware build left for the release image were cleared
//!   (`tk_default::stale`), so a new firmware always tries the image again.
//! - `build`, 2 (without `--write`): a build or a clear is due.
//! - `reason=<word>`, 1: keep stock firmware for that reason.
//!
//! Anything else (a crash, the time limit) also keeps stock firmware. The
//! details go to stderr, which the hook keeps in RAM.

use std::fs::{self, DirBuilder};
use std::io;
use std::os::unix::fs::DirBuilderExt;
use std::path::Path;

use titan_pd_model::tk_build;
use titan_pd_model::tk_default::{self, Attempt, Cleared, Inputs, Owner, Plan, Record};
use witcher_tk_patch::manifest::Manifest;
use witcher_tk_patch::manifests;

use crate::files::write_durably;
use crate::paths::{env_path_or, firmware_id, tk_dir};
use crate::tk_build_io::{self, Failure, TMP_CONFIG, TMP_IMAGE};

/// The build record (`tk_default::Record`) and its temporary file.
const RECORD: &str = "default";
const TMP_RECORD: &str = ".default.tk-build";
/// The default image's rollback record (`titan_pd_model::tk_verdict`).
const VERDICT: &str = "verdict";

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
    let firmware = firmware_id();
    let base = Inputs {
        record: record.as_deref(),
        release: &release,
        firmware: &firmware,
        cached,
        bank,
        ..Inputs::default()
    };
    let (mut plan, cleared) = decide(&dir, &base);
    let mut word = None;
    if plan == Plan::Clear {
        if !write {
            return Outcome::Build;
        }
        if let Err(err) = apply_clear(&dir, &cleared) {
            eprintln!("tk-build boot: clearing what another firmware build left: {err}");
            return Outcome::Stock("build");
        }
        eprintln!(
            "tk-build boot: cleared what another firmware build left for the release image ({}{}{})",
            if cleared.quarantine.is_some() { "its quarantine line " } else { "" },
            if cleared.strikes.is_some() { "strikes " } else { "" },
            if cleared.drop_verdict { "its rollback record" } else { "" },
        );
        word = Some("cleared");
        plan = decide(&dir, &base).0;
    }
    match (plan, bank) {
        (Plan::Ready, _) => match refresh(&dir, &m, &release, config.as_deref(), write) {
            Outcome::Go(_) if word.is_some() => Outcome::Go("cleared"),
            outcome => outcome,
        },
        (Plan::Stock(reason), _) => Outcome::Stock(reason),
        (Plan::Clear, _) => {
            eprintln!("tk-build boot: the records still read as another build's after the clear");
            Outcome::Stock("build")
        }
        (Plan::Build, None) => Outcome::Stock("bank-unknown"),
        (Plan::Build, Some(_)) if !write => Outcome::Build,
        (Plan::Build, Some(bank)) => build(&dir, &m, bank, record.as_deref(), &firmware),
    }
}

/// The plan from `tk/` as it is now, and what a clear would write.
fn decide(dir: &Path, base: &Inputs<'_>) -> (Plan, Cleared) {
    let (strikes, quarantine, verdict) = (read(dir, "strikes"), read(dir, "quarantine"), read(dir, VERDICT));
    let inputs = Inputs {
        strikes: strikes.as_deref(),
        quarantine: quarantine.as_deref(),
        verdict: verdict.as_deref(),
        ..*base
    };
    (tk_default::plan(&inputs), tk_default::clear(&inputs))
}

/// Write what `tk_default::clear` says, each file through a synced
/// temporary one.
fn apply_clear(dir: &Path, cleared: &Cleared) -> io::Result<()> {
    if let Some(text) = &cleared.quarantine {
        write_durably(&dir.join("quarantine"), &dir.join("quarantine.tmp"), text.as_bytes())?;
    }
    if let Some(text) = &cleared.strikes {
        write_durably(&dir.join("strikes"), &dir.join("strikes.tmp"), text.as_bytes())?;
    }
    if cleared.drop_verdict {
        match fs::remove_file(dir.join(VERDICT)) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
    }
    Ok(())
}

/// The image is in place. A default config an earlier firmware wrote for it
/// (its words or comments differ) is rewritten as this firmware writes it.
fn refresh(dir: &Path, m: &Manifest, release: &str, config: Option<&str>, write: bool) -> Outcome {
    let wanted = tk_default::config_text(m.name, release);
    if config == Some(wanted.as_str()) {
        return Outcome::Go("cached");
    }
    if !write {
        return Outcome::Build;
    }
    match write_durably(&dir.join("config"), &dir.join(TMP_CONFIG), wanted.as_bytes()) {
        Ok(()) => Outcome::Go("updated"),
        Err(err) => {
            // The old default config still allows the same image.
            eprintln!("tk-build boot: rewriting the default config: {err}");
            let _ = fs::remove_file(dir.join(TMP_CONFIG));
            Outcome::Go("cached")
        }
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

/// How the record judges one failed attempt.
fn attempt_of(failure: &Failure) -> Attempt<'_> {
    if failure.io {
        Attempt::Io(&failure.text)
    } else if failure.stock {
        Attempt::Stock(&failure.text)
    } else {
        Attempt::Other(&failure.text)
    }
}

/// Record how the build ended, then hand the hook its answer.
fn finish(dir: &Path, record: Record, result: &str, outcome: Outcome) -> Outcome {
    if let Err(err) = save(dir, &record.finish(result)) {
        eprintln!("tk-build boot: recording the result: {err}");
    }
    outcome
}

/// Build the release image from `bank` into `dir`, then write its default
/// config. The build is recorded before it starts; any failure leaves no
/// image and no default config behind.
///
/// Only a failure that repeats counts (`Record::finish`). An I/O error or a
/// killed build is transient. Any other failure is read again once in this
/// run before it is judged: Linux 3.10 hands NAND data with an
/// uncorrectable ECC error back as data, so one bad read looks like another
/// image. If the second read builds, the first was a bad read; if it fails
/// the same way, the record says so (`stock-mismatch` for a bank that is not
/// the stock image, else `failed`).
fn build(dir: &Path, m: &Manifest, bank: &str, record: Option<&str>, firmware: &str) -> Outcome {
    if let Err(err) = prepare(dir) {
        eprintln!("tk-build boot: {}: {err}", dir.display());
        return Outcome::Stock("build");
    }
    let release = m.gzip.sha256.to_string();
    let record = Record::start(record.unwrap_or(""), &release, firmware, bank);
    if let Err(err) = save(dir, &record) {
        // Unrecorded, a build that dies could repeat at every boot.
        eprintln!("tk-build boot: recording the build: {err}");
        return Outcome::Stock("build");
    }
    let proc_mtd = fs::read_to_string(env_path_or("TITAN_TK_PROC_MTD", "/proc/mtd")).unwrap_or_default();
    let Some(part) = tk_build::find_mtd(&proc_mtd, bank) else {
        eprintln!("tk-build boot: /proc/mtd has no {bank} partition");
        return finish(dir, record, "transient", Outcome::Stock("bank-unknown"));
    };
    let attempt = || tk_build_io::build(m, &part, Some(dir));
    let (built, skipped) = match attempt() {
        Ok(done) => done,
        Err(first) if first.io => {
            eprintln!("tk-build boot: {bank} (mtd{}): {} (transient; the next boot tries again)", part.index, first.text);
            let result = tk_default::build_result(attempt_of(&first), None);
            return finish(dir, record, result, Outcome::Stock("build"));
        }
        Err(first) => {
            eprintln!("tk-build boot: {bank} (mtd{}): {}; reading the bank again", part.index, first.text);
            match attempt() {
                Ok(done) => {
                    eprintln!("tk-build boot: the second read built it: the first was a bad read");
                    done
                }
                Err(second) => {
                    let result = tk_default::build_result(attempt_of(&first), Some(attempt_of(&second)));
                    let outcome = match result {
                        "stock-mismatch" => {
                            eprintln!("tk-build boot: the second read failed the same way");
                            Outcome::Stock("stock-mismatch")
                        }
                        "failed" => {
                            eprintln!("tk-build boot: the second read failed the same way");
                            Outcome::Stock("build")
                        }
                        _ => {
                            eprintln!(
                                "tk-build boot: the second read failed otherwise ({}): a bad read, not this unit's firmware; the next boot tries again",
                                second.text
                            );
                            Outcome::Stock("build")
                        }
                    };
                    return finish(dir, record, result, outcome);
                }
            }
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
        // A full volume or a write that did not read back: this attempt's.
        eprintln!("tk-build boot: {why} (transient; the next boot tries again)");
        return finish(dir, record, "transient", Outcome::Stock("build"));
    }
    eprintln!(
        "tk-build boot: built {} from {bank} (mtd{}, {skipped} bad blocks skipped): gzip {} ({} bytes)",
        m.name, part.index, built.gzip, built.gzip_size
    );
    finish(dir, record, "built", Outcome::Go("built"))
}
