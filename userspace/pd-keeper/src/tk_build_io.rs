//! `titan-pd-keeper tk-build check|stage|boot`: build the patched modem image
//! on the unit from its own stock firmware and the manifest built into the
//! keeper (docs/tk-patch.md).
//!
//! - `check` builds in memory, verifies every hash and writes nothing.
//! - `stage` also writes `tk/active.gz` and `tk/config` on the Witcher
//!   volume, each durably (`files`), and touches nothing else. The next
//!   boot's loader does the rest (docs/tk-boot-loader.md). An operator runs
//!   these two.
//! - `boot` is the default image at boot, for the boot hook only
//!   (`crate::tk_default_io`).
//!
//! Tests (scripts/test-tk-build.py) point `TITAN_TK_PROC_MTD` at a stand-in
//! for /proc/mtd and `TITAN_TK_MTD_DIR` at plain files standing in for the
//! banks, and `TITAN_TK_DIR` at the tk directory.

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, BufWriter, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use titan_pd_model::tk_build::{self, Mtd};
use witcher_tk_patch::manifest::Manifest;
use witcher_tk_patch::pipeline::{self, Built};
use witcher_tk_patch::sha256::{Digest, Sha256};
use witcher_tk_patch::{Discard, Error, Sink, manifests};

use crate::files::{replace_durably, write_durably};
use crate::mtd::GoodBlocks;
use crate::paths::{env_path_or, tk_dir};

const USAGE: &str = "usage: titan-pd-keeper tk-build check|stage|boot [--write]";
/// Our temporary files in tk/. A leftover one means a run is going on or died.
pub(crate) const TMP_IMAGE: &str = ".active.gz.tk-build";
pub(crate) const TMP_CONFIG: &str = ".config.tk-build";

pub fn main(args: &[String]) -> i32 {
    if args.first().is_some_and(|a| a == "boot") {
        return crate::tk_default_io::main(&args[1..]);
    }
    let stage = match args {
        [a] if a == "check" => false,
        [a] if a == "stage" => true,
        _ => {
            eprintln!("{USAGE}");
            return 64;
        }
    };
    match run(stage) {
        Ok(()) => 0,
        Err(err) => {
            eprintln!("tk-build: {err}");
            1
        }
    }
}

fn run(stage: bool) -> Result<(), String> {
    // The lowest CPU priority: the unit has one Linux core, and a build must
    // not slow forwarding, the keeper or the vendor daemons.
    if let Ok(pid) = i32::try_from(std::process::id()) {
        let _ = titan_sys::process::set_nice(pid, 19);
    }
    let m = Manifest::parse(manifests::RELEASE).map_err(|e| format!("the built-in manifest: {e}"))?;
    println!(
        "manifest {}: {} sites; image {}; gzip {} ({} bytes)",
        m.name,
        m.sites.len(),
        m.image.sha256,
        m.gzip.sha256,
        m.gzip.size
    );
    let dir = match (stage, tk_dir()) {
        (true, None) => return Err("the Witcher volume is not mounted at /mnt/titan-api".into()),
        (true, Some(dir)) => Some(prepare(&dir).map_err(|e| format!("{}: {e}", dir.display()))?),
        (false, dir) => dir.filter(|d| d.is_dir()),
    };
    let proc_path = env_path_or("TITAN_TK_PROC_MTD", "/proc/mtd");
    let proc_mtd = fs::read_to_string(&proc_path).map_err(|e| format!("{}: {e}", proc_path.display()))?;
    // Where `stage` writes; `check` only reads the directory for its notes.
    let out = dir.as_deref().filter(|_| stage);
    let mut tried = Vec::new();
    for bank in tk_build::BANKS {
        let Some(part) = tk_build::find_mtd(&proc_mtd, bank) else {
            tried.push(format!("{bank}: no such partition"));
            continue;
        };
        match build(&m, &part, out).map_err(|f| f.text) {
            Ok((built, skipped)) => {
                println!(
                    "{bank} (mtd{}, {skipped} bad blocks skipped): stock {}; built image {}, gzip {} ({} bytes)",
                    part.index, built.stock, built.image, built.gzip, built.gzip_size
                );
                if let Some(dir) = out {
                    commit(dir, &built)?;
                    // The RAM log only: staging writes no other file on flash.
                    crate::log_ram(&format!("tk build: staged {} image {} from {bank}", m.name, built.gzip));
                    println!("staged {}: the next boot loads it (reboot outside the SAS window)", dir.join("active.gz").display());
                } else {
                    println!("check passed: stage would write gzip {}", built.gzip);
                }
                for why in dir.as_deref().map(|d| refusals(d, &built.gzip)).unwrap_or_default() {
                    println!("note: {why}");
                }
                return Ok(());
            }
            Err(why) => tried.push(format!("{bank} (mtd{}): {why}", part.index)),
        }
    }
    Err(format!("no tk bank holds the stock image this manifest needs:\n  {}", tried.join("\n  ")))
}

/// The tk directory, created like stage-latency.sh does (mode 0700), with
/// no temporary file left from another run.
fn prepare(dir: &Path) -> io::Result<PathBuf> {
    match fs::symlink_metadata(dir) {
        Ok(meta) if meta.is_dir() => {}
        Ok(_) => return Err(io::Error::other("is not a directory")),
        Err(e) if e.kind() == io::ErrorKind::NotFound => DirBuilder::new().mode(0o700).create(dir)?,
        Err(e) => return Err(e),
    }
    for name in [TMP_IMAGE, TMP_CONFIG] {
        if fs::symlink_metadata(dir.join(name)).is_ok() {
            return Err(io::Error::other(format!(
                "{name} exists: another tk-build is running, or one died (remove the file if none runs)"
            )));
        }
    }
    Ok(dir.to_path_buf())
}

/// A file being written. The pipeline only sees `Error::Write`; the cause stays here.
struct FileSink {
    file: BufWriter<File>,
    error: Option<io::Error>,
}

impl Sink for FileSink {
    fn write(&mut self, data: &[u8]) -> Result<(), Error> {
        self.file.write_all(data).map_err(|e| {
            self.error = Some(e);
            Error::Write
        })
    }
}

fn create(path: &Path) -> io::Result<File> {
    OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)
}

/// Why a build from one bank stopped.
pub(crate) struct Failure {
    /// The bytes read are not the stock image the manifest pins. One read
    /// is not proof: Linux 3.10 hands NAND data with an uncorrectable ECC
    /// error back as data, so the default build reads again before it
    /// judges (`crate::tk_default_io`).
    pub stock: bool,
    /// An I/O error (reading the bank, writing or syncing the image): a
    /// property of this attempt, never of the unit.
    pub io: bool,
    pub text: String,
}

impl From<String> for Failure {
    fn from(text: String) -> Self {
        Self { stock: false, io: true, text }
    }
}

/// Build from one bank; with `dir`, into its temporary image file.
pub(crate) fn build(m: &Manifest, part: &Mtd, dir: Option<&Path>) -> Result<(Built, u32), Failure> {
    // Tests put plain files with no bad block table in another directory.
    let devices = env_path_or("TITAN_TK_MTD_DIR", "/dev");
    let dev = devices.join(format!("mtd{}", part.index));
    let has_bbt = devices == Path::new("/dev");
    let mut src = GoodBlocks::open(&dev, part, has_bbt).map_err(|e| format!("{}: {e}", dev.display()))?;
    let explain = |err: Error, src: &mut GoodBlocks, sink_error: Option<io::Error>| {
        let stock = matches!(
            err,
            Error::Site(_) | Error::Stock(_) | Error::Gzip(_) | Error::Inflate(_) | Error::Truncated
        );
        let io = matches!(err, Error::Read | Error::Write);
        let text = match err {
            Error::Read => format!("reading the bank: {}", src.error.take().map_or("?".into(), |e| e.to_string())),
            Error::Write => format!("writing the image: {}", sink_error.map_or("?".into(), |e| e.to_string())),
            Error::Site(i) => format!("not the stock image: site {} differs", m.sites[i].name),
            other => other.to_string(),
        };
        Failure { stock, io, text }
    };
    let Some(dir) = dir else {
        let built = pipeline::from_gzip(m, &mut src, &mut Discard).map_err(|e| explain(e, &mut src, None))?;
        return Ok((built, src.skipped));
    };
    let tmp = dir.join(TMP_IMAGE);
    let file = create(&tmp).map_err(|e| format!("{}: {e}", tmp.display()))?;
    let mut sink = FileSink { file: BufWriter::new(file), error: None };
    let result = pipeline::from_gzip(m, &mut src, &mut sink).map_err(|e| explain(e, &mut src, sink.error.take()));
    let flushed = result.and_then(|built| {
        let file = sink.file.into_inner().map_err(|e| format!("writing the image: {}", e.error()))?;
        file.sync_all().map_err(|e| format!("syncing the image: {e}"))?;
        Ok(built)
    });
    if flushed.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    Ok((flushed?, src.skipped))
}

pub(crate) fn sha256_file(path: &Path) -> io::Result<Digest> {
    let mut file = File::open(path)?;
    let mut sha = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match file.read(&mut buf)? {
            0 => return Ok(sha.finish()),
            n => sha.update(&buf[..n]),
        }
    }
}

/// Put the built image in place after reading it back from flash, then its
/// config. Until the config names the image's hash the loader refuses the
/// image (not-allowed) and boots stock firmware, so this order is safe.
fn commit(dir: &Path, built: &Built) -> Result<(), String> {
    let config = dir.join("config");
    let old = match fs::read_to_string(&config) {
        Ok(text) => text,
        Err(e) if e.kind() == io::ErrorKind::NotFound => String::new(),
        Err(e) => {
            let _ = fs::remove_file(dir.join(TMP_IMAGE));
            return Err(format!("{}: {e}", config.display()));
        }
    };
    place_image(dir, built)?;
    let new = tk_build::staged_config(&old, &built.gzip.to_string());
    write_durably(&config, &dir.join(TMP_CONFIG), new.as_bytes()).map_err(|e| {
        let _ = fs::remove_file(dir.join(TMP_CONFIG));
        format!("writing {}: {e}", config.display())
    })
}

/// Rename the built image over `active.gz` once what reached the flash reads
/// back as the image that was built. On any failure the temporary file goes.
pub(crate) fn place_image(dir: &Path, built: &Built) -> Result<(), String> {
    let tmp = dir.join(TMP_IMAGE);
    let undo = |why: String| {
        let _ = fs::remove_file(&tmp);
        why
    };
    match sha256_file(&tmp) {
        Ok(sha) if sha == built.gzip => {}
        Ok(sha) => return Err(undo(format!("the image read back as {sha}, not {}", built.gzip))),
        Err(e) => return Err(undo(format!("reading the image back: {e}"))),
    }
    replace_durably(&tmp, &dir.join("active.gz")).map_err(|e| undo(format!("placing active.gz: {e}")))
}

/// Why the loader would still boot stock firmware with this image staged.
fn refusals(dir: &Path, gzip: &Digest) -> Vec<String> {
    let read = |name: &str| fs::read_to_string(dir.join(name)).ok();
    tk_build::loader_refusals(&gzip.to_string(), read("strikes").as_deref(), read("quarantine").as_deref())
}

#[cfg(test)]
mod tests {
    use titan_pd_model::tk_flags::{M1_MAGIC_ADDR, M1_VERSIONS};
    use witcher_tk_patch::manifest::Manifest;
    use witcher_tk_patch::manifests;

    /// `stage` writes the release image, N6H + R4's Rust N4 + R1's PIE with
    /// v1.0.17's uplink AQM defaults. It carries R1's M1 block, version
    /// 0x20261126, and the keeper must manage that version: otherwise its PIE
    /// selector is never written and the image runs N4's AQM.
    #[test]
    fn the_release_image_carries_r1s_m1_block_which_the_keeper_manages() {
        let m = Manifest::parse(manifests::RELEASE).unwrap();
        assert_eq!(m.name, "n6h-r4-r1-s3");
        let block = m.replacement_at(M1_MAGIC_ADDR, 8).expect("the release image carries the M1 block");
        let word = |at: usize| u32::from_le_bytes([block[at], block[at + 1], block[at + 2], block[at + 3]]);
        // The console prints the word most significant byte first: "M1PI".
        assert_eq!(word(0).to_be_bytes(), *b"M1PI");
        assert_eq!(word(4), 0x2026_1126, "R1's M1 block version");
        assert!(M1_VERSIONS.contains(&word(4)), "the keeper does not manage M1 block version {:#x}", word(4));
    }

    /// v1.0.17 ships the uplink AQM's bench step S3 (lanes-20261125/AB3) as
    /// the image's own defaults: PIE drop budget 5% and ceiling 35 ms
    /// (v1.0.16's image: 2% and 50 ms). They are not managed words: only the
    /// selector in the M1 block is ever written.
    #[test]
    fn the_release_image_carries_the_s3_uplink_aqm_defaults() {
        let m = Manifest::parse(manifests::RELEASE).unwrap();
        let words = m.replacement_at(0x841b_5934, 8).expect("the M1 block's PIE words");
        let word = |at: usize| u32::from_le_bytes([words[at], words[at + 1], words[at + 2], words[at + 3]]);
        assert_eq!((word(0), word(4)), (0x000c_cccd, 0x23));
    }
}
