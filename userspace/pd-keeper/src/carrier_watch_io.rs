//! File I/O and vendor signaling for `titan_pd_model::carrier_watch`.
//!
//! Reads `/mnt/cbrslog0.txt` incrementally (never re-reading megabytes per
//! tick, handling log rotation and partial last lines), loads
//! `/mnt/titan-api/carrier-watch/config`, writes `/var/run/witcher-carrier.status`,
//! and runs the vendor handover re-grant trigger (`sqns_network_cbrs=1` +
//! `SIGUSR1` to `rcinit`) only when policy permits.

use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use titan_pd_model::carrier_watch::{self, Config, LogParser};
use titan_pd_model::config;

/// Maximum bytes read on the very first open of `/mnt/cbrslog0.txt`.
/// The vendor rotates at about 128 KB, so this reads a full live file once at
/// startup while bounding memory on a huge synthetic log.
const MAX_INITIAL_READ: u64 = 256 * 1024;
/// Maximum bytes read per 1 s tick after startup.
const CHUNK_READ: u64 = 64 * 1024;
/// Cap on an unterminated trailing line buffer.
const MAX_PENDING_LINE: usize = 16 * 1024;

/// Persistent config directory, only while the volume is mounted (unless
/// overridden in tests).
pub fn config_dir() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("TITAN_CARRIER_DIR") {
        return Some(PathBuf::from(path));
    }
    config::persistent_volume_mounted().then(|| PathBuf::from("/mnt/titan-api/carrier-watch"))
}

pub fn cbrslog_path() -> PathBuf {
    std::env::var_os("TITAN_CBRS_LOG")
        .map_or_else(|| PathBuf::from("/mnt/cbrslog0.txt"), PathBuf::from)
}

pub fn status_path() -> PathBuf {
    std::env::var_os("TITAN_CARRIER_STATUS")
        .map_or_else(|| PathBuf::from("/var/run/witcher-carrier.status"), PathBuf::from)
}

/// Read `carrier-watch/config` when present; default (`mode=log`) otherwise.
pub fn load_config() -> Config {
    let Some(dir) = config_dir() else {
        return Config::default();
    };
    let Ok(text) = fs::read_to_string(dir.join("config")) else {
        return Config::default();
    };
    carrier_watch::parse_config(&text)
}

/// Trigger the proven vendor re-grant sequence: `nvram_set 0 sqns_network_cbrs 1`
/// followed by `SIGUSR1` to `rcinit`.
pub fn trigger_regrant() -> Result<(), String> {
    crate::nvram::set("sqns_network_cbrs", "1")
        .map_err(|()| "nvram_set sqns_network_cbrs=1 failed".to_owned())?;
    crate::nvram::signal_rcinit().map_err(|()| "SIGUSR1 to rcinit failed".to_owned())
}

/// Incremental reader for `/mnt/cbrslog0.txt`.
pub struct CbrsLogTail {
    path: PathBuf,
    ino: Option<u64>,
    offset: u64,
    pending: Vec<u8>,
    pub parser: LogParser,
}

impl CbrsLogTail {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            ino: None,
            offset: 0,
            pending: Vec::new(),
            parser: LogParser::default(),
        }
    }

    /// Read any newly appended bytes, handling initial load, partial trailing
    /// lines, truncation, and inode-changing log rotation.
    pub fn poll(&mut self) {
        let Ok(mut file) = fs::File::open(&self.path) else {
            return;
        };
        let Ok(meta) = file.metadata() else {
            return;
        };
        let len = meta.len();
        let ino = meta.ino();

        let (start, limit, skip_first_partial) = match self.ino {
            None => {
                // First open: if cbrslog0.txt just rotated and is empty, seed
                // from sibling cbrslog1.txt when present.
                if len == 0 {
                    self.seed_from_rotated_sibling();
                }
                if len > MAX_INITIAL_READ {
                    (len - MAX_INITIAL_READ, MAX_INITIAL_READ, true)
                } else {
                    (0, MAX_INITIAL_READ, false)
                }
            }
            Some(prev_ino) if ino != prev_ino || len < self.offset => {
                self.pending.clear();
                self.parser.on_rotate();
                (0, CHUNK_READ, false)
            }
            Some(_) => (self.offset, CHUNK_READ, false),
        };

        self.ino = Some(ino);
        if len <= start {
            self.offset = len;
            return;
        }
        if file.seek(SeekFrom::Start(start)).is_err() {
            return;
        }
        let mut chunk = Vec::new();
        if (&mut file).take(limit).read_to_end(&mut chunk).is_err() {
            return;
        }
        self.offset = start + chunk.len() as u64;
        if chunk.is_empty() {
            return;
        }
        let slice = if skip_first_partial {
            match chunk.iter().position(|b| *b == b'\n') {
                Some(pos) => &chunk[pos + 1..],
                None => return,
            }
        } else {
            &chunk[..]
        };
        self.pending.extend_from_slice(slice);
        while let Some(end) = self.pending.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = self.pending.drain(..=end).collect();
            self.parser.push_line(&String::from_utf8_lossy(&line));
        }
        if self.pending.len() > MAX_PENDING_LINE {
            self.pending.clear();
        }
    }

    fn seed_from_rotated_sibling(&mut self) {
        let Some(name) = self.path.file_name().and_then(|n| n.to_str()) else {
            return;
        };
        let Some(prefix) = name.strip_suffix("0.txt") else {
            return;
        };
        let sibling = self.path.with_file_name(format!("{prefix}1.txt"));
        feed_whole_bounded(&sibling, &mut self.parser);
        self.parser.on_rotate();
    }
}

fn feed_whole_bounded(path: &Path, parser: &mut LogParser) {
    let Ok(mut file) = fs::File::open(path) else {
        return;
    };
    let Ok(len) = file.metadata().map(|m| m.len()) else {
        return;
    };
    let (start, skip_first) = if len > MAX_INITIAL_READ {
        (len - MAX_INITIAL_READ, true)
    } else {
        (0, false)
    };
    if file.seek(SeekFrom::Start(start)).is_err() {
        return;
    }
    let mut buf = Vec::new();
    if (&mut file).take(MAX_INITIAL_READ).read_to_end(&mut buf).is_err() {
        return;
    }
    let slice = if skip_first {
        match buf.iter().position(|b| *b == b'\n') {
            Some(pos) => &buf[pos + 1..],
            None => return,
        }
    } else {
        &buf[..]
    };
    for line in String::from_utf8_lossy(slice).lines() {
        parser.push_line(line);
    }
}
