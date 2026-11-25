//! The keeper's two logs: `keeper.log` on flash for real events, and its RAM
//! copy, which holds every line. See `titan_pd_model::wear`.

use std::fs;
use std::io::Write;
use std::path::Path;

use titan_pd_model::wear;

use crate::clock::unix_now;
use crate::paths::{runtime_dir, state_dir};

/// A real event: the flash log (`keeper.log` in the state directory) and the
/// RAM log, which holds every line.
pub fn log(line: &str) {
    let text = stamped(line);
    let state = state_dir();
    append(&state, &text, wear::FLASH_LOG_BYTES);
    if runtime_dir() != state {
        append(&runtime_dir(), &text, wear::RAM_LOG_BYTES);
    }
    eprintln!("{line}");
}

/// A routine line: the RAM log only, so it never wears the flash.
pub fn log_ram(line: &str) {
    append(&runtime_dir(), &stamped(line), wear::RAM_LOG_BYTES);
}

fn stamped(line: &str) -> String {
    let up = fs::read_to_string("/proc/uptime").unwrap_or_default();
    let up = up.split_whitespace().next().unwrap_or("?").to_owned();
    format!("{} up={up} {line}", unix_now())
}

/// Append one line, moving a full log to `keeper.log.1` first.
fn append(dir: &Path, text: &str, cap: u64) {
    let path = dir.join("keeper.log");
    let _ = fs::create_dir_all(dir);
    if fs::metadata(&path).is_ok_and(|meta| meta.len() > cap) {
        let _ = fs::rename(&path, dir.join("keeper.log.1"));
    }
    if let Ok(mut file) = fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(file, "{text}");
    }
}
