//! Writes that survive a power cut: write a temporary file and sync it,
//! rename it over the old one, then sync the directory. A cut at any moment
//! leaves either the old contents or the new ones, never a torn file.

use std::fs;
use std::io::{self, Write};
use std::path::Path;

/// Replace `path` with `bytes` through the temporary file `temp`.
pub fn write(path: &Path, temp: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = fs::File::create(temp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    replace(temp, path)
}

/// The end of a durable write, for a file written and synced some other way
/// (streamed, say), or one renamed into place: rename `temp` over `path`,
/// then sync the directory.
pub fn replace(temp: &Path, path: &Path) -> io::Result<()> {
    fs::rename(temp, path)?;
    match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => fs::File::open(dir)?.sync_all(),
        _ => Ok(()),
    }
}
