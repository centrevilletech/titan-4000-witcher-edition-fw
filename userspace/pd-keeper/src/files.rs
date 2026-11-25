//! File helpers shared by the keeper's modules.

use std::fs;
use std::io::{self, Write};
use std::path::Path;

/// The file's text, or empty when it is missing, unreadable or not UTF-8.
pub fn read_file(path: impl AsRef<Path>) -> String {
    fs::read_to_string(path.as_ref()).unwrap_or_default()
}

/// Replace `path` with `bytes` through the temporary file `temp`: write and
/// sync it, rename it over `path`, then sync the directory, so a power cut
/// leaves either the old contents or the new ones.
pub fn write_durably(path: &Path, temp: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = fs::File::create(temp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    replace_durably(temp, path)
}

/// The end of a durable write, for a file written and synced some other way
/// (streamed, say): rename `temp` over `path`, then sync the directory.
pub fn replace_durably(temp: &Path, path: &Path) -> io::Result<()> {
    fs::rename(temp, path)?;
    match path.parent() {
        Some(dir) => fs::File::open(dir)?.sync_all(),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_durable_write_replaces_the_file_and_leaves_no_temporary() {
        let dir = std::env::temp_dir().join(format!("witcher-files-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("budget.txt");
        let temp = path.with_extension("new");
        fs::write(&path, "old\n").unwrap();
        write_durably(&path, &temp, b"new\n").unwrap();
        assert_eq!(read_file(&path), "new\n");
        assert!(!temp.exists());
        assert_eq!(read_file(dir.join("missing")), "");
        let _ = fs::remove_dir_all(&dir);
    }
}
