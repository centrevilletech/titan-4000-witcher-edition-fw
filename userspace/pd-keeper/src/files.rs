//! File helpers shared by the keeper's modules.

use std::fs;
use std::path::Path;

/// Durable writes (`titan_pd_model::durable`): write and sync a temporary
/// file, rename it over the old one, then sync the directory, so a power cut
/// leaves either the old contents or the new ones.
pub use titan_pd_model::durable::{replace as replace_durably, write as write_durably};

/// The file's text, or empty when it is missing, unreadable or not UTF-8.
pub fn read_file(path: impl AsRef<Path>) -> String {
    fs::read_to_string(path.as_ref()).unwrap_or_default()
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
