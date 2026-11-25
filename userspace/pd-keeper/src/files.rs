//! File helpers shared by the keeper's modules.

use std::fs;
use std::path::Path;

/// The file's text, or empty when it is missing, unreadable or not UTF-8.
pub fn read_file(path: impl AsRef<Path>) -> String {
    fs::read_to_string(path.as_ref()).unwrap_or_default()
}
