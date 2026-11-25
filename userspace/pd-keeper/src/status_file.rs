//! RAM status files the keeper rewrites only when what they say changes.

use std::fs;
use std::path::Path;

/// The body a status file last carried.
#[derive(Debug, Default)]
pub struct StatusFile {
    body: String,
}

impl StatusFile {
    /// Nothing has been written yet.
    pub fn is_blank(&self) -> bool {
        self.body.is_empty()
    }

    /// Write `render(body)` to `path` when `body` differs from the last one,
    /// or when `force` is set, and say whether it did. A write error is
    /// ignored: the file is for the operator, and the next change rewrites it.
    pub fn update(
        &mut self,
        path: impl AsRef<Path>,
        body: String,
        force: bool,
        render: impl FnOnce(&str) -> String,
    ) -> bool {
        if body == self.body && !force {
            return false;
        }
        self.body = body;
        let _ = fs::write(path, render(&self.body));
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_status_file_is_rewritten_only_on_news_or_when_forced() {
        let path = std::env::temp_dir().join(format!("witcher-status-{}", std::process::id()));
        let mut status = StatusFile::default();
        assert!(status.is_blank());
        assert!(status.update(&path, "state=on\n".into(), false, |body| format!("{body}updated=1\n")));
        assert_eq!(fs::read_to_string(&path).unwrap(), "state=on\nupdated=1\n");
        assert!(!status.update(&path, "state=on\n".into(), false, |_| unreachable!()));
        assert!(status.update(&path, "state=on\n".into(), true, |body| format!("{body}updated=2\n")));
        assert_eq!(fs::read_to_string(&path).unwrap(), "state=on\nupdated=2\n");
        assert!(status.update(&path, "state=off\n".into(), false, |body| body.to_owned()));
        assert_eq!(fs::read_to_string(&path).unwrap(), "state=off\n");
        assert!(!status.is_blank());
        let _ = fs::remove_file(&path);
    }
}
