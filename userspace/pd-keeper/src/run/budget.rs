//! The Ethernet action budget the IPv6 and IPv4 checks share, kept on
//! flash so a keeper restart cannot reset it, and the one action it pays for.

use std::fs;
use std::io;

use crate::files::read_file;
use crate::paths::state_dir;

use super::{CUSTOMER, Keeper};

impl Keeper {
    pub(super) fn budget_tuple(&self) -> (u32, u64, u64) {
        (
            self.health.link_drops,
            self.health.window_start,
            self.health.quiet_until,
        )
    }

    pub(super) fn load_budget(&mut self) {
        let text = read_file(state_dir().join("budget.txt"));
        for line in text.lines() {
            if let Some((key, value)) = line.split_once('=') {
                let Ok(value) = value.trim().parse::<u64>() else {
                    continue;
                };
                match key.trim() {
                    "link_drops" => {
                        self.health.link_drops = u32::try_from(value).unwrap_or(u32::MAX)
                    }
                    "window_start" => self.health.window_start = value,
                    "quiet_until" => self.health.quiet_until = value,
                    _ => {}
                }
            }
        }
    }

    pub(super) fn save_budget(&mut self) -> bool {
        let path = state_dir().join("budget.txt");
        let text = format!(
            "link_drops={}\nwindow_start={}\nquiet_until={}\n",
            self.health.link_drops, self.health.window_start, self.health.quiet_until
        );
        if read_file(&path) != text {
            if let Some(parent) = path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let temporary = path.with_extension("new");
            let saved = (|| -> io::Result<()> {
                fs::write(&temporary, &text)?;
                fs::File::open(&temporary)?.sync_all()?;
                fs::rename(&temporary, &path)?;
                fs::File::open(
                    path.parent()
                        .ok_or_else(|| io::Error::other("no budget directory"))?,
                )?
                .sync_all()
            })();
            if saved.is_err() {
                return false;
            }
        }
        let ok = read_file(&path) == text;
        if ok {
            self.saved_budget = Some(self.budget_tuple());
        }
        ok
    }
}

/// What a link-drop budget step runs. One PHY renegotiation. Not a burst,
/// and not an administrative carrier down, which this router ignores.
pub(super) fn link_recovery() -> (&'static str, &'static [&'static str]) {
    ("mii-tool", &["-r", CUSTOMER])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_recovery_is_one_renegotiation() {
        let (program, args) = link_recovery();
        assert_eq!(program, "mii-tool");
        assert_eq!(args, ["-r", "eth0"]);
    }
}
