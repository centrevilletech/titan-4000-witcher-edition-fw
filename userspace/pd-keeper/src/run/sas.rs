//! The vendor SNAT rule for the unit's own SAS traffic, put back when a
//! vendor firewall restart removes it. See `titan_pd_model::sas_nat`.

use std::fs;
use std::path::PathBuf;

use titan_pd_model::sas_nat::{self, Action as SasAction};

use crate::command::{command_stdout, run_status};

use super::Keeper;

/// Bytes read from a vendor log per call, so a large backlog cannot stall a tick.
const TAIL_READ: u64 = 64 * 1024;

/// A vendor log file, read from where the keeper left off. Lines already in
/// the file when it is first opened are history and are skipped. `rcinit`
/// caps its log at 64 KB and then starts it again empty, so a file shorter
/// than the offset is read from the start.
pub(super) struct FileTail {
    path: PathBuf,
    offset: Option<u64>,
    pending: Vec<u8>,
}

impl FileTail {
    pub(super) fn new(path: PathBuf) -> Self {
        let mut tail = Self {
            path,
            offset: None,
            pending: Vec::new(),
        };
        let _ = tail.lines();
        tail
    }

    /// Complete lines added since the last call.
    fn lines(&mut self) -> Vec<String> {
        use std::io::{Read, Seek, SeekFrom};
        let Ok(mut file) = fs::File::open(&self.path) else {
            return Vec::new();
        };
        let Ok(len) = file.metadata().map(|meta| meta.len()) else {
            return Vec::new();
        };
        let start = match self.offset {
            None => {
                self.offset = Some(len);
                return Vec::new();
            }
            Some(at) if len < at => {
                self.pending.clear();
                0
            }
            Some(at) => at,
        };
        if len == start {
            self.offset = Some(len);
            return Vec::new();
        }
        let mut chunk = Vec::new();
        if file.seek(SeekFrom::Start(start)).is_err()
            || (&mut file).take(TAIL_READ).read_to_end(&mut chunk).is_err()
        {
            return Vec::new();
        }
        self.offset = Some(start + chunk.len() as u64);
        self.pending.extend_from_slice(&chunk);
        let mut lines = Vec::new();
        while let Some(end) = self.pending.iter().position(|byte| *byte == b'\n') {
            let line: Vec<u8> = self.pending.drain(..=end).collect();
            lines.push(String::from_utf8_lossy(&line).trim_end().to_owned());
        }
        if self.pending.len() > 16 * 1024 {
            self.pending.clear();
        }
        lines
    }
}

impl Keeper {
    /// Keep the vendor SNAT rule for the unit's own SAS traffic. A vendor
    /// firewall restart after a handover removes it, and in this build nothing
    /// else puts it back. Restores only after missing checks in a row, checked
    /// every 10 s, or every second for 30 s after a PDN comes up, a vendor log
    /// line that comes before a firewall restart, or any missing check.
    pub(super) fn maintain_sas_nat(&mut self, routes: &str) {
        self.follow_rcinit_log();
        let interval = self.sas_watch.interval(self.now);
        if self
            .last_sas_check
            .is_some_and(|last| self.now.saturating_sub(last) < interval)
        {
            return;
        }
        self.last_sas_check = Some(self.now);
        let local_ip = self.nvram_get_cached("lan_management_ipaddr");
        let data_ip = self.nvram_get_cached("pdn_data_ipaddr");
        let snat = sas_nat::needed(&local_ip, &data_ip, routes);
        let present = snat.and_then(|snat| {
            sas_nat::present(
                &command_stdout("iptables", &["-t", "nat", "-S", "POSTROUTING"]),
                snat,
            )
        });
        let SasAction::Restore(snat) = self.sas_watch.observe(self.now, snat, present) else {
            return;
        };
        let when = if self.sas_watch.bursting(self.now) {
            "missing for 2 s in a row"
        } else {
            "missing twice in a row"
        };
        self.note(&format!(
            "SAS NAT rule {when}; restoring SNAT from {} to {} so the SAS client can reach the SAS",
            snat.local, snat.bearer
        ));
        for (program, args) in sas_nat::restore_commands(snat) {
            let args: Vec<&str> = args.iter().map(String::as_str).collect();
            if let Err(err) = run_status(program, &args) {
                self.note(&format!(
                    "SAS NAT restore failed; retrying in {} s: {err}",
                    sas_nat::RETRY
                ));
                return;
            }
        }
        // Read it back at once. rcinit can flush the table again within a
        // second, before the next check; a restore seen working may repeat
        // after 5 s instead of waiting a minute.
        let back = sas_nat::present(
            &command_stdout("iptables", &["-t", "nat", "-S", "POSTROUTING"]),
            snat,
        );
        if back == Some(true) {
            self.sas_watch.confirm();
            self.note("SAS NAT rule restored");
        } else {
            self.note("SAS NAT rule restored, but it was not in the table when read back");
        }
    }

    /// `rcinit` logs `CBRS LTE Freq changed !` (an in-connection carrier
    /// change) or `Restart service=[cbrs]` just before it rebuilds its
    /// firewall and flushes the SAS SNAT rule. Neither PDN goes down, so the
    /// kernel log has no line for it. Read once a second.
    fn follow_rcinit_log(&mut self) {
        if self.rcinit_read_at == Some(self.now) {
            return;
        }
        self.rcinit_read_at = Some(self.now);
        if self
            .rcinit_log
            .lines()
            .iter()
            .any(|line| sas_nat::firewall_restart(line))
        {
            self.sas_watch.burst(self.now);
            self.last_flood = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_vendor_log_is_followed_from_its_end_and_again_after_a_reset() {
        use std::io::Write;
        let path = std::env::temp_dir().join(format!("witcher-tail-{}", std::process::id()));
        fs::write(&path, " 4:00:00 >|service.c 500 >|   info >| CBRS LTE Freq changed !\n").unwrap();
        let mut tail = FileTail::new(path.clone());
        // What was there before the keeper started is history.
        assert!(tail.lines().is_empty());
        let mut file = fs::OpenOptions::new().append(true).open(&path).unwrap();
        write!(file, " 4:58:41 >|service.c 500 >|   info >| CBRS LTE").unwrap();
        assert!(tail.lines().is_empty(), "half a line waits for the rest");
        writeln!(file, " Freq changed !").unwrap();
        assert_eq!(
            tail.lines(),
            vec![" 4:58:41 >|service.c 500 >|   info >| CBRS LTE Freq changed !".to_owned()]
        );
        assert!(tail.lines().is_empty());
        // rcinit caps its log at 64 KB and then starts it again empty.
        fs::write(&path, " 0:00:01 >|service.c 528 >|   info >| Restart service=[cbrs]\n").unwrap();
        assert_eq!(
            tail.lines(),
            vec![" 0:00:01 >|service.c 528 >|   info >| Restart service=[cbrs]".to_owned()]
        );
        let _ = fs::remove_file(&path);
    }
}
