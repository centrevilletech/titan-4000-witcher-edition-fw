//! The customer DHCP server: finding, stopping and starting `udhcpd -f
//! /tmp/udhcpd.conf` without touching the vendor's Wi-Fi server.

use std::fs;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use titan_sys::process::SpawnExt;

use crate::command::command_stdout;

use super::Keeper;

impl Keeper {
    pub(super) fn customer_dhcp_running(&self) -> bool {
        if self.dhcp_child.is_some() {
            return true;
        }
        if let Some(running) = customer_dhcp_running_proc() {
            return running;
        }
        !customer_dhcp_pids(&command_stdout("ps", &[])).is_empty()
    }
}

fn cmdline_is_customer_dhcp(bytes: &[u8]) -> bool {
    let args: Vec<&[u8]> = bytes
        .split(|&b| b == 0)
        .filter(|part| !part.is_empty())
        .collect();
    let Some(first) = args.first() else {
        return false;
    };
    let prog = first.rsplit(|&b| b == b'/').next().unwrap_or(first);
    if prog != b"udhcpd" {
        return false;
    }
    args.windows(2)
        .any(|pair| pair[0] == b"-f" && pair[1] == b"/tmp/udhcpd.conf")
}

/// Scan `/proc/<pid>/cmdline` without forking `ps`. Returns `None` if `/proc`
/// cannot be read so the caller can fall back to `ps`.
fn customer_dhcp_running_proc() -> Option<bool> {
    let entries = fs::read_dir("/proc").ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        if let Ok(cmdline) = fs::read(entry.path().join("cmdline")) {
            if cmdline_is_customer_dhcp(&cmdline) {
                return Some(true);
            }
        }
    }
    Some(false)
}

/// PIDs of the customer DHCP server. The wifi server is also named udhcpd, and
/// `killall udhcpd` would stop that one too.
pub(super) fn customer_dhcp_pids(listing: &str) -> Vec<i32> {
    listing
        .lines()
        .filter_map(|line| {
            if !line.contains("udhcpd -f /tmp/udhcpd.conf") {
                return None;
            }
            line.split_whitespace().next()?.parse().ok()
        })
        .collect()
}

pub(super) fn stop_customer_udhcpd() {
    let pids = customer_dhcp_pids(&command_stdout("ps", &[]));
    for pid in &pids {
        let _ = Command::new("kill").arg(pid.to_string()).status();
    }
    // setsid does not reparent the server, so the keeper must wait for it.
    // An unreaped restart every minute fills the process table with zombies.
    let deadline = std::time::Instant::now() + Duration::from_millis(200);
    let mut left = pids;
    while !left.is_empty() && std::time::Instant::now() < deadline {
        left.retain(|pid| matches!(titan_sys::process::try_reap(*pid), Ok(false)));
        if !left.is_empty() {
            thread::sleep(Duration::from_millis(20));
        }
    }
}

pub(super) fn spawn_udhcpd() -> Result<std::process::Child, String> {
    Command::new("/usr/sbin/udhcpd")
        .args(["-f", "/tmp/udhcpd.conf"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .new_session()
        .spawn()
        .map_err(|err| err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_wifi_dhcp_server_is_not_the_customer_one() {
        let listing = "\
  5721 root      1928 S    udhcpd -f /tmp/udhcpd.conf
  5723 root      1928 S    udhcpd -f /tmp/udhcpd_wifi.conf
  388 root      2672 S    /bin/sh -c grep udhcpd.conf
";
        assert_eq!(customer_dhcp_pids(listing), vec![5721]);
    }

    #[test]
    fn proc_cmdline_identifies_only_the_customer_udhcpd() {
        assert!(cmdline_is_customer_dhcp(
            b"/usr/sbin/udhcpd\0-f\0/tmp/udhcpd.conf\0"
        ));
        assert!(cmdline_is_customer_dhcp(b"udhcpd\0-f\0/tmp/udhcpd.conf\0"));
        assert!(!cmdline_is_customer_dhcp(
            b"/usr/sbin/udhcpd\0-f\0/tmp/udhcpd_wifi.conf\0"
        ));
        assert!(!cmdline_is_customer_dhcp(
            b"/bin/sh\0-c\0grep udhcpd.conf\0"
        ));
    }
}
