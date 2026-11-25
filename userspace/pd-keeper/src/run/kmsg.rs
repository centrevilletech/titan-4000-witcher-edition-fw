//! The kernel log, read without blocking, and what the keeper does with its
//! lines: the vendor kernel's external device (see `titan_pd_model::extdev`),
//! the management interface id, the IPv4 host MAC, PDN and firewall events,
//! and the flow control report.

use std::fs;
use std::io::Read;
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::path::Path;

use titan_pd_model::ethernet;
use titan_pd_model::extdev::{self, Action as ExtAction};
use titan_pd_model::host_mac;
use titan_pd_model::ipv4;
use titan_pd_model::mgmt;
use titan_pd_model::sas_nat;
use titan_pd_model::tk_flags;

use crate::log;
use crate::command::{command_stdout, run_status};
use crate::netdev::interface_mac;

use super::Keeper;

/// Kernel log records read per tick, so a long backlog cannot stall the loop.
const KMSG_PER_TICK: usize = 1024;

/// The kernel log, read without blocking. `/dev/kmsg` hands out one record per
/// read, starting with the oldest one still held, so the first ticks replay
/// what happened before the keeper started.
pub(super) struct KernelLog {
    file: fs::File,
    pending: Vec<u8>,
}

impl KernelLog {
    pub(super) fn open() -> Option<Self> {
        if let Ok(path) = std::env::var("TITAN_KMSG") {
            return Self::open_path(&path);
        }
        Self::open_path("/dev/kmsg").or_else(|| {
            // The vendor image ships no /dev/kmsg node. Character device 1,11
            // is the kernel log on Linux, so make one in RAM.
            let node = "/tmp/titan-kmsg";
            let _ = titan_sys::kernel::make_char_device(Path::new(node), 0o600, 1, 11);
            Self::open_path(node)
        })
    }

    /// Opened `O_RDONLY | O_NONBLOCK | O_CLOEXEC`: std adds `O_CLOEXEC`.
    fn open_path(path: &str) -> Option<Self> {
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(path)
            .ok()?;
        Some(Self {
            file,
            pending: Vec::new(),
        })
    }

    /// Character devices (`/dev/kmsg`, `/tmp/titan-kmsg`) support `poll(POLLIN)`
    /// cleanly. Regular files (used in tests) are always readable and must not
    /// be passed to `poll`.
    pub(super) fn is_pollable(&self) -> bool {
        self.file
            .metadata()
            .is_ok_and(|meta| meta.file_type().is_char_device())
    }

    /// Complete lines that have arrived since the last call, and whether the
    /// log was read to its end. At start the backlog takes a few ticks.
    fn lines(&mut self) -> (Vec<String>, bool) {
        let mut lines = Vec::new();
        let mut buf = [0u8; 4096];
        let mut drained = false;
        for _ in 0..KMSG_PER_TICK {
            match self.file.read(&mut buf) {
                Ok(0) => {
                    drained = true;
                    break;
                }
                Ok(read) => {
                    self.pending.extend_from_slice(&buf[..read]);
                    while let Some(end) = self.pending.iter().position(|byte| *byte == b'\n') {
                        let line: Vec<u8> = self.pending.drain(..=end).collect();
                        lines.push(String::from_utf8_lossy(&line).trim_end().to_owned());
                    }
                    if self.pending.len() > 16 * 1024 {
                        self.pending.clear();
                    }
                }
                // Records were overwritten before they were read. The next read resumes.
                Err(err) if matches!(err.raw_os_error(), Some(libc::EPIPE) | Some(libc::EINTR)) => {}
                // Nothing more for now (EAGAIN), or a log that cannot be read.
                Err(_) => {
                    drained = true;
                    break;
                }
            }
        }
        (lines, drained)
    }
}

impl AsFd for KernelLog {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.file.as_fd()
    }
}

impl Keeper {
    /// Follow the kernel log for the vendor kernel's external device, and in
    /// passthrough undo it being left on a management bearer. See
    /// `titan_pd_model::extdev`.
    pub(super) fn maintain_external_dev(&mut self) {
        let (lines, drained) = match self.kernel_log.as_mut() {
            Some(log) => log.lines(),
            None => return,
        };
        // Lines before the first full read are the boot backlog.
        let live = self.kmsg_drained;
        for line in lines {
            if live && tk_flags::modem_loaded(&line) {
                self.modem_restart_seen = true;
            }
            if let Some(iid) = mgmt::assigned_iid(&line) {
                self.mgmt_iid = Some(iid);
            }
            if let Some(event) = extdev::parse(&line) {
                self.ext_watch.note(event);
            }
            if let Some(stored) = host_mac::parse(&line) {
                self.host_mac_watch.note(stored);
            }
            match sas_nat::pdn_up(&line) {
                Some(dev) if dev == mgmt::MGMT_DEV => {
                    self.sas_watch.burst(self.now);
                    // Bring management IPv6 up on this tick, not up to 10 s later.
                    self.last_mgmt = 0;
                    self.mgmt_settled = false;
                }
                Some(_) => {
                    self.sas_watch.burst(self.now);
                    self.last_flood = 0;
                }
                None if sas_nat::firewall_restart(&line) => {
                    self.sas_watch.burst(self.now);
                    self.last_flood = 0;
                }
                None => {}
            }
            if let Some(efc) = ethernet::efc(&line) {
                self.flow_report(efc);
            }
        }
        self.kmsg_drained |= drained;
        // `bridged` is how the keeper knows the vendor's bearer setup is over.
        let ready = self.passthrough && self.bridged && drained;
        let settled = self
            .bridged_since
            .is_some_and(|since| self.now.saturating_sub(since) >= extdev::SETTLE);
        let customer = self.bearer.clone();
        if let ExtAction::Repair(dev) = self.ext_watch.decide(self.now, ready, settled, &customer) {
            self.note(&format!(
                "external device guard: the vendor kernel left {dev} as its external device in IP passthrough; clearing it and restoring the bearer's own MAC"
            ));
            self.repair_external_dev(&dev);
            // Close the management bearer to advertisements now, so a second
            // one cannot set the external device again before the next check.
            self.last_mgmt = 0;
            self.mgmt_settled = false;
        }
    }

    /// `kern netif extdev <dev> down`, then the bearer's own MAC. Both leave a
    /// healthy unit unchanged.
    pub(super) fn repair_external_dev(&mut self, dev: &str) {
        let Some(mac) = interface_mac(dev) else {
            self.note(&format!(
                "external device guard: {dev} has no MAC to restore"
            ));
            return;
        };
        for (program, args) in extdev::repair_commands(dev, &ipv4::mac_text(mac)) {
            let args: Vec<&str> = args.iter().map(String::as_str).collect();
            if let Err(err) = run_status(program, &args) {
                self.note(&format!("external device guard: {err}"));
            }
        }
    }
}

// SYSLOG_ACTION_SIZE_BUFFER and READ_ALL leave the ring and other readers alone.
pub(super) fn kernel_messages() -> String {
    if let Ok(size) = titan_sys::kernel::log_buffer_size() {
        if (1..=4 * 1024 * 1024).contains(&size) {
            let mut buffer = vec![0; size];
            if let Ok(read) = titan_sys::kernel::read_log_buffer(&mut buffer) {
                return String::from_utf8_lossy(&buffer[..read]).into_owned();
            }
        }
    }
    command_stdout("dmesg", &[])
}
