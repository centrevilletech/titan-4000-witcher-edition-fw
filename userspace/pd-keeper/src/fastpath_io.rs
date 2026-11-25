//! Staging, loading, `/proc/k1fp` control, and SAS grant lease feeding for
//! `titan_pd_model::fastpath`.
//!
//! The rootfs has no room for `titan_k1fp.ko`, so an operator stages it in
//! `/mnt/titan-api/fastpath` with a `config`. Only bytes matching the SHA-256
//! digest built into the keeper (`device/fastpath/SHA256SUMS`) are copied into
//! the keeper's private RAM directory and loaded from there.

use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write as _};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use titan_pd_model::cbrs_gate::{self, Gate, Step as GateStep};
use titan_pd_model::config;
use titan_pd_model::fastpath::{
    self, Config, LeaseAction, LeaseState, Loaded, Proc, StatusView, TripAction, TripWatch,
};
use titan_pd_model::sha256;

use crate::files::read_file;
use crate::netdev::{bridge_ports, carrier_up};

const MANIFEST: &str = include_str!("../../../device/fastpath/SHA256SUMS");

/// The staged module and its config, only while the volume is mounted.
pub fn staged_dir() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("TITAN_FASTPATH_DIR") {
        return Some(PathBuf::from(path));
    }
    config::persistent_volume_mounted().then(|| PathBuf::from("/mnt/titan-api/fastpath"))
}

pub fn proc_path() -> String {
    std::env::var("TITAN_FASTPATH_PROC").unwrap_or_else(|_| "/proc/k1fp".into())
}

/// Separate write target only when tests point it at a control pipe. On a real
/// unit this is `/proc/k1fp`.
pub fn proc_write_path() -> String {
    std::env::var("TITAN_FASTPATH_PROC_WRITE").unwrap_or_else(|_| proc_path())
}

pub fn modules_path() -> String {
    std::env::var("TITAN_PROC_MODULES").unwrap_or_else(|_| "/proc/modules".into())
}

pub fn status_path() -> String {
    std::env::var("TITAN_FASTPATH_STATUS")
        .unwrap_or_else(|_| "/var/run/witcher-fastpath.status".into())
}

fn insmod_program() -> String {
    std::env::var("TITAN_INSMOD").unwrap_or_else(|_| "insmod".into())
}

/// The digest built into this keeper.
pub fn pinned() -> Option<&'static str> {
    sha256::pinned(MANIFEST, fastpath::FILE)
}

fn short(sha: &str) -> &str {
    sha.get(..12).unwrap_or(sha)
}

/// Copy the staged module into RAM once its bytes match the pinned digest,
/// check the copy again, and return its path.
pub fn stage(dir: &Path) -> Result<PathBuf, String> {
    let want = pinned().ok_or("the keeper's fastpath manifest has no titan_k1fp.ko line")?;
    let source = dir.join(fastpath::FILE);
    let bytes =
        fs::read(&source).map_err(|e| format!("{} is not staged: {e}", source.display()))?;
    let got = sha256::hex(&sha256::digest(&bytes));
    if got != want {
        return Err(format!(
            "{} has SHA-256 {}, not the pinned {}",
            source.display(),
            short(&got),
            short(want)
        ));
    }
    let run = crate::paths::runtime_dir().join("fastpath");
    if !run.is_dir() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&run)
            .map_err(|e| format!("cannot create {}: {e}", run.display()))?;
    }
    let dest = run.join(fastpath::FILE);
    let tmp = run.join(format!(".{}.{}", fastpath::FILE, std::process::id()));
    let _ = fs::remove_file(&tmp);
    let written = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .and_then(|mut file| {
            file.write_all(&bytes)?;
            file.sync_all()
        })
        .and_then(|()| fs::rename(&tmp, &dest));
    if let Err(e) = written {
        let _ = fs::remove_file(&tmp);
        return Err(format!("cannot copy the module into RAM: {e}"));
    }
    let copy = fs::read(&dest).map_err(|e| format!("cannot read the RAM copy: {e}"))?;
    if sha256::hex(&sha256::digest(&copy)) != want {
        let _ = fs::remove_file(&dest);
        return Err("the RAM copy does not match the pinned digest".into());
    }
    Ok(dest)
}

pub fn insmod(path: &Path) -> Result<(), String> {
    let out = Command::new(insmod_program())
        .arg(path)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("insmod did not run: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    let why = String::from_utf8_lossy(&out.stderr).trim().to_owned();
    Err(if why.is_empty() {
        format!("insmod failed ({})", out.status)
    } else {
        format!("insmod failed: {why}")
    })
}

/// One small `write()` to `/proc/k1fp` (no process spawns, fd closed at once
/// so `rmmod titan_k1fp` is never blocked by an open proc file handle).
fn write_proc_cmd(cmd: &str) -> std::io::Result<()> {
    let path = proc_write_path();
    OpenOptions::new()
        .write(true)
        .open(&path)
        .and_then(|mut file| file.write_all(cmd.as_bytes()))
}

fn read_proc_after_mode_write(want: u32) -> Proc {
    let proc = fastpath::parse_proc(&read_file(Path::new(&proc_path())));
    if proc.ours && proc.mode == Some(want) {
        return proc;
    }
    // On a real kernel `/proc/k1fp` updates synchronously on the first read.
    // A brief retry covers a test control pipe updating a stand-in file.
    thread::sleep(Duration::from_millis(50));
    fastpath::parse_proc(&read_file(Path::new(&proc_path())))
}

fn read_proc_after_grant_open() -> Proc {
    let proc = fastpath::parse_proc(&read_file(Path::new(&proc_path())));
    if proc.ours && proc.gate_open == Some(true) {
        return proc;
    }
    thread::sleep(Duration::from_millis(50));
    fastpath::parse_proc(&read_file(Path::new(&proc_path())))
}

fn read_proc_after_grant_close() -> Proc {
    let proc = fastpath::parse_proc(&read_file(Path::new(&proc_path())));
    if proc.ours && proc.gate_open == Some(false) {
        return proc;
    }
    thread::sleep(Duration::from_millis(50));
    fastpath::parse_proc(&read_file(Path::new(&proc_path())))
}

/// Fast path lifecycle and grant-lease state for one keeper process.
#[derive(Default)]
pub struct Watch {
    checked_at: Option<u64>,
    /// Both `eth0` and `lte0pdn2` were up and in `br0` in passthrough since then.
    up_since: Option<u64>,
    /// Last logged `state: detail`, so log lines emit only on state/detail change.
    shown: String,
    /// Last rendered status body (without `updated=`), so the status file is
    /// rewritten whenever state, detail, mode, active_mode, gate, qctrl_present,
    /// wd_trips, or wd_reason changes.
    status_body: String,
    /// A load failed for this config; not retried until config changes or reboot.
    failed_for: Option<Config>,
    refused_logged: Vec<String>,
    /// True while our `titan_k1fp v2.2` module is loaded.
    module_loaded: bool,
    /// True once `maintain()` has loaded or adopted the currently loaded module.
    managed: bool,
    /// True while loaded, configured `mode > 0`, bridge ready, and not tripped.
    active_for_lease: bool,
    lease_state: LeaseState,
    qctrl_present: Option<bool>,
    trip: TripWatch,
}

impl Watch {
    /// Called from `maintain_cbrs_gate()` immediately after `cbrs_gate::Watch::observe()`,
    /// BEFORE logging or running `ebtables`/`ip6tables`.
    ///
    /// Performs at most one small `write()` to `/proc/k1fp` and spawns no processes.
    pub fn on_gate(&mut self, gate: &Gate, step: GateStep) {
        let mut loaded = self.module_loaded;
        if !loaded && self.lease_state == LeaseState::Unknown && step == GateStep::Close {
            // Handle a keeper restart or hand-loaded module before the first
            // `maintain()` tick runs without suppressing the adoption log.
            let text = read_file(Path::new(&proc_path()));
            if fastpath::parse_proc(&text).ours {
                loaded = true;
            }
        }
        if !loaded {
            return;
        }
        let action = fastpath::lease_decision(gate, step, self.lease_state, self.active_for_lease);
        let Some(cmd) = fastpath::lease_command(action) else {
            return;
        };
        let prev_lease = self.lease_state;
        match write_proc_cmd(&cmd) {
            Ok(()) => match action {
                LeaseAction::Renew(_) => self.lease_state = LeaseState::Open,
                LeaseAction::Revoke => self.lease_state = LeaseState::Revoked,
                LeaseAction::Hold => {}
            },
            Err(err) if err.kind() == ErrorKind::NotFound => {
                self.module_loaded = false;
                self.managed = false;
                self.active_for_lease = false;
                self.lease_state = LeaseState::Unknown;
            }
            Err(_) => {}
        }
        if self.lease_state != prev_lease {
            // Re-read /proc/k1fp on this same tick so witcher-fastpath.status
            // reflects the new gate state immediately.
            self.checked_at = None;
        }
    }

    /// Periodic config, staging, load, bridge check, `qctrl_present` tracking,
    /// and watchdog awareness. Must run AFTER `maintain_qctrl()`.
    pub fn maintain(
        &mut self,
        now: u64,
        passthrough: bool,
        qctrl_waiting: bool,
        nvram_cache_path: &Path,
        mut note: impl FnMut(&str),
    ) {
        if self
            .checked_at
            .is_some_and(|at| now.saturating_sub(at) < fastpath::CHECK_EVERY)
        {
            return;
        }
        self.checked_at = Some(now);

        let Some(dir) = staged_dir() else {
            self.module_loaded = false;
            self.managed = false;
            self.active_for_lease = false;
            self.publish(
                "off",
                "the persistent volume is not mounted",
                &Config::default(),
                None,
                false,
                now,
                &mut note,
            );
            return;
        };

        let config = fastpath::parse_config(&read_file(&dir.join("config")));
        if config.refused != self.refused_logged {
            for line in &config.refused {
                note(&format!(
                    "fast path: ignored {line:?} in fastpath/config (allowed: mode=0|1|2|3)"
                ));
            }
            self.refused_logged = config.refused.clone();
        }

        let ports = bridge_ports();
        let shape_ok = fastpath::bridge_shape_ok(ports.iter().map(String::as_str));
        let links_up =
            passthrough && shape_ok && carrier_up(fastpath::LAN) && carrier_up(fastpath::WAN);
        if !links_up {
            self.up_since = None;
        } else if self.up_since.is_none() {
            self.up_since = Some(now);
        }

        let proc_text = read_file(Path::new(&proc_path()));
        let modules_text = read_file(Path::new(&modules_path()));
        let adopted = match fastpath::loaded(&modules_text, &proc_text) {
            Loaded::Other(name) => {
                self.module_loaded = false;
                self.managed = false;
                self.active_for_lease = false;
                let (state, detail) = if config.mode == 0 {
                    (
                        "off",
                        format!("mode 0; another fast path module is loaded ({name})"),
                    )
                } else {
                    (
                        "failed",
                        format!(
                            "another fast path module is loaded ({name}); not loading {}",
                            fastpath::MODULE
                        ),
                    )
                };
                self.publish(state, &detail, &config, None, false, now, &mut note);
                return;
            }
            Loaded::None => {
                self.module_loaded = false;
                self.managed = false;
                self.active_for_lease = false;
                self.qctrl_present = None;
                self.trip.note_paused();
                if config.mode == 0 {
                    self.publish(
                        "off",
                        "mode 0 or no fastpath/config",
                        &config,
                        None,
                        false,
                        now,
                        &mut note,
                    );
                    return;
                }
                if !passthrough {
                    self.publish(
                        "off",
                        "not in IP passthrough",
                        &config,
                        None,
                        false,
                        now,
                        &mut note,
                    );
                    return;
                }
                if !shape_ok {
                    self.publish(
                        "waiting",
                        &format!("bridge shape not ready: {}", fastpath::describe_bridge(&ports)),
                        &config,
                        None,
                        false,
                        now,
                        &mut note,
                    );
                    return;
                }
                if qctrl_waiting {
                    self.publish(
                        "waiting",
                        "for the download clamp to load first",
                        &config,
                        None,
                        false,
                        now,
                        &mut note,
                    );
                    return;
                }
                if !fastpath::settled(self.up_since, now) {
                    self.publish(
                        "waiting",
                        &format!(
                            "for {} and {} to stay up {} s in IP passthrough",
                            fastpath::LAN,
                            fastpath::WAN,
                            fastpath::SETTLE_SECS
                        ),
                        &config,
                        None,
                        false,
                        now,
                        &mut note,
                    );
                    return;
                }
                if self.failed_for.as_ref() == Some(&config) {
                    return;
                }
                if let Err(err) = stage(&dir).and_then(|path| insmod(&path)) {
                    self.failed_for = Some(config.clone());
                    self.publish(
                        "failed",
                        &format!("not loaded: {err}"),
                        &config,
                        None,
                        false,
                        now,
                        &mut note,
                    );
                    return;
                }
                note(&format!(
                    "fast path: loaded {} from the staged copy",
                    fastpath::VERSION_LINE
                ));
                self.module_loaded = true;
                self.managed = true;
                self.lease_state = LeaseState::Revoked;
                false
            }
            Loaded::Ours => {
                let first = !self.managed;
                self.module_loaded = true;
                self.managed = true;
                self.failed_for = None;
                if first {
                    note("fast path: adopted a loaded module");
                }
                first
            }
        };

        let proc = fastpath::parse_proc(&read_file(Path::new(&proc_path())));
        if !proc.ours {
            self.module_loaded = false;
            self.managed = false;
            self.active_for_lease = false;
            self.failed_for = Some(config.clone());
            self.publish(
                "failed",
                &format!("/proc/k1fp does not show {}", fastpath::VERSION_LINE),
                &config,
                None,
                false,
                now,
                &mut note,
            );
            return;
        }

        let mut qctrl_changed = false;
        if let Some(present) = proc.qctrl_present {
            if self.qctrl_present.is_some_and(|prev| prev != present) {
                qctrl_changed = true;
                if present {
                    note("fast path: download clamp detected (qctrl_present=1); downlink invokes clamp, uplink TCP yields to stock");
                } else {
                    note("fast path: download clamp unloaded (qctrl_present=0)");
                }
            }
            self.qctrl_present = Some(present);
        }

        // Only allow non-zero mode in IP passthrough with the exact bridge shape
        // and ports_ok=1 lan_hooked=1 wan_hooked=1. Anything else stays at mode 0.
        if config.mode > 0 && (!passthrough || !shape_ok || !proc.bridge_ready()) {
            let reason = if !passthrough {
                "leaving mode 0: not in IP passthrough".to_owned()
            } else if !shape_ok {
                format!("leaving mode 0: {}", fastpath::describe_bridge(&ports))
            } else {
                format!("leaving mode 0: bridge not ready ({})", proc.bridge_issue())
            };
            self.active_for_lease = false;
            self.trip.note_paused();
            let revoked = self.revoke_if_open();
            let proc = if proc.mode != Some(0) {
                let _ = write_proc_cmd("mode 0\n");
                read_proc_after_mode_write(0)
            } else if revoked {
                read_proc_after_grant_close()
            } else {
                proc
            };
            self.publish(
                "off",
                &reason,
                &config,
                Some(&proc),
                qctrl_changed,
                now,
                &mut note,
            );
            return;
        }

        let action = self.trip.evaluate(&config, &proc);
        if self.trip.take_device_event() {
            note(&format!(
                "fast path: a bridge device was recreated (dev_gone={}, reacq={}); the module is at mode 0 and the keeper applies mode {} again",
                proc.dev_gone.unwrap_or(0),
                proc.reacq.unwrap_or(0),
                config.mode
            ));
        }
        match action {
            TripAction::Normal => {
                self.active_for_lease = config.mode > 0;
                let mut proc = proc;
                if config.mode == 0 {
                    if self.revoke_if_open() {
                        proc = read_proc_after_grant_close();
                    }
                } else if (adopted || self.lease_state != LeaseState::Open)
                    && self.renew_if_grant_held(nvram_cache_path)
                {
                    proc = read_proc_after_grant_open();
                }
                let (state, detail) = if config.mode == 0 {
                    ("off", "mode 0 read back from /proc/k1fp".to_owned())
                } else {
                    (
                        "applied",
                        format!("mode {} read back from /proc/k1fp", config.mode),
                    )
                };
                self.publish(
                    state,
                    &detail,
                    &config,
                    Some(&proc),
                    adopted || qctrl_changed,
                    now,
                    &mut note,
                );
            }
            TripAction::Apply => {
                if let Err(err) = write_proc_cmd(&format!("mode {}\n", config.mode)) {
                    self.active_for_lease = false;
                    self.publish(
                        "failed",
                        &format!("cannot write mode {} to /proc/k1fp: {err}", config.mode),
                        &config,
                        Some(&proc),
                        false,
                        now,
                        &mut note,
                    );
                    return;
                }
                let mut proc = read_proc_after_mode_write(config.mode);
                if !fastpath::matches(&config, &proc) {
                    let shown = proc
                        .mode
                        .map_or_else(|| "nothing".to_owned(), |m| m.to_string());
                    self.active_for_lease = false;
                    self.publish(
                        "failed",
                        &format!("mode {} did not read back (shows {shown})", config.mode),
                        &config,
                        Some(&proc),
                        false,
                        now,
                        &mut note,
                    );
                    return;
                }
                self.trip.note_applied(config.mode, &proc);
                self.active_for_lease = config.mode > 0;
                if config.mode == 0 {
                    if self.revoke_if_open() {
                        proc = read_proc_after_grant_close();
                    }
                } else if self.renew_if_grant_held(nvram_cache_path) {
                    proc = read_proc_after_grant_open();
                }
                let (state, detail) = if config.mode == 0 {
                    ("off", "mode 0 read back from /proc/k1fp".to_owned())
                } else {
                    (
                        "applied",
                        format!("mode {} read back from /proc/k1fp", config.mode),
                    )
                };
                self.publish(
                    state,
                    &detail,
                    &config,
                    Some(&proc),
                    qctrl_changed,
                    now,
                    &mut note,
                );
            }
            TripAction::Rearm { reason } => {
                note(&format!(
                    "fast path: {reason}; re-arming mode {} (automatic re-arm {} of {})",
                    config.mode,
                    self.trip.rearms(),
                    fastpath::MAX_AUTO_REARMS
                ));
                if let Err(err) = write_proc_cmd(&format!("mode {}\n", config.mode)) {
                    self.active_for_lease = false;
                    self.publish(
                        "failed",
                        &format!("cannot re-arm mode {}: {err}", config.mode),
                        &config,
                        Some(&proc),
                        false,
                        now,
                        &mut note,
                    );
                    return;
                }
                let mut proc = read_proc_after_mode_write(config.mode);
                if !fastpath::matches(&config, &proc) {
                    let shown = proc
                        .mode
                        .map_or_else(|| "nothing".to_owned(), |m| m.to_string());
                    self.active_for_lease = false;
                    self.publish(
                        "failed",
                        &format!("re-arm mode {} did not read back (shows {shown})", config.mode),
                        &config,
                        Some(&proc),
                        false,
                        now,
                        &mut note,
                    );
                    return;
                }
                self.trip.note_applied(config.mode, &proc);
                self.active_for_lease = true;
                if self.renew_if_grant_held(nvram_cache_path) {
                    proc = read_proc_after_grant_open();
                }
                self.publish(
                    "applied",
                    &format!("mode {} read back from /proc/k1fp", config.mode),
                    &config,
                    Some(&proc),
                    true,
                    now,
                    &mut note,
                );
            }
            TripAction::Tripped {
                reason,
                first_notice,
            } => {
                self.active_for_lease = false;
                let revoked = self.revoke_if_open();
                let proc = if proc.mode != Some(0) {
                    let _ = write_proc_cmd("mode 0\n");
                    read_proc_after_mode_write(0)
                } else if revoked {
                    read_proc_after_grant_close()
                } else {
                    proc
                };
                let detail = format!("{reason}; staying at mode 0 until config changes or reboot");
                self.publish(
                    "tripped",
                    &detail,
                    &config,
                    Some(&proc),
                    first_notice || qctrl_changed,
                    now,
                    &mut note,
                );
            }
        }
    }

    fn revoke_if_open(&mut self) -> bool {
        if self.lease_state != LeaseState::Revoked && write_proc_cmd("grant 0\n").is_ok() {
            self.lease_state = LeaseState::Revoked;
            return true;
        }
        false
    }

    fn renew_if_grant_held(&mut self, nvram_cache_path: &Path) -> bool {
        let cache = fs::read(nvram_cache_path).ok();
        if matches!(cbrs_gate::decide(cache.as_deref()), Gate::Open(_)) {
            let cmd = format!("grant {}\n", fastpath::GRANT_LEASE_SECS);
            if write_proc_cmd(&cmd).is_ok() {
                self.lease_state = LeaseState::Open;
                return true;
            }
        }
        false
    }

    #[allow(clippy::too_many_arguments)]
    fn publish(
        &mut self,
        state: &str,
        detail: &str,
        config: &Config,
        proc: Option<&Proc>,
        force_status: bool,
        now: u64,
        note: &mut impl FnMut(&str),
    ) {
        let view = StatusView {
            state,
            detail,
            config,
            active_mode: proc.and_then(|p| p.mode),
            gate_open: proc.and_then(|p| p.gate_open),
            qctrl_present: proc.and_then(|p| p.qctrl_present),
            wd_trips: proc.and_then(|p| p.wd_trips).unwrap_or(0),
            wd_reason: proc.and_then(|p| p.wd_reason.as_deref()).unwrap_or("none"),
            now,
        };
        let key = format!("{state}: {detail}");
        let body = fastpath::status_body(&view);
        let log_changed = key != self.shown;
        let status_changed = body != self.status_body;
        if !log_changed && !status_changed && !force_status {
            return;
        }
        let quiet = state == "off" && self.shown.is_empty();
        self.shown = key;
        self.status_body = body;
        let _ = fs::write(status_path(), format!("{}updated={now}\n", self.status_body));
        if log_changed && !quiet {
            note(&format!("fast path {state}: {detail}"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_pins_titan_k1fp() {
        let digest = pinned().expect("device/fastpath/SHA256SUMS must pin titan_k1fp.ko");
        assert_eq!(digest.len(), 64);
        assert!(digest.bytes().all(|b| b.is_ascii_hexdigit()));
    }
}
