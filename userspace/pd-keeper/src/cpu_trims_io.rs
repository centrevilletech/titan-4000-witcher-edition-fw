//! Signals, `/proc` reads and the status file for `titan_pd_model::cpu_trims`.
//!
//! Everything here is undone live: `SIGCONT` puts the vendor LED loop back at
//! its own rate, and `ksoftirqd/0` goes back to nice 0. A keeper that starts
//! always sends one `SIGCONT` first, so a pause left by a keeper that died
//! lasts only until the supervisor has restarted it.
use std::fs;
use std::path::{Path, PathBuf};

use titan_pd_model::cpu_trims::{self, Config, LedPacer, LedState, LedStep, StatusView};
use titan_sys::process::{self, Signal};

use crate::paths::{env_path_or, volume_config};
use crate::status_file::StatusFile;

/// Seconds between log lines about the LED loop changing state.
const LED_LOG_EVERY: u64 = 60;
/// Seconds between status file rewrites while only the counters move.
const STATUS_EVERY: u64 = 60;

pub fn status_path() -> PathBuf {
    env_path_or("TITAN_CPU_TRIMS_STATUS", "/var/run/witcher-cpu-trims.status")
}

fn proc_root() -> PathBuf {
    env_path_or("TITAN_PROC_ROOT", "/proc")
}

fn button_mask() -> PathBuf {
    env_path_or("TITAN_BUTTON_MASK", cpu_trims::BUTTON_MASK)
}

/// `cpu-trims/config` on the volume, or the defaults.
fn load_config() -> Config {
    volume_config("TITAN_CPU_TRIMS_DIR", "cpu-trims")
        .map_or_else(Config::default, |text| cpu_trims::parse_config(&text))
}

fn pids(root: &Path) -> Vec<i32> {
    fs::read_dir(root)
        .map(|entries| {
            entries
                .flatten()
                .filter_map(|entry| entry.file_name().to_str()?.parse::<i32>().ok())
                .filter(|pid| *pid > 1)
                .collect()
        })
        .unwrap_or_default()
}

fn is_led_loop(root: &Path, pid: i32) -> bool {
    fs::read(root.join(pid.to_string()).join("cmdline"))
        .is_ok_and(|cmdline| cpu_trims::cmdline_argv0(&cmdline) == cpu_trims::LED_LOOP.as_bytes())
}

/// The vendor loop's pid. More than one match is not a state the keeper
/// understands, so it then touches none of them.
fn find_led_loop(root: &Path) -> Option<i32> {
    let mut found = pids(root).into_iter().filter(|pid| is_led_loop(root, *pid));
    let first = found.next()?;
    found.next().is_none().then_some(first)
}

fn ksoftirqd_nice(root: &Path, pid: i32) -> Option<i32> {
    let stat = fs::read_to_string(root.join(pid.to_string()).join("stat")).ok()?;
    let (comm, nice) = cpu_trims::stat_comm_nice(&stat)?;
    (comm == cpu_trims::KSOFTIRQD).then_some(nice)
}

fn find_ksoftirqd(root: &Path) -> Option<i32> {
    // Pid 3 on this kernel; look elsewhere only if it is not.
    if ksoftirqd_nice(root, 3).is_some() {
        return Some(3);
    }
    pids(root)
        .into_iter()
        .find(|pid| ksoftirqd_nice(root, *pid).is_some())
}

/// Never init, nor a pid `kill(2)` reads as a group.
fn signal(pid: i32, signal: Signal) -> bool {
    pid > 1 && process::kill(pid, signal).is_ok()
}

fn set_nice(pid: i32, nice: i32) -> bool {
    pid > 1 && process::set_nice(pid, nice).is_ok()
}

#[derive(Default)]
pub struct Watch {
    config: Config,
    config_at: Option<u64>,
    refused_logged: Vec<String>,
    /// The last second `maintain` ran in.
    ran_at: Option<u64>,
    /// The start-up `SIGCONT` was sent.
    started: bool,
    pacer: LedPacer,
    led_pid: Option<i32>,
    led_scan_at: Option<u64>,
    led_state: Option<LedState>,
    led_logged: Option<LedState>,
    led_logged_at: Option<u64>,
    /// `/proc/locks` could not be read, so the loop is never paused.
    led_unverifiable: bool,
    softirq_pid: Option<i32>,
    softirq_scan_at: Option<u64>,
    softirq_shown: String,
    pauses: u64,
    lock_backoffs: u64,
    status: StatusFile,
    status_at: Option<u64>,
}

impl Watch {
    /// Once a second, in every mode. With no trim asked for and nothing to
    /// undo, this reads one small file every `CHECK_EVERY` seconds.
    pub fn maintain(&mut self, now: u64, nvram_cache: &Path, mut note: impl FnMut(&str)) {
        if self.ran_at == Some(now) {
            return;
        }
        self.ran_at = Some(now);
        let root = proc_root();

        let check = self
            .config_at
            .is_none_or(|at| now.saturating_sub(at) >= cpu_trims::CHECK_EVERY);
        if check {
            self.config_at = Some(now);
            let config = load_config();
            if config.refused != self.refused_logged {
                for line in &config.refused {
                    note(&format!(
                        "cpu trims: ignored {line:?} in cpu-trims/config (allowed: trims=none|led|softirq|led,softirq and led_period=2..8)"
                    ));
                }
                self.refused_logged = config.refused.clone();
            }
            if config != self.config {
                note(&format!(
                    "cpu trims: config now trims={} led_period={}",
                    config.names(),
                    config.led_period
                ));
                self.config = config;
            }
        }

        if !self.started {
            self.started = true;
            // A keeper that died may have left the loop paused.
            if let Some(pid) = find_led_loop(&root) {
                self.led_pid = Some(pid);
                signal(pid, Signal::Continue);
            }
            self.led_scan_at = Some(now);
            self.pacer.resumed_at(now);
        }

        self.maintain_led(now, &root, nvram_cache, &mut note);
        if check {
            self.maintain_softirq(now, &root, &mut note);
        }
        self.publish(now);
    }

    /// The loop's pid, checked against `/proc/<pid>/cmdline` on every use.
    fn led_target(&mut self, now: u64, root: &Path) -> Option<i32> {
        if let Some(pid) = self.led_pid {
            if is_led_loop(root, pid) {
                return Some(pid);
            }
            self.led_pid = None;
        }
        if self
            .led_scan_at
            .is_some_and(|at| now.saturating_sub(at) < cpu_trims::RESCAN_EVERY)
        {
            return None;
        }
        self.led_scan_at = Some(now);
        self.led_pid = find_led_loop(root);
        self.led_pid
    }

    fn maintain_led(
        &mut self,
        now: u64,
        root: &Path,
        nvram_cache: &Path,
        note: &mut impl FnMut(&str),
    ) {
        if !self.config.led && !self.pacer.is_paused() {
            self.led_state = Some(LedState::Off);
            self.log_led(now, LedState::Off, &mut *note);
            return;
        }
        let state = if self.config.led && !self.led_unverifiable {
            let button = button_mask().exists();
            // The cache is read only when the answer can matter.
            let healthy = !button
                && fs::read(nvram_cache).is_ok_and(|cache| cpu_trims::signal_healthy(&cache));
            cpu_trims::led_state(true, healthy, button)
        } else {
            LedState::Off
        };
        match self.pacer.step(now, state, self.config.led_period) {
            LedStep::Leave => {}
            LedStep::Resume => {
                if let Some(pid) = self.led_target(now, root) {
                    signal(pid, Signal::Continue);
                }
                self.pacer.resumed_at(now);
            }
            LedStep::Pause => self.pause_led(now, root, &mut *note),
        }
        self.led_state = Some(state);
        self.log_led(now, state, &mut *note);
    }

    fn pause_led(&mut self, now: u64, root: &Path, note: &mut impl FnMut(&str)) {
        let Some(pid) = self.led_target(now, root) else {
            self.pacer.resumed_at(now);
            return;
        };
        let locks = root.join("locks");
        if fs::read_to_string(&locks).is_err() {
            self.led_unverifiable = true;
            self.pacer.resumed_at(now);
            note("cpu trims: cannot read /proc/locks, so the LED loop is never paused");
            return;
        }
        if !signal(pid, Signal::Stop) {
            self.led_pid = None;
            self.pacer.resumed_at(now);
            return;
        }
        // The loop is stopped now, so what it holds cannot change. A lock on
        // the vendor configuration cache would block every other reader.
        let free = fs::read_to_string(&locks).is_ok_and(|text| !cpu_trims::holds_lock(&text, pid));
        if free {
            self.pauses += 1;
            self.pacer.paused_at(now);
        } else {
            signal(pid, Signal::Continue);
            self.lock_backoffs += 1;
            self.pacer.resumed_at(now);
        }
    }

    fn log_led(&mut self, now: u64, state: LedState, note: &mut impl FnMut(&str)) {
        if self.led_logged == Some(state) {
            return;
        }
        // Stay quiet before the first trim, and when the signal flaps.
        if self.led_logged.is_none() && state == LedState::Off {
            self.led_logged = Some(state);
            return;
        }
        if self
            .led_logged_at
            .is_some_and(|at| now.saturating_sub(at) < LED_LOG_EVERY)
        {
            return;
        }
        self.led_logged = Some(state);
        self.led_logged_at = Some(now);
        note(&format!(
            "cpu trims: LED loop {} (period {} s)",
            state.name(),
            self.config.led_period
        ));
    }

    fn maintain_softirq(&mut self, now: u64, root: &Path, note: &mut impl FnMut(&str)) {
        let known = self
            .softirq_pid
            .and_then(|pid| ksoftirqd_nice(root, pid).map(|nice| (pid, nice)));
        let found = known.or_else(|| {
            self.softirq_pid = None;
            if self
                .softirq_scan_at
                .is_some_and(|at| now.saturating_sub(at) < cpu_trims::RESCAN_EVERY)
            {
                return None;
            }
            self.softirq_scan_at = Some(now);
            let pid = find_ksoftirqd(root)?;
            self.softirq_pid = Some(pid);
            ksoftirqd_nice(root, pid).map(|nice| (pid, nice))
        });
        let shown = match found {
            None => "ksoftirqd/0 not found".to_owned(),
            Some((pid, nice)) => match cpu_trims::ksoftirqd_target(self.config.softirq, nice) {
                None => format!("nice {nice}"),
                Some(target) => {
                    if set_nice(pid, target) {
                        note(&format!(
                            "cpu trims: ksoftirqd/0 (pid {pid}) nice {nice} -> {target}"
                        ));
                        format!("nice {target}")
                    } else {
                        format!("nice {nice} (could not set {target})")
                    }
                }
            },
        };
        self.softirq_shown = if self.config.softirq {
            shown
        } else {
            format!("off ({shown})")
        };
    }

    fn publish(&mut self, now: u64) {
        let led = match self.led_state {
            _ if self.config.led && self.led_unverifiable => "off (cannot read /proc/locks)",
            Some(state) => state.name(),
            None => LedState::Off.name(),
        };
        let view = StatusView {
            config: &self.config,
            led,
            softirq: &self.softirq_shown,
            pauses: self.pauses,
            lock_backoffs: self.lock_backoffs,
        };
        let body = cpu_trims::status_body(&view);
        let stale = self.config.any()
            && self
                .status_at
                .is_none_or(|at| now.saturating_sub(at) >= STATUS_EVERY);
        if self.status.update(status_path(), body, stale, |_| cpu_trims::status(&view, now)) {
            self.status_at = Some(now);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_proc(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("witcher-cpu-trims-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn add(root: &Path, pid: i32, cmdline: &[u8], stat: &str) {
        let dir = root.join(pid.to_string());
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("cmdline"), cmdline).unwrap();
        fs::write(dir.join("stat"), stat).unwrap();
    }

    fn stat(pid: i32, comm: &str, nice: i32) -> String {
        format!(
            "{pid} ({comm}) S 2 0 0 0 -1 69238848 0 0 0 0 0 4789 0 0 {} {nice} 1 0 5 0 0",
            20 + nice
        )
    }

    #[test]
    fn finds_the_led_loop_by_argv0_and_refuses_two() {
        let root = fake_proc("led");
        fs::create_dir_all(root.join("net")).unwrap();
        add(&root, 1, b"init\0", &stat(1, "init", 0));
        add(&root, 1834, b"/tmp/gpio\0", &stat(1834, "gpio", 0));
        add(&root, 2001, b"/bin/sh\0-c\0killall /tmp/child_gp\0", &stat(2001, "sh", 0));
        assert_eq!(find_led_loop(&root), None);
        add(&root, 1836, b"/tmp/child_gp\0", &stat(1836, "child_gp", 0));
        assert_eq!(find_led_loop(&root), Some(1836));
        assert!(is_led_loop(&root, 1836));
        assert!(!is_led_loop(&root, 1834));
        assert!(!is_led_loop(&root, 4242));
        add(&root, 1900, b"/tmp/child_gp\0", &stat(1900, "child_gp", 0));
        assert_eq!(find_led_loop(&root), None);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn finds_ksoftirqd_and_reads_its_nice() {
        let root = fake_proc("softirq");
        add(&root, 3, b"", &stat(3, "ksoftirqd/0", -5));
        add(&root, 1542, b"ucid\0", &stat(1542, "ucid", 0));
        assert_eq!(find_ksoftirqd(&root), Some(3));
        assert_eq!(ksoftirqd_nice(&root, 3), Some(-5));
        assert_eq!(ksoftirqd_nice(&root, 1542), None);
        let _ = fs::remove_dir_all(&root);

        // Not at pid 3 on some other kernel.
        let root = fake_proc("softirq-moved");
        add(&root, 3, b"", &stat(3, "kworker/0:0", 0));
        add(&root, 9, b"", &stat(9, "ksoftirqd/0", 0));
        assert_eq!(find_ksoftirqd(&root), Some(9));
        assert_eq!(ksoftirqd_nice(&root, 9), Some(0));
        let _ = fs::remove_dir_all(&root);

        assert_eq!(find_ksoftirqd(Path::new("/nonexistent-witcher-proc")), None);
    }

    #[test]
    fn signals_never_reach_init_or_a_bad_pid() {
        assert!(!signal(1, Signal::Continue));
        assert!(!signal(0, Signal::Continue));
        assert!(!signal(-1, Signal::Continue));
        assert!(!set_nice(1, 0));
        assert!(!set_nice(0, 0));
    }
}
