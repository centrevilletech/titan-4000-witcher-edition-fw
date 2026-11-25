//! Opt-in CPU trims on the Linux core (CPU0). Off by default.
//!
//! The unit has one Linux core. It forwards every customer packet, and the
//! vendor's background work competes with that. An operator turns trims on
//! per unit in `/mnt/titan-api/cpu-trims/config`:
//!
//! ```text
//! trims=led,softirq
//! led_period=4
//! ```
//!
//! An empty or missing file, `trims=none`, or any `trims=` line the keeper
//! cannot read in full leaves every trim off. Removing the file reverts a
//! running unit within `CHECK_EVERY` seconds, with no reboot. See
//! `docs/cpu-trims.md`.
//!
//! `led`: the vendor's `/tmp/child_gp` loop (`rcinit` under another name)
//! wakes every 500 ms. It reads the vendor configuration cache three times,
//! and every eighth pass it forks a shell to ask `ucid` for a radio refresh
//! for the signal LEDs. The same loop also runs the reset button and a
//! "signal is invalid while attached" reconnect, so the keeper never stops
//! it for good. It pauses the loop with `SIGSTOP` and lets it run for about a
//! second in every `led_period` seconds, and only while:
//! - no reset-button press is pending (`/tmp/gpio4_interrupt_mask`, which
//!   `bmon` creates on the button interrupt, does not exist), and
//! - the radio state the loop watches is healthy (attached, with every
//!   `sqns_radio_RSRP` value inside the range the loop accepts).
//!
//! In every other state the loop runs at the vendor's full rate, so the
//! reset button and the reconnect keep their stock timing. A paused loop
//! must not hold the lock on the configuration cache: the keeper reads
//! `/proc/locks` right after each `SIGSTOP` and resumes the loop at once if
//! it holds any lock.
//!
//! `softirq`: `ksoftirqd/0` runs packet work that overflows the interrupt
//! path. At nice 0 it shares the core evenly with every vendor daemon. The
//! keeper sets it to nice `KSOFTIRQD_NICE`. Userspace keeps a share of the
//! core (CFS weights), so the watchdog feeders and the SAS client still run.

use crate::deaf::nvram_field;

/// Seconds between reads of `cpu-trims/config`.
pub const CHECK_EVERY: u64 = 5;
/// Seconds in one LED pacing period: about one second running, the rest paused.
pub const DEFAULT_LED_PERIOD: u64 = 4;
pub const MIN_LED_PERIOD: u64 = 2;
pub const MAX_LED_PERIOD: u64 = 8;
/// Seconds the loop runs in each period before the next pause.
pub const LED_RUN_SECS: u64 = 1;
/// Seconds between scans of `/proc` for a process the keeper cannot find.
pub const RESCAN_EVERY: u64 = 10;
/// The nice value for `ksoftirqd/0` while the `softirq` trim is on.
pub const KSOFTIRQD_NICE: i32 = -5;
/// The kernel's own nice value for `ksoftirqd/0`.
pub const KSOFTIRQD_STOCK_NICE: i32 = 0;
/// `argv[0]` of the vendor LED, reset-button and reconnect loop.
pub const LED_LOOP: &str = "/tmp/child_gp";
/// The kernel thread name in `/proc/<pid>/stat`.
pub const KSOFTIRQD: &str = "ksoftirqd/0";
/// `bmon` creates this on the reset-button interrupt. The vendor loop polls
/// the button only while it exists, and removes it when the button is up.
pub const BUTTON_MASK: &str = "/tmp/gpio4_interrupt_mask";
/// The vendor loop counts a tick towards its reconnect when the RSRP it reads
/// (hundredths of a dBm) is below this ...
pub const RSRP_MIN: i64 = -14_000;
/// ... or above this.
pub const RSRP_MAX: i64 = -2_000;

/// `/mnt/titan-api/cpu-trims/config`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub led: bool,
    pub softirq: bool,
    pub led_period: u64,
    /// Lines that were not used, as written.
    pub refused: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            led: false,
            softirq: false,
            led_period: DEFAULT_LED_PERIOD,
            refused: Vec::new(),
        }
    }
}

impl Config {
    pub fn any(&self) -> bool {
        self.led || self.softirq
    }

    /// The trims asked for, as written in the status file.
    pub fn names(&self) -> String {
        let mut names = Vec::new();
        if self.led {
            names.push("led");
        }
        if self.softirq {
            names.push("softirq");
        }
        if names.is_empty() {
            "none".to_owned()
        } else {
            names.join(",")
        }
    }
}

/// `trims=` takes a comma list of `led` and `softirq`, or `none`. The last
/// `trims=` line wins. One unknown name refuses the whole line and leaves
/// every trim off. `led_period=` takes whole seconds from `MIN_LED_PERIOD` to
/// `MAX_LED_PERIOD`; a bad value keeps the default. `#` starts a comment.
pub fn parse_config(text: &str) -> Config {
    let mut config = Config::default();
    for raw in text.lines() {
        let line: String = raw
            .split('#')
            .next()
            .unwrap_or("")
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        if line.is_empty() {
            continue;
        }
        let ok = match line.split_once('=') {
            Some(("trims", value)) => {
                let mut led = false;
                let mut softirq = false;
                let mut good = true;
                if value != "none" {
                    for name in value.split(',') {
                        match name {
                            "led" => led = true,
                            "softirq" => softirq = true,
                            _ => good = false,
                        }
                    }
                }
                config.led = good && led;
                config.softirq = good && softirq;
                good
            }
            Some(("led_period", value)) => {
                let period = if value.len() <= 2 && value.bytes().all(|b| b.is_ascii_digit()) {
                    value.parse::<u64>().ok()
                } else {
                    None
                };
                match period {
                    Some(secs) if (MIN_LED_PERIOD..=MAX_LED_PERIOD).contains(&secs) => {
                        config.led_period = secs;
                        true
                    }
                    _ => false,
                }
            }
            _ => false,
        };
        if !ok {
            config.refused.push(raw.trim().to_owned());
        }
    }
    config
}

/// True only in the one radio state where the vendor loop does nothing but
/// repaint LEDs: the unit is attached and every RSRP value in the cache is a
/// plain number inside the range the loop accepts. A missing key, a torn
/// read, `-`, `-,-`, or any value out of range is not healthy, and the loop
/// then runs at full rate so its own reconnect keeps its stock 20 s timing.
pub fn signal_healthy(cache: &[u8]) -> bool {
    let attached = matches!(
        nvram_field(cache, "sqns_connection_mediaState").map(str::trim),
        Some("CONNECTED" | "ATTACHED")
    );
    if !attached {
        return false;
    }
    if nvram_field(cache, "sqns_simcard_state").map(str::trim) != Some("Ready") {
        return false;
    }
    let Some(rsrp) = nvram_field(cache, "sqns_radio_RSRP").map(str::trim) else {
        return false;
    };
    if rsrp.is_empty() {
        return false;
    }
    rsrp.split(',').all(|field| {
        let digits = field.strip_prefix('-').unwrap_or(field);
        if digits.is_empty() || digits.len() > 6 || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
        field
            .parse::<i64>()
            .is_ok_and(|value| (RSRP_MIN..=RSRP_MAX).contains(&value))
    })
}

/// What the keeper does to the vendor loop on one tick.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LedStep {
    /// Nothing to send.
    Leave,
    /// Send `SIGCONT`.
    Resume,
    /// Send `SIGSTOP`, then check `/proc/locks`.
    Pause,
}

/// Why the loop runs at the vendor's full rate, or that it is paced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LedState {
    /// The trim is not asked for.
    Off,
    Pacing,
    /// A reset-button press is pending.
    Button,
    /// The radio state is not the healthy one.
    Signal,
}

impl LedState {
    pub fn name(self) -> &'static str {
        match self {
            LedState::Off => "off",
            LedState::Pacing => "pacing",
            LedState::Button => "full-rate (reset button pending)",
            LedState::Signal => "full-rate (signal not healthy)",
        }
    }
}

pub fn led_state(enabled: bool, healthy: bool, button_pending: bool) -> LedState {
    if !enabled {
        LedState::Off
    } else if button_pending {
        LedState::Button
    } else if !healthy {
        LedState::Signal
    } else {
        LedState::Pacing
    }
}

/// The pause and resume schedule for the vendor loop. The keeper reports what
/// it really did with `paused_at` and `resumed_at`; `step` only decides.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LedPacer {
    paused: bool,
    /// When the loop was last paused or resumed.
    since: u64,
}

impl LedPacer {
    pub fn is_paused(&self) -> bool {
        self.paused
    }

    pub fn step(&self, now: u64, state: LedState, period: u64) -> LedStep {
        if state != LedState::Pacing {
            return if self.paused {
                LedStep::Resume
            } else {
                LedStep::Leave
            };
        }
        let period = period.clamp(MIN_LED_PERIOD, MAX_LED_PERIOD);
        let held = now.saturating_sub(self.since);
        if self.paused {
            if held >= period - LED_RUN_SECS {
                LedStep::Resume
            } else {
                LedStep::Leave
            }
        } else if held >= LED_RUN_SECS {
            LedStep::Pause
        } else {
            LedStep::Leave
        }
    }

    /// `SIGSTOP` was sent and the loop holds no lock.
    pub fn paused_at(&mut self, now: u64) {
        self.paused = true;
        self.since = now;
    }

    /// `SIGCONT` was sent, the pause was refused (the loop held a lock), or
    /// the process is gone. The next pause comes `LED_RUN_SECS` later.
    pub fn resumed_at(&mut self, now: u64) {
        self.paused = false;
        self.since = now;
    }
}

/// True when `/proc/locks` shows a lock held by `pid`. A line with `->` is a
/// process waiting for a lock, which is harmless to pause.
///
/// ```text
/// 1: FLOCK  ADVISORY  WRITE 1836 00:0e:5123 0 EOF
/// 1: -> FLOCK  ADVISORY  WRITE 1542 00:0e:5123 0 EOF
/// ```
pub fn holds_lock(locks: &str, pid: i32) -> bool {
    let pid = pid.to_string();
    locks.lines().any(|line| {
        let mut words = line.split_whitespace();
        let _index = words.next();
        let Some(kind) = words.next() else {
            return false;
        };
        if kind == "->" {
            return false;
        }
        // kind, ADVISORY|MANDATORY, READ|WRITE, pid
        words.nth(2) == Some(pid.as_str())
    })
}

/// The first argument of a `/proc/<pid>/cmdline` (NUL-separated).
pub fn cmdline_argv0(cmdline: &[u8]) -> &[u8] {
    cmdline.split(|byte| *byte == 0).next().unwrap_or(&[])
}

/// The command name and nice value from a `/proc/<pid>/stat` line. The name
/// sits in parentheses and may hold spaces; nice is the 19th field.
pub fn stat_comm_nice(stat: &str) -> Option<(&str, i32)> {
    let open = stat.find('(')?;
    let close = stat.rfind(')')?;
    if close < open {
        return None;
    }
    let comm = &stat[open + 1..close];
    // After the name: state is field 3, so nice (field 19) is the 17th word.
    let nice = stat[close + 1..].split_whitespace().nth(16)?.parse().ok()?;
    Some((comm, nice))
}

/// What the keeper does to `ksoftirqd/0` for the nice value it reads.
/// `None`: leave it. The keeper owns only the step between the kernel's
/// value and `KSOFTIRQD_NICE`; any other value is someone else's and stays.
pub fn ksoftirqd_target(enabled: bool, current: i32) -> Option<i32> {
    if enabled && current == KSOFTIRQD_STOCK_NICE {
        Some(KSOFTIRQD_NICE)
    } else if !enabled && current == KSOFTIRQD_NICE {
        Some(KSOFTIRQD_STOCK_NICE)
    } else {
        None
    }
}

/// Fields of `/var/run/witcher-cpu-trims.status`.
pub struct StatusView<'a> {
    pub config: &'a Config,
    pub led: &'a str,
    pub softirq: &'a str,
    /// Times the loop was paused since the keeper started.
    pub pauses: u64,
    /// Pauses undone at once because the loop held a lock.
    pub lock_backoffs: u64,
}

/// The body without counters, for change detection.
pub fn status_body(view: &StatusView<'_>) -> String {
    format!(
        "trims={}\nled={}\nled_period={}\nsoftirq={}\n",
        view.config.names(),
        view.led,
        view.config.led_period,
        view.softirq,
    )
}

pub fn status(view: &StatusView<'_>, now: u64) -> String {
    format!(
        "{}pauses={}\nlock_backoffs={}\nupdated={now}\n",
        status_body(view),
        view.pauses,
        view.lock_backoffs,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cache(media: &str, sim: &str, rsrp: &str) -> Vec<u8> {
        format!(
            "a=1\0sqns_connection_mediaState={media}\0sqns_simcard_state={sim}\0sqns_radio_RSRP={rsrp}\0sqns_radio_RSRP3=-108\0"
        )
        .into_bytes()
    }

    #[test]
    fn config_is_off_unless_every_name_is_known() {
        assert_eq!(parse_config(""), Config::default());
        assert!(!Config::default().any());
        assert_eq!(Config::default().names(), "none");

        let both = parse_config("# trims\ntrims = led, softirq # both\nled_period=6\n");
        assert!(both.led && both.softirq && both.refused.is_empty());
        assert_eq!(both.led_period, 6);
        assert_eq!(both.names(), "led,softirq");

        assert!(parse_config("trims=led\n").led);
        assert!(!parse_config("trims=led\n").softirq);
        assert!(parse_config("trims=softirq\n").softirq);
        assert_eq!(parse_config("trims=none\n"), Config::default());
        // The last line wins, and `none` turns everything off again.
        assert!(!parse_config("trims=led,softirq\ntrims=none\n").any());

        // One unknown name refuses the whole line: nothing is on.
        for bad in ["trims=led,gps", "trims=all", "trims=", "trims=led,", "trims=LED"] {
            let config = parse_config(&format!("trims=softirq\n{bad}\n"));
            assert!(!config.any(), "{bad}");
            assert_eq!(config.refused, vec![bad.to_owned()], "{bad}");
        }
        // A bad period keeps the default and the trims.
        for bad in ["led_period=1", "led_period=9", "led_period=4s", "led_period=", "led_period=-4", "led_period=004"] {
            let config = parse_config(&format!("trims=led\n{bad}\n"));
            assert!(config.led, "{bad}");
            assert_eq!(config.led_period, DEFAULT_LED_PERIOD, "{bad}");
            assert_eq!(config.refused, vec![bad.to_owned()], "{bad}");
        }
        let config = parse_config("trims=led\nnonsense\nmode=2\n");
        assert!(config.led);
        assert_eq!(config.refused, vec!["nonsense", "mode=2"]);
    }

    #[test]
    fn signal_is_healthy_only_when_attached_with_every_rsrp_in_range() {
        // Bench cache values.
        assert!(signal_healthy(&cache("ATTACHED", "Ready", "-10800,-11400,-11720,-11390")));
        assert!(signal_healthy(&cache("CONNECTED", "Ready", "-9550")));
        assert!(signal_healthy(&cache("ATTACHED", "Ready", "-14000,-2000")));

        // The values the vendor loop counts towards its reconnect.
        for rsrp in ["-", "-,-", "", "-14001", "-1999", "0", "-10800,-", "-10800,-14001", "-10800,,-11000", "abc", "-108.5", "--10800", "+10800", "-1080000000000"] {
            assert!(!signal_healthy(&cache("ATTACHED", "Ready", rsrp)), "{rsrp:?}");
        }
        // Not attached, or no SIM: the loop is doing more than repainting.
        for media in ["CONNECTING", "DISCONNECTED", "", "attached"] {
            assert!(!signal_healthy(&cache(media, "Ready", "-10800")), "{media:?}");
        }
        assert!(!signal_healthy(&cache("ATTACHED", "Absent", "-10800")));
        // Missing keys and an empty or torn cache.
        assert!(!signal_healthy(b""));
        assert!(!signal_healthy(b"sqns_connection_mediaState=ATTACHED\0sqns_simcard_state=Ready\0"));
        assert!(!signal_healthy(b"sqns_radio_RSRP=-10800\0"));
        // Newline-separated records read the same.
        assert!(signal_healthy(
            b"sqns_connection_mediaState=ATTACHED\nsqns_simcard_state=Ready\nsqns_radio_RSRP=-10800,-11400\n"
        ));
    }

    #[test]
    fn led_state_puts_the_button_and_a_bad_signal_before_pacing() {
        assert_eq!(led_state(false, true, false), LedState::Off);
        assert_eq!(led_state(false, false, true), LedState::Off);
        assert_eq!(led_state(true, true, false), LedState::Pacing);
        assert_eq!(led_state(true, true, true), LedState::Button);
        assert_eq!(led_state(true, false, true), LedState::Button);
        assert_eq!(led_state(true, false, false), LedState::Signal);
    }

    /// Drive the pacer as the keeper does and return, per second, whether the
    /// loop was running during that second.
    fn drive(period: u64, seconds: u64, state_at: impl Fn(u64) -> LedState) -> Vec<bool> {
        let mut pacer = LedPacer::default();
        let mut running = Vec::new();
        for now in 100..100 + seconds {
            match pacer.step(now, state_at(now), period) {
                LedStep::Pause => pacer.paused_at(now),
                LedStep::Resume => pacer.resumed_at(now),
                LedStep::Leave => {}
            }
            running.push(!pacer.is_paused());
        }
        running
    }

    #[test]
    fn pacer_runs_the_loop_one_second_in_each_period() {
        for period in MIN_LED_PERIOD..=MAX_LED_PERIOD {
            let running = drive(period, 20 * period, |_| LedState::Pacing);
            let ran = running.iter().filter(|r| **r).count() as u64;
            assert_eq!(ran, 20, "period {period}: one running second per period");
            // Never paused longer than period - 1 seconds in a row.
            let longest = running
                .split(|r| *r)
                .map(<[bool]>::len)
                .max()
                .unwrap_or(0) as u64;
            assert_eq!(longest, period - LED_RUN_SECS, "period {period}");
        }
        // An out-of-range period is clamped, never a longer pause.
        let running = drive(1000, 100, |_| LedState::Pacing);
        let longest = running.split(|r| *r).map(<[bool]>::len).max().unwrap_or(0) as u64;
        assert_eq!(longest, MAX_LED_PERIOD - LED_RUN_SECS);
        let running = drive(0, 100, |_| LedState::Pacing);
        assert_eq!(running.iter().filter(|r| **r).count(), 50);
    }

    #[test]
    fn pacer_resumes_at_once_and_stays_running_outside_pacing() {
        // Paused at 100; the button is pressed at 102.
        let running = drive(8, 30, |now| {
            if (102..120).contains(&now) {
                LedState::Button
            } else {
                LedState::Pacing
            }
        });
        assert!(!running[1], "still paused at 101");
        assert!(running[2..20].iter().all(|r| *r), "running through the press");
        assert!(!running[21], "paced again one second after the release");

        for state in [LedState::Off, LedState::Signal, LedState::Button] {
            let mut pacer = LedPacer::default();
            assert_eq!(pacer.step(500, state, 4), LedStep::Leave);
            pacer.paused_at(500);
            assert_eq!(pacer.step(500, state, 4), LedStep::Resume);
            pacer.resumed_at(500);
            for now in 500..520 {
                assert_eq!(pacer.step(now, state, 4), LedStep::Leave);
            }
        }
    }

    #[test]
    fn a_refused_pause_is_retried_a_second_later() {
        let mut pacer = LedPacer::default();
        assert_eq!(pacer.step(100, LedState::Pacing, 4), LedStep::Pause);
        // The loop held a lock: the keeper resumed it and reports that.
        pacer.resumed_at(100);
        assert!(!pacer.is_paused());
        assert_eq!(pacer.step(100, LedState::Pacing, 4), LedStep::Leave);
        assert_eq!(pacer.step(101, LedState::Pacing, 4), LedStep::Pause);
        pacer.paused_at(101);
        assert_eq!(pacer.step(102, LedState::Pacing, 4), LedStep::Leave);
        assert_eq!(pacer.step(103, LedState::Pacing, 4), LedStep::Leave);
        assert_eq!(pacer.step(104, LedState::Pacing, 4), LedStep::Resume);
    }

    #[test]
    fn lock_holders_are_found_and_waiters_are_not() {
        let locks = "\
1: FLOCK  ADVISORY  WRITE 1836 00:0e:5123 0 EOF
1: -> FLOCK  ADVISORY  WRITE 1542 00:0e:5123 0 EOF
2: POSIX  ADVISORY  READ  988 00:0c:77 0 EOF
3: FLOCK  ADVISORY  WRITE 18360 00:0e:9 0 EOF
";
        assert!(holds_lock(locks, 1836));
        assert!(holds_lock(locks, 988));
        assert!(holds_lock(locks, 18360));
        assert!(!holds_lock(locks, 1542), "a waiter holds nothing");
        assert!(!holds_lock(locks, 183), "no prefix match");
        assert!(!holds_lock(locks, 5123), "an inode number is not a pid");
        assert!(!holds_lock(locks, 0));
        assert!(!holds_lock("", 1836));
        assert!(!holds_lock("garbage\n1:\n1: FLOCK\n", 1836));
    }

    #[test]
    fn proc_files_are_read_as_the_kernel_writes_them() {
        assert_eq!(cmdline_argv0(b"/tmp/child_gp\0"), b"/tmp/child_gp");
        assert_eq!(cmdline_argv0(b"/bin/sh\0-c\0echo /tmp/child_gp\0"), b"/bin/sh");
        assert_eq!(cmdline_argv0(b""), b"");

        let stat = "3 (ksoftirqd/0) S 2 0 0 0 -1 69238848 0 0 0 0 0 4789 0 0 20 0 1 0 5 0 0 4294967295 0 0 0 0 0 0 0 2147483647 0 0 0 0 17 0 0 0 0 0 0";
        assert_eq!(stat_comm_nice(stat), Some((KSOFTIRQD, 0)));
        let reniced = stat.replace(" 20 0 1 0 5 ", " 15 -5 1 0 5 ");
        assert_eq!(stat_comm_nice(&reniced), Some((KSOFTIRQD, -5)));
        // A name with spaces and parentheses.
        let odd = "77 (a b) c) S 1 0 0 0 -1 0 0 0 0 0 0 0 0 0 30 10 1 0 5 0 0";
        assert_eq!(stat_comm_nice(odd), Some(("a b) c", 10)));
        assert_eq!(stat_comm_nice(""), None);
        assert_eq!(stat_comm_nice("3 (ksoftirqd/0) S 2"), None);
        assert_eq!(stat_comm_nice(") ("), None);
    }

    #[test]
    fn ksoftirqd_moves_only_between_the_stock_value_and_ours() {
        assert_eq!(ksoftirqd_target(true, 0), Some(KSOFTIRQD_NICE));
        assert_eq!(ksoftirqd_target(true, KSOFTIRQD_NICE), None);
        assert_eq!(ksoftirqd_target(false, KSOFTIRQD_NICE), Some(0));
        assert_eq!(ksoftirqd_target(false, 0), None);
        // A value someone else set stays, on or off.
        for other in [-20, -10, -1, 1, 5, 19] {
            assert_eq!(ksoftirqd_target(true, other), None);
            assert_eq!(ksoftirqd_target(false, other), None);
        }
    }

    #[test]
    fn status_lists_the_trims_and_the_counters() {
        let config = parse_config("trims=led,softirq\nled_period=6\n");
        let view = StatusView {
            config: &config,
            led: LedState::Pacing.name(),
            softirq: "nice -5",
            pauses: 12,
            lock_backoffs: 1,
        };
        assert_eq!(
            status(&view, 4321),
            "trims=led,softirq\nled=pacing\nled_period=6\nsoftirq=nice -5\npauses=12\nlock_backoffs=1\nupdated=4321\n"
        );
        assert!(!status_body(&view).contains("pauses"));
    }
}
