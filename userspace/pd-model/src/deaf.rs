//! Reboot a unit that is attached but hears nothing.
//!
//! A wedged unit keeps its LTE attach and still transmits, but no downlink
//! packet reaches Linux on any bearer. Nothing can reach it to restart it, and
//! only a restart clears it. The keeper therefore pings a few addresses through
//! the core. If one has answered since boot, and then none answers for
//! `deaf_secs` while the modem stays attached, the keeper reboots the unit.
//!
//! Guards against rebooting for the wrong reason:
//! - It arms only after a target has answered in this boot. A target that never
//!   answers, or a core that is down when the unit boots, cannot cause a reboot.
//! - Time spent detached does not count, and neither do the first `SETTLE`
//!   seconds after an attach. A radio drop is not this fault, and a unit needs
//!   about a minute after a re-attach before its pings answer again.
//! - On the first silent round in IP passthrough the keeper first tries the
//!   repair in `extdev`, which needs no reboot.
//! - Each reboot that did not help doubles the wait before the next one, up to
//!   `MAX_WAIT`. An hour of answers clears the count.
use std::net::IpAddr;

/// Seconds between probe rounds.
pub const PROBE_EVERY: u64 = 30;
/// A round with no answer after this long counts as silence.
pub const PROBE_TIMEOUT: u64 = 6;
/// Default silence, attached, before a reboot.
pub const DEAF_SECS: u64 = 300;
const MIN_DEAF_SECS: u64 = 120;
/// Longest wait once reboots have stopped helping.
pub const MAX_WAIT: u64 = 6 * 3600;
/// Answers for this long after arming clear the strike count.
pub const CLEAR_AFTER: u64 = 3600;
const MAX_TARGETS: usize = 4;
/// Silence in the first seconds after an attach is the bearer settling.
pub const SETTLE: u64 = 90;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    pub enabled: bool,
    /// Operator targets. Empty means use the bearer's DNS servers.
    pub targets: Vec<IpAddr>,
    pub deaf_secs: u64,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            enabled: true,
            targets: Vec::new(),
            deaf_secs: DEAF_SECS,
        }
    }
}

/// `watchdog.conf`: `enabled=0|1`, `deaf_secs=<seconds>`, and one `target=<address>`
/// line per address. Unknown or malformed lines are ignored, so a damaged file
/// leaves the defaults in place.
pub fn parse_settings(text: &str) -> Settings {
    let mut settings = Settings::default();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        match key.trim() {
            "enabled" => match value {
                "0" | "false" | "off" => settings.enabled = false,
                "1" | "true" | "on" => settings.enabled = true,
                _ => {}
            },
            "deaf_secs" => {
                if let Ok(secs) = value.parse::<u64>() {
                    settings.deaf_secs = secs.clamp(MIN_DEAF_SECS, MAX_WAIT);
                }
            }
            "target" => {
                if let Some(addr) = usable(value) {
                    if !settings.targets.contains(&addr) && settings.targets.len() < MAX_TARGETS {
                        settings.targets.push(addr);
                    }
                }
            }
            _ => {}
        }
    }
    settings
}

fn usable(text: &str) -> Option<IpAddr> {
    let addr: IpAddr = text.parse().ok()?;
    (!addr.is_unspecified() && !addr.is_loopback()).then_some(addr)
}

/// DNS servers the core handed the unit, from `nvram_get 0 wan_get_dns`
/// (`nvram_get success: 192.0.2.53 0.0.0.0`). They sit behind the bearer, so
/// an answer proves the downlink.
pub fn bearer_dns(output: &str) -> Vec<IpAddr> {
    let value = output.split_once(':').map_or(output, |(_, rest)| rest);
    let mut found = Vec::new();
    for word in value.split_whitespace() {
        if let Some(addr) = usable(word) {
            if !found.contains(&addr) && found.len() < MAX_TARGETS {
                found.push(addr);
            }
        }
    }
    found
}

/// Targets for this round: the operator's, or the bearer's DNS servers.
pub fn targets(settings: &Settings, wan_get_dns: &str) -> Vec<IpAddr> {
    if settings.targets.is_empty() {
        bearer_dns(wan_get_dns)
    } else {
        settings.targets.clone()
    }
}

/// One `key=value` record from the vendor's RAM cache (`/tmp/nvram.cfg`).
/// Records end in a NUL byte (a newline is accepted too).
pub fn nvram_field<'a>(cache: &'a [u8], key: &str) -> Option<&'a str> {
    cache
        .split(|byte| *byte == 0 || *byte == b'\n')
        .find_map(|record| record.strip_prefix(key.as_bytes())?.strip_prefix(b"="))
        .and_then(|value| std::str::from_utf8(value).ok())
}

/// The value as `ucid` reads it: C `atoi`, so leading digits count and
/// anything unreadable is 0.
fn atoi(text: &str) -> i64 {
    let text = text.trim_start();
    let (sign, digits) = match text.as_bytes().first() {
        Some(b'-') => (-1, &text[1..]),
        Some(b'+') => (1, &text[1..]),
        _ => (1, text),
    };
    let end = digits.find(|c: char| !c.is_ascii_digit()).unwrap_or(digits.len());
    digits[..end].parse::<i64>().map_or(0, |n| sign * n)
}

/// The vendor ping watchdog in `ucid` runs while `detection_enable` is not 0.
/// It must stop while this watchdog is on. With this one off, the operator's
/// vendor setting stands. A missing key means the cache is not ready yet.
pub fn vendor_watchdog_must_stop(settings: &Settings, detection_enable: Option<&str>) -> bool {
    settings.enabled && detection_enable.is_some_and(|value| atoi(value) != 0)
}

/// `nvram_get 0 sqns_connection_mediaState` reports `ATTACHED`.
pub fn attached(output: &str) -> bool {
    output.rsplit(':').next().unwrap_or("").trim() == "ATTACHED"
}

/// Silence required before the next reboot, after `strikes` reboots in a row
/// that were each followed by silence again.
pub fn required_silence(deaf_secs: u64, strikes: u32) -> u64 {
    let base = deaf_secs.clamp(MIN_DEAF_SECS, MAX_WAIT);
    base.saturating_mul(1u64 << strikes.min(16)).min(MAX_WAIT)
}

pub fn parse_strikes(text: &str) -> u32 {
    text.lines()
        .find_map(|line| line.trim().strip_prefix("strikes="))
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(0)
}

pub fn format_strikes(strikes: u32) -> String {
    format!("strikes={strikes}\n")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Hold,
    /// First answer of this boot.
    Armed,
    /// First silent round after answers.
    Silent,
    /// Answers came back before a reboot was due.
    Recovered { silent_for: u64 },
    /// Answers have held for `CLEAR_AFTER`; forget earlier strikes.
    ClearStrikes,
    Reboot { silent_for: u64 },
}

#[derive(Default)]
pub struct Watch {
    armed_at: Option<u64>,
    silent_since: Option<u64>,
    attached_since: Option<u64>,
    cleared: bool,
}

impl Watch {
    pub fn armed(&self) -> bool {
        self.armed_at.is_some()
    }

    /// One finished probe round. `attached` is the modem state sampled for
    /// this round. `heard` is `None` when no probe could run (no targets, or
    /// the watchdog is off); that is neither an answer nor silence. `strikes`
    /// is the stored count from earlier boots.
    pub fn observe(
        &mut self,
        now: u64,
        attached: bool,
        heard: Option<bool>,
        deaf_secs: u64,
        strikes: u32,
    ) -> Action {
        if attached {
            self.attached_since.get_or_insert(now);
        } else {
            self.attached_since = None;
        }
        let Some(heard) = heard else {
            self.silent_since = None;
            return Action::Hold;
        };
        if heard {
            let silent = self.silent_since.take();
            let Some(armed_at) = self.armed_at else {
                self.armed_at = Some(now);
                return Action::Armed;
            };
            if let Some(since) = silent {
                // Silence restarts the hour of answers the strike count needs.
                self.armed_at = Some(now);
                return Action::Recovered {
                    silent_for: now.saturating_sub(since),
                };
            }
            if !self.cleared && strikes > 0 && now.saturating_sub(armed_at) >= CLEAR_AFTER {
                self.cleared = true;
                return Action::ClearStrikes;
            }
            return Action::Hold;
        }
        if self.armed_at.is_none() {
            return Action::Hold;
        }
        let Some(attached_since) = self.attached_since else {
            // The radio is down. Silence is expected and is not this fault.
            self.silent_since = None;
            return Action::Hold;
        };
        if now.saturating_sub(attached_since) < SETTLE {
            // Just attached. The bearer has not had time to answer yet.
            self.silent_since = None;
            return Action::Hold;
        }
        let Some(since) = self.silent_since else {
            self.silent_since = Some(now);
            return Action::Silent;
        };
        let silent_for = now.saturating_sub(since);
        if silent_for >= required_silence(deaf_secs, strikes) {
            self.silent_since = Some(now);
            return Action::Reboot { silent_for };
        }
        Action::Hold
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rounds(watch: &mut Watch, from: u64, to: u64, attached: bool, heard: bool) -> Vec<Action> {
        let mut seen = Vec::new();
        let mut now = from;
        while now <= to {
            let action = watch.observe(now, attached, Some(heard), DEAF_SECS, 0);
            if action != Action::Hold {
                seen.push(action);
            }
            now += PROBE_EVERY;
        }
        seen
    }

    #[test]
    fn a_unit_that_never_heard_an_answer_never_reboots() {
        let mut watch = Watch::default();
        assert!(rounds(&mut watch, 0, 86_400, true, false).is_empty());
        assert!(!watch.armed());
    }

    #[test]
    fn silence_while_attached_reboots_after_the_wait() {
        let mut watch = Watch::default();
        assert_eq!(rounds(&mut watch, 0, 600, true, true), vec![Action::Armed]);
        let seen = rounds(&mut watch, 630, 630 + DEAF_SECS, true, false);
        assert_eq!(
            seen,
            vec![
                Action::Silent,
                Action::Reboot {
                    silent_for: DEAF_SECS
                }
            ]
        );
    }

    #[test]
    fn silence_shorter_than_the_wait_does_nothing() {
        let mut watch = Watch::default();
        rounds(&mut watch, 0, 60, true, true);
        let seen = rounds(&mut watch, 90, 90 + DEAF_SECS - PROBE_EVERY, true, false);
        assert_eq!(seen, vec![Action::Silent]);
        let back = watch.observe(90 + DEAF_SECS, true, Some(true), DEAF_SECS, 0);
        assert_eq!(
            back,
            Action::Recovered {
                silent_for: DEAF_SECS
            }
        );
        // The count starts again from zero after an answer.
        let seen = rounds(&mut watch, 1000, 1000 + DEAF_SECS - PROBE_EVERY, true, false);
        assert_eq!(seen, vec![Action::Silent]);
    }

    #[test]
    fn a_detached_radio_does_not_count_as_silence() {
        let mut watch = Watch::default();
        rounds(&mut watch, 0, 60, true, true);
        assert!(rounds(&mut watch, 90, 7200, false, false).is_empty());
        // Attached again and still silent: the wait starts now, not at the detach.
        let seen = rounds(&mut watch, 7230, 7230 + DEAF_SECS - PROBE_EVERY, true, false);
        assert_eq!(seen, vec![Action::Silent]);
    }

    #[test]
    fn silence_right_after_an_attach_is_the_bearer_settling() {
        let mut watch = Watch::default();
        rounds(&mut watch, 0, 60, true, true);
        // Detached for a while, then attached again and silent.
        assert!(rounds(&mut watch, 90, 300, false, false).is_empty());
        assert_eq!(watch.observe(330, true, Some(false), DEAF_SECS, 0), Action::Hold);
        assert_eq!(watch.observe(360, true, Some(false), DEAF_SECS, 0), Action::Hold);
        assert_eq!(watch.observe(390, true, Some(false), DEAF_SECS, 0), Action::Hold);
        // 90 s after the attach was first seen, silence starts to count.
        assert_eq!(
            watch.observe(420, true, Some(false), DEAF_SECS, 0),
            Action::Silent
        );
        assert_eq!(
            watch.observe(420 + DEAF_SECS, true, Some(false), DEAF_SECS, 0),
            Action::Reboot {
                silent_for: DEAF_SECS
            }
        );
        // A detach seen in between starts the whole wait again.
        let mut watch = Watch::default();
        rounds(&mut watch, 0, 120, true, true);
        assert_eq!(
            watch.observe(150, true, Some(false), DEAF_SECS, 0),
            Action::Silent
        );
        assert_eq!(watch.observe(180, false, Some(false), DEAF_SECS, 0), Action::Hold);
        assert_eq!(watch.observe(210, true, Some(false), DEAF_SECS, 0), Action::Hold);
        assert_eq!(
            watch.observe(210 + SETTLE, true, Some(false), DEAF_SECS, 0),
            Action::Silent
        );
    }

    #[test]
    fn a_round_that_could_not_run_is_neither_answer_nor_silence() {
        let mut watch = Watch::default();
        rounds(&mut watch, 0, 60, true, true);
        assert_eq!(
            watch.observe(90, true, Some(false), DEAF_SECS, 0),
            Action::Silent
        );
        assert_eq!(watch.observe(120, true, None, DEAF_SECS, 0), Action::Hold);
        // The earlier silence was dropped, so this is a first silent round again.
        assert_eq!(
            watch.observe(900, true, Some(false), DEAF_SECS, 0),
            Action::Silent
        );
    }

    #[test]
    fn each_reboot_that_did_not_help_doubles_the_wait() {
        assert_eq!(required_silence(DEAF_SECS, 0), 300);
        assert_eq!(required_silence(DEAF_SECS, 1), 600);
        assert_eq!(required_silence(DEAF_SECS, 3), 2400);
        assert_eq!(required_silence(DEAF_SECS, 12), MAX_WAIT);
        assert_eq!(required_silence(DEAF_SECS, 4000), MAX_WAIT);
        assert_eq!(required_silence(1, 0), 120);

        let mut watch = Watch::default();
        watch.observe(0, true, Some(true), DEAF_SECS, 2);
        let mut now = 30;
        let mut fired = None;
        while now <= 3000 && fired.is_none() {
            if let Action::Reboot { silent_for } =
                watch.observe(now, true, Some(false), DEAF_SECS, 2)
            {
                fired = Some(silent_for);
            }
            now += PROBE_EVERY;
        }
        assert_eq!(fired, Some(1200));
    }

    #[test]
    fn an_hour_of_answers_clears_the_strikes_once() {
        let mut watch = Watch::default();
        assert_eq!(
            watch.observe(0, true, Some(true), DEAF_SECS, 2),
            Action::Armed
        );
        assert_eq!(
            watch.observe(CLEAR_AFTER - 30, true, Some(true), DEAF_SECS, 2),
            Action::Hold
        );
        assert_eq!(
            watch.observe(CLEAR_AFTER, true, Some(true), DEAF_SECS, 2),
            Action::ClearStrikes
        );
        assert_eq!(
            watch.observe(CLEAR_AFTER + 30, true, Some(true), DEAF_SECS, 2),
            Action::Hold
        );
    }

    #[test]
    fn silence_restarts_the_hour_the_strike_count_needs() {
        let mut watch = Watch::default();
        watch.observe(0, true, Some(true), DEAF_SECS, 1);
        watch.observe(3000, true, Some(false), DEAF_SECS, 1);
        assert_eq!(
            watch.observe(3030, true, Some(true), DEAF_SECS, 1),
            Action::Recovered { silent_for: 30 }
        );
        assert_eq!(
            watch.observe(CLEAR_AFTER + 60, true, Some(true), DEAF_SECS, 1),
            Action::Hold
        );
        assert_eq!(
            watch.observe(3030 + CLEAR_AFTER, true, Some(true), DEAF_SECS, 1),
            Action::ClearStrikes
        );
    }

    #[test]
    fn settings_default_to_on_with_the_bearer_dns() {
        let settings = parse_settings("");
        assert_eq!(settings, Settings::default());
        assert!(settings.enabled);
        assert_eq!(
            targets(&settings, "nvram_get success: 192.0.2.53 0.0.0.0\n"),
            vec!["192.0.2.53".parse::<IpAddr>().unwrap()]
        );
        assert!(targets(&settings, "nvram_get success: \n").is_empty());
    }

    #[test]
    fn settings_take_operator_targets_and_ignore_damage() {
        let text = "\
# reboot when the core stops answering
enabled=1
deaf_secs=600
target=192.0.2.1
target=2001:db8::1
target=192.0.2.1
target=not-an-address
target=0.0.0.0
target=127.0.0.1
nonsense
";
        let settings = parse_settings(text);
        assert_eq!(settings.deaf_secs, 600);
        assert_eq!(
            settings.targets,
            vec![
                "192.0.2.1".parse::<IpAddr>().unwrap(),
                "2001:db8::1".parse::<IpAddr>().unwrap()
            ]
        );
        assert_eq!(targets(&settings, "nvram_get success: 198.51.100.9"), settings.targets);
        assert!(!parse_settings("enabled=0\n").enabled);
        assert_eq!(parse_settings("deaf_secs=5\n").deaf_secs, 120);
        assert_eq!(parse_settings("deaf_secs=x\n").deaf_secs, DEAF_SECS);
    }

    #[test]
    fn the_modem_state_and_the_strike_file_round_trip() {
        assert!(attached("nvram_get success: ATTACHED\n"));
        assert!(!attached("nvram_get success: SEARCHING\n"));
        assert!(!attached(""));
        assert_eq!(parse_strikes(&format_strikes(3)), 3);
        assert_eq!(parse_strikes("garbage"), 0);
    }

    #[test]
    fn the_vendor_ping_watchdog_is_read_from_the_ram_cache() {
        let cache = b"detection_interval=3\0detection_enable=1\0detection_enable_x=0\0";
        assert_eq!(nvram_field(cache, "detection_enable"), Some("1"));
        assert_eq!(nvram_field(cache, "detection_interval"), Some("3"));
        assert_eq!(nvram_field(b"a=1\nb=2\n", "b"), Some("2"));
        // A longer key with the same start is not this one.
        assert_eq!(nvram_field(b"detection_enable_x=0\0", "detection_enable"), None);
        assert_eq!(nvram_field(b"", "detection_enable"), None);
    }

    #[test]
    fn the_vendor_ping_watchdog_stops_only_while_ours_is_on() {
        let ours = Settings::default();
        assert!(vendor_watchdog_must_stop(&ours, Some("1")));
        assert!(vendor_watchdog_must_stop(&ours, Some(" 2")));
        assert!(vendor_watchdog_must_stop(&ours, Some("1x")));
        // Already off, unreadable as a number (ucid reads 0), or not in the
        // cache yet: nothing to do. Repeating the check is a no-op.
        assert!(!vendor_watchdog_must_stop(&ours, Some("0")));
        assert!(!vendor_watchdog_must_stop(&ours, Some("")));
        assert!(!vendor_watchdog_must_stop(&ours, Some("off")));
        assert!(!vendor_watchdog_must_stop(&ours, None));
        // An operator who turned ours off keeps the vendor one as saved.
        let off = parse_settings("enabled=0\n");
        assert!(!vendor_watchdog_must_stop(&off, Some("1")));
    }
}
