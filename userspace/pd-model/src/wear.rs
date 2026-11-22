//! Keep routine keeper output off flash.
//!
//! The keeper's state directory is on the unit's UBIFS data volume. Before
//! v1.0.12 every periodic router advertisement appended a line to `keeper.log`
//! there, and the new action time made the keeper rewrite `status.json` too:
//! two flash writes every 45 seconds, about 5,700 a day. The bench log held
//! 2,213 of those lines out of 2,860 in 25.6 hours.
//!
//! Now:
//! - Routine lines (a periodic or a solicited advertisement) go to a RAM log
//!   only and do not count as the keeper's last action.
//! - Every other line goes to both logs, with the same repeat filter as before.
//! - `status.json` keeps a live copy in RAM. The flash copy is rewritten only
//!   when its content changes, and at most once a minute. A change inside that
//!   minute is written once the minute is up.

/// Seconds an identical line is held back, unless it is a real action.
pub const REPEAT_SECS: u64 = 60;
/// Least time between two rewrites of the flash copy of `status.json`.
pub const STATUS_FLASH_SECS: u64 = 60;
/// Size at which the RAM log moves to `keeper.log.1`.
pub const RAM_LOG_BYTES: u64 = 64 * 1024;
/// Size at which the flash log moves to `keeper.log.1` (unchanged).
pub const FLASH_LOG_BYTES: u64 = 256 * 1024;

/// A line the keeper repeats on a timer while all is well. It goes to RAM only.
/// A failed send names its reason in a longer line, so it is not routine.
pub fn routine(line: &str) -> bool {
    matches!(line, "periodic router advertisement" | "router solicitation")
}

/// A real action. It is logged every time, even right after the same line.
pub fn always(line: &str) -> bool {
    [
        "link drop",
        "learned ",
        "stopped answering",
        "withdraw",
        "DHCPv6",
        "udhcpd",
        "IPv4 router answered",
        "SAS NAT",
        "deaf watchdog",
        "further router advertisements",
        "without a new advertisement",
        "vendor ping watchdog",
        "CBRS gate closed",
        "CBRS gate open",
        "CBRS gate rules put back",
    ]
    .iter()
    .any(|part| line.contains(part))
}

/// Where one keeper line goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    /// A repeat inside `REPEAT_SECS`: not logged, but still the last action.
    Skip,
    /// Routine: the RAM log only. Not the last action.
    Ram,
    /// The RAM log and the flash log. The last action, with a new time.
    Flash,
}

/// The repeat filter. `now` is monotonic seconds.
#[derive(Default)]
pub struct Notes {
    last: String,
    last_at: u64,
}

impl Notes {
    pub fn route(&mut self, line: &str, now: u64) -> Route {
        if routine(line) {
            return Route::Ram;
        }
        let repeat = line == self.last && now.saturating_sub(self.last_at) < REPEAT_SECS;
        if repeat && !always(line) {
            return Route::Skip;
        }
        self.last = line.to_owned();
        self.last_at = now;
        Route::Flash
    }
}

/// When the flash copy of a changing file may be rewritten. `now` is monotonic
/// seconds, so a clock step cannot open or close the gate.
#[derive(Default)]
pub struct FlashGate {
    written_at: Option<u64>,
}

impl FlashGate {
    /// `differs`: the wanted content is not what flash holds.
    pub fn ready(&self, now: u64, differs: bool) -> bool {
        differs
            && self
                .written_at
                .is_none_or(|at| now.saturating_sub(at) >= STATUS_FLASH_SECS)
    }

    /// A write was attempted. A failed one waits for the gate too, so a full
    /// volume is not retried five times a second.
    pub fn wrote(&mut self, now: u64) {
        self.written_at = Some(now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routine_lines_stay_in_ram_and_never_touch_the_repeat_filter() {
        let mut notes = Notes::default();
        assert_eq!(notes.route("not serving: filter failed", 0), Route::Flash);
        assert_eq!(notes.route("periodic router advertisement", 10), Route::Ram);
        assert_eq!(notes.route("router solicitation", 20), Route::Ram);
        // The repeat filter still sees the last real line. Before, the
        // advertisement in between let this repeat through to flash.
        assert_eq!(notes.route("not serving: filter failed", 30), Route::Skip);
        assert_eq!(notes.route("not serving: filter failed", 59), Route::Skip);
        assert_eq!(notes.route("not serving: filter failed", 60), Route::Flash);
        for now in [105, 150, 195] {
            assert_eq!(notes.route("periodic router advertisement", now), Route::Ram);
        }
    }

    #[test]
    fn a_failed_send_is_not_routine() {
        assert!(!routine("send failed (periodic router advertisement): No such device"));
        assert!(!routine("send failed (router solicitation): Network is down"));
        let mut notes = Notes::default();
        let line = "send failed (periodic router advertisement): No such device";
        assert_eq!(notes.route(line, 0), Route::Flash);
        assert_eq!(notes.route(line, 45), Route::Skip);
        assert_eq!(notes.route(line, 90), Route::Flash);
    }

    #[test]
    fn real_actions_are_logged_every_time() {
        let mut notes = Notes::default();
        for now in [0, 1, 2] {
            assert_eq!(notes.route("SAS NAT rule restored", now), Route::Flash);
        }
        assert_eq!(
            notes.route("IPv4 router answered local ARP; automatic recovery is armed", 3),
            Route::Flash
        );
        assert!(always("vendor ping watchdog: turned off in RAM for this boot"));
        assert!(!always("periodic router advertisement"));
        assert!(!always("router solicitation"));
        // Every CBRS gate change is on record, even two re-attaches a few
        // seconds apart. A failure repeated every second is not.
        for line in [
            "CBRS gate closed: no SAS grant (cbrs_mode_grant=0, cbrs_grant_state=0); dropping customer IPv6 to and from LTE",
            "CBRS gate open: SAS grant held; customer IPv6 may forward",
            "CBRS gate rules put back: a vendor firewall restart removed 4 of 4",
        ] {
            assert!(always(line), "{line}");
        }
        assert!(!always("CBRS gate: ip6tables -I FORWARD 1 -o lte0pdn+ -j DROP failed: not found"));
    }

    #[test]
    fn the_status_gate_writes_a_change_at_most_once_a_minute() {
        let mut gate = FlashGate::default();
        // Nothing to write is never ready.
        assert!(!gate.ready(0, false));
        // The first change is written at once.
        assert!(gate.ready(10, true));
        gate.wrote(10);
        // A second change inside the minute waits, then goes out.
        assert!(!gate.ready(20, true));
        assert!(!gate.ready(69, true));
        assert!(gate.ready(70, true));
        gate.wrote(70);
        // A quiet minute leaves flash alone.
        assert!(!gate.ready(200, false));
        assert!(gate.ready(200, true));
    }

    #[test]
    fn steady_state_writes_nothing_for_a_day() {
        // One periodic advertisement every 45 s for 24 hours, nothing else.
        let mut notes = Notes::default();
        let mut gate = FlashGate::default();
        let mut flash_lines = 0;
        let mut status_writes = 0;
        let mut last_action_at = 0;
        let mut flash_action_at = 0;
        for tick in 0..(24 * 3600 / 45) {
            let now = tick * 45;
            if notes.route("periodic router advertisement", now) == Route::Flash {
                flash_lines += 1;
                last_action_at = now;
            }
            if gate.ready(now, last_action_at != flash_action_at) {
                gate.wrote(now);
                flash_action_at = last_action_at;
                status_writes += 1;
            }
        }
        assert_eq!((flash_lines, status_writes), (0, 0));
    }
}
