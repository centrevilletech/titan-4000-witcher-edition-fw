//! When the radio profile guard tries a saved profile, how it judges one, and
//! what it keeps on flash (v1.0.17: no transient condition may leave a
//! profile off once it clears).
//!
//! A profile (`radio`) changes RAM settings only, so every boot starts on
//! stock settings. The guard (`titan-pd-keeper opt-guard`) tries the saved
//! profile, confirms it, checks it every 30 s, and puts stock back when it
//! fails. The rules:
//!
//! - **A trial needs a working stock baseline.** Only an attached unit whose
//!   management probe answers is tried. A tower, core or SAS outage, a boot
//!   inside the CPAS window, an LTE stack still starting, a pending keeper
//!   recovery or a busy modem console means "not tried": nothing is written
//!   or counted, and the guard looks again `NOT_READY_SECS` later.
//! - **A strike needs comparative evidence.** Management failed under the
//!   profile, then answered on stock right after the rollback, by the same
//!   test (`SETTLE_SECS` of answers within `JUDGE_SECS`). When stock does not
//!   answer either, the network failed: no strike. A failure that is not
//!   management's (a setting that did not read back, RRC trouble, the SQM
//!   tools) is never a strike. `LOCK_STRIKES` strikes with no confirmed trial
//!   between them lock the profile; a confirmed trial clears them.
//! - **The lock clears itself.** Strikes are stamped with the profile and the
//!   firmware they were counted under (`parse_record`): another profile, the
//!   same profile saved again (the guard clears the record on every save) or
//!   a new firmware starts from none. A record from before v1.0.17 or a
//!   damaged one reads as none.
//! - **No give-ups.** After a failed trial or a rollback the profile is tried
//!   again after `backoff`, doubling from `FIRST_BACKOFF` to `MAX_BACKOFF`,
//!   forever (`Retry`). Nothing waits for a reboot.
//! - **A running profile is rolled back for management only after
//!   `SUSTAINED_SECS`** of failed checks while attached, as the deaf watchdog
//!   waits (`Health`). A lost ping, a core blip, a probe that drops ICMP for a
//!   while, a detach or a busy console changes nothing.
//! - **Crash loops stay bounded without a lock.** A trial is counted on flash
//!   (`Record::tries`) before its first write and cleared once judged. A trial
//!   that a power cut, a crash or a restarted guard cut short stays counted,
//!   and the next one waits `backoff(tries)` after boot: flapping power only
//!   delays the profile, and a profile that crashed the unit would run at
//!   most once per `MAX_BACKOFF` of uptime.
//! - **A stock restore that fails is retried** (`Restore`). Only after
//!   `RESTORE_RESTART_SECS` of failures does the guard ask for a restart, and
//!   that goes through the keeper's reboot gate (the CPAS window, the clock,
//!   the daily cap). The saved profile is never touched.
//! - **Radio cycles** (the enforcement re-attach, the picker's visits) change
//!   the carrier set, so the vendor gives back every grant and needs new ones,
//!   and none are issued in the CPAS window. They wait out the reboot gate's
//!   CPAS window widened by `CYCLE_MARGIN_MIN` on each side (`cycle_hold`),
//!   need a set clock, and at most `CYCLE_CAP` run in a day (`cycles_allow`).

use crate::carrier_watch::QuietWindow;
use crate::reboots;

/// Comparative strikes with no confirmed trial between them that lock a
/// profile until it, or the firmware, changes.
pub const LOCK_STRIKES: u32 = 3;
/// The first wait after a failed trial or a rollback.
pub const FIRST_BACKOFF: u64 = 300;
/// The longest wait between two trials.
pub const MAX_BACKOFF: u64 = 3600;
/// How soon the guard looks again when nothing could be tried.
pub const NOT_READY_SECS: u64 = 30;
/// Failed checks of a running profile, while attached, this long roll it back.
pub const SUSTAINED_SECS: u64 = 300;
/// Answers in a row that confirm a profile, or show that stock works.
pub const SETTLE_SECS: u64 = 30;
/// The window those answers must come in.
pub const JUDGE_SECS: u64 = 90;
/// A failed stock restore is tried again after this, doubling to `RESTORE_MAX`.
pub const RESTORE_FIRST: u64 = 30;
pub const RESTORE_MAX: u64 = 600;
/// A stock restore that has failed this long asks for a restart.
pub const RESTORE_RESTART_SECS: u64 = 600;
/// Minutes a radio cycle keeps clear on each side of the CPAS window.
pub const CYCLE_MARGIN_MIN: u16 = 15;
/// Radio cycles allowed in a day (`reboots::WINDOW`). A survey of the most
/// arms (`carrier_pick::MAX_ARMS`) and the return to the chosen one fit.
pub const CYCLE_CAP: usize = 8;

fn doubling(n: u32, first: u64, max: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    first.saturating_mul(1u64 << (n - 1).min(20)).min(max)
}

/// The wait before the next trial after `n` failed or interrupted ones in a
/// row: none for 0, then `FIRST_BACKOFF` doubling to `MAX_BACKOFF`.
pub fn backoff(n: u32) -> u64 {
    doubling(n, FIRST_BACKOFF, MAX_BACKOFF)
}

/// The record on the persistent volume (`radio/strikes`) for one profile
/// under one firmware.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Record {
    /// Comparative strikes since the last confirmed trial.
    pub strikes: u32,
    /// Trials counted before their first write and not judged since.
    pub tries: u32,
}

impl Record {
    pub fn locked(self) -> bool {
        self.strikes >= LOCK_STRIKES
    }

    /// The record to write before a trial's first write.
    pub fn started(self) -> Self {
        Self {
            tries: self.tries.saturating_add(1),
            ..self
        }
    }

    /// The record once a trial or a rollback has been judged.
    pub fn judged(self, verdict: Verdict) -> Self {
        Self {
            strikes: self.strikes + u32::from(verdict == Verdict::Profile),
            tries: 0,
        }
    }
}

/// The id strikes are stamped with: the first 16 hex digits of the SHA-256 of
/// the saved profile.
pub fn profile_id(saved: &[u8]) -> String {
    let hex = crate::sha256::hex(&crate::sha256::digest(saved));
    hex.get(..16).unwrap_or(&hex).to_owned()
}

/// `key=value` lines; anything else is skipped.
fn fields(text: &str) -> impl Iterator<Item = (&str, &str)> {
    text.lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.trim(), value.trim()))
}

/// The record as it applies to `profile` under `firmware`. Counts stamped for
/// another profile or firmware, a record from before v1.0.17 (a bare number,
/// with no stamp) and a damaged file all read as none.
pub fn parse_record(text: &str, profile: &str, firmware: &str) -> Record {
    let mut record = Record::default();
    let (mut stamped_profile, mut stamped_firmware) = (None, None);
    for (key, value) in fields(text) {
        match key {
            "strikes" => record.strikes = value.parse().unwrap_or(0),
            "tries" => record.tries = value.parse().unwrap_or(0),
            "profile" => stamped_profile = Some(value),
            "firmware" => stamped_firmware = Some(value),
            _ => {}
        }
    }
    if stamped_profile == Some(profile) && stamped_firmware == Some(firmware) {
        record
    } else {
        Record::default()
    }
}

pub fn render_record(record: Record, profile: &str, firmware: &str) -> String {
    format!(
        "strikes={}\ntries={}\nprofile={profile}\nfirmware={firmware}\n",
        record.strikes, record.tries
    )
}

/// Whose failure a rollback was, once stock settings are back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Management failed under the profile and answers on stock: a strike.
    Profile,
    /// Management failed and does not answer on stock either: the network's.
    Network,
    /// Not a management failure: no comparison, no strike.
    Unjudged,
}

impl Verdict {
    /// `stock_answers` is the comparison after the rollback, made only for a
    /// management failure.
    pub fn of(management_failed: bool, stock_answers: bool) -> Self {
        match (management_failed, stock_answers) {
            (true, true) => Self::Profile,
            (true, false) => Self::Network,
            (false, _) => Self::Unjudged,
        }
    }

    pub fn describe(self) -> &'static str {
        match self {
            Self::Profile => "management answered on stock settings, so it counts against the profile",
            Self::Network => "management did not answer on stock settings either, so the network failed, not the profile",
            Self::Unjudged => "not a management failure, so it does not count against the profile",
        }
    }
}

/// A running profile's management checks.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Health {
    failing_since: Option<u64>,
}

impl Health {
    /// One check at `now`. `Some(true)`: management answered. `Some(false)`:
    /// it did not, while attached. `None`: not judged (the console was busy).
    /// True once checks have failed for `SUSTAINED_SECS`.
    pub fn observe(&mut self, now: u64, answered: Option<bool>) -> bool {
        match answered {
            Some(true) => {
                self.failing_since = None;
                false
            }
            Some(false) => now.saturating_sub(*self.failing_since.get_or_insert(now)) >= SUSTAINED_SECS,
            None => false,
        }
    }

    /// A detached unit: the tower's doing, not the profile's. Judge afresh
    /// after the next attach.
    pub fn detached(&mut self) {
        self.failing_since = None;
    }

    /// How long checks have failed, for the status.
    pub fn failing_for(&self, now: u64) -> Option<u64> {
        self.failing_since.map(|since| now.saturating_sub(since))
    }
}

/// When the guard may try the saved profile next on this boot. It lives in
/// RAM, so a restarted guard keeps it and a reboot starts it from the record.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Retry {
    /// The profile it is for (`profile_id`).
    pub profile: String,
    /// Failed or interrupted trials in a row.
    pub failures: u32,
    /// Monotonic second the next trial may start.
    pub next_at: u64,
}

impl Retry {
    /// The schedule for `profile` when the record holds `tries` trials that
    /// were never judged: the first waits `backoff(tries)` after boot.
    pub fn new(profile: &str, tries: u32) -> Self {
        Self {
            profile: profile.to_owned(),
            failures: tries,
            next_at: backoff(tries),
        }
    }

    pub fn due(&self, now: u64) -> bool {
        now >= self.next_at
    }

    /// Nothing could be tried: look again soon, at no cost.
    pub fn not_ready(&mut self, now: u64) {
        self.next_at = now + NOT_READY_SECS;
    }

    /// A trial or a running profile failed. Returns the wait.
    pub fn failed(&mut self, now: u64) -> u64 {
        self.failures = self.failures.saturating_add(1);
        let wait = backoff(self.failures);
        self.next_at = now + wait;
        wait
    }

    pub fn parse(text: &str) -> Option<Self> {
        let mut retry = Self::default();
        let mut profile = None;
        for (key, value) in fields(text) {
            match key {
                "profile" => profile = Some(value.to_owned()),
                "failures" => retry.failures = value.parse().ok()?,
                "next_at" => retry.next_at = value.parse().ok()?,
                _ => {}
            }
        }
        retry.profile = profile?;
        Some(retry)
    }

    pub fn render(&self) -> String {
        format!(
            "profile={}\nfailures={}\nnext_at={}\n",
            self.profile, self.failures, self.next_at
        )
    }
}

/// A stock restore that has not confirmed yet. It lives in RAM.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Restore {
    pub failures: u32,
    /// Monotonic second of the first failure.
    pub since: u64,
    pub next_at: u64,
}

impl Restore {
    pub fn due(&self, now: u64) -> bool {
        now >= self.next_at
    }

    /// One more failed restore. Returns the wait before the next.
    pub fn failed(&mut self, now: u64) -> u64 {
        if self.failures == 0 {
            self.since = now;
        }
        self.failures = self.failures.saturating_add(1);
        let wait = doubling(self.failures, RESTORE_FIRST, RESTORE_MAX);
        self.next_at = now + wait;
        wait
    }

    /// The restore has failed for so long that a restart should put stock
    /// back. The keeper's reboot gate decides when.
    pub fn restart_due(&self, now: u64) -> bool {
        self.failures > 0 && now.saturating_sub(self.since) >= RESTORE_RESTART_SECS
    }

    pub fn parse(text: &str) -> Self {
        let mut restore = Self::default();
        for (key, value) in fields(text) {
            let value = value.parse().unwrap_or(0);
            match key {
                "failures" => restore.failures = u32::try_from(value).unwrap_or(u32::MAX),
                "since" => restore.since = value,
                "next_at" => restore.next_at = value,
                _ => {}
            }
        }
        restore
    }

    pub fn render(&self) -> String {
        format!(
            "failures={}\nsince={}\nnext_at={}\n",
            self.failures, self.since, self.next_at
        )
    }
}

/// The window a radio cycle waits out: `cpas` (the reboot gate's CPAS
/// window) widened by `CYCLE_MARGIN_MIN` on each side, so the grants the
/// cycle gives back can come again before the window opens.
pub fn cycle_window(cpas: Option<QuietWindow>) -> Option<QuietWindow> {
    const DAY: u16 = 24 * 60;
    cpas.map(|w| QuietWindow {
        start_min: (w.start_min + DAY - CYCLE_MARGIN_MIN) % DAY,
        end_min: (w.end_min + CYCLE_MARGIN_MIN) % DAY,
    })
}

/// Why a radio cycle must wait now, or `None` when it may go: the time is
/// inside `cycle_window(cpas)`, or the clock is not set. A cycle only ever
/// starts while the SAS grant is held, so it follows the reboot gate's rule
/// for a boot that heard the core (`tk_boot::reboot_hold`).
pub fn cycle_hold(cpas: Option<QuietWindow>, wall: u64) -> Option<&'static str> {
    crate::tk_boot::reboot_hold(cycle_window(cpas), wall, true)
}

/// Whether a radio cycle that needs `slots` free ones fits the daily cap:
/// `reboots::SLOTS_AWAY` for one that moves the unit (itself and the way
/// back), `reboots::SLOTS_BACK` for the way back. `entries` is the cycle log
/// (`radio/cycles`), kept like the keeper's reboot log (`reboots`).
pub fn cycles_allow(entries: &[reboots::Entry], wall: u64, slots: usize) -> bool {
    CYCLE_CAP.saturating_sub(reboots::recent(entries, wall)) >= slots
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tk_boot::{CLOCK_SET_AFTER, CPAS_QUIET};

    /// 2026-11-22 00:00 UTC.
    const DAY0: u64 = 1_795_305_600;
    const P: &str = "0123456789abcdef";
    const FW: &str = "fedcba9876543210";

    fn at(h: u64, m: u64) -> u64 {
        DAY0 + h * 3600 + m * 60
    }

    /// What one trial meets, for the scenarios below.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Meets {
        /// Not attached, or management not answering on stock: no trial.
        NoNetwork,
        /// The power goes (or the unit crashes) during the trial.
        PowerCut,
        /// The profile confirms.
        Confirms,
        /// Management never settles under the profile; stock then answers.
        BreaksManagement,
        /// Management never settles, and stock does not answer either.
        NetworkDrops,
    }

    /// One boot of the guard's trial flow (keeper `radio.rs`, `trial`), as
    /// the model decides it. Returns the record written to flash and whether
    /// the profile ran by the end. `uptime` is how long the boot lasts.
    fn boot(record: &str, meets: &[Meets], uptime: u64) -> (String, bool) {
        let mut rec = parse_record(record, P, FW);
        let mut retry = Retry::new(P, rec.tries);
        let mut flash = record.to_owned();
        let mut meets = meets.iter().copied();
        let mut now = 20;
        while now < uptime {
            if rec.locked() {
                return (flash, false);
            }
            if !retry.due(now) {
                now = retry.next_at;
                continue;
            }
            let Some(m) = meets.next() else {
                return (flash, false);
            };
            if m == Meets::NoNetwork {
                retry.not_ready(now);
                continue;
            }
            rec = rec.started();
            flash = render_record(rec, P, FW);
            match m {
                Meets::PowerCut => return (flash, false),
                Meets::Confirms => {
                    flash = render_record(Record::default(), P, FW);
                    return (flash, true);
                }
                _ => {
                    let verdict = Verdict::of(true, m == Meets::BreaksManagement);
                    rec = rec.judged(verdict);
                    flash = render_record(rec, P, FW);
                    retry.failed(now);
                }
            }
        }
        (flash, false)
    }

    #[test]
    fn a_tower_down_at_boot_is_never_a_trial_and_costs_nothing_later() {
        // The tower is down for the first 40 looks (20 minutes), then back.
        let mut meets = vec![Meets::NoNetwork; 40];
        meets.push(Meets::Confirms);
        let (flash, ran) = boot("", &meets, 86_400);
        assert!(ran, "the profile runs as soon as the tower is back");
        assert_eq!(parse_record(&flash, P, FW), Record::default());
        // Under the old rules this boot wrote strike 1 and blocked the
        // profile for the rest of the boot; three such boots locked it.
        let mut flash = String::new();
        for _ in 0..5 {
            let (next, ran) = boot(&flash, &meets, 86_400);
            assert!(ran);
            flash = next;
        }
        assert!(!parse_record(&flash, P, FW).locked());
    }

    #[test]
    fn flapping_power_delays_the_profile_but_never_locks_it() {
        // A stormy night: thirty boots in a row whose trial a power cut ends.
        let mut flash = String::new();
        let mut waits = Vec::new();
        for _ in 0..30 {
            let rec = parse_record(&flash, P, FW);
            waits.push(Retry::new(P, rec.tries).next_at);
            let (next, ran) = boot(&flash, &[Meets::PowerCut], 86_400);
            assert!(!ran);
            flash = next;
            assert!(!parse_record(&flash, P, FW).locked());
        }
        // Each boot waits longer before its trial, up to an hour of uptime.
        assert_eq!(&waits[..6], &[0, 300, 600, 1200, 2400, 3600]);
        assert!(waits.iter().all(|w| *w <= MAX_BACKOFF));
        // The power settles: the next boot tries after an hour and confirms.
        let (flash, ran) = boot(&flash, &[Meets::Confirms], 86_400);
        assert!(ran);
        assert_eq!(parse_record(&flash, P, FW), Record::default());
        // A boot too short to reach its wait does not try at all.
        let cut = render_record(Record { strikes: 0, tries: 6 }, P, FW);
        assert_eq!(boot(&cut, &[Meets::Confirms], 3599), (cut.clone(), false));
    }

    #[test]
    fn only_management_that_stock_restores_counts_and_three_lock() {
        // Network outages during trials never strike, however many.
        let mut flash = String::new();
        for _ in 0..10 {
            let (next, _) = boot(&flash, &[Meets::NetworkDrops; 3], 86_400);
            flash = next;
        }
        assert_eq!(parse_record(&flash, P, FW).strikes, 0);
        // A profile that breaks management where stock works: three strikes
        // across retries, then locked for this profile and firmware only.
        let (flash, ran) = boot("", &[Meets::BreaksManagement; 3], 86_400);
        assert!(!ran);
        let rec = parse_record(&flash, P, FW);
        assert_eq!(rec, Record { strikes: 3, tries: 0 });
        assert!(rec.locked());
        assert_eq!(boot(&flash, &[Meets::Confirms], 86_400), (flash.clone(), false));
        // A new firmware, or another profile, starts from none.
        assert_eq!(parse_record(&flash, P, "1111111111111111"), Record::default());
        assert_eq!(parse_record(&flash, "2222222222222222", FW), Record::default());
        // A confirmed trial between strikes clears them.
        let two = Record::default()
            .judged(Verdict::Profile)
            .judged(Verdict::Profile);
        assert!(boot(&render_record(two, P, FW), &[Meets::Confirms], 86_400).1);
        // Failures that are not management's never strike.
        assert_eq!(Record::default().judged(Verdict::Unjudged).strikes, 0);
        assert_eq!(Verdict::of(false, true), Verdict::Unjudged);
    }

    #[test]
    fn records_before_this_rule_and_damaged_ones_read_as_none() {
        // v1.0.10-v1.0.16 wrote a bare count, and "3" locked the profile.
        for old in ["3", "3\n", "1", "", "garbage", "strikes=x\ntries=\n"] {
            assert_eq!(parse_record(old, P, FW), Record::default(), "{old:?}");
        }
        let text = render_record(Record { strikes: 2, tries: 1 }, P, FW);
        assert_eq!(parse_record(&text, P, FW), Record { strikes: 2, tries: 1 });
        assert_eq!(profile_id(b"{}").len(), 16);
        assert_ne!(profile_id(b"{}"), profile_id(b"{} "));
    }

    #[test]
    fn a_running_profile_survives_blips_and_is_judged_only_on_sustained_loss() {
        // L1's odds model: two pings 3 s apart every 30 s. One missed check,
        // a 15 s or a 30 s gap reverted a profile under the old rules.
        let mut health = Health::default();
        let mut t = 0;
        for answered in [Some(true), Some(false), Some(true), Some(false), Some(false), Some(true)] {
            assert!(!health.observe(t, answered));
            t += 30;
        }
        // A busy console, or a detach, judges nothing.
        assert!(!health.observe(t, Some(false)));
        for _ in 0..20 {
            t += 30;
            assert!(!health.observe(t, None));
            health.detached();
        }
        // Management lost for five minutes while attached: roll back.
        let mut health = Health::default();
        let mut rolled = None;
        for i in 0..20 {
            if health.observe(i * 30, Some(false)) {
                rolled = Some(i * 30);
                break;
            }
        }
        assert_eq!(rolled, Some(SUSTAINED_SECS));
        assert_eq!(health.failing_for(SUSTAINED_SECS), Some(SUSTAINED_SECS));
    }

    #[test]
    fn retries_back_off_to_an_hour_and_survive_a_guard_restart() {
        let mut retry = Retry::new(P, 0);
        assert!(retry.due(0));
        let waits: Vec<u64> = (0..8).map(|_| retry.failed(1000)).collect();
        assert_eq!(waits, [300, 600, 1200, 2400, 3600, 3600, 3600, 3600]);
        retry.not_ready(5000);
        assert_eq!(retry.next_at, 5000 + NOT_READY_SECS);
        assert_eq!(Retry::parse(&retry.render()), Some(retry.clone()));
        assert_eq!(Retry::parse("failures=1\n"), None);
        assert_eq!(Retry::parse("profile=x\nnext_at=y\n"), None);
    }

    #[test]
    fn a_failed_restore_retries_and_asks_for_a_restart_only_after_ten_minutes() {
        let mut restore = Restore::default();
        let mut now = 100;
        let mut waits = Vec::new();
        while !restore.restart_due(now) {
            assert!(restore.due(now));
            waits.push(restore.failed(now));
            now = restore.next_at;
        }
        assert_eq!(waits, [30, 60, 120, 240, 480]);
        assert!(now - 100 >= RESTORE_RESTART_SECS);
        // It keeps trying while the reboot gate holds the restart.
        assert_eq!(restore.failed(now), RESTORE_MAX);
        assert_eq!(Restore::parse(&restore.render()), restore);
        assert_eq!(Restore::parse("junk"), Restore::default());
    }

    #[test]
    fn radio_cycles_wait_out_the_cpas_window_with_a_margin_and_for_the_clock() {
        let cpas = Some(CPAS_QUIET);
        assert_eq!(
            cycle_window(cpas),
            Some(QuietWindow { start_min: 6 * 60 + 30, end_min: 10 * 60 + 30 })
        );
        let open = Some("the SAS CPAS window is open");
        assert_eq!(cycle_hold(cpas, at(6, 29)), None);
        assert_eq!(cycle_hold(cpas, at(6, 30)), open);
        assert_eq!(cycle_hold(cpas, at(8, 0)), open);
        assert_eq!(cycle_hold(cpas, at(10, 29)), open);
        assert_eq!(cycle_hold(cpas, at(10, 30)), None);
        assert_eq!(cycle_hold(cpas, CLOCK_SET_AFTER - 1), Some("the clock is not set yet"));
        assert_eq!(cycle_hold(None, at(8, 0)), None);
        // A window up to midnight, and one across it.
        let late = QuietWindow { start_min: 23 * 60, end_min: 24 * 60 };
        assert_eq!(cycle_window(Some(late)), Some(QuietWindow { start_min: 22 * 60 + 45, end_min: 15 }));
        assert_eq!(cycle_hold(Some(late), at(0, 14)), open);
        assert_eq!(cycle_hold(Some(late), at(0, 15)), None);
    }

    #[test]
    fn a_day_holds_one_full_survey_and_its_return_and_keeps_the_way_back() {
        let noon = at(12, 0);
        let mut log = Vec::new();
        // Six visits away (the most arms a picker takes), each keeping a slot
        // for the way back.
        for _ in 0..6 {
            assert!(cycles_allow(&log, noon, reboots::SLOTS_AWAY));
            log = reboots::parse(&reboots::record(&log, noon, "visit"));
        }
        // The return to the chosen arm.
        assert!(cycles_allow(&log, noon, reboots::SLOTS_BACK));
        log = reboots::parse(&reboots::record(&log, noon, "hold"));
        // One more: only a way back fits now, never another trip away.
        assert!(!cycles_allow(&log, noon, reboots::SLOTS_AWAY));
        assert!(cycles_allow(&log, noon, reboots::SLOTS_BACK));
        log = reboots::parse(&reboots::record(&log, noon, "back"));
        assert!(!cycles_allow(&log, noon, reboots::SLOTS_BACK));
        // A day later the slots are free again.
        assert!(cycles_allow(&log, noon + reboots::WINDOW, reboots::SLOTS_AWAY));
    }
}
