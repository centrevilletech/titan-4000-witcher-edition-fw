//! Retries that never give up (Josh, 2026-11-25: no transient condition may
//! leave a unit worse off after it clears). After each failure in a row the
//! wait before the next try doubles, from `Policy::first` up to `Policy::cap`,
//! and it goes on for as long as the failures do. A success, or a change that
//! makes a try worth making at once (a new config, a switch turned off and on
//! again), starts over. Nothing here outlives the keeper process.

/// The waits for one kind of retry, in seconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy {
    /// The wait after the first failure.
    pub first: u64,
    /// The longest wait.
    pub cap: u64,
}

/// Kernel module loads and the fast path's re-arm after a watchdog trip:
/// 1 min, 2, 4 ... up to an hour.
pub const MODULES: Policy = Policy {
    first: 60,
    cap: 3600,
};

impl Policy {
    /// The wait after `failures` failures in a row (one or more).
    pub fn wait(self, failures: u32) -> u64 {
        let cap = self.cap.max(self.first);
        let mut wait = self.first;
        for _ in 1..failures {
            if wait >= cap {
                break;
            }
            wait = wait.saturating_mul(2);
        }
        wait.min(cap)
    }

    /// This policy with `first` from `value` when it is a positive number of
    /// seconds. Tests shorten the waits with it; the cap stays.
    pub fn with_first(self, value: Option<&str>) -> Self {
        let first = value
            .and_then(|text| text.trim().parse::<u64>().ok())
            .filter(|secs| *secs > 0);
        Self {
            first: first.unwrap_or(self.first),
            ..self
        }
    }
}

/// Failures in a row and when the next try is due.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Backoff {
    failures: u32,
    due: u64,
}

impl Backoff {
    /// A try may run at `now` (monotonic seconds): no failure is waiting out
    /// its time.
    pub fn ready(&self, now: u64) -> bool {
        self.failures == 0 || now >= self.due
    }

    /// A try failed at `now`. Returns the wait before the next one.
    pub fn failed(&mut self, now: u64, policy: Policy) -> u64 {
        self.failures = self.failures.saturating_add(1);
        let wait = policy.wait(self.failures);
        self.due = now.saturating_add(wait);
        wait
    }

    /// Start over: the next try may run at once.
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    /// Failures in a row so far.
    pub fn failures(&self) -> u32 {
        self.failures
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_wait_doubles_to_the_cap_and_never_stops() {
        let policy = Policy { first: 60, cap: 3600 };
        let waits: Vec<u64> = (1..=9).map(|n| policy.wait(n)).collect();
        assert_eq!(waits, [60, 120, 240, 480, 960, 1920, 3600, 3600, 3600]);
        assert_eq!(policy.wait(u32::MAX), 3600, "no overflow, no give-up");
        assert_eq!(policy.wait(0), 60);
        assert_eq!(MODULES, policy);
        // A cap below the first wait never shortens it.
        assert_eq!(Policy { first: 90, cap: 30 }.wait(5), 90);
    }

    #[test]
    fn a_failure_waits_its_turn_and_a_reset_tries_at_once() {
        let mut retry = Backoff::default();
        assert!(retry.ready(0));
        assert_eq!(retry.failed(100, MODULES), 60);
        assert!(!retry.ready(159));
        assert!(retry.ready(160));
        assert_eq!(retry.failed(160, MODULES), 120);
        assert!(!retry.ready(279));
        assert!(retry.ready(280));
        assert_eq!(retry.failures(), 2);
        // Forever: the hundredth failure in a row still schedules a try.
        for n in 3..=100u32 {
            retry.failed(1_000 * u64::from(n), MODULES);
        }
        assert!(!retry.ready(100_000 + 3599));
        assert!(retry.ready(100_000 + 3600));
        retry.reset();
        assert!(retry.ready(0));
        assert_eq!(retry.failures(), 0);
    }

    #[test]
    fn tests_may_shorten_the_first_wait_only() {
        assert_eq!(MODULES.with_first(Some("3")), Policy { first: 3, cap: 3600 });
        for bad in [None, Some(""), Some("0"), Some("-5"), Some("soon")] {
            assert_eq!(MODULES.with_first(bad), MODULES, "{bad:?}");
        }
    }
}
