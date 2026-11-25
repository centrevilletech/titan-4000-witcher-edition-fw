//! "At most once every so many seconds", on the monotonic second clock.

/// When something last ran.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Pace {
    last: Option<u64>,
}

impl Pace {
    /// True, and recorded as a run at `now`, when it never ran or last ran
    /// `period` or more seconds ago.
    pub fn ready(&mut self, now: u64, period: u64) -> bool {
        if self.last.is_some_and(|at| now.saturating_sub(at) < period) {
            return false;
        }
        self.last = Some(now);
        true
    }

    /// Record a run at `now` without asking.
    pub fn mark(&mut self, now: u64) {
        self.last = Some(now);
    }

    /// Let the next `ready` pass whatever the period.
    pub fn reset(&mut self) {
        self.last = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pace_passes_once_per_period_from_its_last_run() {
        let mut pace = Pace::default();
        assert!(pace.ready(100, 10));
        assert!(!pace.ready(100, 10));
        assert!(!pace.ready(109, 10));
        assert!(pace.ready(110, 10));
        pace.mark(200);
        assert!(!pace.ready(205, 10));
        pace.reset();
        assert!(pace.ready(205, 10));
        // A clock that reads earlier than the last run is treated as no time passed.
        assert!(!pace.ready(150, 10));
    }
}
