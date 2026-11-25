//! The two clocks the keeper reads.

use std::time::{SystemTime, UNIX_EPOCH};

/// Whole seconds on `CLOCK_MONOTONIC`. Keeper processes write it to files for
/// one another (the radio transition deadline, the last radio cycle), which
/// works because every process reads the same clock.
pub fn monotonic() -> u64 {
    titan_sys::kernel::monotonic_secs()
}

/// Whole seconds since 1970 on the wall clock, or 0 before then. The unit
/// boots in 2013 until network time answers.
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
