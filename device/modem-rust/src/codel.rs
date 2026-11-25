//! CoDel's control law (RFC 8289) at Ring-1 enqueue, on the uplink queue in bytes.
//!
//! CoDel acts on a standing queue only: one that stayed above its target for a whole
//! interval. Then it signals (a drop, or a CE mark), and keeps signalling at
//! `interval / sqrt(n)` until the queue falls back under the target. A flow that backs
//! off is signalled about once per interval; traffic that does not is signalled ever
//! faster. Bursts shorter than an interval (TDD framing, HARQ pauses, slow start) pass.
//!
//! RFC 8289 measures each packet's sojourn when it leaves the queue. Hook 4 decides as
//! packets enter Ring 1, and selector 3 holds a byte level rather than a delay: the
//! queue the buffer status report shows the eNB. That one number sets both the delay
//! and, on the Nokia eNB, whether the second uplink carrier is scheduled. `target`
//! comes from `crate::q1` and already folds in the uplink's rate.
//!
//! The state is five block words, so the DM console sees it: `q1_codel_state`,
//! `q1_first_above_tti`, `q1_drop_next_tti`, `q1_count`, `q1_lastcount`.

#![forbid(unsafe_code)]

use crate::block::M1Block;

/// `q1_codel_state`: the queue is above target, timing `q1_first_above_tti`.
pub const ABOVE: u32 = 1 << 0;
/// `q1_codel_state`: in a dropping state.
pub const DROPPING: u32 = 1 << 1;

/// Drop counts stop growing here; the spacing is then 1 ms whatever the interval.
pub const MAX_COUNT: u32 = 0xffff;
/// Intervals above this (and 0) are clamped, so `16 x interval` stays meaningful.
pub const MAX_INTERVAL_MS: u32 = 1000;

impl M1Block {
    /// Whether CoDel signals the bulk packet arriving at `now` to a queue of
    /// `queue_bytes` held at `target` bytes. A queue of two packets or less never
    /// counts as standing.
    pub(crate) fn codel_signals(&self, now: u32, queue_bytes: u32, target: u32, mtu: u32) -> bool {
        let interval = self.q1_interval_ms.get().clamp(1, MAX_INTERVAL_MS);
        let mut state = self.q1_codel_state.get();

        // RFC 8289 `codel_should_drop`: above target for a whole interval.
        let standing = if queue_bytes <= target || queue_bytes <= mtu.saturating_mul(2) {
            state &= !ABOVE;
            false
        } else if state & ABOVE == 0 {
            state |= ABOVE;
            self.q1_first_above_tti.set(now.wrapping_add(interval));
            false
        } else {
            reached(now, self.q1_first_above_tti.get())
        };

        let signal = if state & DROPPING != 0 {
            if !standing {
                state &= !DROPPING;
                false
            } else if reached(now, self.q1_drop_next_tti.get()) {
                let count = self.q1_count.get().saturating_add(1).min(MAX_COUNT);
                self.q1_count.set(count);
                // The next signal follows the last one; after a gap longer than the
                // spacing (sparse packets), it restarts from now instead of firing on
                // every packet until the schedule catches up.
                let gap = spacing(interval, count);
                let next = self.q1_drop_next_tti.get().wrapping_add(gap);
                self.q1_drop_next_tti.set(if reached(now, next) { now.wrapping_add(gap) } else { next });
                true
            } else {
                false
            }
        } else if standing {
            state |= DROPPING;
            // A dropping state that ended recently resumes near its old rate (RFC 8289
            // section 5.6): `now - drop_next < 16 x interval`, signed as the clock wraps.
            let delta = self.q1_count.get().wrapping_sub(self.q1_lastcount.get());
            let since = now.wrapping_sub(self.q1_drop_next_tti.get());
            let recent = (since.wrapping_sub(interval * 16) as i32) < 0;
            let count = if delta > 1 && delta <= MAX_COUNT && recent { delta } else { 1 };
            self.q1_count.set(count);
            self.q1_lastcount.set(count);
            self.q1_drop_next_tti.set(now.wrapping_add(spacing(interval, count)));
            true
        } else {
            false
        };
        self.q1_codel_state.set(state);
        signal
    }
}

/// `at` has come. The 1 ms TTI clock wraps, so this compares by signed distance.
fn reached(now: u32, at: u32) -> bool {
    now.wrapping_sub(at) as i32 >= 0
}

/// CoDel's control law: the gap after the `count`-th signal, at least 1 ms.
pub fn spacing(interval: u32, count: u32) -> u32 {
    (interval / isqrt(count).max(1)).max(1)
}

/// The integer square root of `n <= MAX_COUNT`, digit by digit: no table, no division.
pub fn isqrt(n: u32) -> u32 {
    let n = n.min(MAX_COUNT);
    let (mut rest, mut root, mut bit) = (n, 0u32, 1u32 << 14);
    while bit > n {
        bit >>= 2;
    }
    while bit != 0 {
        if rest >= root + bit {
            rest -= root + bit;
            root = (root >> 1) + bit;
        } else {
            root >>= 1;
        }
        bit >>= 2;
    }
    root
}
