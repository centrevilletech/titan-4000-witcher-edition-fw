//! Exact Ring-0 feeder byte accounting (`n5.s` Hook C: `n5_ring0_submit`).

#![forbid(unsafe_code)]

use modem_atlas::patches::N5State;

use crate::state::{FLAG_DISABLE_R0_FIX, FLAG_FLOW_LANE};

/// Return `true` when Hook C should sum exact Ring-0 IRB byte lengths
/// (`bit 0 == 1` and `bit 2 == 0`).
#[inline(always)]
pub const fn should_fix_ring0(flags: u32) -> bool {
    (flags & (FLAG_FLOW_LANE | FLAG_DISABLE_R0_FIX)) == FLAG_FLOW_LANE
}

/// Sum exact `irb.length` bytes across the next `min(avail, count)` Ring-0 slots
/// using 12-bit modular ring wraparound (`0..4095`).
///
/// `read_slot_len(slot)` returns `Some(len)` for a non-null IRB or `None` for null.
#[inline(always)]
pub fn sum_ring0_bytes<F>(wr: u16, rd: u16, count: u32, mut read_slot_len: F) -> u32
where
    F: FnMut(usize) -> Option<u32>,
{
    if count == 0 {
        return 0;
    }
    let avail = (wr.wrapping_sub(rd) & 0x0fff) as u32;
    let mut rem = avail.min(count);
    if rem == 0 {
        return 0;
    }
    let mut sum = 0u32;
    let mut idx = (rd & 0x0fff) as u32;
    loop {
        if let Some(len) = read_slot_len(idx as usize) {
            sum = sum.wrapping_add(len);
        }
        idx = idx.wrapping_add(1) & 0x0fff;
        rem -= 1;
        if rem == 0 {
            return sum;
        }
    }
}

/// Record a non-zero exact Ring-0 byte submission in `N5State` telemetry counters.
#[inline(always)]
pub fn record_ring0_submit(n5: &mut N5State, exact_bytes: u32) {
    if exact_bytes != 0 {
        n5.c_r0_submit = n5.c_r0_submit.wrapping_add(1);
        n5.c_r0_fix_b = n5.c_r0_fix_b.wrapping_add(exact_bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::boot_n5_state;

    #[test]
    fn ring0_flag_gating_wraparound_sum_and_counters() {
        assert!(!should_fix_ring0(0));
        assert!(should_fix_ring0(1));
        assert!(should_fix_ring0(3));
        assert!(!should_fix_ring0(5));
        assert!(!should_fix_ring0(7));

        let mut slots = [None; 4096];
        slots[4095] = Some(64);
        slots[0] = Some(228);
        slots[1] = Some(1400);
        let sum = sum_ring0_bytes(2, 4095, 3, |s| slots[s]);
        assert_eq!(sum, 1692);
        assert_eq!(sum_ring0_bytes(2, 4095, 10, |s| slots[s]), 1692);

        let mut st = boot_n5_state();
        record_ring0_submit(&mut st, 0);
        assert_eq!(st.c_r0_submit, 0);
        assert_eq!(st.c_r0_fix_b, 0);
        record_ring0_submit(&mut st, sum);
        assert_eq!(st.c_r0_submit, 1);
        assert_eq!(st.c_r0_fix_b, 1692);
    }
}
