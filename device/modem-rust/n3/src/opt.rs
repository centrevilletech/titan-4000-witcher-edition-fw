//! Pure-Rust logic for the Lane N3 MAC UL hot-path optimizations.
//!
//! Zero `unsafe`; all memory access lives in `modem.rs`.

#![forbid(unsafe_code)]

use modem_atlas::mac::bsr_index_in;

/// Return value sentinel meaning "fast-path inconclusive; run stock fallback".
pub const FALLBACK_TO_STOCK: u32 = 2;

/// Fast `SearchMacUlBoIdx` (`0x842c_cf64`) using `bo == 0` early-exit and unrolled 6-step search.
///
/// Bit-identical to stock `SearchMacUlBoIdx` across every `u32` input for both
/// `ROM_STD_BSR_TABLE_VA` (`0x847f_5b1c`) and `ROM_EXT_BSR_TABLE_VA` (`0x847f_5c18`).
#[inline(always)]
pub const fn fast_bo_idx(table: &[u32; 63], bo_bytes: u32) -> u8 {
    bsr_index_in(table, bo_bytes)
}

/// Sound O(1) early-exit decision for `CheckLongBsrDowngradeToShort` (`0x842c_fe34`).
///
/// Returns:
/// - `1` (`true`): `<= 1` active LCG has data -> Long BSR can always downgrade to Short.
/// - `0` (`false`): at least 2 LCGs each have `bo_bytes > tb_rem` -> impossible to empty
///   either LCG in `tb_rem` bytes -> guaranteed cannot downgrade (saves ~820 CPU1 insns!).
/// - [`FALLBACK_TO_STOCK`] (`2`): borderline case -> run stock `CheckLongBsrDowngradeToShort`.
#[inline(always)]
pub const fn fast_long_bsr_downgrade(
    active_lcg_cnt: u8,
    lcg_bo: [u32; 4],
    tb_rem: u32,
) -> u32 {
    if active_lcg_cnt <= 1 {
        return 1;
    }
    let mut unemptiable = 0u32;
    if lcg_bo[0] > tb_rem {
        unemptiable += 1;
    }
    if lcg_bo[1] > tb_rem {
        unemptiable += 1;
    }
    if lcg_bo[2] > tb_rem {
        unemptiable += 1;
    }
    if lcg_bo[3] > tb_rem {
        unemptiable += 1;
    }
    if unemptiable >= 2 {
        0
    } else {
        FALLBACK_TO_STOCK
    }
}

/// Empty-ring & idle-cipher guard for `mac_bsr_pre_work` (`0x842d_a60c`).
///
/// If `ring_pending_bytes != 0` while Ring 0, Ring 1, and both hardware LLCE0 cipher queues
/// are empty, returns `(0, true)` to suppress stale byte-counter drift from leaking into BSR.
#[inline(always)]
pub const fn guarded_pre_bo(
    ring_pending_bytes: u32,
    r0_nonempty: bool,
    r1_nonempty: bool,
    cipher_active: bool,
) -> (u32, bool) {
    if ring_pending_bytes == 0 {
        return (0, false);
    }
    if r0_nonempty || r1_nonempty || cipher_active {
        (ring_pending_bytes, false)
    } else {
        (0, true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use modem_atlas::mac::{EXT_BSR_TABLE, STD_BSR_TABLE};

    fn stock_binary_search(table: &[u32; 63], bo: u32) -> u8 {
        if bo > table[62] {
            return 63;
        }
        let (mut lo, mut hi) = (0usize, 62usize);
        while lo <= hi {
            let mid = (lo + hi) / 2;
            if bo <= table[mid] {
                if mid == 0 {
                    return 0;
                }
                hi = mid - 1;
            } else {
                lo = mid + 1;
            }
        }
        lo as u8
    }

    #[test]
    fn fast_bo_idx_is_bit_identical_on_all_64_buckets_std_and_ext() {
        for table in [&STD_BSR_TABLE, &EXT_BSR_TABLE] {
            assert_eq!(fast_bo_idx(table, 0), 0);
            for &bound in table {
                for delta in [-1i64, 0, 1] {
                    let v = (bound as i64 + delta).max(0) as u32;
                    assert_eq!(
                        fast_bo_idx(table, v),
                        stock_binary_search(table, v),
                        "mismatch at {v}"
                    );
                }
            }
            assert_eq!(fast_bo_idx(table, u32::MAX), 63);
        }
    }

    #[test]
    fn fast_long_bsr_downgrade_decisions() {
        assert_eq!(fast_long_bsr_downgrade(0, [0, 0, 0, 0], 100), 1);
        assert_eq!(fast_long_bsr_downgrade(1, [0, 0, 0, 50_000], 6792), 1);
        assert_eq!(fast_long_bsr_downgrade(2, [0, 15_000, 0, 20_000], 6792), 0);
        assert_eq!(
            fast_long_bsr_downgrade(2, [100, 0, 0, 20_000], 6792),
            FALLBACK_TO_STOCK
        );
        assert_eq!(
            fast_long_bsr_downgrade(2, [6792, 0, 0, 20_000], 6792),
            FALLBACK_TO_STOCK
        );
    }

    #[test]
    fn guarded_pre_bo_suppresses_stale_drift_only_when_idle() {
        assert_eq!(guarded_pre_bo(0, false, false, false), (0, false));
        assert_eq!(guarded_pre_bo(4096, false, false, false), (0, true));
        assert_eq!(guarded_pre_bo(4096, true, false, false), (4096, false));
        assert_eq!(guarded_pre_bo(4096, false, true, false), (4096, false));
        assert_eq!(guarded_pre_bo(4096, false, false, true), (4096, false));
    }
}
