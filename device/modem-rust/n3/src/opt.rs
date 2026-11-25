//! Pure-Rust logic for the combined MAC & PDCP UL hot-path optimizations.
//!
//! Zero `unsafe`; all bare-metal memory access lives in `modem.rs`.

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

/// Unrolled 6-step BSR search for `bo_bytes > 0` (caller already handled `bo_bytes == 0`).
#[inline(always)]
pub const fn fast_bo_idx_nz(table: &[u32; 63], bo_bytes: u32) -> u8 {
    if bo_bytes > table[62] {
        return 63;
    }
    let mut lo: usize = 0;
    if bo_bytes > table[31] {
        lo = 31;
    }
    if bo_bytes > table[lo + 16] {
        lo += 16;
    }
    if bo_bytes > table[lo + 8] {
        lo += 8;
    }
    if bo_bytes > table[lo + 4] {
        lo += 4;
    }
    if bo_bytes > table[lo + 2] {
        lo += 2;
    }
    if bo_bytes > table[lo + 1] {
        lo += 1;
    }
    (lo + 1) as u8
}

/// Sound O(1) early-exit decision for `CheckLongBsrDowngradeToShort` (`0x842c_fe34`).
///
/// Returns:
/// - `1` (`true`): `<= 1` active LCG has data -> Long BSR can always downgrade to Short.
/// - `0` (`false`): at least 2 LCGs each have `bo_bytes > tb_rem` -> impossible to empty
///   either LCG in `tb_rem` bytes -> guaranteed cannot downgrade (saves ~800 CPU1 insns).
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

/// Pure-Rust tuned `do_tc` (`0x842e_5b06`) staging cap (`FLAG_DO_TC_CAP`):
/// computes `clamp((ul_250ms_bytes * target_ms) / 250, cap_min, cap_max)` using
/// pure 32-bit arithmetic (zero 64-bit `__aeabi_uldivmod` libcalls in Thumb-2).
///
/// Uses `((clamped_bytes >> 2) * 1049) >> 16`:
/// note `1049 / (4 * 65536) = 1049 / 262144 = 0.0040016 ~= 1 / 250` (`+0.04%` accuracy),
/// avoiding any division or 64-bit helper while clamping safely against overflow.
#[inline]
pub const fn compute_do_tc_cap(
    ul_250ms_bytes: u32,
    target_ms: u32,
    cap_min: u32,
    cap_max: u32,
) -> u32 {
    let min_b = if cap_min == 0 { 6_144 } else { cap_min };
    let max_b = if cap_max < min_b { min_b } else { cap_max };
    let t_ms = if target_ms == 0 {
        8
    } else if target_ms > 50 {
        50
    } else {
        target_ms
    };
    // Cap ul_250ms_bytes at 4 MiB / 250 ms (~134 Mbps) so intermediate never overflows u32:
    // (4_194_304 >> 2) = 1_048_576; * 1049 >> 16 = 16_784; * 50 = 839_200 << u32::MAX.
    let clamped_bytes = if ul_250ms_bytes > 0x0040_0000 {
        0x0040_0000
    } else {
        ul_250ms_bytes
    };
    let bytes_per_ms = ((clamped_bytes >> 2).wrapping_mul(1049)) >> 16;
    let desired = bytes_per_ms.wrapping_mul(t_ms);
    if desired < min_b {
        min_b
    } else if desired > max_b {
        max_b
    } else {
        desired
    }
}

/// Pure-Rust byte-accurate Ring-1 packet counter (`FLAG_PDCP_BYTE_PACING`).
///
/// Walks up to `max_pkts` packet lengths yielded by `next_len(i)` (adding 2 B PDCP header
/// per packet) and returns how many head packets fit inside `headroom_bytes`.
#[inline]
pub fn count_fitting_packets<F>(headroom_bytes: u32, max_pkts: u32, mut next_len: F) -> u32
where
    F: FnMut(u32) -> Option<u16>,
{
    let mut acc: u32 = 0;
    let mut cnt: u32 = 0;
    while cnt < max_pkts {
        let Some(ip_len) = next_len(cnt) else {
            break;
        };
        let pdu_bytes = (ip_len as u32).saturating_add(2);
        if acc.saturating_add(pdu_bytes) > headroom_bytes {
            break;
        }
        acc += pdu_bytes;
        cnt += 1;
    }
    cnt
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

    #[test]
    fn tuned_do_tc_cap_clamps_cleanly() {
        // 1CC 8 Mbps PHY = 250,000 B / 250 ms -> 8 ms target ~= 8,000 B
        let c1 = compute_do_tc_cap(250_000, 8, 6_144, 12_288);
        assert!((7_950..=8_050).contains(&c1), "c1={c1}");
        // Idle -> clamps to min
        assert_eq!(compute_do_tc_cap(0, 8, 6_144, 12_288), 6_144);
        // 2CC 17.5 Mbps PHY = 547,000 B / 250 ms -> 8 ms target = 17.5 KB -> clamps to max 12,288
        assert_eq!(compute_do_tc_cap(547_000, 8, 6_144, 12_288), 12_288);
        // Huge value never overflows
        assert_eq!(compute_do_tc_cap(u32::MAX, 50, 6_144, 12_288), 12_288);
    }

    #[test]
    fn byte_accurate_packet_counting() {
        let lens = [200u16, 200, 200, 1480, 1480];
        // Headroom 700 B: fits 3 small packets (3 * 202 = 606 B), stops before 1482 B
        assert_eq!(
            count_fitting_packets(700, 5, |i| lens.get(i as usize).copied()),
            3
        );
        // Headroom 2200 B: fits 3 * 202 + 1482 = 2088 B (4 packets)
        assert_eq!(
            count_fitting_packets(2200, 5, |i| lens.get(i as usize).copied()),
            4
        );
        // Headroom 100 B: 0 packets fit
        assert_eq!(
            count_fitting_packets(100, 5, |i| lens.get(i as usize).copied()),
            0
        );
    }
}
