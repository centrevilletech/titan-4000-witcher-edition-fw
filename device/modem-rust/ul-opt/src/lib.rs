//! `no_std` Rust Thumb-2 hot-path optimizations for the Titan 4000 PDCP/RLC/BSR uplink stack.
//!
//! Every optimization sits behind a boot-off bit in [`logic::N2OptState`] at `0x841b_b5c0`
//! (with magic `"N2OP"` and version `0x2026_1125`; any unknown flag bit forces all hooks off).

#![no_std]

pub mod hooks;
pub mod logic;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[cfg(test)]
mod tests {
    use crate::logic::{
        N2OptState, N2_FLAGS_KNOWN_MASK, N2_FLAG_BYTE_PACING, N2_FLAG_DO_TC_CAP, N2_FLAG_FAST_BSR,
        N2_FLAG_FAST_DIV, N2_OPT_MAGIC, bsr_idx_from_table, compute_do_tc_cap,
        count_fitting_packets,
    };
    use modem_atlas::mac::{EXT_BSR_TABLE, STD_BSR_TABLE, bsr_index_ext, bsr_index_std};

    #[test]
    fn control_block_layout_and_boot_off_invariants() {
        assert_eq!(core::mem::size_of::<N2OptState>(), 64);
        let mut st = N2OptState::boot_default();
        assert_eq!(st.magic, N2_OPT_MAGIC);
        assert_eq!(st.flags, 0);
        assert_eq!(st.active_flags(), 0);

        // Known bits activate cleanly
        st.flags = N2_FLAGS_KNOWN_MASK;
        assert_eq!(st.active_flags(), N2_FLAGS_KNOWN_MASK);

        // Any unknown bit forces ALL switches OFF
        st.flags = N2_FLAG_FAST_BSR | (1 << 4);
        assert_eq!(st.active_flags(), 0);

        // Bad magic forces ALL switches OFF
        st.flags = N2_FLAG_FAST_BSR | N2_FLAG_FAST_DIV | N2_FLAG_BYTE_PACING | N2_FLAG_DO_TC_CAP;
        st.magic = 0xDEAD_BEEF;
        assert_eq!(st.active_flags(), 0);
    }

    #[test]
    fn fast_bsr_idx_matches_atlas_for_every_boundary() {
        for &(bo_tbl, is_ext) in &[(&STD_BSR_TABLE, false), (&EXT_BSR_TABLE, true)] {
            for &b in &[0u32, 1, 9, 10, 11, 100, 1000, 150_000, 3_000_000, u32::MAX] {
                let got = bsr_idx_from_table(b, bo_tbl);
                let exp = if is_ext {
                    bsr_index_ext(b)
                } else {
                    bsr_index_std(b)
                };
                assert_eq!(got, exp, "bo={b} ext={is_ext}");
            }
            for &edge in bo_tbl {
                for delta in [-1i64, 0, 1] {
                    let b = (edge as i64 + delta).max(0) as u32;
                    let got = bsr_idx_from_table(b, bo_tbl);
                    let exp = if is_ext {
                        bsr_index_ext(b)
                    } else {
                        bsr_index_std(b)
                    };
                    assert_eq!(got, exp, "edge={edge} b={b} ext={is_ext}");
                }
            }
        }
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
