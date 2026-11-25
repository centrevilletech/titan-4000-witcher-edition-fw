//! N5 control block constants, feature flags, boot defaults, and helpers.

#![forbid(unsafe_code)]

use modem_atlas::patches::{N5FlowEntry, N5State};

/// Magic `"N5FL"` (`0x4e35_464c`) at `N5_STATE_VA + 0x00` (`0x8448_9a64`).
pub const N5_MAGIC: u32 = 0x4e35_464c;

/// Build version word (`0x2026_1123`) at `N5_STATE_VA + 0x04`.
pub const N5_VERSION: u32 = 0x2026_1123;

/// Feature flag bits in `N5State::flags` (`0x8448_9a6c`).
/// Bit 0: enable per-flow sparse Ring-0 lane and exact Ring-0 feeder accounting.
pub const FLAG_FLOW_LANE: u32 = 1 << 0;
/// Bit 1: enable first-class PDCP staging limit override (`n5_pdcp_limit`).
pub const FLAG_PDCP_LIMIT: u32 = 1 << 1;
/// Bit 2: disable exact Ring-0 feeder byte accounting even when bit 0 is set.
pub const FLAG_DISABLE_R0_FIX: u32 = 1 << 2;

/// Boot-default tunable values (all features OFF until enabled via `wm`).
pub const DEFAULT_FLAGS: u32 = 0;
pub const DEFAULT_RATE_BPMS: u32 = 40;
pub const DEFAULT_BURST_B: u32 = 3_072;
pub const DEFAULT_HOLD_MS: u32 = 500;
pub const DEFAULT_BUDGET_PCT: u32 = 10;
pub const DEFAULT_BUDGET_FIXED: u32 = 0;
pub const DEFAULT_PDCP_MIN: u32 = 16_384;
pub const DEFAULT_PDCP_MAX: u32 = 24_576;
pub const DEFAULT_PDCP_K_Q4: u32 = 0;
pub const DEFAULT_R0_MAX_PKTS: u32 = 128;

/// Minimum 100 ms Ring-0 promotion byte budget floor when `G_ema` is cold or low.
pub const BUDGET_FLOOR_B: u32 = 8_192;

/// Quiet interval (ms) after which a flow's leaky bucket is treated as empty.
pub const BUCKET_QUIET_RESET_MS: u32 = 2_000;

/// Global Ring-0 promotion budget accounting window (ms).
pub const BUDGET_WINDOW_MS: u32 = 100;

/// Return `val` if non-zero, otherwise `fallback`.
#[inline]
pub const fn default_nz(val: u32, fallback: u32) -> u32 {
    if val == 0 { fallback } else { val }
}

/// Panic-free unsigned clamp applying lower bound first, then upper bound.
///
/// Mirrors Thumb-2 `cmp/movlo` then `cmp/movhi` without ever panicking when `lo > hi`.
#[inline]
#[allow(clippy::manual_clamp)]
pub const fn clamp_u32(val: u32, lo: u32, hi: u32) -> u32 {
    let v = if val < lo { lo } else { val };
    if v > hi { hi } else { v }
}

/// Construct a boot-initialized [`N5State`] matching the static `.n5blk` image layout
/// (magic `"N5FL"`, version `0x2026_1123`, `flags = 0`, default tunables, zeroed
/// runtime/counters/table).
pub const fn boot_n5_state() -> N5State {
    N5State {
        magic: N5_MAGIC,
        version: N5_VERSION,
        flags: DEFAULT_FLAGS,
        rate_bpms: DEFAULT_RATE_BPMS,
        burst_b: DEFAULT_BURST_B,
        hold_ms: DEFAULT_HOLD_MS,
        budget_pct: DEFAULT_BUDGET_PCT,
        budget_fixed: DEFAULT_BUDGET_FIXED,
        pdcp_min: DEFAULT_PDCP_MIN,
        pdcp_max: DEFAULT_PDCP_MAX,
        pdcp_k_q4: DEFAULT_PDCP_K_Q4,
        r0_max_pkts: 0,
        bud_win_tti: 0,
        bud_used: 0,
        last_bud_cap: 0,
        last_pdcp_lim: 0,
        c_promo_pkts: 0,
        c_promo_bytes: 0,
        c_refused_bud: 0,
        c_marked_bulk: 0,
        c_evictions: 0,
        c_held_bulk: 0,
        c_stock_r0: 0,
        c_bad_hdr: 0,
        c_r0_submit: 0,
        c_r0_fix_b: 0,
        c_seen: 0,
        c_r1_nonempty_hold: 0,
        _pad0: [0; 4],
        last_r1_rd: [0; 8],
        r1_deq_seq: [0; 8],
        flow_tbl: [N5FlowEntry {
            tag: 0,
            level: 0,
            last_tti: 0,
            bulk_until: 0,
            r1_drain: 0,
        }; 64],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{offset_of, size_of};

    #[test]
    fn n5_state_layout_and_boot_defaults() {
        assert_eq!(size_of::<N5State>(), 0x4b0);
        assert_eq!(size_of::<N5FlowEntry>(), 0x10);
        assert_eq!(offset_of!(N5State, magic), 0x00);
        assert_eq!(offset_of!(N5State, version), 0x04);
        assert_eq!(offset_of!(N5State, flags), 0x08);
        assert_eq!(offset_of!(N5State, rate_bpms), 0x0c);
        assert_eq!(offset_of!(N5State, burst_b), 0x10);
        assert_eq!(offset_of!(N5State, hold_ms), 0x14);
        assert_eq!(offset_of!(N5State, budget_pct), 0x18);
        assert_eq!(offset_of!(N5State, budget_fixed), 0x1c);
        assert_eq!(offset_of!(N5State, pdcp_min), 0x20);
        assert_eq!(offset_of!(N5State, pdcp_max), 0x24);
        assert_eq!(offset_of!(N5State, pdcp_k_q4), 0x28);
        assert_eq!(offset_of!(N5State, r0_max_pkts), 0x2c);
        assert_eq!(offset_of!(N5State, bud_win_tti), 0x30);
        assert_eq!(offset_of!(N5State, bud_used), 0x34);
        assert_eq!(offset_of!(N5State, last_bud_cap), 0x38);
        assert_eq!(offset_of!(N5State, last_pdcp_lim), 0x3c);
        assert_eq!(offset_of!(N5State, c_promo_pkts), 0x40);
        assert_eq!(offset_of!(N5State, c_r1_nonempty_hold), 0x6c);
        assert_eq!(offset_of!(N5State, last_r1_rd), 0x80);
        assert_eq!(offset_of!(N5State, r1_deq_seq), 0x90);
        assert_eq!(offset_of!(N5State, flow_tbl), 0xb0);

        let st = boot_n5_state();
        assert_eq!(st.magic, 0x4e35_464c);
        assert_eq!(st.version, 0x2026_1123);
        assert_eq!(st.flags, 0);
        assert_eq!(st.rate_bpms, 40);
        assert_eq!(st.burst_b, 3_072);
        assert_eq!(st.hold_ms, 500);
        assert_eq!(st.budget_pct, 10);
        assert_eq!(st.pdcp_min, 16_384);
        assert_eq!(st.pdcp_max, 24_576);
        assert_eq!(st.r0_max_pkts, 0);
    }
}
