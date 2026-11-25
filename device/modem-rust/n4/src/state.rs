//! N4 v2 state constants, sparse-flow bucket layout, and lazy initialization.

#![forbid(unsafe_code)]

use core::sync::atomic::{Ordering, fence};

use modem_atlas::patches::N4State;

/// Magic `"N4V2"` (`0x4e34_5632`) written at `N4_STATE_VA + 0x00` after defaults publish.
pub const N4_MAGIC: u32 = 0x4e34_5632;

/// Feature flag bits in `N4State::flags` (`0x847e_d604`).
pub const FLAG_TRUE_BO_PDCP: u32 = 1 << 0;
pub const FLAG_PI_LEAD: u32 = 1 << 1;
pub const FLAG_AQM: u32 = 1 << 2;
pub const FLAG_SPARSE: u32 = 1 << 3;
pub const FLAG_SHORT_BSR_RESCUE: u32 = 1 << 4;
pub const FLAG_HANDSHAKE_SPARE: u32 = 1 << 5;

/// Boot-default tunable values (all features OFF until enabled via `wm`).
pub const DEFAULT_FLAGS: u32 = 0;
pub const DEFAULT_PDCP_MIN: u32 = 16_384;
pub const DEFAULT_PDCP_MAX: u32 = 24_576;
pub const DEFAULT_LEAD_CAP: u32 = 0;
pub const DEFAULT_IDLE_MS: u32 = 22;
pub const DEFAULT_AQM_IVL_MS: u32 = 35;
pub const DEFAULT_SPARSE_LEN: u32 = 127;
pub const DEFAULT_AQM_MINLEN: u32 = 600;
pub const DEFAULT_AQM_QMIN: u32 = 20_480;

/// Offset of the 64-entry legacy sparse table from `N4_STATE_VA` (`0x847e_d680`).
pub const N4_SPARSE_TBL_VA: u32 = modem_atlas::addr::N4_STATE_VA + 0x80;

/// Address of IMG4's N4 v3 handshake-spare counters (`[quic, tls]`, `0x847e_cef8`).
pub const N4_V3_HANDSHAKE_CNT_VA: u32 = 0x847e_cef8;

/// One 4-byte bucket in N4's 64-entry legacy sparse table (`0x847e_d680..0x847e_d77f`).
#[repr(C)]
#[derive(Copy, Clone, Default, Debug, PartialEq, Eq)]
pub struct SparseBucket {
    pub prev_tti16: u16,
    pub burst_bytes: u16,
}

/// IMG4 N4 v3 TLS/QUIC handshake spare counters at `0x847e_cef8`.
#[repr(C)]
#[derive(Copy, Clone, Default, Debug, PartialEq, Eq)]
pub struct N4HandshakeCounters {
    pub quic: u32,
    pub tls: u32,
}

/// Lazily publish boot defaults into `N4State` on first execution after modem boot.
///
/// Mirrors `ensure_init` in `n4_ul_engine.s`: writes only the default tunable words,
/// emits a full memory barrier (`dmb sy`), then publishes `N4_MAGIC`. All other runtime
/// fields and counters are left untouched.
#[inline]
pub fn ensure_init(st: &mut N4State) -> bool {
    if st.magic == N4_MAGIC {
        return false;
    }
    st.flags = DEFAULT_FLAGS;
    st.pdcp_min = DEFAULT_PDCP_MIN;
    st.pdcp_max = DEFAULT_PDCP_MAX;
    st.lead_cap = DEFAULT_LEAD_CAP;
    st.idle_ms = DEFAULT_IDLE_MS;
    st.aqm_ivl_ms = DEFAULT_AQM_IVL_MS;
    st.sparse_len = DEFAULT_SPARSE_LEN;
    st.aqm_minlen = DEFAULT_AQM_MINLEN;
    st.aqm_qmin = DEFAULT_AQM_QMIN;
    fence(Ordering::SeqCst);
    st.magic = N4_MAGIC;
    true
}

/// Panic-free unsigned clamp matching Thumb-2 `min` then `max` sequence.
///
/// Unlike `Ord::clamp`, this never panics when `lo > hi`; instead it applies the lower
/// bound first and the upper bound second, matching `n4_ul_engine.s` exactly.
#[inline]
pub const fn clamp_u32(val: u32, lo: u32, hi: u32) -> u32 {
    let v = if val < lo { lo } else { val };
    if v > hi { hi } else { v }
}

/// Quarter-weight EWMA `(3 * ema + sample) >> 2` with exact 32-bit wrapping arithmetic.
#[inline]
pub const fn ewma_quarter(ema: u32, sample: u32) -> u32 {
    ema.wrapping_mul(3).wrapping_add(sample) >> 2
}

#[cfg(test)]
pub(crate) fn zeroed_n4_state() -> N4State {
    N4State {
        magic: 0,
        flags: 0,
        pdcp_min: 0,
        pdcp_max: 0,
        lead_cap: 0,
        idle_ms: 0,
        aqm_ivl_ms: 0,
        sparse_len: 0,
        last_tb_tti: 0,
        g_tti: 0,
        pad_tti: 0,
        g_ema: 0,
        l_int: 0,
        last_lead: 0,
        last_bsr_tti: 0,
        last_arr_tti: 0,
        arr_win_tti: 0,
        arr_win_b: 0,
        a_ema: 0,
        last_aqm_tti: 0,
        last_drb_rbc: modem_atlas::Ptr32::NULL,
        last_q_true: 0,
        cnt_tb: 0,
        cnt_bsr: 0,
        cnt_refill: 0,
        cnt_aqm_mark: 0,
        cnt_aqm_drop: 0,
        cnt_sparse: 0,
        cnt_sh_fix: 0,
        aqm_minlen: 0,
        aqm_qmin: 0,
        cnt_spared: 0,
    }
}

#[cfg(test)]
pub(crate) fn zeroed_n4_ext() -> modem_atlas::patches::N4ExtCounters {
    modem_atlas::patches::N4ExtCounters {
        cnt_bsr_all: 0,
        cnt_bsr_marg: 0,
        cnt_bsr_hold: 0,
        last_margin: 0,
        cnt_drop_hard: 0,
        cnt_ce_hard: 0,
        cnt_sh_zero: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{offset_of, size_of};

    #[test]
    fn layout_and_ensure_init_defaults() {
        assert_eq!(size_of::<SparseBucket>(), 4);
        assert_eq!(offset_of!(SparseBucket, prev_tti16), 0);
        assert_eq!(offset_of!(SparseBucket, burst_bytes), 2);
        assert_eq!(size_of::<[SparseBucket; 64]>(), 256);
        assert_eq!(N4_SPARSE_TBL_VA, 0x847e_d680);

        let mut st = zeroed_n4_state();
        st.last_drb_rbc = modem_atlas::Ptr32::new(0x8510_a000);
        assert!(ensure_init(&mut st));
        assert_eq!(st.magic, N4_MAGIC);
        assert_eq!(st.flags, 0);
        assert_eq!(st.pdcp_min, 16_384);
        assert_eq!(st.pdcp_max, 24_576);
        assert_eq!(st.lead_cap, 0);
        assert_eq!(st.idle_ms, 22);
        assert_eq!(st.aqm_ivl_ms, 35);
        assert_eq!(st.sparse_len, 127);
        assert_eq!(st.aqm_minlen, 600);
        assert_eq!(st.aqm_qmin, 20_480);
        assert_eq!(st.last_drb_rbc.addr(), 0x8510_a000);

        // Second call is a no-op and preserves live knob edits.
        st.flags = 0x15;
        assert!(!ensure_init(&mut st));
        assert_eq!(st.flags, 0x15);
    }

    #[test]
    fn clamp_handles_inverted_bounds_without_panic() {
        assert_eq!(clamp_u32(10, 20, 30), 20);
        assert_eq!(clamp_u32(25, 20, 30), 25);
        assert_eq!(clamp_u32(40, 20, 30), 30);
        // Inverted lo > hi matches assembly's sequential lo-then-hi clamp.
        assert_eq!(clamp_u32(10, 30, 20), 20);
        assert_eq!(clamp_u32(25, 30, 20), 20);
    }
}
