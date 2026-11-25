//! Hooks 2 (`hook_calc_lcg_bo` at `0x842d_d21c`) and 2b (`hook_short_bsr` at `0x842c_d5f4`).

#![forbid(unsafe_code)]

use modem_atlas::patches::{N4ExtCounters, N4State};

use crate::state::{
    FLAG_PI_LEAD, FLAG_SHORT_BSR_RESCUE, FLAG_TRUE_BO_PDCP, clamp_u32, ensure_init,
};

/// Compute augmented `bo_margin` returned in `r2` by Hook 2 (`hook_calc_lcg_bo`).
///
/// `read_ring_pending` and `read_tti` are invoked lazily only on the branches that
/// read them in `n4_ul_engine.s`, preserving exact memory-access behavior.
#[allow(clippy::too_many_arguments)]
#[inline]
pub fn calc_lcg_bo<FP, FT>(
    st: &mut N4State,
    ext: &mut N4ExtCounters,
    lcg_id: u32,
    rbc_va: u32,
    bo_margin: u32,
    actual_bo: u32,
    hdr_bo: u32,
    read_ring_pending: FP,
    read_tti: FT,
) -> u32
where
    FP: FnOnce() -> u32,
    FT: FnOnce() -> u32,
{
    ensure_init(st);

    // Always-on N4 BSR diagnostics (every LCG, never modifies returned r2).
    ext.cnt_bsr_all = ext.cnt_bsr_all.wrapping_add(1);
    if bo_margin != 0 {
        ext.cnt_bsr_marg = ext.cnt_bsr_marg.wrapping_add(1);
        ext.last_margin = bo_margin;
        if (actual_bo | hdr_bo) == 0 {
            ext.cnt_bsr_hold = ext.cnt_bsr_hold.wrapping_add(1);
        }
    }

    // Never touch SRB (LCG 0).
    if lcg_id == 0 {
        return bo_margin;
    }

    let flags = st.flags;
    if (flags & (FLAG_TRUE_BO_PDCP | FLAG_PI_LEAD)) == 0 {
        return bo_margin;
    }

    st.cnt_bsr = st.cnt_bsr.wrapping_add(1);

    let mut out_bo = bo_margin;
    let mut pending_ring = 0u32;

    // Step 1 (bit 0): true-backlog pending_ring_bytes with empty-ring/cipher guard.
    if (flags & FLAG_TRUE_BO_PDCP) != 0 {
        pending_ring = read_ring_pending();
        out_bo = out_bo.wrapping_add(pending_ring);
    }

    // Step 2 (bit 1): damped PI TDD pipeline canceller (clamped to 0 when lead_cap == 0).
    if (flags & FLAG_PI_LEAD) == 0 {
        return out_bo;
    }
    if st.last_drb_rbc.is_null() || st.last_drb_rbc.addr() != rbc_va {
        return out_bo;
    }

    let q_true = actual_bo.wrapping_add(hdr_bo).wrapping_add(pending_ring);
    st.last_q_true = q_true;

    let now_tti = read_tti();
    let elapsed = now_tti.wrapping_sub(st.last_arr_tti);
    if elapsed > st.idle_ms {
        // Idle timeout: zero L_int, A_ema, last_lead. Keep G_ema (N3R D4).
        st.l_int = 0;
        st.a_ema = 0;
        st.last_lead = 0;
        st.last_bsr_tti = now_tti;
        return out_bo;
    }

    if q_true >= 16_384 {
        // Saturated guard: decay L_int gently, add 0 lead.
        st.l_int = st.l_int.wrapping_mul(3) >> 2;
        st.last_lead = 0;
        st.last_bsr_tti = now_tti;
        return out_bo;
    }

    if now_tti == st.last_bsr_tti {
        return out_bo.wrapping_add(st.last_lead);
    }
    st.last_bsr_tti = now_tti;

    let mut l_int = st.l_int;
    let lead_cap = st.lead_cap;
    if q_true != 0 {
        let step = clamp_u32(q_true >> 2, 256, 1536);
        l_int = l_int.wrapping_add(step);
        if l_int > lead_cap {
            l_int = lead_cap;
        }
    } else {
        let pad = st.pad_tti;
        if pad > 768 {
            let mut trim = (pad - 512) >> 2;
            if trim > 1024 {
                trim = 1024;
            }
            l_int = if l_int > trim { l_int - trim } else { 0 };
        }
    }
    st.l_int = l_int;

    let mut ff = st.a_ema.wrapping_add(512);
    if ff > 24_576 {
        ff = 24_576;
    }
    let lead_base = if l_int < ff { ff } else { l_int };

    // Schur-Cohn damping: lead = clamp(lead_base - ((G_tti - G_ema) >> 1), 0, lead_cap)
    let damp = (st.g_tti.wrapping_sub(st.g_ema) as i32) >> 1;
    let damped = (lead_base as i32).wrapping_sub(damp);
    let mut lead = if damped < 0 { 0u32 } else { damped as u32 };
    if lead > lead_cap {
        lead = lead_cap;
    }
    st.last_lead = lead;
    out_bo.wrapping_add(lead)
}

/// Hook 2b (`hook_short_bsr` at `0x842c_d5f4`): rescue short/truncated BSR LCG in `r8`
/// when `lcg_bo[selected_lcg] == 0` while another LCG holds bytes.
#[inline]
pub fn rescue_short_bsr(
    st: &mut N4State,
    ext: &mut N4ExtCounters,
    lcg_bo: &[u32; 4],
    selected_lcg: u32,
) -> u32 {
    ensure_init(st);

    if let Some(&bo) = lcg_bo.get(selected_lcg as usize) {
        if bo != 0 {
            return selected_lcg;
        }
    }

    let mut i = 0usize;
    while i < 4 {
        if lcg_bo[i] != 0 {
            ext.cnt_sh_zero = ext.cnt_sh_zero.wrapping_add(1);
            if (st.flags & (FLAG_TRUE_BO_PDCP | FLAG_PI_LEAD | FLAG_SHORT_BSR_RESCUE)) != 0 {
                st.cnt_sh_fix = st.cnt_sh_fix.wrapping_add(1);
                return i as u32;
            }
            return selected_lcg;
        }
        i += 1;
    }
    selected_lcg
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{zeroed_n4_ext, zeroed_n4_state};
    use modem_atlas::Ptr32;

    #[test]
    fn always_on_counters_and_srb_isolation() {
        let mut st = zeroed_n4_state();
        let mut ext = zeroed_n4_ext();
        ensure_init(&mut st);

        assert_eq!(calc_lcg_bo(&mut st, &mut ext, 3, 0x1000, 0, 0, 0, || 999, || 0), 0);
        assert_eq!(calc_lcg_bo(&mut st, &mut ext, 3, 0x1000, 10, 0, 0, || 999, || 0), 10);
        assert_eq!(calc_lcg_bo(&mut st, &mut ext, 0, 0x1000, 10, 500, 4, || 999, || 0), 10);
        assert_eq!(ext.cnt_bsr_all, 3);
        assert_eq!(ext.cnt_bsr_marg, 2);
        assert_eq!(ext.cnt_bsr_hold, 1);
        assert_eq!(ext.last_margin, 10);
        assert_eq!(st.cnt_bsr, 0);

        st.flags = FLAG_TRUE_BO_PDCP;
        assert_eq!(calc_lcg_bo(&mut st, &mut ext, 0, 0x1000, 10, 0, 0, || 40_000, || 0), 10);
        assert_eq!(calc_lcg_bo(&mut st, &mut ext, 3, 0x1000, 10, 0, 0, || 40_000, || 0), 40_010);
        assert_eq!(st.cnt_bsr, 1);
    }

    #[test]
    fn pi_lead_keeps_g_ema_across_idle_and_respects_lead_cap() {
        let mut st = zeroed_n4_state();
        let mut ext = zeroed_n4_ext();
        ensure_init(&mut st);
        st.flags = FLAG_TRUE_BO_PDCP | FLAG_PI_LEAD;
        st.g_ema = 17_000;
        st.a_ema = 4_000;
        st.l_int = 2_000;
        st.last_drb_rbc = Ptr32::new(0x8500_1000);
        st.last_arr_tti = 1000;

        // Idle (> 22 ms): zeroes L_int & A_ema, keeps G_ema.
        assert_eq!(
            calc_lcg_bo(&mut st, &mut ext, 3, 0x8500_1000, 0, 0, 0, || 0, || 1030),
            0
        );
        assert_eq!(st.g_ema, 17_000);
        assert_eq!(st.l_int, 0);
        assert_eq!(st.a_ema, 0);

        // Active with default lead_cap = 0 -> 0 phantom bytes.
        st.last_arr_tti = 1030;
        assert_eq!(
            calc_lcg_bo(&mut st, &mut ext, 3, 0x8500_1000, 0, 1000, 0, || 0, || 1035),
            0
        );
    }

    #[test]
    fn short_bsr_rescue_respects_flags() {
        let mut st = zeroed_n4_state();
        let mut ext = zeroed_n4_ext();
        ensure_init(&mut st);
        let bo = [0, 0, 0, 10];

        assert_eq!(rescue_short_bsr(&mut st, &mut ext, &bo, 0), 0);
        assert_eq!(ext.cnt_sh_zero, 1);
        assert_eq!(st.cnt_sh_fix, 0);

        st.flags = FLAG_SHORT_BSR_RESCUE;
        assert_eq!(rescue_short_bsr(&mut st, &mut ext, &bo, 0), 3);
        assert_eq!(ext.cnt_sh_zero, 2);
        assert_eq!(st.cnt_sh_fix, 1);
    }
}
