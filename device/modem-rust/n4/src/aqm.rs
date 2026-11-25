//! Hook 4 AQM v2 decision engine (`hook4_check_aqm`, `n4_ul_engine.s` lines 685..814).

#![forbid(unsafe_code)]

use modem_atlas::patches::{N4ExtCounters, N4State};

use crate::ecn::try_mark_ce;
use crate::handshake::{HandshakeKind, classify_handshake};
use crate::state::{
    FLAG_AQM, FLAG_HANDSHAKE_SPARE, FLAG_TRUE_BO_PDCP, N4HandshakeCounters, clamp_u32,
};

/// Ring-1 AQM decision for a packet exceeding 127 B.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AqmOutcome {
    /// Exit B: enqueue normally into Ring 1 (possibly CE-marked in place).
    Enqueue,
    /// Exit D: clean Ring 1 drop (`r2 = rbc.ring1`, jump to `0x842d_a3e0`).
    Drop,
}

/// Evaluate N4 AQM v2 (and optional IMG4 v3 bit-5 handshake spare) on a Ring-1 packet.
#[inline]
pub fn evaluate_aqm(
    st: &mut N4State,
    ext: &mut N4ExtCounters,
    q_total: u32,
    pkt_len: u32,
    now_tti: u32,
    ip: &mut [u8],
    handshake: Option<&mut N4HandshakeCounters>,
) -> AqmOutcome {
    // N3R D3: AQM runs only when BOTH bit 0 (PDCP limit) and bit 2 (AQM) are set.
    let flags = st.flags;
    if (flags & (FLAG_TRUE_BO_PDCP | FLAG_AQM)) != (FLAG_TRUE_BO_PDCP | FLAG_AQM) {
        return AqmOutcome::Enqueue;
    }

    let q_target = clamp_u32(st.g_ema.wrapping_mul(3), st.aqm_qmin, 49_152);
    if q_total <= q_target {
        return AqmOutcome::Enqueue;
    }

    // N4 AQM v2: small packets (< aqm_minlen) are never dropped or marked.
    if pkt_len < st.aqm_minlen {
        st.cnt_spared = st.cnt_spared.wrapping_add(1);
        return AqmOutcome::Enqueue;
    }

    // Overload ceiling: 4 * Q_target (every big packet dropped, including ECT and handshakes).
    let overload = q_target.wrapping_shl(2);
    if q_total > overload {
        ext.cnt_drop_hard = ext.cnt_drop_hard.wrapping_add(1);
        st.cnt_aqm_drop = st.cnt_aqm_drop.wrapping_add(1);
        return AqmOutcome::Drop;
    }

    // Optional IMG4 v3 handshake spare (bit 5) below 4 * Q_target.
    if (flags & FLAG_HANDSHAKE_SPARE) != 0 {
        if let Some(hc) = handshake {
            if let Some(kind) = classify_handshake(ip, pkt_len) {
                match kind {
                    HandshakeKind::Quic => hc.quic = hc.quic.wrapping_add(1),
                    HandshakeKind::Tls => hc.tls = hc.tls.wrapping_add(1),
                }
                return AqmOutcome::Enqueue;
            }
        }
    }

    let hard = q_total > q_target.wrapping_shl(1);

    // Big ECT(0)/ECT(1) packet above Q_target: always step-mark CE up to 4 * Q_target.
    if try_mark_ce(ip) {
        st.cnt_aqm_mark = st.cnt_aqm_mark.wrapping_add(1);
        if hard {
            ext.cnt_ce_hard = ext.cnt_ce_hard.wrapping_add(1);
        }
        return AqmOutcome::Enqueue;
    }

    // Big non-ECT packet: hard drop above 2 * Q_target, paced drop in (Q_target, 2 * Q_target].
    if hard {
        ext.cnt_drop_hard = ext.cnt_drop_hard.wrapping_add(1);
        st.cnt_aqm_drop = st.cnt_aqm_drop.wrapping_add(1);
        return AqmOutcome::Drop;
    }

    if now_tti.wrapping_sub(st.last_aqm_tti) < st.aqm_ivl_ms {
        return AqmOutcome::Enqueue;
    }
    st.last_aqm_tti = now_tti;
    st.cnt_aqm_drop = st.cnt_aqm_drop.wrapping_add(1);
    AqmOutcome::Drop
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{ensure_init, zeroed_n4_ext, zeroed_n4_state};

    #[test]
    fn aqm_v2_regions_small_spare_ecn_and_pacing() {
        let mut st = zeroed_n4_state();
        let mut ext = zeroed_n4_ext();
        ensure_init(&mut st);
        st.flags = FLAG_TRUE_BO_PDCP | FLAG_AQM;
        st.g_ema = 6250; // Q_target = 20_480, 2x = 40_960, 4x = 81_920

        let mut ip = [0u8; 40];
        ip[0] = 0x45;

        // Small packet spared even in overload.
        assert_eq!(evaluate_aqm(&mut st, &mut ext, 120_000, 228, 1000, &mut ip, None), AqmOutcome::Enqueue);
        assert_eq!(st.cnt_spared, 1);
        assert_eq!(st.cnt_aqm_drop, 0);

        // Big non-ECT in paced region: drops once per 35 ms.
        assert_eq!(evaluate_aqm(&mut st, &mut ext, 30_000, 1400, 1000, &mut ip, None), AqmOutcome::Drop);
        assert_eq!(evaluate_aqm(&mut st, &mut ext, 30_000, 1400, 1034, &mut ip, None), AqmOutcome::Enqueue);
        assert_eq!(evaluate_aqm(&mut st, &mut ext, 30_000, 1400, 1035, &mut ip, None), AqmOutcome::Drop);
        assert_eq!(st.cnt_aqm_drop, 2);
        assert_eq!(ext.cnt_drop_hard, 0);

        // Big ECT(0) in hard region: CE-marked, not dropped.
        ip[1] = 0x02;
        assert_eq!(evaluate_aqm(&mut st, &mut ext, 60_000, 1400, 1036, &mut ip, None), AqmOutcome::Enqueue);
        assert_eq!(ip[1] & 3, 3);
        assert_eq!(st.cnt_aqm_mark, 1);
        assert_eq!(ext.cnt_ce_hard, 1);

        // Above 4 * Q_target: even ECT dropped.
        ip[1] = 0x02;
        assert_eq!(evaluate_aqm(&mut st, &mut ext, 81_921, 1400, 1037, &mut ip, None), AqmOutcome::Drop);
        assert_eq!(ext.cnt_drop_hard, 1);
        assert_eq!(st.cnt_aqm_drop, 3);
    }
}
