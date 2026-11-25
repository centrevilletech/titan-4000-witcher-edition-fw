//! Hook 4 ingress tracking and legacy bit-3 sparse-flow promotion (`hook_gipc_rx`).

#![forbid(unsafe_code)]

use modem_atlas::Ptr32;
use modem_atlas::patches::N4State;

use crate::state::{FLAG_SPARSE, SparseBucket, ensure_init, ewma_quarter};

/// Record active DRB pointer, arrival timestamp, and 5 ms arrival-rate EWMA (`A_ema`).
#[inline]
pub fn record_arrival(st: &mut N4State, rbc_va: u32, pkt_len: u32, now_tti: u32) {
    ensure_init(st);
    st.last_drb_rbc = Ptr32::new(rbc_va);
    st.last_arr_tti = now_tti;

    let mut win_b = st.arr_win_b.wrapping_add(pkt_len);
    let dt = now_tti.wrapping_sub(st.arr_win_tti);
    if dt >= 5 {
        let new_a = if dt > 20 {
            win_b
        } else {
            ewma_quarter(st.a_ema, win_b)
        };
        st.a_ema = new_a;
        st.arr_win_tti = now_tti;
        win_b = 0;
    }
    st.arr_win_b = win_b;
}

/// Evaluate N4's legacy bit-3 sparse-flow Ring-0 promotion (`n4_ul_engine.s` lines 593..680).
///
/// Returns `true` if the packet should take Exit C (promote to Ring 0).
#[inline]
pub fn try_legacy_sparse<F>(
    st: &mut N4State,
    tbl: &mut [SparseBucket; 64],
    pkt_len: u32,
    now_tti: u32,
    ip: &[u8],
    read_ring0_occ: F,
) -> bool
where
    F: FnOnce() -> Option<u16>,
{
    if (st.flags & FLAG_SPARSE) == 0 || pkt_len > st.sparse_len {
        return false;
    }
    if ip.len() < 40 {
        return false;
    }

    let b0 = ip[0];
    let ver = b0 & 0xf0;
    let hash: u8 = if ver == 0x40 {
        let mut h = ip[9] ^ ip[18] ^ ip[19];
        if b0 == 0x45 {
            h ^= ip[21] ^ ip[23];
        }
        h
    } else if ver == 0x60 {
        ip[6] ^ ip[36] ^ ip[39] ^ ip[3]
    } else {
        return false;
    };

    let bucket = &mut tbl[(hash & 63) as usize];
    let dt16 = (now_tti as u16).wrapping_sub(bucket.prev_tti16) as u32;
    let drained = if dt16 >= 64 {
        0u32
    } else {
        let drain = dt16.wrapping_mul(40);
        let cur = bucket.burst_bytes as u32;
        if cur > drain { cur - drain } else { 0 }
    };

    let mut new_burst = drained.wrapping_add(pkt_len);
    if new_burst > 2048 {
        if new_burst > 4096 {
            new_burst = 4096;
        }
        bucket.prev_tti16 = now_tti as u16;
        bucket.burst_bytes = new_burst as u16;
        return false;
    }

    bucket.prev_tti16 = now_tti as u16;
    bucket.burst_bytes = new_burst as u16;

    if let Some(occ) = read_ring0_occ() {
        if occ < 128 {
            st.cnt_sparse = st.cnt_sparse.wrapping_add(1);
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::zeroed_n4_state;

    #[test]
    fn arrival_window_resets_after_idle_and_smooths_when_active() {
        let mut st = zeroed_n4_state();
        record_arrival(&mut st, 0x8500_0000, 1000, 100);
        assert_eq!(st.arr_win_b, 0);
        assert_eq!(st.a_ema, 1000);
        assert_eq!(st.arr_win_tti, 100);

        record_arrival(&mut st, 0x8500_0000, 2000, 102);
        assert_eq!(st.arr_win_b, 2000);
        assert_eq!(st.a_ema, 1000);

        // 5 ms elapsed (<= 20 ms): EWMA (3*1000 + 3000) >> 2 = 1500
        record_arrival(&mut st, 0x8500_0000, 1000, 105);
        assert_eq!(st.a_ema, 1500);
        assert_eq!(st.arr_win_b, 0);
    }

    #[test]
    fn legacy_sparse_off_by_default_and_promotes_when_enabled() {
        let mut st = zeroed_n4_state();
        ensure_init(&mut st);
        let mut tbl = [SparseBucket::default(); 64];
        let mut ip = [0u8; 40];
        ip[0] = 0x45;
        ip[9] = 17;

        // Default sparse_len=127 disables promotion even with bit 3 set.
        st.flags = FLAG_SPARSE;
        assert!(!try_legacy_sparse(&mut st, &mut tbl, 228, 1000, &ip, || Some(0)));

        st.sparse_len = 500;
        assert!(try_legacy_sparse(&mut st, &mut tbl, 228, 1000, &ip, || Some(10)));
        assert_eq!(st.cnt_sparse, 1);

        // Ring 0 occupancy >= 128 refuses promotion safely.
        assert!(!try_legacy_sparse(&mut st, &mut tbl, 228, 1010, &ip, || Some(128)));
    }
}
