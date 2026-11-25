//! Hook 1 (`hook_mac_tb` at `0x842d_0914`): per-TTI grant/padding tracker and `G_ema`.

#![forbid(unsafe_code)]

use modem_atlas::patches::N4State;

use crate::state::{FLAG_TRUE_BO_PDCP, ensure_init, ewma_quarter};

/// Inputs read from `GenerateMacUlPdu`'s `MacTbBuildFrame` and the 1 ms TTI clock.
#[derive(Copy, Clone, Debug)]
pub struct TbInputs {
    pub tb_size: u32,
    pub used_bytes: u32,
    pub has_trailing_pad: bool,
    pub now_tti: u32,
}

/// Active bearer queue snapshot used for the refill-eligible counter (N3R D6).
#[derive(Copy, Clone, Debug)]
pub struct DrbRefillInfo {
    pub active: u8,
    pub ring_pending_bytes: u32,
    pub pdcp_rlc_tx_bo: u32,
}

/// Update `N4State` on every MAC UL TB build.
///
/// `read_drb` is invoked lazily only when bit 0 is set and `last_drb_rbc` is non-null.
#[inline]
pub fn on_mac_tb<F>(st: &mut N4State, inp: TbInputs, read_drb: F)
where
    F: FnOnce(u32) -> DrbRefillInfo,
{
    ensure_init(st);
    st.cnt_tb = st.cnt_tb.wrapping_add(1);

    let pad = if inp.has_trailing_pad && inp.tb_size > inp.used_bytes {
        inp.tb_size - inp.used_bytes
    } else {
        0
    };

    if inp.now_tti == st.last_tb_tti {
        // Same TTI (e.g. 2CC UL CA SCell TB): sum into current TTI.
        st.g_tti = st.g_tti.wrapping_add(inp.tb_size);
        st.pad_tti = st.pad_tti.wrapping_add(pad);
    } else {
        // New TTI: fold completed previous TTI g_tti into G_ema = (3*G_ema + prev_g) >> 2.
        let prev_g = st.g_tti;
        if prev_g != 0 {
            st.g_ema = if st.g_ema == 0 {
                prev_g
            } else {
                ewma_quarter(st.g_ema, prev_g)
            };
        }
        st.last_tb_tti = inp.now_tti;
        st.g_tti = inp.tb_size;
        st.pad_tti = pad;
    }

    // N3R D6: count refill-eligible TTIs without calling post_event.
    if (st.flags & FLAG_TRUE_BO_PDCP) != 0 && !st.last_drb_rbc.is_null() {
        let info = read_drb(st.last_drb_rbc.addr());
        if info.active == 1 && info.ring_pending_bytes != 0 && info.pdcp_rlc_tx_bo < st.pdcp_max {
            st.cnt_refill = st.cnt_refill.wrapping_add(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::zeroed_n4_state;
    use modem_atlas::Ptr32;

    #[test]
    fn sums_same_tti_and_folds_ewma_on_new_tti() {
        let mut st = zeroed_n4_state();
        let no_drb = |_| DrbRefillInfo {
            active: 0,
            ring_pending_bytes: 0,
            pdcp_rlc_tx_bo: 0,
        };
        on_mac_tb(
            &mut st,
            TbInputs {
                tb_size: 6000,
                used_bytes: 5000,
                has_trailing_pad: true,
                now_tti: 100,
            },
            no_drb,
        );
        on_mac_tb(
            &mut st,
            TbInputs {
                tb_size: 4000,
                used_bytes: 4000,
                has_trailing_pad: false,
                now_tti: 100,
            },
            no_drb,
        );
        assert_eq!(st.cnt_tb, 2);
        assert_eq!(st.g_tti, 10_000);
        assert_eq!(st.pad_tti, 1000);
        assert_eq!(st.g_ema, 0);

        // Next TTI seeds cold G_ema = 10_000.
        on_mac_tb(
            &mut st,
            TbInputs {
                tb_size: 6000,
                used_bytes: 6000,
                has_trailing_pad: false,
                now_tti: 105,
            },
            no_drb,
        );
        assert_eq!(st.g_ema, 10_000);
        assert_eq!(st.g_tti, 6000);
        assert_eq!(st.pad_tti, 0);

        // Following TTI folds: (3*10000 + 6000) >> 2 = 9000.
        on_mac_tb(
            &mut st,
            TbInputs {
                tb_size: 8000,
                used_bytes: 8000,
                has_trailing_pad: false,
                now_tti: 110,
            },
            no_drb,
        );
        assert_eq!(st.g_ema, 9000);
    }

    #[test]
    fn refill_counter_respects_bit0_and_thresholds() {
        let mut st = zeroed_n4_state();
        st.last_drb_rbc = Ptr32::new(0x8500_0000);
        let ready = |_| DrbRefillInfo {
            active: 1,
            ring_pending_bytes: 5000,
            pdcp_rlc_tx_bo: 12_000,
        };
        // First call initializes defaults with flags=0 -> no refill increment.
        on_mac_tb(
            &mut st,
            TbInputs {
                tb_size: 6000,
                used_bytes: 6000,
                has_trailing_pad: false,
                now_tti: 1,
            },
            ready,
        );
        assert_eq!(st.cnt_refill, 0);

        st.flags = FLAG_TRUE_BO_PDCP;
        on_mac_tb(
            &mut st,
            TbInputs {
                tb_size: 6000,
                used_bytes: 6000,
                has_trailing_pad: false,
                now_tti: 2,
            },
            ready,
        );
        assert_eq!(st.cnt_refill, 1);
    }
}
