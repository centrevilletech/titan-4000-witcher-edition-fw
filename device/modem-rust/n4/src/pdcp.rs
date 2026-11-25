//! Hook 3 (`hook_pdcp_limit` at `0x842d_cca2`): dynamic JIT-PDCP staging cap.

#![forbid(unsafe_code)]

use modem_atlas::patches::N4State;

use crate::state::{FLAG_TRUE_BO_PDCP, clamp_u32, ensure_init};

/// Compute the PDCP UL staging cap returned in `r0` by Hook 3.
#[inline]
pub fn pdcp_limit(st: &mut N4State, stock_cap: u32) -> u32 {
    ensure_init(st);
    if (st.flags & FLAG_TRUE_BO_PDCP) == 0 {
        return stock_cap;
    }
    clamp_u32(st.g_ema.wrapping_add(4096), st.pdcp_min, st.pdcp_max)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::zeroed_n4_state;

    #[test]
    fn stock_when_bit0_off_and_clamped_when_on() {
        let mut st = zeroed_n4_state();
        assert_eq!(pdcp_limit(&mut st, 65_536), 65_536);

        st.flags = FLAG_TRUE_BO_PDCP;
        st.g_ema = 5_000;
        assert_eq!(pdcp_limit(&mut st, 65_536), 16_384);

        st.g_ema = 16_000;
        assert_eq!(pdcp_limit(&mut st, 65_536), 20_096);

        st.g_ema = 30_000;
        assert_eq!(pdcp_limit(&mut st, 65_536), 24_576);
    }
}
