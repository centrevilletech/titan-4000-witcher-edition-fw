//! First-class PDCP staging limit override (`n5.s` Hook B: `n5_pdcp_limit`).

#![forbid(unsafe_code)]

use modem_atlas::patches::N5State;

use crate::state::{DEFAULT_PDCP_MAX, DEFAULT_PDCP_MIN, FLAG_PDCP_LIMIT, clamp_u32, default_nz};

/// Compute the JIT-PDCP staging byte limit for Hook B (`n5_pdcp_limit`).
///
/// `read_n4_bounds` is only invoked when `N5State::flags` bit 1 is `0`, avoiding
/// two redundant volatile loads on the active N5 path.
#[inline(always)]
pub fn compute_pdcp_limit<F>(n5: &mut N5State, g_ema: u32, read_n4_bounds: F) -> u32
where
    F: FnOnce() -> (u32, u32),
{
    if (n5.flags & FLAG_PDCP_LIMIT) == 0 {
        let (n4_min, n4_max) = read_n4_bounds();
        return clamp_u32(g_ema.wrapping_add(4_096), n4_min, n4_max);
    }
    let k_q4 = n5.pdcp_k_q4;
    let base = if k_q4 != 0 {
        g_ema.wrapping_mul(k_q4) >> 4
    } else {
        g_ema.wrapping_add(4_096)
    };
    let min = default_nz(n5.pdcp_min, DEFAULT_PDCP_MIN);
    let max = default_nz(n5.pdcp_max, DEFAULT_PDCP_MAX).max(min);
    let lim = clamp_u32(base, min, max);
    n5.last_pdcp_lim = lim;
    lim
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::boot_n5_state;

    #[test]
    fn pdcp_limit_off_and_on_modes() {
        let mut st = boot_n5_state();
        assert_eq!(compute_pdcp_limit(&mut st, 9_062, || (16_384, 24_576)), 16_384);
        assert_eq!(compute_pdcp_limit(&mut st, 18_000, || (16_384, 24_576)), 22_096);
        assert_eq!(st.last_pdcp_lim, 0);

        st.flags = FLAG_PDCP_LIMIT;
        st.pdcp_min = 8_192;
        st.pdcp_max = 12_288;
        assert_eq!(compute_pdcp_limit(&mut st, 3_000, || unreachable!()), 8_192);
        assert_eq!(compute_pdcp_limit(&mut st, 6_000, || unreachable!()), 10_096);
        assert_eq!(compute_pdcp_limit(&mut st, 9_062, || unreachable!()), 12_288);
        assert_eq!(st.last_pdcp_lim, 12_288);

        st.pdcp_min = 4_096;
        st.pdcp_max = 16_384;
        st.pdcp_k_q4 = 20;
        assert_eq!(compute_pdcp_limit(&mut st, 9_062, || unreachable!()), (9_062 * 20) >> 4);

        st.pdcp_k_q4 = 0;
        st.pdcp_min = 8_192;
        st.pdcp_max = 4_096;
        assert_eq!(compute_pdcp_limit(&mut st, 9_062, || unreachable!()), 8_192);
    }
}
