//! FCC Part 96 / WInnForum SAS compliance models and verified `tk.bin`
//! power-control formulas.
//!
//! All values use `0.1 dBm`, `0.1 dB`, or `0.1 dBi` fixed-point units unless
//! the parameter name ends in `_dbm` or `_dbi`.

/// Titan 4000 integrated Band 48 directional antenna gain (`14.0 dBi` = `140`).
pub const TITAN_ANTENNA_GAIN_01DBI: i32 = 140;

/// Exact 100-entry `i16` ROM lookup table from stock `tk.bin` at `0x847e_a92c`.
///
/// Entry `i` (for `n_rb = i + 1`, `1..=100`) equals `round(100 * log10(18 * n_rb))`,
/// so `PSD_RB_LUT_01DB[n_rb - 1] - 200 == round(100 * log10(0.18 * n_rb))` in `0.1 dB`.
pub const PSD_RB_LUT_01DB: [i16; 100] = [
    126, 156, 173, 186, 195, 203, 210, 216, 221, 226,
    230, 233, 237, 240, 243, 246, 249, 251, 253, 256,
    258, 260, 262, 264, 265, 267, 269, 270, 272, 273,
    275, 276, 277, 279, 280, 281, 282, 284, 285, 286,
    287, 288, 289, 290, 291, 292, 293, 294, 295, 295,
    296, 297, 298, 299, 300, 300, 301, 302, 303, 303,
    304, 305, 305, 306, 307, 307, 308, 309, 309, 310,
    311, 311, 312, 312, 313, 314, 314, 315, 315, 316,
    316, 317, 317, 318, 318, 319, 319, 320, 320, 321,
    321, 322, 322, 323, 323, 324, 324, 325, 325, 326,
];

/// Exact replica of stock `txm_hw_commit` (`0x842a_678e..0x842a_67d0`) PSD cap.
///
/// Returns the maximum conducted TX power in `0.1 dBm` when `AT%TXPOWLMTMHZ` is
/// active (`psd_limit_01dbm_mhz` = `10 * lim_dbm`), or `None` if `n_rb` is out
/// of `1..=100`.
pub const fn tk_psd_cap_01dbm(psd_limit_01dbm_mhz: i32, n_rb: u32, is_pucch: bool) -> Option<i32> {
    if n_rb < 1 || n_rb > 100 {
        return None;
    }
    let lut_val = if is_pucch {
        126 // 0x7e in 0x842a_67b8
    } else {
        PSD_RB_LUT_01DB[(n_rb - 1) as usize] as i32
    };
    Some(psd_limit_01dbm_mhz - 200 + lut_val)
}

/// FCC Part 96 / WInnForum WINNF-TS-0016 1 MHz RBW conducted power cap (`0.1 dBm`).
///
/// For `1..=5` RBs (`0.18..=0.90 MHz`), all energy lies inside a 1 MHz measurement
/// window, so `lut_val` is floored at `200` (`0.0 dB` relative to 1 MHz).
/// For `6..=100` RBs (`1.08..=18.0 MHz`), uses `PSD_RB_LUT_01DB[n_rb - 1]`.
pub const fn legal_1mhz_rbw_cap_01dbm(
    grant_max_eirp_01dbm_mhz: i32,
    ant_gain_01dbi: i32,
    n_rb: u32,
) -> Option<i32> {
    if n_rb < 1 || n_rb > 100 {
        return None;
    }
    let raw = PSD_RB_LUT_01DB[(n_rb - 1) as usize] as i32;
    let floored = if raw < 200 { 200 } else { raw };
    let cond_psd_01dbm_mhz = grant_max_eirp_01dbm_mhz - ant_gain_01dbi;
    Some(cond_psd_01dbm_mhz + (floored - 200))
}

/// Effective EIRP PSD integrated over a 1 MHz RBW (`0.1 dBm/MHz`).
pub const fn eirp_psd_1mhz_01dbm(
    tx_cond_01dbm: i32,
    ant_gain_01dbi: i32,
    n_rb: u32,
) -> Option<i32> {
    if n_rb < 1 || n_rb > 100 {
        return None;
    }
    let raw = PSD_RB_LUT_01DB[(n_rb - 1) as usize] as i32;
    let bw_rel_1mhz = if raw < 200 { 0 } else { raw - 200 };
    Some(tx_cond_01dbm + ant_gain_01dbi - bw_rel_1mhz)
}

/// Exact replica of `txm_calc_cbrs_mpr` (`0x842a_5e04`) Band 48 backoff in `0.1 dB`.
pub const fn cbrs_mpr_01db(n_rb: u32, is_2cc: bool) -> i32 {
    if is_2cc {
        if n_rb <= 62 {
            60
        } else if n_rb <= 78 {
            50
        } else {
            40
        }
    } else if n_rb <= 62 {
        30
    } else if n_rb <= 78 {
        20
    } else if n_rb <= 99 {
        10
    } else {
        0
    }
}

/// Exact replica of stock `cbrs_fsm` (`0xd234..0xd26c`) `maxTxPower` formula (dBm).
///
/// Known compliance bug: ignores channel bandwidth, returning `26 dBm` on a
/// 10 MHz channel when `cdd_en && en_max_tx_pwr` (`+3 dB` over grant).
pub const fn stock_cbrs_fsm_max_tx_dbm(
    grant_max_eirp_dbm_mhz: i32,
    cdd_en: bool,
    en_max_tx_pwr: bool,
) -> i32 {
    let mut lim = grant_max_eirp_dbm_mhz - 4;
    if cdd_en && en_max_tx_pwr {
        lim += 3;
    }
    if lim > 26 {
        26
    } else {
        lim
    }
}

/// Bandwidth-aware conducted power cap (dBm) for a nominal channel bandwidth
/// (`10` or `20` MHz) and antenna gain (`14` dBi), capped by hardware max (`26` dBm).
pub const fn compliant_channel_max_tx_dbm(
    grant_max_eirp_dbm_mhz: i32,
    ant_gain_dbi: i32,
    chan_bw_mhz: u32,
    hw_max_dbm: i32,
) -> i32 {
    let bw_db = match chan_bw_mhz {
        20 => 13, // 10*log10(20) = 13.01 dB
        15 => 11, // floor(10*log10(15) = 11.76 dB)
        10 => 10, // 10*log10(10) = 10.00 dB
        5 => 6,   // floor(10*log10(5) = 6.99 dB)
        _ => 0,
    };
    let lim = grant_max_eirp_dbm_mhz - ant_gain_dbi + bw_db;
    if lim > hw_max_dbm {
        hw_max_dbm
    } else {
        lim
    }
}

/// Fixed-point 10^(x / 100) approximation for `x` in `0..=60` (`0.0..=6.0 dB`),
/// scaled by `1000` (used for `#![no_std]` dual-CC total-power scaling).
const POW10_01DB_X1000: [u32; 61] = [
    1000, 1023, 1047, 1072, 1096, 1122, 1148, 1175, 1202, 1230,
    1259, 1288, 1318, 1349, 1380, 1413, 1445, 1479, 1514, 1549,
    1585, 1622, 1660, 1698, 1738, 1778, 1820, 1862, 1905, 1950,
    1995, 2042, 2089, 2138, 2188, 2239, 2291, 2344, 2399, 2455,
    2512, 2570, 2630, 2692, 2754, 2818, 2884, 2951, 3020, 3090,
    3162, 3236, 3311, 3388, 3467, 3548, 3631, 3715, 3802, 3890,
    3981,
];

/// Compute equal-ratio dual-CC PUSCH+PUSCH reduction (`0.1 dB`, ceiling-rounded)
/// required so `P_lin(p0 - drop) + P_lin(p1 - drop) <= P_lin(p_uemax)`.
///
/// Unlike stock `tk.bin` (`0x842a_f228`, `0x842a_f2da`, `0x842a_ea3c`), this
/// never skips the reduction when `drop > 30` (`3.0 dB`).
pub fn dual_cc_equal_drop_01db(p0_01dbm: i32, p1_01dbm: i32, p_uemax_01dbm: i32) -> i32 {
    let (hi, lo) = if p0_01dbm >= p1_01dbm {
        (p0_01dbm, p1_01dbm)
    } else {
        (p1_01dbm, p0_01dbm)
    };
    let diff = hi - lo;
    // Total power above `hi` is 10*log10(1 + 10^(-diff/100)) in 0.1 dB.
    let add_01db = if diff >= 60 {
        1 // <= 0.1 dB for diff >= 6 dB
    } else {
        // 1 + 1000 / POW10[diff] = (POW10[diff] + 1000) / POW10[diff]
        // Find smallest k in 0..=30 where POW10[k] * POW10[diff] >= 1000 * (POW10[diff] + 1000)
        let denom = POW10_01DB_X1000[diff as usize] as u64;
        let rhs = 1000u64 * (denom + 1000u64);
        let mut k = 0i32;
        while k < 31 {
            if (POW10_01DB_X1000[k as usize] as u64) * denom >= rhs {
                break;
            }
            k += 1;
        }
        k
    };
    let total_01dbm = hi + add_01db;
    if total_01dbm > p_uemax_01dbm {
        total_01dbm - p_uemax_01dbm
    } else {
        0
    }
}

/// 3GPP TS 36.213 section 5.1.1.1 priority scaling for simultaneous PCell PUCCH
/// + SCell PUSCH: protects PUCCH up to `p_uemax`, reducing SCell PUSCH so total
/// radiated power never exceeds `p_uemax`.
///
/// Returns `(scaled_pucch_01dbm, scaled_scell_pusch_01dbm)`.
pub fn dual_cc_pucch_pusch_scale_01db(
    p_pucch_01dbm: i32,
    p_scell_pusch_01dbm: i32,
    p_uemax_01dbm: i32,
) -> (i32, i32) {
    let pucch = if p_pucch_01dbm > p_uemax_01dbm {
        p_uemax_01dbm
    } else {
        p_pucch_01dbm
    };
    let margin = p_uemax_01dbm - pucch;
    if margin <= 0 {
        // PUCCH consumes full budget; SCell PUSCH must drop to minimum (-40.0 dBm).
        return (pucch, -400);
    }
    if margin >= 60 {
        // PUCCH is >= 6 dB below P_UEMAX; remaining budget is ~P_UEMAX - 1.1 dB,
        // check exact bound via dual_cc_equal_drop_01db against P_UEMAX.
        let mut scell = p_scell_pusch_01dbm;
        if scell > p_uemax_01dbm {
            scell = p_uemax_01dbm;
        }
        while dual_cc_equal_drop_01db(pucch, scell, p_uemax_01dbm) > 0 && scell > -400 {
            scell -= 1;
        }
        return (pucch, scell);
    }
    // Exact linear remaining budget: P_rem = P_UEMAX - P_PUCCH.
    // Find largest `scell <= p_scell_pusch_01dbm` such that total <= p_uemax.
    let mut scell = if p_scell_pusch_01dbm > p_uemax_01dbm {
        p_uemax_01dbm
    } else {
        p_scell_pusch_01dbm
    };
    while dual_cc_equal_drop_01db(pucch, scell, p_uemax_01dbm) > 0 && scell > -400 {
        scell -= 1;
    }
    (pucch, scell)
}

/// Integer square root matching `tk.bin` helper `0x842a_2770` (`floor(sqrt(n))`).
pub const fn isqrt_u32(n: u32) -> u32 {
    let mut x = n;
    let mut c = 0u32;
    let mut d = 1u32 << 30;
    while d > n {
        d >>= 2;
    }
    while d != 0 {
        if x >= c + d {
            x -= c + d;
            c = (c >> 1) + d;
        } else {
            c >>= 1;
        }
        d >>= 2;
    }
    c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rom_lut_and_isqrt_match_bench_evidence() {
        assert_eq!(PSD_RB_LUT_01DB[0], 126); // 1 RB: 10*log10(18) = 12.55 dB
        assert_eq!(PSD_RB_LUT_01DB[4], 195); // 5 RB: 10*log10(90) = 19.54 dB
        assert_eq!(PSD_RB_LUT_01DB[9], 226); // 10 RB: 10*log10(180) = 22.55 dB
        assert_eq!(PSD_RB_LUT_01DB[49], 295); // 50 RB: 10*log10(900) = 29.54 dB
        assert_eq!(PSD_RB_LUT_01DB[55], 300); // 56 RB: 10*log10(1008) = 30.03 dB
        assert_eq!(PSD_RB_LUT_01DB[99], 326); // 100 RB: 10*log10(1800) = 32.55 dB

        // Lead's 02:58 UTC read: 0x84d4_7d44 = 0x1f = 31 for p0_srs = -1000 (-100.0 dBm)
        assert_eq!(isqrt_u32(1000), 0x1f);
        assert_eq!(isqrt_u32(1024), 32);
    }

    #[test]
    fn psd_caps_expose_stock_pucch_penalty_and_narrow_rb_overshoot() {
        let grant = 270; // 27.0 dBm/MHz EIRP
        let cond_psd = grant - TITAN_ANTENNA_GAIN_01DBI; // 13.0 dBm/MHz conducted

        // Stock AT%TXPOWLMTMHZ=1,13 caps 1-RB PUCCH at 5.6 dBm (7.4 dB below 1 MHz RBW legal 13.0 dBm)
        assert_eq!(tk_psd_cap_01dbm(cond_psd, 1, true), Some(56));
        assert_eq!(legal_1mhz_rbw_cap_01dbm(grant, TITAN_ANTENNA_GAIN_01DBI, 1), Some(130));
        assert_eq!(legal_1mhz_rbw_cap_01dbm(grant, TITAN_ANTENNA_GAIN_01DBI, 5), Some(130));

        // 50 RB (9 MHz): 22.5 dBm conducted -> 27.0 dBm/MHz EIRP
        assert_eq!(tk_psd_cap_01dbm(cond_psd, 50, false), Some(225));
        assert_eq!(legal_1mhz_rbw_cap_01dbm(grant, TITAN_ANTENNA_GAIN_01DBI, 50), Some(225));

        // 56 RB (10.08 MHz): exact 2-CC 23.0 dBm/CC boundary
        assert_eq!(legal_1mhz_rbw_cap_01dbm(grant, TITAN_ANTENNA_GAIN_01DBI, 56), Some(230));
        assert_eq!(eirp_psd_1mhz_01dbm(230, TITAN_ANTENNA_GAIN_01DBI, 56), Some(270));

        // 100 RB (18.0 MHz): 25.6 dBm conducted -> 27.0 dBm/MHz EIRP
        assert_eq!(tk_psd_cap_01dbm(cond_psd, 100, false), Some(256));
        assert_eq!(eirp_psd_1mhz_01dbm(256, TITAN_ANTENNA_GAIN_01DBI, 100), Some(270));

        // Uncapped 1-RB PUSCH at 26.0 dBm conducted hits 40.0 dBm/MHz (+13.0 dB OVER 27 dBm/MHz grant)
        assert_eq!(eirp_psd_1mhz_01dbm(260, TITAN_ANTENNA_GAIN_01DBI, 1), Some(400));
        // Even with cbrs_mpr (3 dB backoff -> 23.0 dBm), 1-RB still hits 37.0 dBm/MHz (+10.0 dB OVER)
        let after_cbrs_mpr = 260 - cbrs_mpr_01db(1, false);
        assert_eq!(after_cbrs_mpr, 230);
        assert_eq!(eirp_psd_1mhz_01dbm(after_cbrs_mpr, TITAN_ANTENNA_GAIN_01DBI, 1), Some(370));
    }

    #[test]
    fn cbrs_fsm_10mhz_overshoot_vs_compliant_bw_cap() {
        // Stock cbrs_fsm returns 26 dBm regardless of channel bandwidth -> +3 dB over on 10 MHz
        assert_eq!(stock_cbrs_fsm_max_tx_dbm(27, true, true), 26);
        assert_eq!(compliant_channel_max_tx_dbm(27, 14, 10, 26), 23);
        assert_eq!(compliant_channel_max_tx_dbm(27, 14, 20, 26), 26);
        // Lower SAS grant (e.g. 24 dBm/MHz) scales down cleanly
        assert_eq!(compliant_channel_max_tx_dbm(24, 14, 10, 26), 20);
        assert_eq!(compliant_channel_max_tx_dbm(24, 14, 20, 26), 23);
    }

    #[test]
    fn dual_cc_scaler_handles_over_3db_drop_and_pucch_priority() {
        // 23.0 + 23.0 dBm = 26.0103 dBm -> strict ceiling-rounded drop is 0.1 dB against 26.0 dBm
        assert_eq!(dual_cc_equal_drop_01db(230, 230, 260), 1);
        assert_eq!(dual_cc_equal_drop_01db(229, 230, 260), 0);
        // 23.0 + 23.0 dBm = 26.0103 dBm against single-PA 23.0 dBm -> 3.1 dB drop (> 3.0 dB!)
        assert_eq!(dual_cc_equal_drop_01db(230, 230, 230), 31);
        // 23.0 + 23.0 dBm against 21.0 dBm P_UEMAX -> 5.1 dB drop (stock bug skips > 3.0 dB!)
        assert_eq!(dual_cc_equal_drop_01db(230, 230, 210), 51);

        // Simultaneous PCell PUCCH (20.0 dBm) + SCell PUSCH (23.0 dBm) against 23.0 dBm P_UEMAX:
        // PUCCH stays 20.0 dBm, SCell PUSCH scales down to 19.9 dBm (100.0 + 97.7 mW <= 199.5 mW).
        let (pucch, scell) = dual_cc_pucch_pusch_scale_01db(200, 230, 230);
        assert_eq!(pucch, 200);
        assert_eq!(scell, 199);
        assert_eq!(dual_cc_equal_drop_01db(pucch, scell, 230), 0);

        // PUCCH at full P_UEMAX forces SCell PUSCH to minimum (-40.0 dBm)
        assert_eq!(dual_cc_pucch_pusch_scale_01db(260, 230, 260), (260, -400));
    }
}
