//! Byte-exact `#[repr(C)]` TXM power-control structures verified against
//! stock `tk.bin` V1.6.0.P0 disassembly.
//!
//! All power and pathloss fields use `0.1 dBm` or `0.1 dB` fixed-point units
//! unless noted otherwise.

/// Per-component-carrier TXM UL power-control context (`0x214` = 532 bytes).
///
/// Lives at `TxmGlobal + 0x95c`:
/// - PCell (`cc = 0`): `0x84d4_7928` (`f_0(i)` at `0x84d4_7b34`)
/// - SCell (`cc = 1`): `0x84d4_7b3c` (`f_1(i)` at `0x84d4_7d48`)
#[repr(C)]
pub struct TxmCcCtx {
    /// `+0x000` (`+0x95c`): ULPC configured/enabled flag.
    pub ulpc_enabled: u8,
    pub _pad_001: [u8; 3],
    /// `+0x004` (`+0x960`): SIB1/SIB2/RRC `p-Max` (0.1 dBm).
    pub p_max_l3: i32,
    /// `+0x008` (`+0x964`): Configured `P_CMAX,H` ceiling (0.1 dBm).
    pub p_cmax_h_cfg: i32,
    pub _pad_00c: u32,
    /// `+0x010` (`+0x96c`): Active per-CC `P_CMAX,H,c` (0.1 dBm; `230` in 2CC B48, `260` in 1CC CDD).
    pub p_cmax_h: i32,
    pub _pad_014: u32,
    /// `+0x018` (`+0x974`): Base `P_CMAX,H` before CA/HPUE adjustment (0.1 dBm).
    pub p_cmax_h_base: i32,
    /// `+0x01c` (`+0x978`): Minimum UE TX power (`-400` = -40.0 dBm).
    pub p_min: i32,
    pub _pad_020: u32,
    /// `+0x024` (`+0x980`): Last pathloss used in power calculation (0.1 dB).
    pub last_pl: i32,
    /// `+0x028` (`+0x984`): Last computed PUSCH transmit power (0.1 dBm).
    pub last_pusch_pwr: i32,
    /// `+0x02c` (`+0x988`): Last computed SRS transmit power (0.1 dBm).
    pub last_srs_pwr: i32,
    pub _pad_030: [u8; 0x28],
    /// `+0x058` (`+0x9b4`): Network Signaling value (`27` = `NS_27` on Band 48).
    pub ns_value: u32,
    /// `+0x05c` (`+0x9b8`): UE power class (`3` default, `2` HPUE PC2).
    pub ue_power_class: u32,
    pub _pad_060: [u8; 0x08],
    /// `+0x068` (`+0x9c4`): Total UE max power `P_UEMAX` (0.1 dBm; `260` dual-PA, `230` single-PA).
    pub p_uemax: i32,
    pub _pad_06c: u32,
    /// `+0x070` (`+0x9cc`): `accumulationEnabled` (`1` = cumulative TPC).
    pub accum_enabled: u32,
    pub _pad_074: [u8; 0x18],
    /// `+0x08c` (`+0x9e8`): `P_O_PUCCH` (`P_O_NOMINAL_PUCCH + P_O_UE_PUCCH`, 0.1 dBm).
    pub p0_pucch: i32,
    pub _pad_090: [u8; 0x9c],
    /// `+0x12c` (`+0xa88`): Closed-loop PUCCH accumulator `g(i)` (0.1 dB).
    pub g_i: i32,
    pub _pad_130: [u8; 0x0c],
    /// `+0x13c` (`+0xa98`): Dynamic `P_O_PUSCH` (`P_O_NOMINAL + P_O_UE`, 0.1 dBm).
    pub p0_pusch_dyn: i32,
    /// `+0x140` (`+0xa9c`): SPS `P_O_PUSCH` (0.1 dBm).
    pub p0_pusch_sps: i32,
    /// `+0x144` (`+0xaa0`): Last configured `P_O_UE_PUSCH` (dB, compared on reconfig for `f_c` reset).
    pub p0_ue_pusch_saved: i32,
    pub _pad_148: u32,
    /// `+0x14c` (`+0xaa8`): Pathloss compensation `alpha * 10` (`0..=10`).
    pub alpha: i32,
    /// `+0x150` (`+0xaac`): `deltaMCS-Enabled` (`1` => `K_s = 1.25`).
    pub delta_mcs_en: u8,
    pub _pad_151: [u8; 0x77],
    /// `+0x1c8` (`+0xb24`): 4-slot pending TPC ring (`0xffff` = empty).
    pub tpc_ring: [u32; 4],
    pub _pad_1d8: [u8; 0x0c],
    /// `+0x1e4` (`+0xb40`): Power-limit saturation state (`0`=normal, `1`=min, `2`=max).
    pub pwr_lim: u32,
    pub _pad_1e8: [u8; 0x10],
    /// `+0x1f8` (`+0xb54`): `P_O_SRS = p0_pusch_dyn + 10 * (pSrsOffset - 3)` (0.1 dBm).
    pub p0_srs: i32,
    pub _pad_1fc: [u8; 0x0c],
    /// `+0x208` (`+0xb64`): `isqrt(abs(p0_srs))` via `0x842a_2770` (`31 = 0x1f` for `-1000`).
    pub isqrt_abs_p0_srs: u32,
    /// `+0x20c` (`+0xb68`): Closed-loop PUSCH TPC accumulator `f_c(i)` (0.1 dB).
    pub f_c: i32,
    /// `+0x210` (`+0xb6c`): Cached pathloss (`-1` = invalid / query `l1u_get_pl`).
    pub cached_pl: i32,
}

/// Per-band `AT%TXPOWLMT=1,<lim>,<band>` table at `TxmGlobal + 0xd8c` (`0x84d4_7d58`).
#[repr(C)]
pub struct TxPowLmtBandTable {
    pub count: i32,
    pub bands: [u8; 8],
    pub limits_dbm: [i8; 8],
}

/// CA power-limit state at `TxmGlobal + 0xdc0` (`0x84d4_7d8c`).
#[repr(C)]
pub struct PLimitCaState {
    pub enable: u32,
    pub band: u32,
    pub limit_pcell: i32,
    pub limit_scell: i32,
}

/// Band 48 CBRS MPR state at `TxmGlobal + 0xdd0` (`0x84d4_7d9c`).
#[repr(C)]
pub struct CbrsMprState {
    pub enable: u32,
    pub cached_valid: u32,
    pub cached_val: i32,
    pub ofs: i32,
}

/// Primary TXM global state block at `0x84d4_6fcc`.
#[repr(C)]
pub struct TxmGlobal {
    /// `+0x000..+0x958`: Active MPR / A-MPR / CA-A-MPR table copied from NVM staging `0x84d4_80ec`.
    pub mpr_table: [u8; 0x958],
    /// `+0x958`: Non-zero once NVM MPR table has been loaded.
    pub mpr_table_loaded: u8,
    pub _pad_959: [u8; 3],
    /// `+0x95c`: Per-CC contexts (`cc[0]` = PCell, `cc[1]` = SCell).
    pub cc: [TxmCcCtx; 2],
    /// `+0xd84` (`0x84d4_7d50`): `AT%TXPOWLMT` mode (`0`=off, `1`=NV, `2`=AT override).
    pub txpowlmt_mode: u32,
    /// `+0xd88` (`0x84d4_7d54`): RSRP threshold for conditional power limit.
    pub txpowlmt_rsrp_thr: i16,
    pub _pad_d8a: u16,
    /// `+0xd8c` (`0x84d4_7d58`): Per-band `AT%TXPOWLMT` table.
    pub txpowlmt_band_tbl: TxPowLmtBandTable,
    pub _pad_da0: [u8; 0x20],
    /// `+0xdc0` (`0x84d4_7d8c`): CA power-limit override.
    pub p_limit_ca: PLimitCaState,
    /// `+0xdd0` (`0x84d4_7d9c`): Band 48 CBRS MPR state (`0x842a_5e04`).
    pub cbrs_mpr: CbrsMprState,
    pub _pad_de0: [u8; 0x64],
    /// `+0xe44` (`0x84d4_7e10`): Global HW commit TX power offset (0.1 dB).
    pub tx_pwr_ofs_01db: i32,
    /// `+0xe48` (`0x84d4_7e14`): Last RB allocation passed to `txm_hw_commit` (`1..=100`).
    pub last_n_rb: u32,
    /// `+0xe4c` (`0x84d4_7e18`): `AT%TXPOWLMTMHZ` PSD limiter enable (`0` = off, `1` = on).
    pub psd_limit_en: u32,
    /// `+0xe50` (`0x84d4_7e1c`): `AT%TXPOWLMTMHZ` PSD limit in `0.1 dBm/MHz` conducted.
    pub psd_limit_val: i32,
    pub _pad_e54: [u8; 0x2c],
    /// `+0xe80` (`0x84d4_7e4c`): Last applied single-CC MPR (0.1 dB).
    pub last_mpr: i16,
    /// `+0xe82` (`0x84d4_7e4e`): Last applied A-MPR (0.1 dB).
    pub last_ampr: i16,
    /// `+0xe84` (`0x84d4_7e50`): Last dual-CC scaler drop per CC (0.1 dB).
    pub last_ca_drop: [i16; 2],
    /// `+0xe88` (`0x84d4_7e54`): Last CA MPR mode per CC (Mode 7 = non-contiguous `W_gap > 35 MHz`).
    pub last_ca_mode: [u32; 2],
    /// `+0xe90` (`0x84d4_7e5c`): Non-contiguous CA MPR option (`0` = stock zero-MPR on Mode 7).
    pub mpr_ca_opt: u32,
    pub _pad_e94: [u8; 0x0c],
    /// `+0xea0` (`0x84d4_7e6c`): Per-CC `P_CMAX` before `txm_apply_txpowlmt` (0.1 dBm).
    pub p_cmax_pre_lmt: [i32; 2],
    /// `+0xea8` (`0x84d4_7e74`): Global A-MPR enable byte.
    pub ampr_en: u8,
    pub _pad_ea9: [u8; 3],
}

/// Auxiliary TXM state starting at `0x84d4_80bc` (`TXM_AUX_ANCHOR_VA - 0x08`).
#[repr(C)]
pub struct TxmAux {
    /// `anchor - 0x08` (`0x84d4_80bc`): Last reported `P_CMAX,c` (dBm) per CC.
    pub last_reported_pcmax_dbm: [i32; 2],
    /// `anchor + 0x00` (`0x84d4_80c4`): SFN of last reported `P_CMAX,c` per CC.
    pub last_reported_pcmax_sfn: [u32; 2],
    /// `anchor + 0x08` (`0x84d4_80cc`): Global PHR offset (dB).
    pub phr_ofs: i32,
    /// `anchor + 0x0c` (`0x84d4_80d0`): Shadow TX power per CC written when `txpowlmt_mode != 0`.
    pub tx_pwr_shadow: [i32; 2],
    /// `anchor + 0x14` (`0x84d4_80d8`): `AT%TXTOTMAXPWR` enable byte.
    pub txtotmaxpwr_en: u8,
    pub _pad_1d: [u8; 3],
    /// `anchor + 0x18` (`0x84d4_80dc`): `AT%TXTOTMAXPWR` total power ceiling (0.1 dBm, `240..=330`).
    pub txtotmaxpwr: i32,
}

/// Initialized `.data` TXM configuration at `0x84a0_b8a0`.
#[repr(C)]
pub struct TxmRoConfig {
    /// `+0x00`: MPR/A-MPR control mask (default `3`).
    pub mpr_ampr_ctrl: u32,
    /// `+0x04`: Band 48 `NS_27` A-MPR option (default `2`).
    pub ns27_opt: u32,
    pub _pad_08: [u8; 0x30],
    /// `+0x38` (`0x84a0_b8d8`): Active `AT%TXPOWLMT=1,<lim>` limit (0.1 dBm, default `230`).
    pub txpowlmt_val: i32,
    /// `+0x3c`: Global MPR enable flag (default `1`).
    pub mpr_en_flag: u32,
    /// `+0x40`: Hardware commit state byte (`0xff` on idle reset).
    pub commit_state: u8,
    pub _pad_41: [u8; 7],
    /// `+0x48` (`0x84a0_b8e8`): Minimum Power Headroom clamp (dB, default `-23`).
    pub ph_min: i32,
    pub _pad_4c: u32,
    /// `+0x50`: `P_CMAX,L` delta (0.1 dB, default `-30`).
    pub p_cmax_delta_low: i32,
    /// `+0x54`: `P_CMAX` report mode (default `1`).
    pub pcmax_report_mode: u32,
    /// `+0x58`: Last PCell PUSCH power sentinel (default `20000`).
    pub last_pcell_pusch_pwr: i32,
}

/// Per-CC cell descriptor at `0x84d4_4d90` (`[TxmCellInfo; 2]`, stride `0x74`).
#[repr(C)]
pub struct TxmCellInfo {
    /// `+0x00`: UL bandwidth index (`0..=5`, `5` = 20 MHz / 100 RB).
    pub ul_bw_idx: u32,
    /// `+0x04`: Duplex mode (`1` = TDD).
    pub duplex_mode: u32,
    /// `+0x08`: TDD UL/DL configuration (`2` on Band 48 bench).
    pub tdd_ul_dl_cfg: u32,
    pub _pad_0c: [u8; 0x20],
    /// `+0x2c`: Active TXM state.
    pub txm_state: u32,
    pub _pad_30: [u8; 0x18],
    /// `+0x48`: UL EARFCN (e.g. `55440`, `56440`, `56638`).
    pub ul_earfcn: u32,
    pub _pad_4c: u32,
    /// `+0x50`: Configured UL carrier RB count (`50` or `100`).
    pub ul_n_rb: u32,
    pub _pad_54: [u8; 0x10],
    /// `+0x64`: LTE band number (`48`).
    pub band: u32,
    pub _pad_68: u16,
    /// `+0x6a`: TX antenna configuration.
    pub tx_ant_cfg: u16,
    /// `+0x6c`: Internal band table index.
    pub band_idx: u32,
    /// `+0x70` (`0x84d4_4e00` PCell / `0x84d4_4e74` SCell): Single-PA flag (`0` = dual-PA).
    pub s_pa: u8,
    /// `+0x71`: HPUE PC2 request flag (`0x842a_a486` / `0x842a_a5b0`).
    pub hpue_pc2_req: u8,
    pub _pad_72: [u8; 2],
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr;
    use core::mem::{offset_of, size_of};

    #[test]
    fn txm_cc_ctx_layout_matches_tk_bin() {
        assert_eq!(size_of::<TxmCcCtx>(), 0x214);
        assert_eq!(offset_of!(TxmCcCtx, ulpc_enabled), 0x000);
        assert_eq!(offset_of!(TxmCcCtx, p_max_l3), 0x004);
        assert_eq!(offset_of!(TxmCcCtx, p_cmax_h_cfg), 0x008);
        assert_eq!(offset_of!(TxmCcCtx, p_cmax_h), 0x010);
        assert_eq!(offset_of!(TxmCcCtx, p_cmax_h_base), 0x018);
        assert_eq!(offset_of!(TxmCcCtx, p_min), 0x01c);
        assert_eq!(offset_of!(TxmCcCtx, last_pl), 0x024);
        assert_eq!(offset_of!(TxmCcCtx, last_pusch_pwr), 0x028);
        assert_eq!(offset_of!(TxmCcCtx, last_srs_pwr), 0x02c);
        assert_eq!(offset_of!(TxmCcCtx, ns_value), 0x058);
        assert_eq!(offset_of!(TxmCcCtx, ue_power_class), 0x05c);
        assert_eq!(offset_of!(TxmCcCtx, p_uemax), 0x068);
        assert_eq!(offset_of!(TxmCcCtx, accum_enabled), 0x070);
        assert_eq!(offset_of!(TxmCcCtx, p0_pucch), 0x08c);
        assert_eq!(offset_of!(TxmCcCtx, g_i), 0x12c);
        assert_eq!(offset_of!(TxmCcCtx, p0_pusch_dyn), 0x13c);
        assert_eq!(offset_of!(TxmCcCtx, p0_pusch_sps), 0x140);
        assert_eq!(offset_of!(TxmCcCtx, p0_ue_pusch_saved), 0x144);
        assert_eq!(offset_of!(TxmCcCtx, alpha), 0x14c);
        assert_eq!(offset_of!(TxmCcCtx, delta_mcs_en), 0x150);
        assert_eq!(offset_of!(TxmCcCtx, tpc_ring), 0x1c8);
        assert_eq!(offset_of!(TxmCcCtx, pwr_lim), 0x1e4);
        assert_eq!(offset_of!(TxmCcCtx, p0_srs), 0x1f8);
        assert_eq!(offset_of!(TxmCcCtx, isqrt_abs_p0_srs), 0x208);
        assert_eq!(offset_of!(TxmCcCtx, f_c), 0x20c);
        assert_eq!(offset_of!(TxmCcCtx, cached_pl), 0x210);
    }

    #[test]
    fn txm_global_layout_matches_bench_vm_addresses() {
        assert_eq!(offset_of!(TxmGlobal, mpr_table_loaded), 0x958);
        assert_eq!(offset_of!(TxmGlobal, cc), 0x95c);
        assert_eq!(offset_of!(TxmGlobal, txpowlmt_mode), 0xd84);
        assert_eq!(offset_of!(TxmGlobal, txpowlmt_rsrp_thr), 0xd88);
        assert_eq!(offset_of!(TxmGlobal, txpowlmt_band_tbl), 0xd8c);
        assert_eq!(offset_of!(TxmGlobal, p_limit_ca), 0xdc0);
        assert_eq!(offset_of!(TxmGlobal, cbrs_mpr), 0xdd0);
        assert_eq!(offset_of!(TxmGlobal, tx_pwr_ofs_01db), 0xe44);
        assert_eq!(offset_of!(TxmGlobal, last_n_rb), 0xe48);
        assert_eq!(offset_of!(TxmGlobal, psd_limit_en), 0xe4c);
        assert_eq!(offset_of!(TxmGlobal, psd_limit_val), 0xe50);
        assert_eq!(offset_of!(TxmGlobal, last_mpr), 0xe80);
        assert_eq!(offset_of!(TxmGlobal, last_ampr), 0xe82);
        assert_eq!(offset_of!(TxmGlobal, last_ca_drop), 0xe84);
        assert_eq!(offset_of!(TxmGlobal, last_ca_mode), 0xe88);
        assert_eq!(offset_of!(TxmGlobal, mpr_ca_opt), 0xe90);
        assert_eq!(offset_of!(TxmGlobal, p_cmax_pre_lmt), 0xea0);
        assert_eq!(offset_of!(TxmGlobal, ampr_en), 0xea8);

        // Verify absolute addresses against lead's 2026-11-25 02:58 UTC vm dump
        let cc0_va = addr::TXM_GLOBAL_VA + offset_of!(TxmGlobal, cc) as u32;
        let cc1_va = cc0_va + size_of::<TxmCcCtx>() as u32;
        assert_eq!(cc0_va, addr::TXM_PCELL_CTX_VA);
        assert_eq!(cc1_va, addr::TXM_SCELL_CTX_VA);
        assert_eq!(cc0_va + offset_of!(TxmCcCtx, g_i) as u32, addr::TXM_PCELL_GI_VA);
        assert_eq!(cc0_va + offset_of!(TxmCcCtx, f_c) as u32, addr::TXM_PCELL_FC_VA);
        assert_eq!(
            cc1_va + offset_of!(TxmCcCtx, isqrt_abs_p0_srs) as u32,
            addr::TXM_SCELL_ISQRT_P0_SRS_VA
        );
        assert_eq!(cc1_va + offset_of!(TxmCcCtx, f_c) as u32, addr::TXM_SCELL_FC_VA);
        assert_eq!(
            cc1_va + offset_of!(TxmCcCtx, cached_pl) as u32,
            addr::TXM_SCELL_CACHED_PL_VA
        );
        assert_eq!(
            addr::TXM_GLOBAL_VA + offset_of!(TxmGlobal, txpowlmt_mode) as u32,
            addr::TXM_TXPOWLMT_MODE_VA
        );
        assert_eq!(
            addr::TXM_GLOBAL_VA + offset_of!(TxmGlobal, psd_limit_en) as u32,
            addr::TXM_PSD_LIMIT_EN_VA
        );
        assert_eq!(
            addr::TXM_GLOBAL_VA + offset_of!(TxmGlobal, psd_limit_val) as u32,
            addr::TXM_PSD_LIMIT_VAL_VA
        );
        assert_eq!(
            addr::TXM_GLOBAL_VA + offset_of!(TxmGlobal, mpr_ca_opt) as u32,
            addr::TXM_MPR_CA_OPT_VA
        );
    }

    #[test]
    fn txm_aux_ro_config_and_cell_info_layouts_match_tk_bin() {
        assert_eq!(size_of::<TxmAux>(), 0x24);
        assert_eq!(
            addr::TXM_AUX_VA + offset_of!(TxmAux, last_reported_pcmax_sfn) as u32,
            addr::TXM_AUX_ANCHOR_VA
        );
        assert_eq!(
            addr::TXM_AUX_VA + offset_of!(TxmAux, txtotmaxpwr_en) as u32,
            addr::TXM_TXTOTMAXPWR_EN_VA
        );
        assert_eq!(
            addr::TXM_AUX_VA + offset_of!(TxmAux, txtotmaxpwr) as u32,
            addr::TXM_TXTOTMAXPWR_VAL_VA
        );

        assert_eq!(size_of::<TxmRoConfig>(), 0x5c);
        assert_eq!(
            addr::TXM_RO_CONFIG_VA + offset_of!(TxmRoConfig, txpowlmt_val) as u32,
            addr::TXM_TXPOWLMT_VAL_VA
        );
        assert_eq!(
            addr::TXM_RO_CONFIG_VA + offset_of!(TxmRoConfig, ph_min) as u32,
            addr::TXM_PH_MIN_VA
        );

        assert_eq!(size_of::<TxmCellInfo>(), 0x74);
        assert_eq!(
            addr::TXM_CELL_INFO_VA + offset_of!(TxmCellInfo, s_pa) as u32,
            addr::TXM_PCELL_SPA_VA
        );
        assert_eq!(
            addr::TXM_CELL_INFO_VA + size_of::<TxmCellInfo>() as u32 + offset_of!(TxmCellInfo, s_pa) as u32,
            addr::TXM_SCELL_SPA_VA
        );
    }
}
