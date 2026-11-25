//! Verified modem virtual addresses for `tk.bin` V1.6.0.P0 uplink power control
//! (TXM, TPC, MPR/A-MPR, PSD limiting, and MAC PHR/EPHR).
//!
//! File offset for any image-resident VA is `va - TK_LOAD_VA`.

/// Base load VA of `tk.bin` in CPU1 SDRAM.
pub const TK_LOAD_VA: u32 = 0x8410_0000;

// ---------------------------------------------------------------------------
// Global TXM state and ROM tables
// ---------------------------------------------------------------------------

/// `TxmCellInfo[2]` array (stride `0x74`, PCell `0x84d4_4d90`, SCell `0x84d4_4e04`).
pub const TXM_CELL_INFO_VA: u32 = 0x84d4_4d90;
/// PCell single-PA flag (`TxmCellInfo[0].s_pa`, `0` = dual-PA 26 dBm total).
pub const TXM_PCELL_SPA_VA: u32 = 0x84d4_4e00;
/// SCell single-PA flag (`TxmCellInfo[1].s_pa`).
pub const TXM_SCELL_SPA_VA: u32 = 0x84d4_4e74;

/// Primary TXM global state (`TxmGlobal`).
pub const TXM_GLOBAL_VA: u32 = 0x84d4_6fcc;
/// `TxmCcCtx[0]` (PCell, stride `0x214`).
pub const TXM_PCELL_CTX_VA: u32 = 0x84d4_7928;
/// `TxmCcCtx[1]` (SCell, stride `0x214`).
pub const TXM_SCELL_CTX_VA: u32 = 0x84d4_7b3c;
/// PCell closed-loop PUCCH accumulator `g(i)` (`i32`, 0.1 dB).
pub const TXM_PCELL_GI_VA: u32 = 0x84d4_7a54;
/// PCell closed-loop PUSCH accumulator `f_0(i)` (`i32`, 0.1 dB).
pub const TXM_PCELL_FC_VA: u32 = 0x84d4_7b34;
/// SCell `isqrt(abs(p0_srs))` (`u32`, e.g. `31 = 0x1f` for `p0_srs = -1000`).
pub const TXM_SCELL_ISQRT_P0_SRS_VA: u32 = 0x84d4_7d44;
/// SCell closed-loop PUSCH accumulator `f_1(i)` (`i32`, 0.1 dB).
pub const TXM_SCELL_FC_VA: u32 = 0x84d4_7d48;
/// SCell cached pathloss (`i32`, 0.1 dB; `-1` = invalid / query `l1u_get_pl`).
pub const TXM_SCELL_CACHED_PL_VA: u32 = 0x84d4_7d4c;
/// Active `AT%TXPOWLMT` mode (`0`=off, `1`=NV, `2`=`AT%TXPOWLMT=1,<lim>`).
pub const TXM_TXPOWLMT_MODE_VA: u32 = 0x84d4_7d50;
/// `PLimitCaState` (`enable`, `band`, `limit_pcell`, `limit_scell`).
pub const TXM_PLIMIT_CA_VA: u32 = 0x84d4_7d8c;
/// `CbrsMprState` (`enable`, `cached_valid`, `cached_val`, `ofs`).
pub const TXM_CBRS_MPR_VA: u32 = 0x84d4_7d9c;
/// Last committed RB count (`u32`, `1..=100`, read at `0x842a_678a`).
pub const TXM_LAST_N_RB_VA: u32 = 0x84d4_7e14;
/// `AT%TXPOWLMTMHZ` PSD limiter enable (`u32`, read at `0x842a_678e`).
pub const TXM_PSD_LIMIT_EN_VA: u32 = 0x84d4_7e18;
/// `AT%TXPOWLMTMHZ` PSD limit in `0.1 dBm/MHz` conducted (`i32`, read at `0x842a_67c0`).
pub const TXM_PSD_LIMIT_VAL_VA: u32 = 0x84d4_7e1c;
/// Non-contiguous CA MPR option (`u32`, `0` = stock Mode 7 zero-MPR behavior).
pub const TXM_MPR_CA_OPT_VA: u32 = 0x84d4_7e5c;
/// `P_CMAX` saved before `txm_apply_txpowlmt` (`[i32; 2]`, 0.1 dBm).
pub const TXM_PCMAX_PRE_LMT_VA: u32 = 0x84d4_7e6c;
/// Global A-MPR enable byte (`u8`).
pub const TXM_AMPR_EN_VA: u32 = 0x84d4_7e74;

/// Start of `TxmAux` (`TXM_AUX_ANCHOR_VA - 0x08`).
pub const TXM_AUX_VA: u32 = 0x84d4_80bc;
/// Base pointer loaded via `movw/movt` (`0x84d4_80c4`) across TXM routines.
pub const TXM_AUX_ANCHOR_VA: u32 = 0x84d4_80c4;
/// `AT%TXTOTMAXPWR` enable byte (`TXM_AUX_ANCHOR_VA + 0x14`).
pub const TXM_TXTOTMAXPWR_EN_VA: u32 = 0x84d4_80d8;
/// `AT%TXTOTMAXPWR` limit in `0.1 dBm` (`TXM_AUX_ANCHOR_VA + 0x18`).
pub const TXM_TXTOTMAXPWR_VAL_VA: u32 = 0x84d4_80dc;
/// NVM MPR staging buffer (`0x958` bytes, loaded by `0x842a_d3a0`).
pub const TXM_NVM_MPR_STAGE_VA: u32 = 0x84d4_80ec;

/// Initialized `.data` configuration block (`TxmRoConfig`).
pub const TXM_RO_CONFIG_VA: u32 = 0x84a0_b8a0;
/// Active `AT%TXPOWLMT=1,<lim>` limit in `0.1 dBm` (`TxmRoConfig + 0x38`).
pub const TXM_TXPOWLMT_VAL_VA: u32 = 0x84a0_b8d8;
/// Minimum reported Power Headroom clamp (`TxmRoConfig + 0x48`, default `-23`).
pub const TXM_PH_MIN_VA: u32 = 0x84a0_b8e8;

/// ROM `i16[100]` LUT for `round(100 * log10(18 * N_RB))` used by `txm_hw_commit`.
pub const TXM_PSD_RB_LUT_VA: u32 = 0x847e_a92c;

/// MAC PHR state block (`+0x08` trig, `+0x09` prohibit_expired, `+0x0c` dl_pl_chg, `+0x10` 8x16B EPHR slots).
pub const MAC_PHR_STATE_VA: u32 = 0x84d9_3f84;
/// MAC SCell state table (stride `0x18` bytes per SCell, `+0x08` = active flag).
pub const MAC_SCELL_TBL_VA: u32 = 0x84d9_4710;

// ---------------------------------------------------------------------------
// Verified TXM and MAC PHR/EPHR function entry points (Thumb addresses, even)
// ---------------------------------------------------------------------------

pub const FN_TXM_ACT_SCELL: u32 = 0x842a_2138;
pub const FN_TXM_DEACT_SCELL: u32 = 0x842a_21a0;
pub const FN_TXM_REL_SCELL: u32 = 0x842a_2208;
pub const FN_TXM_ISQRT: u32 = 0x842a_2770;
pub const FN_TXM_CALC_SINGLE_CC_AMPR: u32 = 0x842a_2868;
pub const FN_TXM_DUAL_CC_SCALE: u32 = 0x842a_4828;
pub const FN_TXM_GET_PUEMAX_AND_PCMAXH: u32 = 0x842a_4ba0;
pub const FN_TXM_APPLY_TXPOWLMT: u32 = 0x842a_5860;
pub const FN_TXM_CALC_SRS_PWR_WITH_CC: u32 = 0x842a_599c;
pub const FN_TXM_APPLY_PLIMIT_CA: u32 = 0x842a_5d0c;
pub const FN_TXM_CALC_CBRS_MPR: u32 = 0x842a_5e04;
pub const FN_TXM_CALC_CA_MPR_CLASS_C: u32 = 0x842a_619c;
pub const FN_TXM_CA_MPR_MODE_SELECT: u32 = 0x842a_6550;
pub const FN_TXM_HW_COMMIT: u32 = 0x842a_668c;
pub const FN_TXM_CALC_MPR_AMPR: u32 = 0x842a_7844;
pub const FN_L1_CALCULATE_MEAS_INFO: u32 = 0x842a_97ac;
pub const FN_TXM_ULPC_INIT: u32 = 0x842a_a77c;
pub const FN_TXM_CFG_PCELL_ULPC: u32 = 0x842a_a924;
pub const FN_TXM_CFG_SCELL_ULPC: u32 = 0x842a_b418;
pub const FN_TXM_LOAD_NVM_MPR: u32 = 0x842a_d3a0;
pub const FN_TXM_SAVE_TPC_FOR_PUSCH: u32 = 0x842a_d8b4;
pub const FN_TXM_APPLY_TPC_ACCUM: u32 = 0x842a_da50;
pub const FN_TXM_SET_PRACH_PWR: u32 = 0x842a_e278;
pub const FN_TXM_SET_SRS_PWR: u32 = 0x842a_e5ec;
pub const FN_TXM_SET_PUSCH_PWR: u32 = 0x842a_ec00;
pub const FN_TXM_SET_PUCCH_PWR: u32 = 0x842a_fc40;
pub const FN_TXM_SET_TXPOWLMT: u32 = 0x842b_0610;
pub const FN_TXM_SET_PSD_LIMIT: u32 = 0x842b_06b4;
pub const FN_TXM_SET_TXTOTMAXPWR: u32 = 0x842b_08a0;
pub const FN_TXM_SETUP_SRS_SCELL: u32 = 0x842b_4e84;
pub const FN_L1U_GET_PL: u32 = 0x8425_57f0;
pub const FN_L1U_GET_PL_BY_CC: u32 = 0x8425_5840;
pub const FN_MAC_BUILD_EPHR: u32 = 0x842c_f7a0;
pub const FN_MAC_PACK_EPHR_PCMAX: u32 = 0x842c_f948;
pub const FN_MAC_PHR_TRIGGER: u32 = 0x842d_1c40;
pub const FN_ATM_CMD_TXPOWLMT: u32 = 0x8447_dc80;
pub const FN_ATM_CMD_TXTOTMAXPWR: u32 = 0x8447_de50;
pub const FN_ATM_CMD_TXPOWLMTMHZ: u32 = 0x8447_e1f8;

// ---------------------------------------------------------------------------
// Compliance defect sites and IMG4/N6H/M1 boot-off hook control blocks
// ---------------------------------------------------------------------------

/// `cbnz r1, 0x842a_ea12` in `TXM_SetSRSTransmitPow` skips loading `P_UEMAX` when `txpowlmt_mode != 0`.
pub const BUG_SRS_TXPOWLMT_PUEMAX_SKIP_VA: u32 = 0x842a_ea02;
/// `cmp r3, #0x1e; bhi` skip in `TXM_SetSRSTransmitPow` (skips drop > 3.0 dB).
pub const BUG_SRS_SCALER_SKIP_VA: u32 = 0x842a_ea3c;
/// `cmp r3, #0x1e; bhi` skip in `TXM_SetPUSCHTransmitPow` (skips drop > 3.0 dB).
pub const BUG_PUSCH_SCALER_SKIP_1_VA: u32 = 0x842a_f228;
/// Wrong-variable compare (`cmp` on raw power instead of drop) in PUSCH+SRS path.
pub const BUG_PUSCH_SRS_WRONG_VAR_VA: u32 = 0x842a_f23e;
/// Secondary `cmp r3, #0x1e; bhi` skip in `TXM_SetPUSCHTransmitPow`.
pub const BUG_PUSCH_SCALER_SKIP_2_VA: u32 = 0x842a_f2da;
/// PSD LUT load site in `txm_hw_commit` (1-RB/PUCCH uses `126` instead of `200`).
pub const SITE_PSD_LUT_LOAD_VA: u32 = 0x842a_67bc;

/// IMG3/IMG4/N6H/M1 boot-off PHR hook control flag (`0` at boot).
pub const PATCH_PHR_FLAG_VA: u32 = 0x847e_cf10;
/// IMG4/N5/N6H/M1 boot-off R17-F1 `f_1(i)` reset control flag (`0` at boot).
pub const PATCH_R17_FLAG_VA: u32 = 0x847e_cff8;
