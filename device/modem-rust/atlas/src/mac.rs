//! MAC UL structures: BSR, LCG mapping, TB builder frame, SR/RACH, HARQ,
//! SCell activation table, PHR state, L1U SR config, and 3GPP BSR lookup tables.
//!
//! Verified against `SearchMacUlBoIdx` (`0x842c_cf64`), `RestartBsrTimer` (`0x842c_d080`),
//! `ExpireBSRTimer` (`0x842c_d104`), `ExpireRetxBSRTimer` (`0x842c_d1ec`),
//! `UpdateMacUlBo` (`0x842c_d298`), `GetMacUlBsrValue` (`0x842c_d54c`),
//! `GenerateMacUlPdu` (`0x842d_0248`), `AccessRa` (`0x842d_3abc`),
//! `GetMacUlSR` (`0x842d_4ca4`), `ClearMacUlBuffer` (`0x842d_54fc`), and
//! `HandleHarqProc` (`0x842d_5bd4`).

use crate::Ptr32;

/// MAC UL BSR LCIDs (3GPP TS 36.321 Table 6.2.1-2).
pub const MAC_LCID_TRUNCATED_BSR: u8 = 28;
pub const MAC_LCID_SHORT_BSR: u8 = 29;
pub const MAC_LCID_LONG_BSR: u8 = 30;
pub const MAC_LCID_PADDING: u8 = 31;
/// Sentinel returned by `GetMacUlBsrFormat` (`0x842c_d46c`) when no BSR CE fits or applies.
pub const MAC_LCID_NONE: u8 = 0xff;
/// Sentinel LCG ID stored in `default_lcg` / `trigger_lcg` when unmapped/empty.
pub const MAC_LCG_NONE: u8 = 4;

/// `MacUlBsrCtx::bsr_trigger_mask` (`+0x04`) bitmasks verified from `tk.bin`.
pub const BSR_TRIG_PERIODIC: u32 = 0x01;
pub const BSR_TRIG_PADDING: u32 = 0x02;
pub const BSR_TRIG_REGULAR_BIT: u32 = 0x10;
pub const BSR_TRIG_REGULAR_ARRIVAL: u32 = 0x12;
pub const BSR_TRIG_RETX: u32 = 0x14;

/// `MacUlCfg::bsr_timer_flags` (`+0x1c`) enable bits.
pub const BSR_TMR_FLAG_PERIODIC: u16 = 1 << 2;
pub const BSR_TMR_FLAG_RETX: u16 = 1 << 5;

/// `MacTbBuildFrame::ce_enable_mask` (`+0x3c`) bits.
pub const TB_CE_CRNTI: u32 = 1 << 0;
pub const TB_CE_BSR: u32 = 1 << 1;
pub const TB_CE_PHR: u32 = 1 << 2;
pub const TB_CE_EXT_PHR: u32 = 1 << 3;
pub const TB_CE_DC_PHR: u32 = 1 << 4;

/// MAC UL HARQ process action codes in `MacHarqProc::pending_action` (`+0x20`).
pub const HARQ_ACT_NEW_TX: u32 = 0;
pub const HARQ_ACT_ADAPT_RETX: u32 = 1;
pub const HARQ_ACT_NON_ADAPT_RETX: u32 = 2;
pub const HARQ_ACT_ACK_SUSPEND: u32 = 3;
pub const HARQ_ACT_IGNORE: u32 = 4;

/// Per-logical-channel MAC UL configuration (`0x14` = 20 bytes),
/// starting at `MAC_UL_CFG_VA + 0x74` (`0x84d6_2a10`).
///
/// Indexed by `lcid` (`0..=10`): `priority` is at `0x78 + lcid * 0x14`,
/// `lcg_id` at `0x79 + lcid * 0x14` (`UpdateMacUlBo`), and `pbr_bytes_per_tti`
/// at `0x7c + lcid * 0x14` (`UpdateBj` `0x842c_fb1c`).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct MacUlLcCfg {
    pub _head: u32,
    /// `+0x04` (`+0x78` from `MacUlCfg`): 3GPP logical channel priority (`1..16`, lower = higher priority).
    pub priority: u8,
    /// `+0x05` (`+0x79` from `MacUlCfg`): Assigned Logical Channel Group ID (`0..3`, `>3` = unmapped).
    pub lcg_id: u8,
    pub _pad0: u16,
    /// `+0x08` (`+0x7c` from `MacUlCfg`): Prioritised Bit Rate increment in bytes/TTI (`UpdateBj`).
    pub pbr_bytes_per_tti: u32,
    pub _rest: [u8; 0x08],
}

/// Per-LCG buffer occupancy state inside `MacUlBsrCtx` (`8` bytes),
/// starting at `MAC_UL_BSR_CTX_VA + 0x3c` (`0x84d6_297c`).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct MacUlLcgState {
    /// `+0x00` (`+0x3c + lcg*8`): Non-zero when this LCG has pending RLC data.
    pub has_data: u8,
    pub _pad: [u8; 3],
    /// `+0x04` (`+0x40 + lcg*8`): Cached RLC BO bytes for this LCG (excludes `ring_pending_bytes`).
    pub bo_bytes: u32,
}

/// MAC UL BSR dynamic state at `MAC_UL_BSR_CTX_VA` (`0x84d6_2940`, `0x5c` bytes,
/// immediately followed by [`MacUlCfg`] at `0x84d6_299c`).
#[repr(C)]
pub struct MacUlBsrCtx {
    /// `+0x00`: Set to `1` by `GetMacUlBsrValue` (`0x842c_d708`); checked & cleared in
    /// `HandleHarqProc` NewTx (`0x842d_6152`), restarting `retxBSR-Timer` when `0`.
    pub bsr_sent_in_tb: u8,
    /// `+0x01`: Non-zero when a Regular or Periodic BSR is pending.
    pub bsr_pending: u8,
    /// `+0x02`: Set to `1` when SR was triggered for a pending BSR (`AccessRa`).
    pub sr_triggered_flag: u8,
    pub _pad1: u8,
    /// `+0x04`: BSR trigger bitmask (`BSR_TRIG_*`).
    pub bsr_trigger_mask: u32,
    /// `+0x08`: Highest priority (lowest numeric value, `0xff` = none) among LCs with RLC BO > 0.
    pub highest_prio_with_data: u8,
    pub _pad1b: [u8; 3],
    /// `+0x0c..+0x37`: Per-LC cached RLC BO array (`lcid 0..=10`, `UpdateMacUlBo`).
    pub lc_bo: [u32; 11],
    /// `+0x38`: Default LCG ID (highest-priority configured LC, typically `0` = SRB, `4` = none).
    pub default_lcg: u8,
    /// `+0x39`: Triggering LCG ID (`0..3`, reset to `4` when bearer RLC buffer drains).
    pub trigger_lcg: u8,
    pub _pad2: u8,
    /// `+0x3b`: Count of LCGs with non-zero RLC BO (checked by `ExpireRetxBSRTimer` & `GetMacUlBsrFormat`).
    pub retx_bsr_has_data: u8,
    /// `+0x3c..+0x5b`: Per-LCG state (`[MacUlLcgState; 4]`).
    pub lcg: [MacUlLcgState; 4],
}

/// MAC UL RRC configuration block at `MAC_UL_CFG_VA` (`0x84d6_299c`, `0x160` bytes).
#[repr(C)]
pub struct MacUlCfg {
    /// `+0x00`: Feature bitmask (`bit 1 = 0x02`: UL CA active).
    pub feature_flags: u32,
    /// `+0x04`: Duplex mode (`0` = FDD, `1` = TDD).
    pub duplex_mode: u8,
    /// `+0x05`: 3GPP TDD UL/DL configuration (`0..=6`; `2` on Band 48 CBRS bench).
    pub tdd_ul_dl_cfg: u8,
    pub _pad0: [u8; 0x16],
    /// `+0x1c`: BSR timer enable flags (`bit 2` periodic, `bit 5` retx).
    pub bsr_timer_flags: u16,
    pub _pad1: u16,
    /// `+0x20`: L2 timer table ID for `periodicBSR-Timer`.
    pub periodic_bsr_tmr_id: u32,
    pub _pad2: u32,
    /// `+0x28`: Pending `periodicBSR-Timer` duration update in ms.
    pub periodic_bsr_pending_ms: u16,
    /// `+0x2a`: Non-zero if `periodic_bsr_pending_ms` must be applied on restart.
    pub periodic_bsr_dirty: u8,
    pub _pad3a: [u8; 0x19],
    /// `+0x44`: L2 timer table ID for `retxBSR-Timer` (`RestartRetxBsrTimer` `0x842c_d196`).
    pub retx_bsr_tmr_id: u32,
    pub _pad3b: u32,
    /// `+0x4c`: Pending `retxBSR-Timer` duration update in ms.
    pub retx_bsr_pending_ms: u16,
    /// `+0x4e`: Non-zero if `retx_bsr_pending_ms` must be applied on restart.
    pub retx_bsr_dirty: u8,
    pub _pad3c: [u8; 0x0e],
    /// `+0x5d`: Configured `maxHARQ-Tx` (`7` on Nokia bench).
    pub max_harq_tx: u8,
    pub _pad4a: [u8; 0x0a],
    /// `+0x68`: PHR reporting mode (`2` = Extended PHR, `4` = Dual-Connectivity PHR).
    pub phr_mode: u32,
    pub _pad4b: u32,
    /// `+0x70`: Bitmask of active logical channels (`rlc_upd_cur_bo`, `mac_bsr_pre_work`).
    pub active_lc_mask: u32,
    /// `+0x74..+0x14f`: Per-LC configuration table (`11` LCIDs `0..=10`, stride `0x14`).
    pub lc_cfg: [MacUlLcCfg; 11],
    /// `+0x150`: TTI bundling enabled flag (`0` = off, `1` = on).
    pub tti_bundling_en: u8,
    pub _pad5: u8,
    /// `+0x152`: BSR table selector (`1` = Standard 36.321 Table 6.1.3.1-1, `2` = Extended r10).
    pub ext_bsr_mode: u8,
    pub _pad6a: [u8; 9],
    /// `+0x15c`: Measurement gap active flag (`HandleHarqEntity` `0x842d_77f6`).
    pub meas_gap_en: u8,
    pub _pad6b: [u8; 3],
}

/// Per-LC scheduling/raw BO pair (`8` bytes) inside [`MacUlLcpTbl`] (`+0x60 + lcid*8`).
#[repr(C)]
#[derive(Copy, Clone, Default, Debug, PartialEq, Eq)]
pub struct MacUlLcBoPair {
    /// `+0x00`: Scheduling BO (`new_bo + hdr_bo + 2`, or `0` when `new_bo == 0`),
    /// decremented in-place across PCell then SCell by `AssignScheduleSize2LC` / `SecondStepPBR`.
    pub sched_bo: u32,
    /// `+0x04`: Raw RLC BO (`new_bo`) reported to `UpdateMacUlBo`.
    pub raw_bo: u32,
}

/// Per-LC PBR token bucket (`8` bytes) inside [`MacUlLcpTbl`] (`+0xb8 + lcid*8`).
#[repr(C)]
#[derive(Copy, Clone, Default, Debug, PartialEq, Eq)]
pub struct MacUlLcPbr {
    /// `+0x00`: Bucket cap (`PBR * bucketSizeDuration`, bytes).
    pub bj_max: u32,
    /// `+0x04`: Signed current token bucket `Bj` (incremented once per TTI by `UpdateBj`,
    /// decremented by PCell then SCell in `AssignScheduleSize2LC`).
    pub bj: i32,
}

/// MAC UL LCP scheduling & PBR token-bucket table at `MAC_UL_LCP_TBL_VA`
/// (`0x84d6_2c70`, `0x110` = 272 bytes).
///
/// Verified against `UpdateMacUlBo` (`0x842c_d298`), `UpdateBj` (`0x842c_fad8`),
/// `AssignScheduleSize2LC` (`0x842c_fd40`), `SecondStepPBR` (`0x842c_fb34`), and
/// `CheckLongBsrDowngradeToShort` (`0x842c_fe34`, which `memcpy`s all `0x110` bytes).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct MacUlLcpTbl {
    /// `+0x00`: Sum of raw RLC BO (`lc_bo[lcid].raw_bo`) across all logical channels.
    pub total_bo: u32,
    /// `+0x04`: MSB-first bitmask of active priorities (`bit (31 - (prio - 1))`, scanned with `clz`).
    pub active_prio_mask: u32,
    /// `+0x08..+0x47`: Bitmask of LCIDs belonging to each priority index `0..15` (`prio - 1`).
    pub prio_lc_mask: [u32; 16],
    pub _pad0: u32,
    /// `+0x4c..+0x5b`: Round-robin LCID cursor per priority index `0..15`.
    pub prio_rr_cursor: [u8; 16],
    pub _pad1: u32,
    /// `+0x60..+0xb7`: Per-LC `(sched_bo, raw_bo)` for `lcid 0..=10`.
    pub lc_bo: [MacUlLcBoPair; 11],
    /// `+0xb8..+0x10f`: Per-LC `(bj_max, bj)` token buckets for `lcid 0..=10`.
    pub lc_pbr: [MacUlLcPbr; 11],
}

/// MAC UL global control block at `MAC_UL_GLOBAL_VA` (`0x84d9_426c`, `0x30` bytes).
///
/// Verified against `HandleHarqEntity` (`0x842d_7424`), `HandleHarqProc` (`0x842d_5fa0`),
/// `GenerateMacUlPdu` (`0x842d_03de`), and `ScheduleUlData` (`0x842d_89ec`).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct MacUlGlobal {
    pub _pad0: [u8; 0x14],
    /// `+0x14` (`0x84d9_4280`): Remaining NewTx grants to build in this TTI.
    /// Incremented by `HandleHarqEntity` per NewTx CC and decremented by `HandleHarqProc`
    /// before `GenerateMacUlPdu`. Non-zero on PCell in a 2CC NewTx TTI so Regular/Periodic
    /// BSR defers to SCell (`GenerateMacUlPdu` `0x842d_03de`).
    pub pending_newtx_cnt: u8,
    pub _pad1: [u8; 7],
    /// `+0x1c`: SFN wrap counter used in TDD/SPS timing.
    pub sfn_wrap_cnt: u32,
    /// `+0x20`: Configured UL SPS interval (subframes).
    pub sps_interval: u16,
    pub _pad2: u16,
    /// `+0x24`: Last UL SPS TTI.
    pub sps_last_tti: u32,
    /// `+0x28`: `implicitReleaseAfter` threshold for UL SPS.
    pub sps_implicit_rel_after: u8,
    pub _pad3: [u8; 2],
    /// `+0x2b`: UL SPS active flag.
    pub sps_active: u8,
    /// `+0x2c`: Consecutive zero-MAC-SDU UL SPS transmissions.
    pub sps_zero_sdu_cnt: u32,
}

/// Per-CC UL scheduling descriptor (`0x64` = 100 bytes), passed to `ReconstructSchedInfo`
/// (`0x842d_5258`), `HandleHarqEntity` (`0x842d_6d68`), and `HandleHarqProc` (`0x842d_5bd4`).
/// In 2CC UL CA, PCell is at `sched_msg + 0x00` and SCell is at `sched_msg + 0x64`.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct MacUlSchedInfo {
    /// `+0x00`: L1/MAC subframe index (`SFN * 10 + sf`, modulo `10240`).
    pub tti: u32,
    /// `+0x04`: Grant validity (`1` = DCI-0 UL grant present, `2` = skip/idle).
    pub valid: u32,
    /// `+0x08`: Grant/bundling flags copied to `MacHarqProc + 0x14`.
    pub grant_flags: u32,
    pub _pad0: u32,
    /// `+0x10`: Component Carrier index (`0` = PCell, `1` = SCell).
    pub cc: u8,
    /// `+0x11`: DCI format / grant type (`4` = RA Msg3/special).
    pub dci_type: u8,
    pub _pad1: u16,
    /// `+0x14`: Raw TB size in bytes from L1D.
    pub tb_size: u32,
    pub _pad2: [u8; 8],
    /// `+0x20`: DCI-0 MCS (`0..31`; `29..31` = adaptive retx RV 1..3).
    pub mcs: u8,
    /// `+0x21`: DCI-0 New Data Indicator bit (`0` or `1`).
    pub ndi: u8,
    pub _pad3: [u8; 4],
    /// `+0x26`: TDD Config 0 UL index / multi-TTI flag.
    pub ul_idx: u8,
    pub _pad4: [u8; 9],
    /// `+0x30`: Reconstructed effective MCS (`ReconstructSchedInfo`).
    pub eff_mcs: u8,
    pub _pad5: u8,
    /// `+0x32`: Reconstructed effective NDI (`ReconstructSchedInfo`).
    pub eff_ndi: u8,
    pub _pad6: u8,
    /// `+0x34`: Reconstructed effective TB size in bytes (`HandleHarqProc` `0x842d_605e`).
    pub eff_tb_size: u32,
    pub _pad7: u32,
    /// `+0x3c`: Calculated TB size returned by `0x842b_c3a8`.
    pub calc_tb_size: u32,
    /// `+0x40`: Grant count reconstructed for this CC.
    pub grant_cnt: u8,
    pub _pad8: [u8; 3],
    /// `+0x44`: Resolved HARQ action (`HARQ_ACT_*`).
    pub harq_action: u32,
    pub _pad9: u32,
    /// `+0x4c`: Non-zero when a valid DCI-0 grant was reconstructed.
    pub has_grant: u8,
    pub _pad10: [u8; 3],
    /// `+0x50`: Raw PHICH feedback word from L1D (`1` = ACK, `0` = NACK, `2` = none).
    pub phich_ack_raw: u32,
    pub _pad11: u32,
    /// `+0x58`: Body index (`0` for normal UL).
    pub body_idx: u32,
    /// `+0x5c`: Resolved PHICH ACK indicator (`1` = ACK).
    pub phich_ack: u32,
    pub _pad12: u32,
}

/// Stack frame layout pointed to by `r7` inside `GenerateMacUlPdu` (`0x842d_0248`),
/// inspected by N4 Hook 1 at `0x842d_0914`.
#[repr(C)]
pub struct MacTbBuildFrame {
    pub _pad0: [u8; 0x2c],
    /// `+44` (`+0x2c`): Bitmask of LCIDs that contributed MAC SDUs to this TB.
    pub packed_lc_mask: u32,
    /// `+48` (`+0x30`): Granted transport block size (`tbSize`) in bytes.
    pub tb_size: u32,
    pub _pad1a: u32,
    /// `+56` (`+0x38`): Transport block index (`0` in single-layer LTE UL).
    pub tb_idx: u32,
    /// `+60` (`+0x3c`): Enabled MAC CE bitmask (`TB_CE_*`).
    pub ce_enable_mask: u32,
    pub _pad1b: [u8; 0x1c],
    /// `+92` (`+0x5c`): Bytes actually packed into the TB (MAC subheaders + CEs + SDUs).
    pub used_bytes: u32,
    /// `+96` (`+0x60`): Pointer to the last MAC subheader (for clearing the `E` extension bit).
    pub last_subhdr_ptr: Ptr32<u8>,
    /// `+100` (`+0x64`): Total MAC subheader bytes emitted so far.
    pub mac_hdr_len: u32,
    /// `+104` (`+0x68`): BSR type (`0` = Regular/Periodic, `1` = Padding).
    pub bsr_type: u32,
    /// `+108` (`+0x6c`): Chosen BSR MAC CE LCID (`255` if none yet -> eligible for Padding BSR).
    pub bsr_lcid: u8,
    pub _pad3: [u8; 3],
    /// `+112` (`+0x70`): Set to `1` when Regular/Periodic BSR was deferred to SCell (`pending_newtx_cnt != 0`).
    pub deferred_bsr_flag: u8,
    /// `+113` (`+0x71`): Non-zero if trailing MAC padding is present (`pad = tb_size - used_bytes`).
    pub has_trailing_pad: u8,
    pub _pad4: [u8; 2],
}

/// MAC RACH & Scheduling Request context at `MAC_RA_SR_CTX_VA` (`0x84d9_40b8`).
#[repr(C)]
pub struct MacRaSrCtx {
    /// `+0x00`: Random Access FSM state (`0` = idle).
    pub ra_state: u32,
    pub _pad0: [u8; 0xe8],
    /// `+0xec` (`0x84d9_41a4`): PUCCH SR configured by RRC (`1` = yes).
    pub sr_configured: u8,
    /// `+0xed` (`0x84d9_41a5`): SR currently pending (`1` = waiting for PUCCH SR slot).
    pub sr_pending: u8,
    /// `+0xee` (`0x84d9_41a6`): PUCCH SR resource valid (`1` after RACH completion).
    pub sr_pucch_valid: u8,
    pub _pad1: u8,
    /// `+0xf0` (`0x84d9_41a8`): Current `SR_COUNTER` attempts sent.
    pub sr_counter: u32,
    /// `+0xf4` (`0x84d9_41ac`): Active `dsr-TransMax` snapshot (`64` on Nokia bench).
    pub dsr_trans_max_active: u32,
    /// `+0xf8` (`0x84d9_41b0`): RRC-configured `dsr-TransMax`.
    pub dsr_trans_max_cfg: u32,
    pub _pad2: [u8; 0xa8],
    /// `+0x1a4` (`0x84d9_425c`): Counter of SR-to-RACH fallbacks.
    pub sr_to_rach_cnt: u32,
}

/// Single UL HARQ process descriptor (`0x78` = 120 bytes).
///
/// Table at `MAC_HARQ_PROC_TBL_VA` (`0x84d6_3780`): `table[cc][hq_id]` where
/// `cc` is `0..3` (stride `0x3c0`) and `hq_id` is `0..7` (stride `0x78`).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct MacHarqProc {
    pub _pad0: [u8; 4],
    /// `+0x04`: `HARQ_FEEDBACK` (`0` = NACK / active, `1` = PHICH ACK / suspended).
    pub harq_feedback: u8,
    pub _pad1: [u8; 7],
    /// `+0x0c`: Last seen DCI-0 New Data Indicator bit (`PrevNDI`).
    pub prev_ndi: u8,
    /// `+0x0d`: Last MCS (`0xff` when flushed).
    pub mcs: u8,
    /// `+0x0e`: `CURRENT_TX_NB` (`0xff` when empty, `0` on NewTx).
    pub current_tx_nb: u8,
    /// `+0x0f`: `maxHARQ-Tx` copied from `MacUlCfg::max_harq_tx` (`7` on bench).
    pub max_harq_tx: u8,
    pub _pad2: u8,
    /// `+0x11`: Redundancy Version sequence index (`0..3`, `0xff` when empty).
    pub rv_idx: u8,
    /// `+0x12`: Redundancy Version (`0, 2, 3, 1`, `0xff` when empty).
    pub rv: u8,
    pub _pad3: [u8; 5],
    /// `+0x18`: Flag checked in `HandleHarqProc` case 2.
    pub bundle_or_ra_flag: u8,
    pub _pad4: [u8; 7],
    /// `+0x20`: Pending action code (`HARQ_ACT_*`).
    pub pending_action: u32,
    pub _pad5: [u8; 0x44],
    /// `+0x68`: Pointer to flat raw MAC PDU bytes in non-cacheable DMA pool (`0x85f0_0800+`).
    pub tb_buf: Ptr32<u8>,
    /// `+0x6c`: Pool handle freed by `ClearMacUlBuffer` (`0x842d_99c4`).
    pub tb_pool_handle: u32,
    pub _pad6: [u32; 2],
}

/// L1U PUCCH SR schedule config at `L1U_SR_CFG_VA` (`0x84d4_9c54`).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct L1uSrCfg {
    /// `+0x00`: `SR_periodicity` in ms (`20` on bench `c5`).
    pub periodicity_ms: u32,
    /// `+0x04`: `SR_offset` in subframes (`12` on bench `c5`, SF 2 of odd frames).
    pub offset_sf: u32,
}

/// 3GPP TS 36.321 Table 6.1.3.1-1 Standard BSR upper bounds (`idx 0..62`),
/// matching `tk.bin` ROM at `0x847f_5b1c`. Values `> 150_000` map to index `63`.
pub const STD_BSR_TABLE: [u32; 63] = [
    0, 10, 12, 14, 17, 19, 22, 26, 31, 36, 42, 49, 57, 67, 78, 91, 107, 125, 146, 171, 200, 234,
    274, 321, 376, 440, 515, 603, 706, 826, 967, 1132, 1326, 1552, 1817, 2127, 2490, 2915, 3413,
    3995, 4677, 5476, 6411, 7505, 8787, 10287, 12043, 14099, 16507, 19325, 22624, 26487, 31009,
    36304, 42502, 49759, 58255, 68201, 79846, 93479, 109439, 128125, 150000,
];

/// 3GPP TS 36.321 Table 6.1.3.1-2 Extended BSR upper bounds (`idx 0..62`),
/// matching `tk.bin` ROM at `0x847f_5c18`. Values `> 3_000_000` map to index `63`.
pub const EXT_BSR_TABLE: [u32; 63] = [
    0, 10, 13, 16, 19, 23, 29, 35, 43, 53, 65, 80, 98, 120, 147, 181, 223, 274, 337, 414, 509,
    625, 769, 945, 1162, 1429, 1757, 2161, 2657, 3267, 4017, 4940, 6074, 7469, 9185, 11294, 13888,
    17077, 20999, 25822, 31752, 39045, 48012, 59039, 72598, 89272, 109774, 134986, 165989, 204111,
    250990, 308634, 379519, 466683, 573866, 705666, 867737, 1067031, 1312097, 1613447, 1984009,
    2439678, 3000000,
];

/// 3GPP TS 36.211 / `tk.bin` ROM (`0x847f_5370` cfg 2): TDD Config 2 UL subframe mask (`SF 2` & `SF 7`).
pub const TDD_CFG2_UL_SF: [u8; 10] = [0, 0, 1, 0, 0, 0, 0, 1, 0, 0];
/// 3GPP TS 36.213 Table 8-2 / `tk.bin` ROM (`0x847f_5e20` cfg 2): `k_PUSCH` (`SF 3->7`, `SF 8->2`).
pub const TDD_CFG2_K_PUSCH: [u8; 10] = [0, 0, 0, 4, 0, 0, 0, 0, 4, 0];
/// 3GPP TS 36.213 Table 9.1.2-1 / `tk.bin` ROM (`0x847f_5dd8` cfg 2): `k_PHICH` (`SF 2->8`, `SF 7->3`).
pub const TDD_CFG2_K_PHICH: [u8; 10] = [0, 0, 6, 0, 0, 0, 0, 6, 0, 0];
/// `tk.bin` ROM (`0x847f_5f18` cfg 2): TDD Config 2 UL HARQ process ID (`SF 2 -> 0`, `SF 7 -> 1`).
pub const TDD_CFG2_HARQ_ID: [u8; 10] = [0, 0, 0, 0, 0, 0, 0, 1, 0, 0];
/// `tk.bin` ROM (`0x847f_8384`): Non-adaptive HARQ retx Redundancy Version sequence (`(rv_idx+1)&3`).
pub const HARQ_RV_SEQ: [u8; 4] = [0, 2, 3, 1];
/// `tk.bin` ROM (`0x847f_8358`): Inverse map from RV (`0..3`) to `rv_idx` (`0..3`).
pub const HARQ_RV_TO_IDX: [u8; 4] = [0, 3, 1, 2];
/// Exact HARQ RTT in TDD Config 2 (`k_PHICH = 6 ms` + `k_PUSCH = 4 ms` = `10 ms`).
pub const HARQ_TDD_CFG2_RTT_MS: u32 = 10;

/// Exact mirror of `SearchMacUlBoIdx` (`0x842c_cf64`) for the Standard BSR table.
#[inline]
pub fn bsr_index_std(bo_bytes: u32) -> u8 {
    bsr_index_in(&STD_BSR_TABLE, bo_bytes)
}

/// Exact mirror of `SearchMacUlBoIdx` (`0x842c_cf64`) for the Extended BSR table.
#[inline]
pub fn bsr_index_ext(bo_bytes: u32) -> u8 {
    bsr_index_in(&EXT_BSR_TABLE, bo_bytes)
}

/// Unrolled 6-step binary search with `bo_bytes == 0` fast-path.
///
/// Bit-identical to stock `SearchMacUlBoIdx` (`0x842c_cf64`) across all `u32` inputs
/// for both Standard and Extended 3GPP BSR tables, while eliminating the loop overhead
/// and early-exiting on the common `0`-byte LCG case.
#[inline]
pub const fn bsr_index_in(table: &[u32; 63], bo_bytes: u32) -> u8 {
    if bo_bytes == 0 {
        return 0;
    }
    if bo_bytes > table[62] {
        return 63;
    }
    // 6-step branchless binary search for the largest k in 0..=61 with bo_bytes > table[k].
    // Max offset sum is 31 + 16 + 8 + 4 + 2 + 1 = 62 < 63, so every index is provably in bounds.
    let mut lo: usize = 0;
    if bo_bytes > table[lo + 31] {
        lo += 31;
    }
    if bo_bytes > table[lo + 16] {
        lo += 16;
    }
    if bo_bytes > table[lo + 8] {
        lo += 8;
    }
    if bo_bytes > table[lo + 4] {
        lo += 4;
    }
    if bo_bytes > table[lo + 2] {
        lo += 2;
    }
    if bo_bytes > table[lo + 1] {
        lo += 1;
    }
    (lo + 1) as u8
}
