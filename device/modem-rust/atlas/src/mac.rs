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

/// MAC UL HARQ process action codes in `MacHarqProc::pending_action` (`+0x20`).
pub const HARQ_ACT_NEW_TX: u32 = 0;
pub const HARQ_ACT_ADAPT_RETX: u32 = 1;
pub const HARQ_ACT_NON_ADAPT_RETX: u32 = 2;
pub const HARQ_ACT_ACK_SUSPEND: u32 = 3;
pub const HARQ_ACT_IGNORE: u32 = 4;

/// Per-logical-channel MAC UL configuration (`0x14` = 20 bytes),
/// starting at `MAC_UL_CFG_VA + 0x74` (`0x84d6_2a10`).
///
/// Indexed by `lcid` (`0..=10`): `priority` is at `0x78 + lcid * 0x14` and
/// `lcg_id` is at `0x79 + lcid * 0x14` (`UpdateMacUlBo` `0x842c_d2ce..0x842c_d322`).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct MacUlLcCfg {
    pub _head: u32,
    /// `+0x04` (`+0x78` from `MacUlCfg`): 3GPP logical channel priority (`1..16`, lower = higher priority).
    pub priority: u8,
    /// `+0x05` (`+0x79` from `MacUlCfg`): Assigned Logical Channel Group ID (`0..3`, `>3` = unmapped).
    pub lcg_id: u8,
    pub _rest: [u8; 0x0e],
}

/// Per-LCG buffer occupancy state inside `MacUlBsrCtx` (`8` bytes),
/// starting at `MAC_UL_BSR_CTX_VA + 0x3c` (`0x84d6_297c`).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct MacUlLcgState {
    /// `+0x00` (`+0x3c + lcg*8`): Non-zero when this LCG has pending data.
    pub has_data: u8,
    pub _pad: [u8; 3],
    /// `+0x04` (`+0x40 + lcg*8`): Cached BO bytes for this LCG.
    pub bo_bytes: u32,
}

/// MAC UL BSR dynamic state at `MAC_UL_BSR_CTX_VA` (`0x84d6_2940`, `0x5c` bytes,
/// immediately followed by [`MacUlCfg`] at `0x84d6_299c`).
#[repr(C)]
pub struct MacUlBsrCtx {
    pub _pad0: u8,
    /// `+0x01`: Non-zero when a Regular or Periodic BSR is pending.
    pub bsr_pending: u8,
    /// `+0x02`: Set to `1` when SR was triggered for a pending BSR (`AccessRa`).
    pub sr_triggered_flag: u8,
    pub _pad1: u8,
    /// `+0x04`: BSR trigger bitmask (`0x01` periodic, `0x10` regular, `0x14` retx).
    pub bsr_trigger_mask: u32,
    pub _pad1b: u32,
    /// `+0x0c..+0x37`: Per-LC cached BO array (`lcid 0..=10`, `UpdateMacUlBo`).
    pub lc_bo: [u32; 11],
    /// `+0x38`: Default LCG ID (highest-priority configured LC, typically `0` = SRB).
    pub default_lcg: u8,
    /// `+0x39`: Triggering LCG ID (`0..3`, reset to `4` when bearer buffer drains).
    pub trigger_lcg: u8,
    pub _pad2: u8,
    /// `+0x3b`: Count of LCGs with non-zero data (checked by `ExpireRetxBSRTimer`).
    pub retx_bsr_has_data: u8,
    /// `+0x3c..+0x5b`: Per-LCG state (`[MacUlLcgState; 4]`).
    pub lcg: [MacUlLcgState; 4],
}

/// MAC UL RRC configuration block at `MAC_UL_CFG_VA` (`0x84d6_299c`).
#[repr(C)]
pub struct MacUlCfg {
    /// `+0x00`: Feature bitmask (`bit 1 = 0x02`: UL CA active).
    pub feature_flags: u32,
    pub _pad0: [u8; 0x18],
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
    pub _pad3: [u8; 0x32],
    /// `+0x5d`: Configured `maxHARQ-Tx` (`7` on Nokia bench).
    pub max_harq_tx: u8,
    pub _pad4: [u8; 0x12],
    /// `+0x70`: Bitmask of active logical channels (`rlc_upd_cur_bo`).
    pub active_lc_mask: u32,
    /// `+0x74..+0x14f`: Per-LC configuration table (`11` LCIDs `0..=10`, stride `0x14`).
    pub lc_cfg: [MacUlLcCfg; 11],
    pub _pad5: [u8; 2],
    /// `+0x152`: BSR table selector (`1` = Standard 36.321 Table 6.1.3.1-1, `2` = Extended r10).
    pub ext_bsr_mode: u8,
    pub _pad6: u8,
}

/// Stack frame layout pointed to by `r7` inside `GenerateMacUlPdu` (`0x842d_0248`),
/// inspected by N4 Hook 1 at `0x842d_0914`.
#[repr(C)]
pub struct MacTbBuildFrame {
    pub _pad0: [u8; 48],
    /// `+48` (`+0x30`): Granted transport block size (`tbSize`) in bytes.
    pub tb_size: u32,
    pub _pad1: [u8; 40],
    /// `+92` (`+0x5c`): Bytes actually packed into the TB (MAC subheaders + CEs + SDUs).
    pub used_bytes: u32,
    pub _pad2: [u8; 12],
    /// `+108` (`+0x6c`): Chosen BSR MAC CE LCID (`255` if none yet -> eligible for Padding BSR).
    pub bsr_lcid: u8,
    pub _pad3: [u8; 4],
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

#[inline]
fn bsr_index_in(table: &[u32; 63], bo_bytes: u32) -> u8 {
    if bo_bytes > table[62] {
        return 63;
    }
    let mut lo: usize = 0;
    let mut hi: usize = 62;
    while lo <= hi {
        let mid = (lo + hi) / 2;
        if bo_bytes <= table[mid] {
            if mid == 0 {
                return 0;
            }
            hi = mid - 1;
        } else {
            lo = mid + 1;
        }
    }
    lo as u8
}
