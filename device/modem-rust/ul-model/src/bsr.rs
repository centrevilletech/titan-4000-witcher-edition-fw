//! Exact model of RLC buffer occupancy (`get_rlc_cur_bo` / `rlc_upd_cur_bo`)
//! and 3GPP TS 36.321 BSR index lookup (`SearchMacUlBoIdx`).

use modem_atlas::l2::{RLC_MODE_AM, RLC_MODE_UM};
use modem_atlas::mac::{bsr_index_ext, bsr_index_std};

/// Snapshot of the `Rbc` buffer-occupancy fields read by `get_rlc_cur_bo` (`0x842d_d134`)
/// and `rlc_upd_cur_bo` (`0x842d_d194`).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct BearerBoSnapshot {
    pub rlc_mode: u8,
    pub active: bool,
    pub lcg_id: u8,
    pub rlc_tm_bo: u32,
    pub rlc_status_bo: u16,
    pub rlc_am_newtx_bo: u32,
    pub rlc_am_retx_bo: u32,
    pub pdcp_rlc_hdr_bo: u16,
    pub rlc_reest_hdr_bo: u16,
    pub retx_hdr_bo: u16,
    pub am_extra_hdr_bo: u16,
    pub ring_pending_bytes: u32,
    pub bo_margin_bytes: u32,
}

/// Result of `get_rlc_cur_bo` (`0x842d_d134`): `(data_bo, hdr_bo)`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct RlcCurBo {
    pub data_bo: u32,
    pub hdr_bo: u32,
}

/// Exact behavioural model of `get_rlc_cur_bo` (`0x842d_d134`).
#[inline]
pub const fn get_rlc_cur_bo(s: &BearerBoSnapshot) -> RlcCurBo {
    if s.rlc_mode == RLC_MODE_AM {
        let data_bo = s
            .rlc_am_newtx_bo
            .wrapping_add(s.rlc_am_retx_bo)
            .wrapping_add(s.rlc_status_bo as u32);
        let hdr_bo = (s.pdcp_rlc_hdr_bo as u32)
            .wrapping_add(s.rlc_reest_hdr_bo as u32)
            .wrapping_add(s.retx_hdr_bo as u32)
            .wrapping_add(s.am_extra_hdr_bo as u32);
        RlcCurBo { data_bo, hdr_bo }
    } else if s.rlc_mode == RLC_MODE_UM {
        let data_bo = s.rlc_am_retx_bo;
        let hdr_bo = (s.pdcp_rlc_hdr_bo as u32).wrapping_add(s.rlc_reest_hdr_bo as u32);
        RlcCurBo { data_bo, hdr_bo }
    } else {
        // TM (mode 1) and any other non-AM/UM mode fall through to rlc_tm_bo (+0x140).
        RlcCurBo {
            data_bo: s.rlc_tm_bo,
            hdr_bo: 0,
        }
    }
}

/// Exact behavioural model of `rlc_upd_cur_bo` (`0x842d_d194`) with optional
/// N4 `TRUE_BO` (`+ ring_pending_bytes`) extension.
///
/// Matches stock `0x842d_d194..0x842d_d232` when `include_ring_pending == false`:
/// - Initializes `lcg_bo` from `seed_bo` (`L2_RLC_LCG_SEED_BO_VA`).
/// - For each active bearer:
///   - When `timer_offset_nonzero` (`*(u32*)0x8410_ea00 != 0`):
///     adds `data_bo + hdr_bo + bo_margin_bytes` (plus `ring_pending_bytes` under N4 `TRUE_BO`).
///   - Otherwise: adds `data_bo` only.
pub fn calc_lcg_bo(
    bearers: &[BearerBoSnapshot],
    seed_bo: [u32; 4],
    timer_offset_nonzero: bool,
    include_ring_pending: bool,
) -> [u32; 4] {
    let mut out = seed_bo;
    for b in bearers {
        if !b.active || b.lcg_id >= 4 {
            continue;
        }
        let bo = get_rlc_cur_bo(b);
        let extra = if timer_offset_nonzero {
            let base = bo.hdr_bo.wrapping_add(b.bo_margin_bytes);
            if include_ring_pending {
                base.wrapping_add(b.ring_pending_bytes)
            } else {
                base
            }
        } else {
            0
        };
        let lcg = b.lcg_id as usize;
        out[lcg] = out[lcg].wrapping_add(bo.data_bo).wrapping_add(extra);
    }
    out
}

/// Exact behavioural model of `SearchMacUlBoIdx` (`0x842c_cf64`).
///
/// Maps a byte count to its 6-bit 3GPP TS 36.321 BSR index (`0..=63`),
/// using Table 6.1.3.1-1 (`ext_bsr == false`) or Table 6.1.3.1-2 (`ext_bsr == true`).
#[inline]
pub fn search_bsr_idx(bo: u32, ext_bsr: bool) -> u8 {
    if ext_bsr {
        bsr_index_ext(bo)
    } else {
        bsr_index_std(bo)
    }
}
