//! Pure-Rust `#![no_std]` behavioural model of the Titan 4000 (`tk.bin` V1.6.0.P0)
//! MAC uplink: BSR triggers & reporting, two-carrier PCell-then-SCell TB split,
//! and TDD Config 2 HARQ retransmission timing.
//!
//! Every rule in this module mirrors the disassembled Thumb-2 functions in `tk.bin`
//! and is cross-checked against Unicorn emulation of real `tk.bin` (stock and v1.0.16):
//! - `SearchMacUlBoIdx` (`0x842c_cf64`)
//! - `UpdateMacUlBo` (`0x842c_d298`), `ExpireBSRTimer` (`0x842c_d104`),
//!   `ExpireRetxBSRTimer` (`0x842c_d1ec`), `ResetMacUlBsrEvent` (`0x842c_d254`)
//! - `GetMacUlBsrFormat` (`0x842c_d46c`) & `GetMacUlBsrValue` (`0x842c_d54c`)
//! - `mac_bsr_pre_work` (`0x842d_a60c`), `get_rlc_cur_bo` (`0x842d_d134`),
//!   `rlc_upd_cur_bo` (`0x842d_d194`), `do_bo.isra.0` (`0x8452_c95c`)
//! - `UpdateBj` (`0x842c_fad8`), `AssignScheduleSize2LC` (`0x842c_fd40`),
//!   `SecondStepPBR` (`0x842c_fb34`), `CheckLongBsrDowngradeToShort` (`0x842c_fe34`)
//! - `GenerateMacUlPdu` (`0x842d_0248`), `HandleHarqEntity` (`0x842d_6d68`),
//!   `HandleHarqProc` (`0x842d_5bd4`), `ScheduleUlData` (`0x842d_89ac`)

#![forbid(unsafe_code)]

use crate::mac::{
    bsr_index_ext, bsr_index_std, BSR_TMR_FLAG_PERIODIC, BSR_TMR_FLAG_RETX, BSR_TRIG_PADDING,
    BSR_TRIG_PERIODIC, BSR_TRIG_REGULAR_ARRIVAL, BSR_TRIG_RETX, HARQ_ACT_ACK_SUSPEND,
    HARQ_ACT_ADAPT_RETX, HARQ_ACT_IGNORE, HARQ_ACT_NEW_TX, HARQ_ACT_NON_ADAPT_RETX,
    HARQ_RV_SEQ, HARQ_RV_TO_IDX, HARQ_TDD_CFG2_RTT_MS, MAC_LCG_NONE, MAC_LCID_LONG_BSR,
    MAC_LCID_NONE, MAC_LCID_SHORT_BSR, MAC_LCID_TRUNCATED_BSR, TDD_CFG2_HARQ_ID,
    TDD_CFG2_K_PHICH, TDD_CFG2_K_PUSCH, TDD_CFG2_UL_SF,
};

/// Maximum LCID index supported by `tk.bin` (`0..=10`).
pub const MAX_LCIDS: usize = 11;

/// BSR table format (`MacUlCfg::ext_bsr_mode`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BsrTableMode {
    /// 3GPP TS 36.321 Table 6.1.3.1-1 (`ext_bsr_mode == 1`, max 150,000 B).
    Standard,
    /// 3GPP TS 36.321 Table 6.1.3.1-2 (`ext_bsr_mode == 2`, max 3,000,000 B).
    Extended,
}

impl BsrTableMode {
    #[inline]
    pub fn bo_to_index(self, bo_bytes: u32) -> u8 {
        match self {
            Self::Standard => bsr_index_std(bo_bytes),
            Self::Extended => bsr_index_ext(bo_bytes),
        }
    }
}

/// BSR calculation variant modelled in `rlc_upd_cur_bo` + `GetMacUlBsrValue`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BsrReportingMode {
    /// Stock `tk.bin` V1.6.0.P0:
    /// - `mac_bsr_pre_work` adds raw (unguarded) `rbc.ring_pending_bytes` (1x) for active DRBs;
    /// - `rlc_upd_cur_bo` adds `actual_bo + hdr_bo + bo_margin_bytes` (Ring-0-only `bo_margin`);
    /// - `GetMacUlBsrValue` suffers from the Short-BSR LCG-0 zero bug when `rlc_bo == 0` and
    ///   `packed_lc_mask == 0`.
    Stock,
    /// Witcher v1.0.16 (`N4` `FLAG_TRUE_BO_PDCP`, `0x842d_d21c` + `0x842c_d5f4`):
    /// - `mac_bsr_pre_work` seeds `lcg_bo` with 1x `ring_pending_bytes`;
    /// - N4 Hook 2 adds guarded `ring_pending_bytes` a **second time** (`2x ring_pending_bytes`)
    ///   on non-SRB LCGs (`lcg_id != 0`);
    /// - N4 Hook 2b rescues Short-BSR `r8` to the first non-zero LCG.
    V1016N4TrueBo,
    /// Clean exact guarded reporting (N3 design):
    /// - `mac_bsr_pre_work` adds guarded `1x ring_pending_bytes` (0 if rings & LLCE0 are empty);
    /// - `rlc_upd_cur_bo` adds `actual_bo + hdr_bo + bo_margin_bytes` (no double count);
    /// - Short-BSR LCG rescue fixes the LCG-0 zero bug.
    N3GuardedExact,
}

/// Per-LC static configuration (mirrors `MacUlCfg::lc_cfg[lcid]`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct LcConfig {
    pub active: bool,
    /// `0` = DRB, `1` = MRB, `2` = SRB (`Rbc::rb_type` at `+0x30`).
    pub rb_type: u8,
    /// 3GPP logical channel priority (`1..=16`, lower = higher priority).
    pub priority: u8,
    /// Logical Channel Group (`0..=3`).
    pub lcg_id: u8,
    /// Prioritised Bit Rate increment per TTI (`MacUlLcCfg::pbr_bytes_per_tti`).
    pub pbr_bytes_per_tti: u32,
    /// Token bucket upper bound (`MacUlLcPbr::bj_max`).
    pub bj_max: u32,
}

impl Default for LcConfig {
    fn default() -> Self {
        Self {
            active: false,
            rb_type: 0,
            priority: 16,
            lcg_id: MAC_LCG_NONE,
            pbr_bytes_per_tti: 0,
            bj_max: 0,
        }
    }
}

/// Live per-bearer queue snapshot (Ring 0, Ring 1, PDCP/RLC, `bo_margin`).
#[derive(Copy, Clone, Default, Debug, PartialEq, Eq)]
pub struct BearerQueue {
    /// Bytes waiting in Ring 0 + Ring 1 + in-flight LLCE0 (`Rbc::ring_pending_bytes`, `+0x130`).
    pub ring_pending_bytes: u32,
    /// True when Ring 0, Ring 1, or LLCE0 actually holds at least one packet/batch.
    pub rings_or_cipher_nonempty: bool,
    /// Ciphered RLC AM new-TX payload bytes (`Rbc::rlc_newtx_bo`, `+0x158`).
    pub rlc_newtx_bo: u32,
    /// RLC AM retransmission payload bytes (`Rbc::rlc_retx_bo`, `+0x154`).
    pub rlc_retx_bo: u32,
    /// RLC AM STATUS PDU bytes (`Rbc::rlc_status_bo`, `+0x144`).
    pub rlc_status_bo: u16,
    /// Sum of RLC/PDCP header BO terms (`pdcp_rlc_hdr_bo + rlc_um_hdr_bo + retx_hdr_bo + am_extra_hdr_bo`).
    pub hdr_bo: u32,
    /// Active per-bearer `bo_margin` hold (`Rbc::bo_margin_bytes`, `+0x244`).
    pub bo_margin_bytes: u32,
    /// Last TTI Ring 0 drained (`Rbc::ring0_last_tx_cnt`, `+0xd4`).
    pub ring0_last_tx_tti: u32,
    /// Last TTI observed by `do_bo.isra.0` (`Rbc::bo_hold_last_cnt`, `+0x240`).
    pub bo_hold_last_cnt: u32,
}

impl BearerQueue {
    /// Exact mirror of `get_rlc_cur_bo` (`0x842d_d134`) for RLC AM (`rlc_mode == 3`).
    #[inline]
    pub fn rlc_actual_bo(&self) -> u32 {
        self.rlc_retx_bo
            .wrapping_add(self.rlc_newtx_bo)
            .wrapping_add(self.rlc_status_bo as u32)
    }

    /// True physical backlog waiting for the air interface (Ring 0/1 + LLCE0 + RLC).
    #[inline]
    pub fn true_backlog_bytes(&self) -> u32 {
        let ring = if self.rings_or_cipher_nonempty {
            self.ring_pending_bytes
        } else {
            0
        };
        ring.saturating_add(self.rlc_actual_bo())
            .saturating_add(self.hdr_bo)
    }

    /// Stock `l2_proc_pdcp_ul` (`0x842d_ccf8..0x842d_cd88`) Ring-0-only `bo_margin` arming.
    pub fn on_ring0_drain(&mut self, now_tti: u32, global_bo_margin: u32) {
        self.ring0_last_tx_tti = now_tti;
        if global_bo_margin != 0 {
            self.bo_margin_bytes = global_bo_margin;
        }
        if self.bo_hold_last_cnt == 0 {
            self.bo_hold_last_cnt = now_tti.wrapping_sub(1);
        }
    }

    /// Exact mirror of stock `do_bo.isra.0` (`0x8452_c95c`, called every 250 ms by `do_tc`).
    ///
    /// Ring-1 traffic never updates `ring0_last_tx_tti`, so pure Ring-1 flows always expire to `0`.
    pub fn do_bo_tick_stock(&mut self, global_bo_margin: u32) {
        if self.ring0_last_tx_tti != 0 && self.ring0_last_tx_tti > self.bo_hold_last_cnt {
            self.bo_hold_last_cnt = self.ring0_last_tx_tti;
            self.bo_margin_bytes = global_bo_margin;
        } else {
            self.bo_margin_bytes = 0;
        }
    }
}

/// Encoded BSR MAC Control Element produced by `GetMacUlBsrValue` (`0x842c_d54c`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EncodedBsrCe {
    None,
    /// Short (`lcid=29`) or Truncated (`lcid=28`) BSR: 1-byte payload `(lcg << 6) | idx`.
    Short {
        lcid: u8,
        lcg: u8,
        idx: u8,
        ce_word: u32,
    },
    /// Long (`lcid=30`) BSR: 3-byte payload packed into upper 24 bits of `ce_word`.
    Long {
        idx: [u8; 4],
        ce_word: u32,
    },
}

/// Complete MAC UL BSR + LCP behavioural model.
#[derive(Clone, Debug)]
pub struct MacUlModel {
    pub lc_cfg: [LcConfig; MAX_LCIDS],
    pub bsr_table_mode: BsrTableMode,
    pub bsr_timer_flags: u16,
    /// Mirrors `DP_BSR_FIX_BOI_VA` (`0x84b2_6619`): `0` = off, `1..=63` = minimum BSR index.
    pub fix_boi: u8,
    /// Mirrors `L2_TIMER_OFFSET_VA` (`0x8410_ea00`): non-zero at boot enables `hdr_bo + bo_margin`.
    pub include_hdr_and_margin: bool,

    // `MacUlBsrCtx` dynamic fields (`0x84d6_2940`)
    pub bsr_sent_in_tb: bool,
    pub bsr_pending: bool,
    pub sr_triggered: bool,
    pub bsr_trigger_mask: u32,
    pub highest_prio_with_data: u8,
    pub lc_bo: [u32; MAX_LCIDS],
    pub default_lcg: u8,
    pub trigger_lcg: u8,
    pub active_lcg_cnt: u8,
    pub lcg_bo_cached: [u32; 4],

    // `MacUlLcpTbl` dynamic fields (`0x84d6_2c70`)
    pub total_bo: u32,
    pub sched_bo: [u32; MAX_LCIDS],
    pub raw_bo: [u32; MAX_LCIDS],
    pub bj: [i32; MAX_LCIDS],
    pub prio_rr_cursor: [u8; 16],

    // `L2_BSR_PRE_BO_VA` (`0x84dd_9d18`)
    pub lcg_pre_bo: [u32; 4],
}

impl Default for MacUlModel {
    fn default() -> Self {
        Self::new()
    }
}

impl MacUlModel {
    /// Mirrors `InitMacUlBsrInfo` (`0x842c_cff8`).
    pub fn new() -> Self {
        Self {
            lc_cfg: [LcConfig::default(); MAX_LCIDS],
            bsr_table_mode: BsrTableMode::Standard,
            bsr_timer_flags: BSR_TMR_FLAG_PERIODIC | BSR_TMR_FLAG_RETX,
            fix_boi: 0,
            include_hdr_and_margin: true,
            bsr_sent_in_tb: false,
            bsr_pending: false,
            sr_triggered: false,
            bsr_trigger_mask: 0,
            highest_prio_with_data: 0xff,
            lc_bo: [0; MAX_LCIDS],
            default_lcg: MAC_LCG_NONE,
            trigger_lcg: MAC_LCG_NONE,
            active_lcg_cnt: 0,
            lcg_bo_cached: [0; 4],
            total_bo: 0,
            sched_bo: [0; MAX_LCIDS],
            raw_bo: [0; MAX_LCIDS],
            bj: [0; MAX_LCIDS],
            prio_rr_cursor: [0; 16],
            lcg_pre_bo: [0; 4],
        }
    }

    /// Configure one logical channel (`lcid 0..=10`).
    pub fn configure_lc(&mut self, lcid: usize, cfg: LcConfig) {
        if lcid < MAX_LCIDS {
            self.lc_cfg[lcid] = cfg;
        }
    }

    /// Exact mirror of `ResetMacUlBsrEvent` (`0x842c_d254`).
    pub fn reset_bsr_event(&mut self) {
        self.bsr_pending = false;
        self.sr_triggered = false;
        self.bsr_trigger_mask = 0;
    }

    /// Exact mirror of `ExpireBSRTimer` (`0x842c_d104`).
    pub fn expire_periodic_bsr(&mut self) {
        if (self.bsr_timer_flags & BSR_TMR_FLAG_PERIODIC) == 0 {
            return;
        }
        if !self.bsr_pending {
            self.bsr_pending = true;
            self.bsr_trigger_mask = BSR_TRIG_PERIODIC;
        }
    }

    /// Exact mirror of `ExpireRetxBSRTimer` (`0x842c_d1ec`).
    pub fn expire_retx_bsr(&mut self) {
        if (self.bsr_timer_flags & BSR_TMR_FLAG_RETX) == 0 {
            return;
        }
        if self.active_lcg_cnt != 0 {
            self.bsr_pending = true;
            self.bsr_trigger_mask = BSR_TRIG_RETX;
        }
    }

    /// Exact mirror of `UpdateMacUlBo(lcid, new_bo, hdr_bo)` (`0x842c_d298`).
    ///
    /// Note: `upd_lcid_bo_to_mac` feeds ONLY RLC BO (`get_rlc_cur_bo`), never `ring_pending_bytes`.
    pub fn update_bo(&mut self, lcid: usize, new_bo: u32, hdr_bo: u32) {
        if lcid >= MAX_LCIDS || !self.lc_cfg[lcid].active {
            return;
        }
        let cfg = self.lc_cfg[lcid];
        let old_bo = self.lc_bo[lcid];
        self.lc_bo[lcid] = new_bo;
        self.total_bo = self.total_bo.wrapping_sub(old_bo).wrapping_add(new_bo);
        self.raw_bo[lcid] = new_bo;
        self.sched_bo[lcid] = if new_bo == 0 {
            0
        } else {
            new_bo.wrapping_add(hdr_bo).wrapping_add(2)
        };

        let lcg = cfg.lcg_id as usize;
        if lcg < 4 {
            let prev_lcg = self.lcg_bo_cached[lcg];
            let next_lcg = prev_lcg.wrapping_sub(old_bo).wrapping_add(new_bo);
            self.lcg_bo_cached[lcg] = next_lcg;
            if prev_lcg == 0 && next_lcg != 0 {
                self.active_lcg_cnt = self.active_lcg_cnt.saturating_add(1);
            } else if prev_lcg != 0 && next_lcg == 0 {
                self.active_lcg_cnt = self.active_lcg_cnt.saturating_sub(1);
            }
        }

        if new_bo > 0 {
            if cfg.priority < self.highest_prio_with_data {
                self.highest_prio_with_data = cfg.priority;
                self.trigger_lcg = cfg.lcg_id;
                self.bsr_pending = true;
                self.bsr_trigger_mask = BSR_TRIG_REGULAR_ARRIVAL;
            }
        } else if old_bo > 0 && cfg.priority == self.highest_prio_with_data {
            // Recompute highest priority and trigger_lcg across all active LCs with BO > 0.
            let mut best_prio = 0xffu8;
            let mut best_lcg = MAC_LCG_NONE;
            for id in 0..MAX_LCIDS {
                if self.lc_cfg[id].active && self.lc_bo[id] > 0 && self.lc_cfg[id].priority < best_prio
                {
                    best_prio = self.lc_cfg[id].priority;
                    best_lcg = self.lc_cfg[id].lcg_id;
                }
            }
            self.highest_prio_with_data = best_prio;
            self.trigger_lcg = best_lcg;
        }
    }

    /// Exact mirror of `GetMacUlBsrFormat` (`0x842c_d46c`).
    ///
    /// `bsr_kind`: `0` = Regular/Periodic, `1` = Padding.
    pub fn select_bsr_format(
        &mut self,
        bsr_kind: u32,
        tb_size: u32,
        used_bytes: u32,
        deferred_bsr_flag: bool,
    ) -> u8 {
        let avail = (tb_size as i32) - (used_bytes as i32) - 1;
        if avail <= 0 {
            return MAC_LCID_NONE;
        }
        match bsr_kind {
            0 => {
                if !self.bsr_pending {
                    return MAC_LCID_NONE;
                }
                if self.active_lcg_cnt <= 1 {
                    MAC_LCID_SHORT_BSR
                } else if avail > 2 {
                    MAC_LCID_LONG_BSR
                } else {
                    self.reset_bsr_event();
                    MAC_LCID_NONE
                }
            }
            1 => {
                if !deferred_bsr_flag && self.bsr_pending {
                    return MAC_LCID_NONE;
                }
                if avail > 2 {
                    MAC_LCID_LONG_BSR
                } else if self.active_lcg_cnt < 2 {
                    MAC_LCID_SHORT_BSR
                } else {
                    MAC_LCID_TRUNCATED_BSR
                }
            }
            _ => MAC_LCID_NONE,
        }
    }

    /// Exact mirror of `mac_bsr_pre_work` (`0x842d_a60c`) with optional N3 empty-ring guard.
    pub fn mac_bsr_pre_work(&mut self, queues: &[BearerQueue; MAX_LCIDS], guarded: bool) {
        self.lcg_pre_bo = [0; 4];
        for (lcid, &q) in queues.iter().enumerate() {
            let cfg = self.lc_cfg[lcid];
            if !cfg.active || cfg.rb_type != 0 || cfg.lcg_id >= 4 {
                continue;
            }
            let pending = if guarded && !q.rings_or_cipher_nonempty {
                0
            } else {
                q.ring_pending_bytes
            };
            self.lcg_pre_bo[cfg.lcg_id as usize] =
                self.lcg_pre_bo[cfg.lcg_id as usize].wrapping_add(pending);
        }
    }

    /// Exact mirror of `rlc_upd_cur_bo` (`0x842d_d194`) across Stock, v1.0.16 N4, and N3 modes.
    pub fn compute_lcg_bo(
        &self,
        queues: &[BearerQueue; MAX_LCIDS],
        mode: BsrReportingMode,
    ) -> [u32; 4] {
        let mut lcg_bo = self.lcg_pre_bo;
        for (lcid, &q) in queues.iter().enumerate() {
            let cfg = self.lc_cfg[lcid];
            if !cfg.active || cfg.lcg_id >= 4 {
                continue;
            }
            let actual = q.rlc_actual_bo();
            let mut extra = 0u32;
            if self.include_hdr_and_margin {
                let mut marg = q.bo_margin_bytes;
                // In v1.0.16 N4 (`FLAG_TRUE_BO_PDCP`), Hook 2 at 0x842d_d21c adds guarded
                // `ring_pending_bytes` on non-SRB LCGs ON TOP OF `lcg_pre_bo` -> 2x Ring-1!
                if mode == BsrReportingMode::V1016N4TrueBo
                    && cfg.lcg_id != 0
                    && q.rings_or_cipher_nonempty
                {
                    marg = marg.wrapping_add(q.ring_pending_bytes);
                }
                extra = marg.wrapping_add(q.hdr_bo);
            }
            let idx = cfg.lcg_id as usize;
            lcg_bo[idx] = lcg_bo[idx].wrapping_add(actual).wrapping_add(extra);
        }
        lcg_bo
    }

    /// Exact mirror of `GetMacUlBsrValue` (`0x842c_d54c`) + N4 Hook 2b (`0x842c_d5f4`).
    pub fn build_bsr_ce(
        &mut self,
        bsr_lcid: u8,
        packed_lc_mask: u32,
        queues: &[BearerQueue; MAX_LCIDS],
        mode: BsrReportingMode,
    ) -> ([u32; 4], EncodedBsrCe) {
        let lcg_bo = self.compute_lcg_bo(queues, mode);
        let apply_floor = |mut idx: u8| -> u8 {
            if self.fix_boi != 0 {
                let floor = if self.fix_boi > 63 { 63 } else { self.fix_boi };
                if idx < floor {
                    idx = floor;
                }
            }
            idx
        };

        let ce = match bsr_lcid {
            MAC_LCID_TRUNCATED_BSR | MAC_LCID_SHORT_BSR => {
                let mut sel = if self.trigger_lcg == MAC_LCG_NONE {
                    self.default_lcg
                } else {
                    self.trigger_lcg
                };
                if sel < 4 && self.lcg_bo_cached[sel as usize] == 0 && packed_lc_mask != 0 {
                    // Scan `packed_lc_mask` for highest-priority LC (lowest numeric priority).
                    let mut best_prio = 16u8;
                    for lcid in 0..MAX_LCIDS {
                        if (packed_lc_mask & (1u32 << lcid)) != 0
                            && self.lc_cfg[lcid].priority < best_prio
                        {
                            best_prio = self.lc_cfg[lcid].priority;
                            sel = self.lc_cfg[lcid].lcg_id;
                        }
                    }
                }
                // Short-BSR LCG rescue (N4 Hook 2b / N3): if selected LCG is 0 while another has data.
                if mode != BsrReportingMode::Stock
                    && (sel >= 4 || lcg_bo[sel as usize] == 0)
                {
                    for (i, &bo) in lcg_bo.iter().enumerate() {
                        if bo != 0 {
                            sel = i as u8;
                            break;
                        }
                    }
                }
                let bo = if sel < 4 { lcg_bo[sel as usize] } else { 0 };
                let idx = apply_floor(self.bsr_table_mode.bo_to_index(bo));
                let ce_word = ((sel as u32) << 30) | ((idx as u32) << 24);
                EncodedBsrCe::Short {
                    lcid: bsr_lcid,
                    lcg: sel,
                    idx,
                    ce_word,
                }
            }
            MAC_LCID_LONG_BSR => {
                let mut idxs = [0u8; 4];
                for i in 0..4 {
                    idxs[i] = apply_floor(self.bsr_table_mode.bo_to_index(lcg_bo[i]));
                }
                let ce_word = ((idxs[0] as u32) << 26)
                    | ((idxs[1] as u32) << 20)
                    | ((idxs[2] as u32) << 14)
                    | ((idxs[3] as u32) << 8);
                EncodedBsrCe::Long { idx: idxs, ce_word }
            }
            _ => EncodedBsrCe::None,
        };

        if !matches!(ce, EncodedBsrCe::None) {
            self.reset_bsr_event();
            self.bsr_sent_in_tb = true;
        }
        (lcg_bo, ce)
    }

    /// Exact mirror of `UpdateBj(tti_delta)` (`0x842c_fad8`), invoked ONCE per TTI before PCell & SCell.
    pub fn update_bj(&mut self, tti_delta: u32) {
        for lcid in 0..MAX_LCIDS {
            let cfg = self.lc_cfg[lcid];
            if !cfg.active {
                continue;
            }
            let inc = cfg.pbr_bytes_per_tti.wrapping_mul(tti_delta) as i32;
            let next = self.bj[lcid].saturating_add(inc);
            let cap = cfg.bj_max as i32;
            self.bj[lcid] = if next > cap { cap } else { next };
        }
    }

    /// Exact mirror of `AssignScheduleSize2LC` (`0x842c_fd40`) + `SecondStepPBR` (`0x842c_fb34`).
    ///
    /// Mutates `self.sched_bo` and `self.bj` in place — identical to stock `tk.bin`, where
    /// PCell and SCell share the single global `MacUlLcpTbl` (`0x84d6_2c70`).
    pub fn assign_lcp_bytes(&mut self, tb_rem: u32) -> ([u32; MAX_LCIDS], u32) {
        let mut alloc = [0u32; MAX_LCIDS];
        let mut rem = tb_rem;

        // Pass 1: PBR allocation (`bj > 0`), high-to-low priority (`1..=16`).
        for prio in 1u8..=16u8 {
            if rem == 0 {
                break;
            }
            let rr = self.prio_rr_cursor[(prio - 1) as usize] as usize;
            let mut submasks = [0u32; 2];
            let mut full_mask = 0u32;
            for lcid in 0..MAX_LCIDS {
                if self.lc_cfg[lcid].active && self.lc_cfg[lcid].priority == prio {
                    full_mask |= 1u32 << lcid;
                }
            }
            if full_mask == 0 {
                continue;
            }
            if rr == 0 {
                submasks[0] = full_mask;
            } else {
                let lo_mask = (1u32 << rr) - 1;
                submasks[0] = full_mask & lo_mask;
                submasks[1] = full_mask & !lo_mask;
            }
            for mut m in submasks {
                while m != 0 && rem > 0 {
                    let lcid = (31 - m.leading_zeros()) as usize;
                    m &= !(1u32 << lcid);
                    let sbo = self.sched_bo[lcid];
                    let bj = self.bj[lcid];
                    if sbo == 0 || bj <= 0 {
                        continue;
                    }
                    let take = (bj as u32).min(sbo).min(rem);
                    alloc[lcid] += take;
                    rem -= take;
                    self.sched_bo[lcid] -= take;
                    self.bj[lcid] -= take as i32;
                }
            }
        }

        // Pass 2 (`SecondStepPBR` `0x842c_fb34`): distribute remaining bytes by priority.
        if rem > 0 {
            for prio in 1u8..=16u8 {
                if rem == 0 {
                    break;
                }
                let mut mask = 0u32;
                let mut group_bo = 0u32;
                for lcid in 0..MAX_LCIDS {
                    if self.lc_cfg[lcid].active
                        && self.lc_cfg[lcid].priority == prio
                        && self.sched_bo[lcid] > 0
                    {
                        mask |= 1u32 << lcid;
                        group_bo = group_bo.saturating_add(self.sched_bo[lcid]);
                    }
                }
                if group_bo == 0 {
                    continue;
                }
                if group_bo <= rem {
                    let mut m = mask;
                    while m != 0 {
                        let lcid = (31 - m.leading_zeros()) as usize;
                        m &= !(1u32 << lcid);
                        let take = self.sched_bo[lcid];
                        alloc[lcid] += take;
                        self.sched_bo[lcid] = 0;
                    }
                    rem -= group_bo;
                } else {
                    // Equal water-filling across LCs with `sched_bo > 0` at this priority.
                    let mut active_cnt = mask.count_ones();
                    while active_cnt > 0 && rem > 0 {
                        if active_cnt == 1 {
                            let lcid = (31 - mask.leading_zeros()) as usize;
                            alloc[lcid] += rem;
                            self.sched_bo[lcid] -= rem;
                            rem = 0;
                            break;
                        }
                        let share = rem / active_cnt;
                        if share == 0 {
                            let mut m = mask;
                            while m != 0 && rem > 0 {
                                let lcid = (31 - m.leading_zeros()) as usize;
                                m &= !(1u32 << lcid);
                                if self.sched_bo[lcid] > 0 {
                                    alloc[lcid] += 1;
                                    self.sched_bo[lcid] -= 1;
                                    rem -= 1;
                                }
                            }
                            break;
                        }
                        let mut m = mask;
                        while m != 0 {
                            let lcid = (31 - m.leading_zeros()) as usize;
                            m &= !(1u32 << lcid);
                            let sbo = self.sched_bo[lcid];
                            if sbo == 0 {
                                continue;
                            }
                            if share < sbo {
                                alloc[lcid] += share;
                                self.sched_bo[lcid] -= share;
                                rem -= share;
                            } else {
                                alloc[lcid] += sbo;
                                self.sched_bo[lcid] = 0;
                                rem -= sbo;
                                mask &= !(1u32 << lcid);
                                active_cnt -= 1;
                            }
                        }
                    }
                }
            }
        }

        (alloc, rem)
    }

    /// O(1) sound early-exit proof for `CheckLongBsrDowngradeToShort` (`0x842c_fe34`).
    ///
    /// Returns `Some(false)` when at least two LCGs each hold strictly more than `tb_rem`
    /// raw RLC bytes (making it mathematically impossible for this TB to leave <= 1 non-empty
    /// LCG), `Some(true)` when `<= 1` LCG has data, and `None` when the full simulation is needed.
    #[inline]
    pub fn check_long_bsr_downgrade_fast(&self, tb_rem: u32) -> Option<bool> {
        if self.active_lcg_cnt <= 1 {
            return Some(true);
        }
        let mut unemptiable = 0u32;
        for &bo in &self.lcg_bo_cached {
            if bo > tb_rem {
                unemptiable += 1;
            }
        }
        if unemptiable >= 2 {
            return Some(false);
        }
        None
    }

    /// Simulate one complete 1CC or 2CC UL TTI (`ScheduleUlData`: PCell first, SCell second).
    ///
    /// Models:
    /// 1. `mac_bsr_pre_work` (at TTI entry);
    /// 2. `UpdateBj(tti_delta)` ONCE for the TTI;
    /// 3. `pending_newtx_cnt = (pcell_tb > 0) + (scell_tb > 0)` (defers Regular/Periodic BSR
    ///    from PCell to SCell when both carriers have NewTx grants!);
    /// 4. PCell TB build -> RLC drain -> `UpdateMacUlBo` -> optional Padding BSR;
    /// 5. SCell TB build -> RLC drain -> `UpdateMacUlBo` -> final post-(PCell+SCell) BSR!
    pub fn step_tti(
        &mut self,
        pcell_tb: u32,
        scell_tb: u32,
        tti_delta: u32,
        queues: &mut [BearerQueue; MAX_LCIDS],
        mode: BsrReportingMode,
    ) -> TwoCarrierTtiOutcome {
        self.mac_bsr_pre_work(queues, mode == BsrReportingMode::N3GuardedExact);
        self.update_bj(tti_delta);

        let mut pending_newtx = u8::from(pcell_tb > 0) + u8::from(scell_tb > 0);
        let pcell = if pcell_tb > 0 {
            pending_newtx -= 1;
            self.build_one_tb(pcell_tb, pending_newtx, queues, mode)
        } else {
            TbOutcome::empty()
        };
        let scell = if scell_tb > 0 {
            pending_newtx -= 1;
            self.build_one_tb(scell_tb, pending_newtx, queues, mode)
        } else {
            TbOutcome::empty()
        };

        TwoCarrierTtiOutcome { pcell, scell }
    }

    fn build_one_tb(
        &mut self,
        tb_size: u32,
        remaining_newtx_after_this: u8,
        queues: &mut [BearerQueue; MAX_LCIDS],
        mode: BsrReportingMode,
    ) -> TbOutcome {
        let mut used = 0u32;
        let mut deferred_bsr_flag = false;
        let mut bsr_lcid = MAC_LCID_NONE;

        // Mirrors `GenerateMacUlPdu` (`0x842d_03de..0x842d_0400`):
        // If another NewTx CC follows in this TTI (`pending_newtx_cnt != 0`), defer Reg/Per BSR!
        if remaining_newtx_after_this != 0 {
            if self.bsr_pending {
                deferred_bsr_flag = true;
            }
        } else {
            bsr_lcid = self.select_bsr_format(0, tb_size, used, false);
            if bsr_lcid == MAC_LCID_SHORT_BSR {
                used += 2;
            } else if bsr_lcid == MAC_LCID_LONG_BSR {
                used += 4;
            }
        }

        let rem_for_data = tb_size.saturating_sub(used);
        let (alloc, _rem_after_lcp) = self.assign_lcp_bytes(rem_for_data);
        let mut packed_lc_mask = 0u32;
        let mut data_packed = 0u32;

        // Drain RLC payload per LC and update `MacUlBsrCtx` (`upd_lcid_bo_to_mac`).
        for lcid in 0..MAX_LCIDS {
            let take = alloc[lcid];
            if take == 0 {
                continue;
            }
            packed_lc_mask |= 1u32 << lcid;
            data_packed += take;

            // Approximate RLC payload drain: 2-byte MAC subheader + RLC/PDCP overhead absorbed.
            let q = &mut queues[lcid];
            let mut budget = take.saturating_sub(2);
            let status_take = budget.min(q.rlc_status_bo as u32);
            q.rlc_status_bo -= status_take as u16;
            budget -= status_take;
            let retx_take = budget.min(q.rlc_retx_bo);
            q.rlc_retx_bo -= retx_take;
            budget -= retx_take;
            let newtx_take = budget.min(q.rlc_newtx_bo);
            q.rlc_newtx_bo -= newtx_take;
            if q.rlc_actual_bo() == 0 {
                q.hdr_bo = 0;
            }
            self.update_bo(lcid, q.rlc_actual_bo(), q.hdr_bo);
        }

        used += data_packed;

        // If no Regular/Periodic BSR was reserved and `>= 2` trailing padding bytes remain,
        // emit a Padding BSR (`GenerateMacUlPdu` `0x842d_0ebc..0x842d_0f5e`).
        let mut is_padding_bsr = false;
        if bsr_lcid == MAC_LCID_NONE && tb_size.saturating_sub(used) >= 2 {
            let pad_lcid = self.select_bsr_format(1, tb_size, used, deferred_bsr_flag);
            if pad_lcid != MAC_LCID_NONE {
                bsr_lcid = pad_lcid;
                is_padding_bsr = true;
                used += if pad_lcid == MAC_LCID_LONG_BSR { 4 } else { 2 };
                self.bsr_trigger_mask = BSR_TRIG_PADDING;
            }
        }

        let padding_bytes = tb_size.saturating_sub(used);
        let (lcg_bo_reported, bsr_ce) = if bsr_lcid != MAC_LCID_NONE {
            self.build_bsr_ce(bsr_lcid, packed_lc_mask, queues, mode)
        } else {
            ([0; 4], EncodedBsrCe::None)
        };

        TbOutcome {
            tb_size,
            used_bytes: used,
            padding_bytes,
            lc_alloc: alloc,
            packed_lc_mask,
            deferred_bsr_flag,
            is_padding_bsr,
            lcg_bo_reported,
            bsr_ce,
        }
    }
}

/// Output for one carrier's TB in [`TwoCarrierTtiOutcome`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TbOutcome {
    pub tb_size: u32,
    pub used_bytes: u32,
    pub padding_bytes: u32,
    pub lc_alloc: [u32; MAX_LCIDS],
    pub packed_lc_mask: u32,
    pub deferred_bsr_flag: bool,
    pub is_padding_bsr: bool,
    pub lcg_bo_reported: [u32; 4],
    pub bsr_ce: EncodedBsrCe,
}

impl TbOutcome {
    pub const fn empty() -> Self {
        Self {
            tb_size: 0,
            used_bytes: 0,
            padding_bytes: 0,
            lc_alloc: [0; MAX_LCIDS],
            packed_lc_mask: 0,
            deferred_bsr_flag: false,
            is_padding_bsr: false,
            lcg_bo_reported: [0; 4],
            bsr_ce: EncodedBsrCe::None,
        }
    }
}

/// Combined PCell + SCell output of one TTI in [`MacUlModel::step_tti`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TwoCarrierTtiOutcome {
    pub pcell: TbOutcome,
    pub scell: TbOutcome,
}

/// Per-CC UL HARQ state machine for TDD Config 2 (`SF 2` -> `hq_id 0`, `SF 7` -> `hq_id 1`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TddCfg2HarqProc {
    pub active: bool,
    pub harq_feedback_ack: bool,
    pub prev_ndi: u8,
    pub current_tx_nb: u8,
    pub max_harq_tx: u8,
    pub rv_idx: u8,
    pub rv: u8,
    pub last_tx_tti: u32,
}

impl TddCfg2HarqProc {
    pub const fn empty(max_harq_tx: u8) -> Self {
        Self {
            active: false,
            harq_feedback_ack: false,
            prev_ndi: 0,
            current_tx_nb: 0xff,
            max_harq_tx,
            rv_idx: 0xff,
            rv: 0xff,
            last_tx_tti: 0,
        }
    }
}

/// Event produced when evaluating one subframe in [`TddCfg2HarqEntity`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HarqStepResult {
    pub pusch_tti: u32,
    pub hq_id: u8,
    pub action: u32,
    pub tx_nb: u8,
    pub rv: u8,
    pub flushed: bool,
}

/// TDD Config 2 UL HARQ timing model (1 CC = 2 HARQ processes, 10 ms RTT).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TddCfg2HarqEntity {
    pub procs: [TddCfg2HarqProc; 2],
}

impl TddCfg2HarqEntity {
    pub const fn new(max_harq_tx: u8) -> Self {
        Self {
            procs: [
                TddCfg2HarqProc::empty(max_harq_tx),
                TddCfg2HarqProc::empty(max_harq_tx),
            ],
        }
    }

    /// Return the PUSCH TTI scheduled by a DCI-0 / PHICH arriving in `dl_tti` (TDD Config 2).
    /// Returns `None` on subframes without a UL grant/PHICH occasion (anything other than SF 3 or SF 8).
    #[inline]
    pub const fn pusch_tti_for_dl_tti(dl_tti: u32) -> Option<(u32, u8)> {
        let sf = (dl_tti % 10) as usize;
        let k = TDD_CFG2_K_PUSCH[sf];
        if k == 0 {
            return None;
        }
        let pusch_tti = dl_tti + (k as u32);
        let hq_id = TDD_CFG2_HARQ_ID[(pusch_tti % 10) as usize];
        Some((pusch_tti, hq_id))
    }

    /// Return the PHICH TTI carrying ACK/NACK for a PUSCH transmitted in `pusch_tti` (TDD Config 2).
    #[inline]
    pub const fn phich_tti_for_pusch_tti(pusch_tti: u32) -> Option<u32> {
        let sf = (pusch_tti % 10) as usize;
        if TDD_CFG2_UL_SF[sf] == 0 {
            return None;
        }
        Some(pusch_tti + (TDD_CFG2_K_PHICH[sf] as u32))
    }

    /// Process DCI-0 / PHICH arriving in `dl_tti` and advance the corresponding HARQ process.
    ///
    /// Mirrors `HandleHarqEntity` (`0x842d_6d68`) + `HandleHarqProc` (`0x842d_5bd4`):
    /// - `dci_grant = Some((ndi, mcs))`: toggled NDI -> NewTx (`tx_nb = 0, rv = 0`);
    ///   unchanged NDI -> Adaptive Retx (MCS 29..31 selects RV 1..3, else RV 0).
    /// - `dci_grant = None`, `phich_ack = Some(true)` -> ACK suspend (`HARQ_ACT_ACK_SUSPEND`).
    /// - `dci_grant = None`, `phich_ack = Some(false)` -> Non-Adaptive Retx cycling RV `[0, 2, 3, 1]`
    ///   until `current_tx_nb >= max_harq_tx` (flush via `ClearMacUlBuffer`).
    pub fn on_dl_sf(
        &mut self,
        dl_tti: u32,
        dci_grant: Option<(u8, u8)>,
        phich_ack: Option<bool>,
    ) -> Option<HarqStepResult> {
        let (pusch_tti, hq_id) = Self::pusch_tti_for_dl_tti(dl_tti)?;
        let p = &mut self.procs[hq_id as usize];

        if let Some((ndi, mcs)) = dci_grant {
            let is_new_tx = !p.active || ndi != p.prev_ndi;
            if is_new_tx {
                p.active = true;
                p.harq_feedback_ack = false;
                p.prev_ndi = ndi;
                p.current_tx_nb = 0;
                let rv = if (29..=31).contains(&mcs) { mcs - 28 } else { 0 };
                p.rv = rv;
                p.rv_idx = HARQ_RV_TO_IDX[rv as usize];
                p.last_tx_tti = pusch_tti;
                return Some(HarqStepResult {
                    pusch_tti,
                    hq_id,
                    action: HARQ_ACT_NEW_TX,
                    tx_nb: 0,
                    rv,
                    flushed: false,
                });
            }
            // Adaptive retransmission
            p.current_tx_nb = p.current_tx_nb.wrapping_add(1);
            if p.current_tx_nb >= p.max_harq_tx {
                *p = TddCfg2HarqProc::empty(p.max_harq_tx);
                return Some(HarqStepResult {
                    pusch_tti,
                    hq_id,
                    action: HARQ_ACT_IGNORE,
                    tx_nb: 0xff,
                    rv: 0xff,
                    flushed: true,
                });
            }
            let rv = if (29..=31).contains(&mcs) { mcs - 28 } else { 0 };
            p.rv = rv;
            p.rv_idx = HARQ_RV_TO_IDX[rv as usize];
            p.harq_feedback_ack = false;
            p.last_tx_tti = pusch_tti;
            return Some(HarqStepResult {
                pusch_tti,
                hq_id,
                action: HARQ_ACT_ADAPT_RETX,
                tx_nb: p.current_tx_nb,
                rv,
                flushed: false,
            });
        }

        // No DCI-0 grant -> check PHICH
        if !p.active {
            return Some(HarqStepResult {
                pusch_tti,
                hq_id,
                action: HARQ_ACT_IGNORE,
                tx_nb: 0xff,
                rv: 0xff,
                flushed: false,
            });
        }

        match phich_ack {
            Some(true) => {
                p.harq_feedback_ack = true;
                Some(HarqStepResult {
                    pusch_tti,
                    hq_id,
                    action: HARQ_ACT_ACK_SUSPEND,
                    tx_nb: p.current_tx_nb,
                    rv: p.rv,
                    flushed: false,
                })
            }
            Some(false) => {
                p.current_tx_nb = p.current_tx_nb.wrapping_add(1);
                if p.current_tx_nb >= p.max_harq_tx {
                    *p = TddCfg2HarqProc::empty(p.max_harq_tx);
                    return Some(HarqStepResult {
                        pusch_tti,
                        hq_id,
                        action: HARQ_ACT_IGNORE,
                        tx_nb: 0xff,
                        rv: 0xff,
                        flushed: true,
                    });
                }
                // `HandleHarqProc` (`0x842d_657e..0x842d_658e`): `(rv_idx + 1) & 3` -> `[0, 2, 3, 1]`.
                p.rv_idx = (p.rv_idx.wrapping_add(1)) & 3;
                p.rv = HARQ_RV_SEQ[p.rv_idx as usize];
                p.last_tx_tti = pusch_tti;
                Some(HarqStepResult {
                    pusch_tti,
                    hq_id,
                    action: HARQ_ACT_NON_ADAPT_RETX,
                    tx_nb: p.current_tx_nb,
                    rv: p.rv,
                    flushed: false,
                })
            }
            None => Some(HarqStepResult {
                pusch_tti,
                hq_id,
                action: HARQ_ACT_IGNORE,
                tx_nb: p.current_tx_nb,
                rv: p.rv,
                flushed: false,
            }),
        }
    }

    /// Exact span in ms from initial TX to final (`max_harq_tx`-th) TX in TDD Config 2.
    #[inline]
    pub const fn max_retx_span_ms(max_harq_tx: u8) -> u32 {
        if max_harq_tx <= 1 {
            0
        } else {
            ((max_harq_tx - 1) as u32) * HARQ_TDD_CFG2_RTT_MS
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bench_drb_model(table: BsrTableMode) -> (MacUlModel, [BearerQueue; MAX_LCIDS]) {
        let mut m = MacUlModel::new();
        m.bsr_table_mode = table;
        m.default_lcg = 0; // SRB
        m.configure_lc(
            1,
            LcConfig {
                active: true,
                rb_type: 2, // SRB
                priority: 1,
                lcg_id: 0,
                pbr_bytes_per_tti: 100_000,
                bj_max: 100_000,
            },
        );
        m.configure_lc(
            3,
            LcConfig {
                active: true,
                rb_type: 0, // DRB
                priority: 11,
                lcg_id: 3,
                pbr_bytes_per_tti: 8,
                bj_max: 800,
            },
        );
        (m, [BearerQueue::default(); MAX_LCIDS])
    }

    /// Cross-checked bit-for-bit against Unicorn execution of stock `tk.bin` & v1.0.16 `tk.bin`
    /// (`lanes-20261125/N3/work/verify_mac_ul.py` Suite 3).
    #[test]
    fn bsr_pipeline_matches_unicorn_stock_and_v1016() {
        // Case A: Stock Long BSR (Std), Ring-1=30KB, RLC=10KB, hdr=20 -> 40,020 B (idx 54)
        let (mut m, mut q) = bench_drb_model(BsrTableMode::Standard);
        q[3] = BearerQueue {
            ring_pending_bytes: 30_000,
            rings_or_cipher_nonempty: true,
            rlc_newtx_bo: 10_000,
            hdr_bo: 20,
            ..Default::default()
        };
        m.update_bo(3, 10_000, 20);
        m.mac_bsr_pre_work(&q, false);
        assert_eq!(m.lcg_pre_bo, [0, 0, 0, 30_000]);
        let (lcg_bo, ce) = m.build_bsr_ce(MAC_LCID_LONG_BSR, 1 << 3, &q, BsrReportingMode::Stock);
        assert_eq!(lcg_bo, [0, 0, 0, 40_020]);
        assert_eq!(
            ce,
            EncodedBsrCe::Long {
                idx: [0, 0, 0, 54],
                ce_word: 54u32 << 8
            }
        );

        // Case B: Stock Long BSR (Ext), + bo_margin=320 -> 40,340 B (Ext idx 42)
        let (mut m, mut q) = bench_drb_model(BsrTableMode::Extended);
        q[3] = BearerQueue {
            ring_pending_bytes: 30_000,
            rings_or_cipher_nonempty: true,
            rlc_newtx_bo: 10_000,
            hdr_bo: 20,
            bo_margin_bytes: 320,
            ..Default::default()
        };
        m.update_bo(3, 10_000, 20);
        m.mac_bsr_pre_work(&q, false);
        let (lcg_bo, ce) = m.build_bsr_ce(MAC_LCID_LONG_BSR, 1 << 3, &q, BsrReportingMode::Stock);
        assert_eq!(lcg_bo, [0, 0, 0, 40_340]);
        assert_eq!(
            ce,
            EncodedBsrCe::Long {
                idx: [0, 0, 0, 42],
                ce_word: 42u32 << 8
            }
        );

        // Case C: Stock SHORT-BSR ZERO BUG! Ring-1=30KB, RLC=0, packed_lc_mask=0 -> (LCG 0, idx 0)!
        let (mut m, mut q) = bench_drb_model(BsrTableMode::Standard);
        q[3] = BearerQueue {
            ring_pending_bytes: 30_000,
            rings_or_cipher_nonempty: true,
            rlc_newtx_bo: 0,
            ..Default::default()
        };
        m.update_bo(3, 0, 0);
        m.mac_bsr_pre_work(&q, false);
        let (lcg_bo, ce) = m.build_bsr_ce(MAC_LCID_SHORT_BSR, 0, &q, BsrReportingMode::Stock);
        assert_eq!(lcg_bo, [0, 0, 0, 30_000]);
        assert_eq!(
            ce,
            EncodedBsrCe::Short {
                lcid: MAC_LCID_SHORT_BSR,
                lcg: 0,
                idx: 0,
                ce_word: 0
            }
        );

        // Case D: v1.0.16 N4 TRUE_BO double-count! 2*30,000 + 10,000 + 20 = 70,020 B (Std idx 58)
        let (mut m, mut q) = bench_drb_model(BsrTableMode::Standard);
        q[3] = BearerQueue {
            ring_pending_bytes: 30_000,
            rings_or_cipher_nonempty: true,
            rlc_newtx_bo: 10_000,
            hdr_bo: 20,
            ..Default::default()
        };
        m.update_bo(3, 10_000, 20);
        m.mac_bsr_pre_work(&q, false);
        let (lcg_bo, ce) =
            m.build_bsr_ce(MAC_LCID_LONG_BSR, 1 << 3, &q, BsrReportingMode::V1016N4TrueBo);
        assert_eq!(lcg_bo, [0, 0, 0, 70_020]);
        assert_eq!(
            ce,
            EncodedBsrCe::Long {
                idx: [0, 0, 0, 58],
                ce_word: 58u32 << 8
            }
        );

        // Case E: v1.0.16 N4 Short-BSR rescue (60,000 B -> LCG 3, idx 57) vs N3 exact (30,000 B -> LCG 3, idx 52)
        let (mut m, mut q) = bench_drb_model(BsrTableMode::Standard);
        q[3] = BearerQueue {
            ring_pending_bytes: 30_000,
            rings_or_cipher_nonempty: true,
            rlc_newtx_bo: 0,
            ..Default::default()
        };
        m.mac_bsr_pre_work(&q, false);
        let (lcg_n4, ce_n4) =
            m.build_bsr_ce(MAC_LCID_SHORT_BSR, 0, &q, BsrReportingMode::V1016N4TrueBo);
        assert_eq!(lcg_n4, [0, 0, 0, 60_000]);
        assert_eq!(
            ce_n4,
            EncodedBsrCe::Short {
                lcid: MAC_LCID_SHORT_BSR,
                lcg: 3,
                idx: 57,
                ce_word: (3u32 << 30) | (57u32 << 24)
            }
        );
        let (lcg_n3, ce_n3) =
            m.build_bsr_ce(MAC_LCID_SHORT_BSR, 0, &q, BsrReportingMode::N3GuardedExact);
        assert_eq!(lcg_n3, [0, 0, 0, 30_000]);
        assert_eq!(
            ce_n3,
            EncodedBsrCe::Short {
                lcid: MAC_LCID_SHORT_BSR,
                lcg: 3,
                idx: 52,
                ce_word: (3u32 << 30) | (52u32 << 24)
            }
        );
    }

    /// Cross-checked bit-for-bit against Unicorn execution of `UpdateBj` + `AssignScheduleSize2LC`
    /// (`lanes-20261125/N3/work/verify_mac_ul.py` Suite 5).
    #[test]
    fn two_carrier_lcp_split_matches_unicorn() {
        // Scenario 5a: SRB1 (100+4+2=106 B) + DRB1 (12,000+40+2=12,042 B) across 6792 + 6792 B
        let (mut m, _) = bench_drb_model(BsrTableMode::Standard);
        m.update_bo(1, 100, 4);
        m.update_bo(3, 12_000, 40);
        m.update_bj(5);
        let (p_alloc, p_rem) = m.assign_lcp_bytes(6792);
        let (s_alloc, s_rem) = m.assign_lcp_bytes(6792);
        assert_eq!(p_alloc[1], 106);
        assert_eq!(p_alloc[3], 6686);
        assert_eq!(p_rem, 0);
        assert_eq!(s_alloc[1], 0);
        assert_eq!(s_alloc[3], 5356);
        assert_eq!(s_rem, 1436); // SCell wasted padding when RLC staging < TB_PCell + TB_SCell!

        // Scenario 5c: Equal-priority 2-DRB split (PBR consumed in PCell, 50/50 in SCell)
        let mut m = MacUlModel::new();
        m.configure_lc(
            3,
            LcConfig {
                active: true,
                rb_type: 0,
                priority: 11,
                lcg_id: 3,
                pbr_bytes_per_tti: 100,
                bj_max: 1000,
            },
        );
        m.configure_lc(
            4,
            LcConfig {
                active: true,
                rb_type: 0,
                priority: 11,
                lcg_id: 1,
                pbr_bytes_per_tti: 20,
                bj_max: 200,
            },
        );
        m.update_bo(3, 5000, 20);
        m.update_bo(4, 5000, 20);
        m.update_bj(5);
        let (p_alloc, p_rem) = m.assign_lcp_bytes(4000);
        let (s_alloc, s_rem) = m.assign_lcp_bytes(4000);
        assert_eq!((p_alloc[3], p_alloc[4], p_rem), (2200, 1800, 0));
        assert_eq!((s_alloc[3], s_alloc[4], s_rem), (2000, 2000, 0));
    }

    /// Verify 2CC deferred Regular BSR: PCell defers BSR to SCell so SCell reports post-(PCell+SCell).
    #[test]
    fn two_carrier_tti_defers_regular_bsr_to_scell() {
        let (mut m, mut q) = bench_drb_model(BsrTableMode::Standard);
        q[3] = BearerQueue {
            ring_pending_bytes: 30_000,
            rings_or_cipher_nonempty: true,
            rlc_newtx_bo: 20_000,
            hdr_bo: 40,
            ..Default::default()
        };
        m.update_bo(3, 20_000, 40);
        assert!(m.bsr_pending);

        let out = m.step_tti(6792, 6792, 5, &mut q, BsrReportingMode::Stock);
        // PCell deferred Regular BSR (`pending_newtx_cnt == 1`), packed full 6792 B, emitted no BSR.
        assert!(out.pcell.deferred_bsr_flag);
        assert_eq!(out.pcell.bsr_ce, EncodedBsrCe::None);
        assert_eq!(out.pcell.padding_bytes, 0);

        // SCell carried the Regular Short BSR (2 B) + 6790 B data, reporting post-(PCell+SCell) BO!
        assert!(!out.scell.deferred_bsr_flag);
        assert!(!out.scell.is_padding_bsr);
        // Remaining RLC after PCell (6790) + SCell (6788) = 20,000 - 13,578 = 6,422 + 40 hdr + 30,000 Ring-1 = 36,462 B (Std idx 54)
        assert_eq!(out.scell.lcg_bo_reported[3], 36_462);
        assert_eq!(
            out.scell.bsr_ce,
            EncodedBsrCe::Short {
                lcid: MAC_LCID_SHORT_BSR,
                lcg: 3,
                idx: 54,
                ce_word: (3u32 << 30) | (54u32 << 24),
            }
        );
    }

    #[test]
    fn bo_margin_is_ring0_only_and_expires_after_250ms_idle() {
        let mut q = BearerQueue::default();
        // Pure Ring-1 traffic never calls on_ring0_drain -> bo_margin stays 0.
        q.do_bo_tick_stock(1024);
        assert_eq!(q.bo_margin_bytes, 0);

        // Ring-0 packet arms bo_margin immediately and survives one 250 ms tick.
        q.on_ring0_drain(500, 1024);
        assert_eq!(q.bo_margin_bytes, 1024);
        q.do_bo_tick_stock(1024);
        assert_eq!(q.bo_margin_bytes, 1024);
        assert_eq!(q.bo_hold_last_cnt, 500);
        // Next 250 ms tick without new Ring-0 activity zeroes bo_margin.
        q.do_bo_tick_stock(1024);
        assert_eq!(q.bo_margin_bytes, 0);
    }

    #[test]
    fn tdd_cfg2_harq_timing_rv_cycle_and_7tx_flush() {
        assert_eq!(TddCfg2HarqEntity::pusch_tti_for_dl_tti(3), Some((7, 1)));
        assert_eq!(TddCfg2HarqEntity::pusch_tti_for_dl_tti(8), Some((12, 0)));
        assert_eq!(TddCfg2HarqEntity::pusch_tti_for_dl_tti(0), None);
        assert_eq!(TddCfg2HarqEntity::phich_tti_for_pusch_tti(2), Some(8));
        assert_eq!(TddCfg2HarqEntity::phich_tti_for_pusch_tti(7), Some(13));
        assert_eq!(TddCfg2HarqEntity::max_retx_span_ms(7), 60);

        let mut hq = TddCfg2HarqEntity::new(7);
        // Initial DCI-0 in SF 3 -> PUSCH at TTI 7 (hq_id 1, tx_nb 0, RV 0)
        let r0 = hq.on_dl_sf(3, Some((1, 20)), None).unwrap();
        assert_eq!((r0.pusch_tti, r0.hq_id, r0.action, r0.tx_nb, r0.rv), (7, 1, HARQ_ACT_NEW_TX, 0, 0));

        // 6 consecutive PHICH NACKs every 10 ms (SF 13, 23, 33, 43, 53, 63) -> RV 2, 3, 1, 0, 2, 3
        let expected_rvs = [2u8, 3, 1, 0, 2, 3];
        for (i, &exp_rv) in expected_rvs.iter().enumerate() {
            let dl_tti = 13 + (i as u32) * 10;
            let r = hq.on_dl_sf(dl_tti, None, Some(false)).unwrap();
            assert_eq!(r.pusch_tti, dl_tti + 4);
            assert_eq!(r.hq_id, 1);
            assert_eq!(r.action, HARQ_ACT_NON_ADAPT_RETX);
            assert_eq!(r.tx_nb, (i as u8) + 1);
            assert_eq!(r.rv, exp_rv);
            assert!(!r.flushed);
        }
        // 7th NACK at TTI 73 -> exceeds maxHARQ-Tx = 7 -> flushed!
        let rf = hq.on_dl_sf(73, None, Some(false)).unwrap();
        assert!(rf.flushed);
        assert!(!hq.procs[1].active);
    }

    #[test]
    fn fast_downgrade_early_exit_matches_exact_condition() {
        let (mut m, _) = bench_drb_model(BsrTableMode::Standard);
        m.configure_lc(
            4,
            LcConfig {
                active: true,
                rb_type: 0,
                priority: 11,
                lcg_id: 1,
                pbr_bytes_per_tti: 8,
                bj_max: 800,
            },
        );
        m.update_bo(3, 20_000, 40);
        assert_eq!(m.check_long_bsr_downgrade_fast(6792), Some(true));
        m.update_bo(4, 15_000, 30);
        // Both LCG 3 (20K) and LCG 1 (15K) exceed 6792 -> guaranteed cannot downgrade!
        assert_eq!(m.check_long_bsr_downgrade_fast(6792), Some(false));
        // If LCG 1 drops to 100 B, fallback to full simulation (None).
        m.update_bo(4, 100, 4);
        assert_eq!(m.check_long_bsr_downgrade_fast(6792), None);
    }
}
