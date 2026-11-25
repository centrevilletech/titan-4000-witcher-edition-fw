//! Pure-Rust `no_std` behavioural model of the GDM7243A RLC AM UL engine:
//! - `rlc_can_fit` (`0x842d_d404`) SDU fit & alternating 1.5 B LI sizing
//! - `rlc_timer_create` (`0x842e_1fb0`) `-2 ms` timer offset (`L2_TIMER_OFFSET_VA`)
//! - `ProcessPduRetx` (`0x842d_d794`) `RETX_COUNT`, `maxRetxThreshold`, duplicate guard
//! - `rlc_poll_check` (`0x842d_d89c`) window-stall & empty-buffer poll trigger
//! - `rlc_am_ul_bo_notify` (`0x842d_eaec`) new-TX BO sync
//! - `rlc_ul_am_proc_status_rpt` (`0x842d_eb44`) ACK_SN / NACKs / `t-PollRetransmit` stop
//! - `RlcAmUlGenPdu` (`0x842d_f4f4`) STATUS > RETX > New-TX PDU generation, segmentation,
//!   re-segmentation, `pollPDU` / `pollByte` counters, `POLL_SN` & timer restart
//! - `rlc_am_poll_retx_expire` (`0x8452_b398`) empty-buffer-only expiry re-enqueue

use modem_atlas::l2::{
    RLC_AM_WIN_SIZE, RLC_MODE_AM, RLC_POLL_BYTE_TABLE, RLC_POLL_CFG_BYTE, RLC_POLL_CFG_PDU,
};

use crate::bsr::BearerBoSnapshot;
use crate::pdcp::{PDCP_SN_MASK, PdcpUlState};

/// 10-bit RLC AM SN modulus (`0..1023`).
pub const RLC_AM_SN_MOD: u16 = 1024;
pub const RLC_AM_SN_MASK: u16 = RLC_AM_SN_MOD - 1;
/// Maximum PDUs emitted in one `RlcAmUlGenPdu` call (1 STATUS + up to 15 data PDUs).
pub const MAX_PDUS_PER_GRANT: usize = 16;
/// Maximum PDCP SDUs concatenated into one AMD PDU tracked for confirmation.
pub const MAX_SDUS_PER_PDU: usize = 16;

/// Exact behavioural model of `rlc_can_fit` (`0x842d_d404..0x842d_d426`).
///
/// Matches the compiled Thumb-2 `cmp r0, #0; it ne; cmpne r0, r1; bcc ret0` sequence:
/// - `0`: `rem != 0 && rem < sdu_len` (cannot fit whole SDU -> segment)
/// - `1`: `rem == 0 || (sdu_len <= rem <= sdu_len + li_bytes)` (fits as last SDU without LI)
/// - `2`: `rem > sdu_len + li_bytes` (fits with LI and room for a subsequent SDU)
#[inline]
pub const fn rlc_can_fit(rem: u32, sdu_len: u32, li_bytes: u32) -> u8 {
    if rem != 0 && rem < sdu_len {
        0
    } else if rem > sdu_len.saturating_add(li_bytes) {
        2
    } else {
        1
    }
}

/// Exact behavioural model of `rlc_timer_create` / `rlc_timer_modify` (`0x842e_1fb0`/`1fe0`).
///
/// Subtracts `timer_offset_ms` (`*(u32*)0x8410_ea00`, boot `2`) whenever `duration_ms > offset`.
#[inline]
pub const fn rlc_timer_effective_ms(duration_ms: u32, timer_offset_ms: u32) -> u32 {
    if duration_ms > timer_offset_ms {
        duration_ms - timer_offset_ms
    } else {
        duration_ms
    }
}

/// RLC AM UL configuration parameters (matching RRC `rlc-Config` `am` / Nokia `rlcProf2`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RlcAmConfig {
    /// `maxRetxThreshold` (`rbc+0x169`, `16` on Nokia QCI 9).
    pub max_retx_threshold: u8,
    /// `poll_cfg_flags` (`rbc+0x16b`): `RLC_POLL_CFG_PDU | RLC_POLL_CFG_BYTE`.
    pub poll_cfg_flags: u8,
    /// `pollPDU` (`rbc+0x170`, `64` on Nokia QCI 9).
    pub poll_pdu: u16,
    /// `pollByte` (`rbc+0x180`, e.g. `RLC_POLL_BYTE_TABLE[4]` = `125_000` B).
    pub poll_byte: u32,
    /// Configured `t-PollRetransmit` in ms (`120` on Nokia `rlcProf2`, `118` effective).
    pub t_poll_retx_ms: u32,
    /// `*(u32*)0x8410_ea00` timer offset in ms (`2` in stock).
    pub timer_offset_ms: u32,
    /// LCG ID (`0..3`, `3` for QCI 9 default DRB).
    pub lcg_id: u8,
}

impl Default for RlcAmConfig {
    fn default() -> Self {
        Self {
            max_retx_threshold: 16,
            poll_cfg_flags: RLC_POLL_CFG_PDU | RLC_POLL_CFG_BYTE,
            poll_pdu: 64,
            poll_byte: RLC_POLL_BYTE_TABLE[4], // 125_000 B
            t_poll_retx_ms: 120,
            timer_offset_ms: 2,
            lcg_id: 3,
        }
    }
}

/// One entry in the 512-slot RLC AM UL TX buffer (`RlcAmTxEntry`, indexed by `sn & 511`).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct RlcAmTxSlot {
    pub occupied: bool,
    pub acked: bool,
    pub sn: u16,
    /// Total AMD PDU length (RLC header + data payload).
    pub total_len: u32,
    /// RLC header length (`2` base + LI bytes).
    pub hdr_len: u16,
    /// `RETX_COUNT` (`+0x10`).
    pub retx_count: u8,
    /// `+0x13`: set once retransmitted; gates `RETX_COUNT` increment in `ProcessPduRetx`.
    pub was_nacked: u8,
    /// `+0x14`: duplicate guard while queued in `retx_ring`.
    pub in_retx_queue: u8,
    /// Number of complete PDCP SDUs whose final byte landed in this AMD PDU.
    pub completed_sdu_cnt: u8,
    /// PDCP SNs of completed SDUs in this AMD PDU (confirmed on STATUS ACK).
    pub completed_sdu_sns: [u16; MAX_SDUS_PER_PDU],
    /// First-transmission TTI (ms).
    pub first_tx_ms: u32,
}

/// One entry in the 512-slot RLC AM UL retransmission ring (`RlcAmRetxEntry`).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct RlcAmRetxSlot {
    pub valid: bool,
    pub sn: u16,
    pub flags: u8,
    /// `0` = full AMD PDU pending, `1` = re-segmentation in progress.
    pub seg_state: u8,
    /// Remaining un-retransmitted payload bytes (`total_len - hdr_len` initially).
    pub seg_rem_bytes: u16,
    /// Current 3GPP Segment Offset (`SO`).
    pub seg_so: u16,
}

/// Kind of PDU emitted by `RlcAmUlGenPdu` (`0x842d_f4f4`).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum GeneratedPduKind {
    #[default]
    None,
    Status,
    RetxFull,
    RetxSeg,
    NewTx,
}

/// One PDU produced during a `RlcAmUlGenPdu` call.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct GeneratedPdu {
    pub kind: GeneratedPduKind,
    pub sn: u16,
    /// Total RLC PDU bytes (`out_pdu_sizes[i]`).
    pub size: u32,
    /// RLC data payload bytes (excluding fixed+LI header).
    pub data_bytes: u32,
    /// `P` (Poll) bit stamped in AMD header (`byte0 & 0x20`).
    pub poll_bit: bool,
    /// Segment offset (`0` for full PDUs).
    pub so: u16,
    /// `true` if this segment finishes the AMD PDU (`LSF = 1`).
    pub is_last_seg: bool,
}

/// Output of one `RlcAmUlGenPdu` (`0x842d_f4f4`) invocation.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct GenPduResult {
    pub pdu_count: u8,
    pub ctrl_pdu_cnt: u8,
    pub data_pdu_cnt: u16,
    pub pdus: [GeneratedPdu; MAX_PDUS_PER_GRANT],
    pub bytes_consumed: u32,
    pub started_poll_retx_tmr: bool,
    pub window_stalled: bool,
}

/// Output of `rlc_ul_am_proc_status_rpt` (`0x842d_eb44`).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct StatusRptResult {
    pub acked_rlc_pdus: u32,
    pub nacked_rlc_pdus: u32,
    pub confirmed_pdcp_sdus: u32,
    pub stopped_poll_retx_tmr: bool,
    pub max_retx_reached: bool,
}

/// Complete RLC AM UL state for one bearer (`Rbc` `+0x104..+0x20a`).
pub struct RlcAmUlState {
    pub cfg: RlcAmConfig,
    /// Partial head PDCP SDU currently being segmented (`+0x104`, `+0x108`).
    pub cur_sdu_sn: u16,
    pub cur_sdu_rem: u16,
    pub cur_sdu_valid: bool,

    /// `+0x144` / `+0x1f2`: pending UL STATUS PDU bytes & extra header BO.
    pub rlc_status_bo: u16,
    pub am_extra_hdr_bo: u16,
    /// `+0x154`: RLC AM UL new-TX BO (`pdcp_rlc_tx_bo + reest_tx_bo`).
    pub rlc_am_newtx_bo: u32,
    /// `+0x158`: RLC AM UL retx BO (mirrored from `retx_bytes`).
    pub rlc_am_retx_bo: u32,

    /// `+0x16c`: poll pending flag.
    pub poll_trigger: bool,
    /// `+0x16d`: deferred `t-PollRetransmit` restart flag.
    pub start_poll_retx_tmr: bool,
    /// `+0x16e`: `POLL_SN`.
    pub poll_sn: u16,
    /// `+0x174`: `VT(A)` (lowest un-ACKed SN).
    pub vt_a: u16,
    /// `+0x176`: `VT(S)` (next new SN to assign).
    pub vt_s: u16,
    /// `+0x17c`: `PDU_WITHOUT_POLL`.
    pub pdu_without_poll: u32,
    /// `+0x184`: `BYTE_WITHOUT_POLL` (data field bytes only).
    pub byte_without_poll: u32,
    /// `+0x19a`: free window slots (`512` initially; `0` = window stall).
    pub ul_am_free_win_slots: u16,

    /// `+0x1b0`: 512-entry TX buffer indexed by `sn & 0x1ff`.
    pub tx_buf: [RlcAmTxSlot; RLC_AM_WIN_SIZE],

    /// `+0x1cc..+0x1d8`: 512-entry RETX FIFO ring.
    pub retx_ring: [RlcAmRetxSlot; RLC_AM_WIN_SIZE],
    pub retx_wr: u16,
    pub retx_rd: u16,
    pub retx_cnt: u16,
    pub retx_hdr_bo: u16,
    pub retx_bytes: u32,

    /// Software `t-PollRetransmit` running state and expiry tick (ms).
    pub poll_retx_tmr_running: bool,
    pub poll_retx_tmr_expiry_ms: u32,

    /// Telemetry counters.
    pub total_newtx_pdus: u64,
    pub total_retx_pdus: u64,
    pub total_win_stalls: u64,
    pub total_poll_tmr_expiries: u64,
    pub max_retx_events: u64,
}

impl RlcAmUlState {
    pub fn new(cfg: RlcAmConfig) -> Self {
        Self {
            cfg,
            cur_sdu_sn: 0,
            cur_sdu_rem: 0,
            cur_sdu_valid: false,
            rlc_status_bo: 0,
            am_extra_hdr_bo: 0,
            rlc_am_newtx_bo: 0,
            rlc_am_retx_bo: 0,
            poll_trigger: false,
            start_poll_retx_tmr: false,
            poll_sn: 0,
            vt_a: 0,
            vt_s: 0,
            pdu_without_poll: 0,
            byte_without_poll: 0,
            ul_am_free_win_slots: RLC_AM_WIN_SIZE as u16,
            tx_buf: [RlcAmTxSlot::default(); RLC_AM_WIN_SIZE],
            retx_ring: [RlcAmRetxSlot::default(); RLC_AM_WIN_SIZE],
            retx_wr: 0,
            retx_rd: 0,
            retx_cnt: 0,
            retx_hdr_bo: 0,
            retx_bytes: 0,
            poll_retx_tmr_running: false,
            poll_retx_tmr_expiry_ms: 0,
            total_newtx_pdus: 0,
            total_retx_pdus: 0,
            total_win_stalls: 0,
            total_poll_tmr_expiries: 0,
            max_retx_events: 0,
        }
    }

    /// Exact model of `rlc_am_ul_bo_notify` (`0x842d_eaec`): syncs `rlc_am_newtx_bo` (`+0x154`)
    /// from `pdcp.pdcp_rlc_tx_bo` (`+0x10c`).
    #[inline]
    pub fn notify_pdcp_bo(&mut self, pdcp: &PdcpUlState) {
        self.rlc_am_newtx_bo = pdcp.pdcp_rlc_tx_bo;
    }

    /// Exact model of `upd_retx_bo` (`0x842d_dbc0`): mirrors `retx_bytes` (`+0x1d8`)
    /// into `rlc_am_retx_bo` (`+0x158`).
    #[inline]
    pub fn sync_retx_bo(&mut self) {
        self.rlc_am_retx_bo = self.retx_bytes;
    }

    /// Build a [`BearerBoSnapshot`] for `get_rlc_cur_bo` / `rlc_upd_cur_bo` / BSR.
    pub fn bo_snapshot(&self, pdcp: &PdcpUlState, bo_margin_bytes: u32) -> BearerBoSnapshot {
        BearerBoSnapshot {
            rlc_mode: RLC_MODE_AM,
            active: true,
            lcg_id: self.cfg.lcg_id,
            rlc_tm_bo: 0,
            rlc_status_bo: self.rlc_status_bo,
            rlc_am_newtx_bo: self.rlc_am_newtx_bo,
            rlc_am_retx_bo: self.rlc_am_retx_bo,
            pdcp_rlc_hdr_bo: pdcp.pdcp_rlc_hdr_bo,
            rlc_reest_hdr_bo: 0,
            retx_hdr_bo: self.retx_hdr_bo,
            am_extra_hdr_bo: self.am_extra_hdr_bo,
            ring_pending_bytes: pdcp.ring_pending_bytes,
            bo_margin_bytes,
        }
    }

    /// Exact model of `rlc_poll_check` (`0x842d_d89c..0x842d_d8fa`).
    ///
    /// Sets `poll_trigger = true` if:
    /// - The transmit window has reached stall (`((vt_s - 511 - vt_a) & 0x3ff) < 512`), OR
    /// - Both `pdcp_rlc_tx_bo == 0` AND `retx_bytes == 0` (no further new/retx data).
    pub fn rlc_poll_check(&mut self, pdcp_rlc_tx_bo: u32) {
        // Exact 0x842d_d8a2..0x842d_d8ba:
        // mvn r4, #510 (-511 = 0xffff_fe01); r2 = (vt_s + (-511) - vt_a) & 0x3ff
        let diff = self
            .vt_s
            .wrapping_sub(511)
            .wrapping_sub(self.vt_a)
            & RLC_AM_SN_MASK;
        if diff < 512 {
            self.poll_trigger = true;
            return;
        }
        if pdcp_rlc_tx_bo == 0 && self.retx_bytes == 0 {
            self.poll_trigger = true;
        }
    }

    /// Exact model of `ProcessPduRetx` (`0x842d_d794..0x842d_d89a`).
    ///
    /// Returns `true` if `RETX_COUNT` reached `max_retx_threshold` (RLF trigger).
    pub fn process_pdu_retx(&mut self, sn: u16, flags: u8) -> bool {
        let idx = (sn as usize) & (RLC_AM_WIN_SIZE - 1);
        let tx = &mut self.tx_buf[idx];
        if !tx.occupied || tx.sn != sn {
            return false;
        }
        // Duplicate guard (+0x14)
        if tx.in_retx_queue != 0 {
            return false;
        }
        let mut hit_max = false;
        if tx.was_nacked != 0 {
            tx.retx_count = tx.retx_count.saturating_add(1);
            if tx.retx_count >= self.cfg.max_retx_threshold {
                hit_max = true;
                self.max_retx_events += 1;
            }
        }
        if (self.retx_cnt as usize) >= RLC_AM_WIN_SIZE {
            return hit_max;
        }

        let payload = tx.total_len.saturating_sub(tx.hdr_len as u32);
        tx.in_retx_queue = 1;

        let wr = self.retx_wr as usize;
        self.retx_ring[wr] = RlcAmRetxSlot {
            valid: true,
            sn,
            flags,
            seg_state: 0,
            seg_rem_bytes: payload as u16,
            seg_so: 0,
        };
        self.retx_wr = ((wr + 1) & (RLC_AM_WIN_SIZE - 1)) as u16;
        self.retx_cnt += 1;
        self.retx_hdr_bo = self.retx_hdr_bo.saturating_add(tx.hdr_len);
        self.retx_bytes = self.retx_bytes.saturating_add(payload);
        self.sync_retx_bo();
        hit_max
    }

    /// Exact model of `RlcAmUlGenPdu` (`0x842d_f4f4..0x842e_0490`).
    ///
    /// Priority order:
    /// 1. Pending UL STATUS PDU (`rlc_status_bo > 0`)
    /// 2. Retransmission ring (`retx_cnt > 0`): full AMD PDU if `total_len + 1 <= rem`,
    ///    otherwise re-segment if `rem > 5` (4 B AMD segment header + >=1 B payload + 1 B MAC subhdr)
    /// 3. New-TX AMD PDU (`rem >= 4` and `ul_am_free_win_slots > 0` and SDU bytes exist):
    ///    uses exact `rlc_can_fit` with alternating `li = 2, 1, 2, 1...` (1.5 B/LI) and
    ///    `payload_budget = rem - 3` (2 B fixed AM header + 1 B MAC subheader), updating
    ///    `VT(S)`, `rlc_poll_check`, `pollPDU`, `pollByte` (data bytes only), `POLL_SN`,
    ///    and `t-PollRetransmit`.
    pub fn gen_pdu(
        &mut self,
        pdcp: &mut PdcpUlState,
        grant_bytes: u32,
        now_ms: u32,
    ) -> GenPduResult {
        let mut res = GenPduResult::default();
        let mut rem = grant_bytes;
        self.start_poll_retx_tmr = false;

        // 1. STATUS PDU first (0x842d_f516)
        if self.rlc_status_bo > 0 && rem >= 3 {
            let st_len = (self.rlc_status_bo as u32).min(rem.saturating_sub(1));
            if st_len >= 2 {
                let mac_subhdr = if st_len < 128 { 1 } else { 2 };
                let used = (st_len + mac_subhdr).min(rem);
                rem = rem.saturating_sub(used);
                self.rlc_status_bo = 0;
                self.am_extra_hdr_bo = 0;
                res.pdus[res.pdu_count as usize] = GeneratedPdu {
                    kind: GeneratedPduKind::Status,
                    sn: 0,
                    size: st_len,
                    data_bytes: 0,
                    poll_bit: false,
                    so: 0,
                    is_last_seg: true,
                };
                res.pdu_count += 1;
                res.ctrl_pdu_cnt = 1;
                res.bytes_consumed += used;
            }
        }

        // 2. RETX ring second (0x842d_f524..0x842d_f950)
        while self.retx_cnt > 0 && rem > 0 && (res.pdu_count as usize) < MAX_PDUS_PER_GRANT {
            let rd = self.retx_rd as usize;
            let entry = self.retx_ring[rd];
            if !entry.valid {
                break;
            }
            let tx_idx = (entry.sn as usize) & (RLC_AM_WIN_SIZE - 1);
            let tx_total = self.tx_buf[tx_idx].total_len;
            let tx_hdr = self.tx_buf[tx_idx].hdr_len as u32;

            if entry.seg_state == 0 && tx_total < rem {
                // Full AMD PDU retransmission (0x842d_f566..0x842d_f66e)
                let payload = tx_total.saturating_sub(tx_hdr);
                self.tx_buf[tx_idx].was_nacked = 1;
                self.tx_buf[tx_idx].in_retx_queue = 0;
                self.retx_hdr_bo = self.retx_hdr_bo.saturating_sub(tx_hdr as u16);
                self.retx_bytes = self.retx_bytes.saturating_sub(payload);
                self.retx_ring[rd].valid = false;
                self.retx_rd = ((rd + 1) & (RLC_AM_WIN_SIZE - 1)) as u16;
                self.retx_cnt -= 1;
                self.sync_retx_bo();

                let mac_subhdr = if tx_total < 128 { 1 } else { 2 };
                // Exact 0x842d_f5d6..0x842d_f5ee: remaining grant after PDU + MAC subhdr
                rem = rem.saturating_sub(tx_total + mac_subhdr);

                // Poll check on RETX
                self.rlc_poll_check(pdcp.pdcp_rlc_tx_bo);
                let poll = self.consume_poll_if_triggered();

                res.pdus[res.pdu_count as usize] = GeneratedPdu {
                    kind: GeneratedPduKind::RetxFull,
                    sn: entry.sn,
                    size: tx_total,
                    data_bytes: payload,
                    poll_bit: poll,
                    so: 0,
                    is_last_seg: true,
                };
                res.pdu_count += 1;
                res.data_pdu_cnt += 1;
                res.bytes_consumed += tx_total + mac_subhdr;
                self.total_retx_pdus += 1;
            } else if rem > 5 {
                // AMD PDU re-segmentation (4 B segment header + 1 B MAC subhdr = 5 B min)
                let seg_hdr = 4u32;
                let max_payload = rem.saturating_sub(seg_hdr + 1);
                let take = (entry.seg_rem_bytes as u32).min(max_payload);
                if take == 0 {
                    break;
                }
                let pdu_size = seg_hdr + take;
                let mac_subhdr = if pdu_size < 128 { 1 } else { 2 };
                let used = (pdu_size + mac_subhdr).min(rem);
                rem = rem.saturating_sub(used);

                let cur_so = entry.seg_so;
                let new_rem = (entry.seg_rem_bytes as u32).saturating_sub(take) as u16;
                let is_last = new_rem == 0;

                self.retx_bytes = self.retx_bytes.saturating_sub(take);
                if is_last {
                    self.tx_buf[tx_idx].was_nacked = 1;
                    self.tx_buf[tx_idx].in_retx_queue = 0;
                    self.retx_hdr_bo = self.retx_hdr_bo.saturating_sub(tx_hdr as u16);
                    self.retx_ring[rd].valid = false;
                    self.retx_rd = ((rd + 1) & (RLC_AM_WIN_SIZE - 1)) as u16;
                    self.retx_cnt -= 1;
                } else {
                    self.retx_ring[rd].seg_state = 1;
                    self.retx_ring[rd].seg_rem_bytes = new_rem;
                    self.retx_ring[rd].seg_so = cur_so.saturating_add(take as u16);
                }
                self.sync_retx_bo();

                self.rlc_poll_check(pdcp.pdcp_rlc_tx_bo);
                let poll = self.consume_poll_if_triggered();

                res.pdus[res.pdu_count as usize] = GeneratedPdu {
                    kind: GeneratedPduKind::RetxSeg,
                    sn: entry.sn,
                    size: pdu_size,
                    data_bytes: take,
                    poll_bit: poll,
                    so: cur_so,
                    is_last_seg: is_last,
                };
                res.pdu_count += 1;
                res.data_pdu_cnt += 1;
                res.bytes_consumed += used;
                self.total_retx_pdus += 1;
                break; // Re-segmentation consumes the remaining grant.
            } else {
                break;
            }
        }

        // 3. New-TX AMD PDU third (0x842d_fdf0..0x842e_0450)
        // Minimum grant for a new AMD PDU: 2 B fixed RLC AM header + 1 B MAC subhdr + >=1 B data = 4 B
        if rem >= 4
            && (res.pdu_count as usize) < MAX_PDUS_PER_GRANT
            && (self.cur_sdu_valid || pdcp.pdcp_to_rlc_cnt > 0)
        {
            if self.ul_am_free_win_slots == 0 {
                res.window_stalled = true;
                self.total_win_stalls += 1;
            } else {
                // Exact 0x842d_fe38: payload_budget = rem - 3 (2 B fixed AM hdr + 1 B MAC subhdr;
                // if PDU >= 128 B, MAC subhdr is 2 B, accounted conservatively by grant_rem)
                let mut payload_rem = rem - 3;
                let mut hdr_len = 2u32;
                let mut data_bytes = 0u32;
                let mut li_count = 0u32;
                let mut completed_sns = [0u16; MAX_SDUS_PER_PDU];
                let mut completed_cnt = 0u8;

                // Loop packing partial head SDU + subsequent committed PDCP SDUs
                while payload_rem > 0 {
                    // Load next SDU if we don't currently hold a partial head SDU
                    if !self.cur_sdu_valid {
                        if let Some(next_pdu) = pdcp.peek_committed_to_rlc() {
                            if next_pdu.discarded {
                                let _ = pdcp.pop_committed_to_rlc();
                                continue;
                            }
                            let popped = pdcp.pop_committed_to_rlc().unwrap();
                            self.cur_sdu_sn = popped.pdcp_sn;
                            self.cur_sdu_rem = popped.len;
                            self.cur_sdu_valid = true;
                        } else {
                            break;
                        }
                    }

                    let sdu_len = self.cur_sdu_rem as u32;
                    // Alternating 1.5 B LI per additional SDU: 2, 1, 2, 1...
                    let li_bytes = if (li_count & 1) == 0 { 2 } else { 1 };
                    let fit = rlc_can_fit(payload_rem, sdu_len, li_bytes);

                    if fit == 0 {
                        // Segment the current SDU to fill all remaining payload bytes
                        let take = payload_rem;
                        data_bytes += take;
                        self.cur_sdu_rem = (sdu_len - take) as u16;
                        pdcp.pdcp_rlc_tx_bo = pdcp.pdcp_rlc_tx_bo.saturating_sub(take);
                        payload_rem = 0;
                    } else if fit == 1 {
                        // Fits as the final SDU in this AMD PDU (no LI needed for this one)
                        data_bytes += sdu_len;
                        pdcp.pdcp_rlc_tx_bo = pdcp.pdcp_rlc_tx_bo.saturating_sub(sdu_len);
                        if (completed_cnt as usize) < MAX_SDUS_PER_PDU {
                            completed_sns[completed_cnt as usize] = self.cur_sdu_sn;
                            completed_cnt += 1;
                        }
                        self.cur_sdu_rem = 0;
                        self.cur_sdu_valid = false;
                        payload_rem = 0;
                    } else {
                        // fit == 2: fits with room for LI + next SDU; only charge LI if another SDU exists
                        data_bytes += sdu_len;
                        pdcp.pdcp_rlc_tx_bo = pdcp.pdcp_rlc_tx_bo.saturating_sub(sdu_len);
                        if (completed_cnt as usize) < MAX_SDUS_PER_PDU {
                            completed_sns[completed_cnt as usize] = self.cur_sdu_sn;
                            completed_cnt += 1;
                        }
                        self.cur_sdu_rem = 0;
                        self.cur_sdu_valid = false;
                        payload_rem -= sdu_len;

                        if pdcp.pdcp_to_rlc_cnt > 0
                            && (completed_cnt as usize) < MAX_SDUS_PER_PDU
                            && payload_rem > li_bytes
                        {
                            hdr_len += li_bytes;
                            payload_rem -= li_bytes;
                            li_count += 1;
                        } else {
                            break;
                        }
                    }
                }

                if data_bytes > 0 {
                    let pdu_size = hdr_len + data_bytes;
                    let sn = self.vt_s;
                    let tx_idx = (sn as usize) & (RLC_AM_WIN_SIZE - 1);

                    self.tx_buf[tx_idx] = RlcAmTxSlot {
                        occupied: true,
                        acked: false,
                        sn,
                        total_len: pdu_size,
                        hdr_len: hdr_len as u16,
                        retx_count: 0,
                        was_nacked: 0,
                        in_retx_queue: 0,
                        completed_sdu_cnt: completed_cnt,
                        completed_sdu_sns: completed_sns,
                        first_tx_ms: now_ms,
                    };
                    self.ul_am_free_win_slots = self.ul_am_free_win_slots.saturating_sub(1);

                    // Exact 0x842e_033a..0x842e_03fc poll & VT(S) sequence:
                    // 1) rlc_poll_check (before VT(S) increment!)
                    self.rlc_poll_check(pdcp.pdcp_rlc_tx_bo);

                    // 2) pollPDU check (0x842e_033e..0x842e_037a)
                    if (self.cfg.poll_cfg_flags & RLC_POLL_CFG_PDU) != 0 {
                        self.pdu_without_poll = self.pdu_without_poll.wrapping_add(1);
                        if self.pdu_without_poll >= self.cfg.poll_pdu as u32 {
                            self.poll_trigger = true;
                        }
                    }

                    // 3) pollByte check — DATA bytes only! (0x842e_037c..0x842e_03b4)
                    if (self.cfg.poll_cfg_flags & RLC_POLL_CFG_BYTE) != 0 {
                        self.byte_without_poll = self.byte_without_poll.wrapping_add(data_bytes);
                        if self.byte_without_poll >= self.cfg.poll_byte {
                            self.poll_trigger = true;
                        }
                    }

                    // 4) Advance VT(S) (0x842e_03b6..0x842e_03c0)
                    self.vt_s = (self.vt_s + 1) & RLC_AM_SN_MASK;

                    // 5) Stamp P=1 if poll_trigger != 0 (0x842e_03ce..0x842e_03fc)
                    let poll = self.consume_poll_if_triggered();

                    // 6) Sync rlc_am_newtx_bo (+0x154) (0x842e_0436..0x842e_044c)
                    self.rlc_am_newtx_bo = pdcp.pdcp_rlc_tx_bo;

                    let mac_subhdr = if pdu_size < 128 { 1 } else { 2 };
                    res.pdus[res.pdu_count as usize] = GeneratedPdu {
                        kind: GeneratedPduKind::NewTx,
                        sn,
                        size: pdu_size,
                        data_bytes,
                        poll_bit: poll,
                        so: 0,
                        is_last_seg: true,
                    };
                    res.pdu_count += 1;
                    res.data_pdu_cnt += 1;
                    res.bytes_consumed += pdu_size + mac_subhdr;
                    self.total_newtx_pdus += 1;
                }
            }
        }

        // Deferred t-PollRetransmit restart on exit of RlcAmUlGenPdu (0x842e_04c0)
        if self.start_poll_retx_tmr {
            self.start_poll_retx_tmr = false;
            let eff = rlc_timer_effective_ms(self.cfg.t_poll_retx_ms, self.cfg.timer_offset_ms);
            self.poll_retx_tmr_running = true;
            self.poll_retx_tmr_expiry_ms = now_ms.saturating_add(eff);
            res.started_poll_retx_tmr = true;
        }

        res
    }

    /// Stamp `P=1` if `poll_trigger` is set, resetting `PDU_WITHOUT_POLL`, `BYTE_WITHOUT_POLL`,
    /// recording `POLL_SN = (VT(S) - 1) & 0x3ff`, and arming `start_poll_retx_tmr`.
    fn consume_poll_if_triggered(&mut self) -> bool {
        if !self.poll_trigger {
            return false;
        }
        self.poll_trigger = false;
        self.pdu_without_poll = 0;
        self.byte_without_poll = 0;
        self.poll_sn = self.vt_s.wrapping_sub(1) & RLC_AM_SN_MASK;
        self.start_poll_retx_tmr = true;
        true
    }

    /// Check if `sn` falls in the half-open modular window `[lo, hi)` (10-bit SN).
    #[inline]
    fn sn_in_range(sn: u16, lo: u16, hi: u16) -> bool {
        let span = hi.wrapping_sub(lo) & RLC_AM_SN_MASK;
        let off = sn.wrapping_sub(lo) & RLC_AM_SN_MASK;
        off < span
    }

    /// Exact model of `rlc_ul_am_proc_status_rpt` (`0x842d_eb44..0x842d_ef40`).
    ///
    /// Processes a peer STATUS PDU carrying `ack_sn` and optional `nack_sns`:
    /// - Releases positively acknowledged TX entries up to the lowest NACK (or `ack_sn`),
    ///   confirming their completed PDCP SDUs via `pdcp.proc_drb_cnf`.
    /// - Stops `t-PollRetransmit` if `POLL_SN` was ACKed or explicitly NACKed.
    /// - Enqueues each NACKed SN via `process_pdu_retx`.
    pub fn proc_status_rpt(
        &mut self,
        pdcp: &mut PdcpUlState,
        ack_sn: u16,
        nack_sns: &[u16],
    ) -> StatusRptResult {
        let mut res = StatusRptResult::default();
        let old_vt_a = self.vt_a;

        // Check if POLL_SN is covered by ACK_SN or listed in NACKs
        let poll_acked = Self::sn_in_range(self.poll_sn, old_vt_a, ack_sn);
        let poll_nacked = nack_sns.contains(&self.poll_sn);
        if self.poll_retx_tmr_running && (poll_acked || poll_nacked) {
            self.poll_retx_tmr_running = false;
            res.stopped_poll_retx_tmr = true;
        }

        // Mark positively acknowledged SNs in [vt_a, ack_sn) that are not NACKed
        let mut sn = old_vt_a;
        while sn != ack_sn && Self::sn_in_range(sn, old_vt_a, self.vt_s) {
            if !nack_sns.contains(&sn) {
                let idx = (sn as usize) & (RLC_AM_WIN_SIZE - 1);
                if self.tx_buf[idx].occupied && self.tx_buf[idx].sn == sn {
                    self.tx_buf[idx].acked = true;
                }
            }
            sn = (sn + 1) & RLC_AM_SN_MASK;
        }

        // Advance VT(A) in-order across contiguous ACKed slots, confirming PDCP SDUs
        // only once every RLC PDU up through the SDU's final byte is acknowledged.
        while self.vt_a != self.vt_s {
            let idx = (self.vt_a as usize) & (RLC_AM_WIN_SIZE - 1);
            if !self.tx_buf[idx].occupied || !self.tx_buf[idx].acked {
                break;
            }
            let cnt = self.tx_buf[idx].completed_sdu_cnt as usize;
            let sns = self.tx_buf[idx].completed_sdu_sns;
            for &psn in &sns[..cnt] {
                let p = psn & PDCP_SN_MASK;
                res.confirmed_pdcp_sdus += pdcp.proc_drb_cnf(p, p);
            }
            self.tx_buf[idx].occupied = false;
            self.tx_buf[idx].acked = false;
            self.ul_am_free_win_slots =
                (self.ul_am_free_win_slots + 1).min(RLC_AM_WIN_SIZE as u16);
            res.acked_rlc_pdus += 1;
            self.vt_a = (self.vt_a + 1) & RLC_AM_SN_MASK;
        }

        // Enqueue NACKed SNs into the RETX ring
        for &nsn in nack_sns {
            if Self::sn_in_range(nsn, self.vt_a, self.vt_s) {
                let hit_max = self.process_pdu_retx(nsn, 0);
                res.nacked_rlc_pdus += 1;
                res.max_retx_reached |= hit_max;
            }
        }

        res
    }

    /// Exact model of `rlc_am_poll_retx_expire` (`0x8452_b398..0x8452_b470`).
    ///
    /// Crucial stock firmware invariant (`0x8452_b3dc..0x8452_b3e6`):
    /// Only re-enqueues `VT(A)` and sets `poll_trigger = true` when **both**
    /// `rlc_am_newtx_bo == 0` AND `rlc_am_retx_bo == 0`!
    pub fn tick_poll_retx_timer(&mut self, now_ms: u32) -> bool {
        if !self.poll_retx_tmr_running || now_ms < self.poll_retx_tmr_expiry_ms {
            return false;
        }
        self.poll_retx_tmr_running = false;
        self.total_poll_tmr_expiries += 1;

        if self.rlc_am_newtx_bo != 0 || self.rlc_am_retx_bo != 0 {
            return false;
        }
        if self.vt_a != self.vt_s {
            let _ = self.process_pdu_retx(self.vt_a, 1);
        }
        self.sync_retx_bo();
        self.poll_trigger = true;
        true
    }
}
