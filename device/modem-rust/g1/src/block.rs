//! G1 MAC timeline tracer control block (`0x8412_a340`, 128 B in dead `ossDupWorld`)
//! and pure recording + auto-freeze state machine.
//!
//! Pure `no_std`, `#![forbid(unsafe_code)]`.

#![forbid(unsafe_code)]

use crate::record::{BsrFormat, EventKind, PhrSample, TraceRecord};

/// Control block magic (`"G1TR"`).
pub const MAGIC: u32 = 0x4731_5452;
/// Control block ABI version (`2026-11-25`).
pub const VERSION: u32 = 0x2026_1125;

/// Enable value that turns the tracer on. Every other value (including `0` at boot) means off.
pub const ENABLE_ON: u32 = 1;

/// Non-cacheable SDRAM ring buffer base inside the dead `srch_run_pss_*` buffer (`0x87f6_ed40..0x87f9_4540`).
pub const RING_BASE: u32 = 0x87f7_0000;
/// Number of 32-byte records in `G1_RING` (`4096 * 32 = 128 KiB`, ~10.24 s at full 2CC TDD Config 2).
pub const RING_SLOTS: u32 = 4096;
/// Power-of-two slot mask (`RING_SLOTS - 1`).
pub const RING_MASK: u32 = RING_SLOTS - 1;
/// Fixed record size in bytes.
pub const RECORD_SIZE: u32 = 32;

/// Auto-freeze mode bits (`G1Block::af_mode`, live via `wm`):
/// - `AF_SCELL_DROP`: freeze if SCell (`cc=1`) gets no grant for `af_tti_thresh` grant-TTIs while
///   PCell gets grants and `ring1 + rlc_bo >= af_bo_thresh`.
pub const AF_SCELL_DROP: u32 = 1 << 0;
/// - `AF_PCELL_DROP`: freeze if PCell (`cc=0`) gets no grant for `af_tti_thresh` grant-TTIs while
///   SCell gets grants and `ring1 + rlc_bo >= af_bo_thresh`.
pub const AF_PCELL_DROP: u32 = 1 << 1;
/// - `AF_BOTH_STALL`: freeze if NEITHER CC gets a grant for `af_tti_thresh * 5` ms while
///   `ring1 + rlc_bo >= af_bo_thresh`.
pub const AF_BOTH_STALL: u32 = 1 << 2;
/// - `AF_ALLOW_UNSEEN`: allow SCell/PCell drop trigger even before that CC has been seen active
///   since enable.
pub const AF_ALLOW_UNSEEN: u32 = 1 << 3;

/// Freeze reason codes written to `G1Block::freeze` and `G1Block::af_trigger_reason`.
pub const FREEZE_NONE: u32 = 0;
pub const FREEZE_SCELL_DROP: u32 = 1;
pub const FREEZE_PCELL_DROP: u32 = 2;
pub const FREEZE_BOTH_STALL: u32 = 3;

/// 128-byte control block placed in dead `ossDupWorld` (`0x8412_a340..0x8412_a3c0`).
///
/// Every switch boots off (`enable = 0`, `freeze = 0`, `af_mode = 0`).
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct G1Block {
    // --- Header (`0x00..0x0f`) ---
    pub magic: u32,
    pub version: u32,
    /// `+0x08`: `0` (boot) = off, `1` = on, any other value = off.
    pub enable: u32,
    /// `+0x0c`: `0` (boot) = running, non-zero = frozen (stops writing to ring).
    pub freeze: u32,

    // --- Ring geometry (`0x10..0x1f`) ---
    pub ring_base: u32,
    pub ring_slots: u32,
    pub record_size: u32,
    /// `+0x1c`: Total records written (slot index is `wr_idx & RING_MASK`).
    pub wr_idx: u32,

    // --- Auto-freeze controls (`0x20..0x3f`) ---
    /// `+0x20`: Auto-freeze bitmask (`AF_*`); `0` at boot = disabled.
    pub af_mode: u32,
    /// `+0x24`: Consecutive grant-TTIs with missing CC before triggering (boot: `10` = 50 ms @ TDD2).
    pub af_tti_thresh: u32,
    /// `+0x28`: Minimum `ring1_bytes + rlc_bo_bytes` to arm drop detector (boot: `16_000` B).
    pub af_bo_thresh: u32,
    /// `+0x2c`: Number of extra records to capture after trigger before freezing (boot: `128`).
    pub af_post_events: u32,
    /// `+0x30`: Active post-trigger countdown (`0` = not armed).
    pub af_post_countdown: u32,
    /// `+0x34`: Latched trigger reason (`FREEZE_*`).
    pub af_trigger_reason: u32,
    /// `+0x38`: `wr_idx` when auto-freeze triggered.
    pub af_trigger_seq: u32,
    /// `+0x3c`: `tti_ms` when auto-freeze triggered.
    pub af_trigger_tti: u32,

    // --- Auto-freeze state & summary counters (`0x40..0x67`) ---
    pub cc0_nogrant_streak: u32,
    pub cc1_nogrant_streak: u32,
    /// `+0x48`: Bit `0` = PCell grant seen, bit `1` = SCell grant seen.
    pub cc_seen_mask: u32,
    /// `+0x4c`: `tti_ms` of most recent grant on any CC.
    pub last_grant_tti: u32,
    pub cnt_newtx_cc0: u32,
    pub cnt_newtx_cc1: u32,
    pub cnt_retx: u32,
    pub cnt_sr: u32,
    pub cnt_bsr: u32,
    pub cnt_phr: u32,

    // --- Pre-CE scratch between Hook 1 (`0x842d_0918`) and Hook 2 (`0x842d_098a`) (`0x68..0x77`) ---
    pub snap_ce_buf: u32,
    pub snap_bsr_trig: u32,
    pub snap_phr_evt: u32,
    /// `+0x74`: `air_sti` when auto-freeze triggered.
    pub af_trigger_sti: u32,

    // --- Reserved (`0x78..0x7f`) ---
    pub reserved: [u32; 2],
}

const _: () = assert!(core::mem::size_of::<G1Block>() == 128);

/// Inputs captured for a NewTx TB event at `GenerateMacUlPdu` (`0x842d_098a`).
#[derive(Copy, Clone, Debug)]
pub struct NewTxEvent {
    pub tti_ms: u32,
    pub air_sti: u16,
    pub cc: u8,
    pub hq_id: u8,
    pub ext_bsr_mode: bool,
    pub ce_mask: u8,
    pub has_trailing_pad: bool,
    pub bsr_lcid: u8,
    pub bsr_is_padding: bool,
    pub tbs_bytes: u16,
    pub used_bytes: u16,
    pub bsr_ce: [u8; 3],
    pub phr_cc0: PhrSample,
    pub phr_cc1: PhrSample,
    pub ring1_bytes: u32,
    pub rlc_bo_bytes: u32,
}

/// Inputs captured for a HARQ retransmission at `L1A_L2_SendTxPdu` (`0x842c_ed8c`).
#[derive(Copy, Clone, Debug)]
pub struct RetxEvent {
    pub tti_ms: u32,
    pub air_sti: u16,
    pub cc: u8,
    pub hq_id: u8,
    pub adaptive: bool,
    pub tbs_bytes: u16,
    pub mcs: u8,
    pub tx_nb: u8,
    pub rv: u8,
    pub ring1_bytes: u32,
    pub rlc_bo_bytes: u32,
}

/// Inputs captured for a PUCCH SR transmission at `GetMacUlSR` (`0x842d_4cd4`).
#[derive(Copy, Clone, Debug)]
pub struct SrEvent {
    pub tti_ms: u32,
    pub air_sti: u16,
    pub sr_counter: u16,
    pub bsr_trigger_mask: u32,
    pub ring1_bytes: u32,
    pub rlc_bo_bytes: u32,
}

/// End-of-TTI observation from `ScheduleUlData` (`0x842d_8b7a`).
#[derive(Copy, Clone, Debug)]
pub struct TtiEndInput {
    pub tti_ms: u32,
    pub air_sti: u16,
    /// `0xff` if PCell had no grant/HARQ action in this `ScheduleUlData`, else `0..7`.
    pub hq0: u8,
    /// `0xff` if SCell had no grant/HARQ action in this `ScheduleUlData`, else `0..7`.
    pub hq1: u8,
    pub ul_ca_configured: bool,
    pub ring1_bytes: u32,
    pub rlc_bo_bytes: u32,
}

impl G1Block {
    /// Boot-default image constants. `enable == 0` (off), `freeze == 0`, `af_mode == 0`.
    pub const fn boot_default() -> Self {
        Self {
            magic: MAGIC,
            version: VERSION,
            enable: 0,
            freeze: 0,
            ring_base: RING_BASE,
            ring_slots: RING_SLOTS,
            record_size: RECORD_SIZE,
            wr_idx: 0,
            af_mode: 0,
            af_tti_thresh: 10,
            af_bo_thresh: 16_000,
            af_post_events: 128,
            af_post_countdown: 0,
            af_trigger_reason: FREEZE_NONE,
            af_trigger_seq: 0,
            af_trigger_tti: 0,
            cc0_nogrant_streak: 0,
            cc1_nogrant_streak: 0,
            cc_seen_mask: 0,
            last_grant_tti: 0,
            cnt_newtx_cc0: 0,
            cnt_newtx_cc1: 0,
            cnt_retx: 0,
            cnt_sr: 0,
            cnt_bsr: 0,
            cnt_phr: 0,
            snap_ce_buf: 0,
            snap_bsr_trig: 0,
            snap_phr_evt: 0,
            af_trigger_sti: 0,
            reserved: [0; 2],
        }
    }

    /// True only when `enable == ENABLE_ON` (`1`) and `freeze == 0`.
    /// Any unknown `enable` value (`!= 1`) is treated as off.
    #[inline]
    pub const fn is_recording(&self) -> bool {
        self.enable == ENABLE_ON && self.freeze == FREEZE_NONE
    }

    /// Advance the ring cursor and return the `(slot_index, seq)` for a new record,
    /// enforcing any active post-trigger countdown.
    pub fn alloc_slot(&mut self) -> Option<(usize, u32)> {
        if !self.is_recording() {
            return None;
        }
        let seq = self.wr_idx;
        self.wr_idx = seq.wrapping_add(1);
        if self.af_post_countdown > 0 {
            self.af_post_countdown -= 1;
            if self.af_post_countdown == 0 {
                self.freeze = if self.af_trigger_reason != 0 {
                    self.af_trigger_reason
                } else {
                    FREEZE_SCELL_DROP
                };
            }
        }
        Some(((seq & RING_MASK) as usize, seq))
    }

    /// Build and enqueue a NewTx TB record. Returns `(slot_index, record)` when written.
    #[inline]
    pub fn record_newtx(&mut self, ev: NewTxEvent) -> Option<(usize, TraceRecord)> {
        let (slot, seq) = self.alloc_slot()?;
        if (ev.cc & 1) == 0 {
            self.cnt_newtx_cc0 = self.cnt_newtx_cc0.wrapping_add(1);
        } else {
            self.cnt_newtx_cc1 = self.cnt_newtx_cc1.wrapping_add(1);
        }
        let has_bsr = (ev.ce_mask & 0x02) != 0;
        let has_phr = (ev.ce_mask & 0x1c) != 0;
        if has_bsr {
            self.cnt_bsr = self.cnt_bsr.wrapping_add(1);
        }
        if has_phr {
            self.cnt_phr = self.cnt_phr.wrapping_add(1);
        }
        let bsr_fmt = if has_bsr {
            BsrFormat::from_lcid(ev.bsr_lcid)
        } else {
            BsrFormat::None
        };
        let rec = TraceRecord {
            tti_ms: ev.tti_ms,
            air_sti: ev.air_sti,
            flags0: TraceRecord::pack_flags0(EventKind::NewTx, ev.cc, ev.hq_id, ev.ext_bsr_mode),
            flags1: TraceRecord::pack_flags1(ev.ce_mask, ev.has_trailing_pad, bsr_fmt),
            tbs_bytes: ev.tbs_bytes,
            used_or_retx: ev.used_bytes,
            bsr_trig: TraceRecord::pack_bsr_trig(
                self.snap_bsr_trig,
                ev.bsr_is_padding,
                self.snap_phr_evt,
            ),
            bsr_ce: if has_bsr { ev.bsr_ce } else { [0; 3] },
            phr_cc0_ph_v: ev.phr_cc0.pack_ph_v(),
            phr_cc0_pcmax: ev.phr_cc0.pack_pcmax(),
            phr_cc1_ph_v: ev.phr_cc1.pack_ph_v(),
            phr_cc1_pcmax: ev.phr_cc1.pack_pcmax(),
            ring1_bytes: ev.ring1_bytes,
            rlc_bo_bytes: ev.rlc_bo_bytes,
            seq,
        };
        Some((slot, rec))
    }

    /// Build and enqueue a HARQ retransmission record.
    #[inline]
    pub fn record_retx(&mut self, ev: RetxEvent) -> Option<(usize, TraceRecord)> {
        let (slot, seq) = self.alloc_slot()?;
        self.cnt_retx = self.cnt_retx.wrapping_add(1);
        let kind = if ev.adaptive {
            EventKind::AdaptRetx
        } else {
            EventKind::NonAdaptRetx
        };
        let rec = TraceRecord {
            tti_ms: ev.tti_ms,
            air_sti: ev.air_sti,
            flags0: TraceRecord::pack_flags0(kind, ev.cc, ev.hq_id, false),
            flags1: 0,
            tbs_bytes: ev.tbs_bytes,
            used_or_retx: TraceRecord::pack_retx_meta(ev.mcs, ev.tx_nb, ev.rv),
            bsr_trig: 0,
            bsr_ce: [0; 3],
            phr_cc0_ph_v: 0,
            phr_cc0_pcmax: 0xff,
            phr_cc1_ph_v: 0,
            phr_cc1_pcmax: 0xff,
            ring1_bytes: ev.ring1_bytes,
            rlc_bo_bytes: ev.rlc_bo_bytes,
            seq,
        };
        Some((slot, rec))
    }

    /// Build and enqueue a PUCCH SR record.
    #[inline]
    pub fn record_sr(&mut self, ev: SrEvent) -> Option<(usize, TraceRecord)> {
        let (slot, seq) = self.alloc_slot()?;
        self.cnt_sr = self.cnt_sr.wrapping_add(1);
        let rec = TraceRecord {
            tti_ms: ev.tti_ms,
            air_sti: ev.air_sti,
            flags0: TraceRecord::pack_flags0(EventKind::PucchSr, 0, 0, false),
            flags1: 0,
            tbs_bytes: ev.sr_counter,
            used_or_retx: 0,
            bsr_trig: TraceRecord::pack_bsr_trig(ev.bsr_trigger_mask, false, 0),
            bsr_ce: [0; 3],
            phr_cc0_ph_v: 0,
            phr_cc0_pcmax: 0xff,
            phr_cc1_ph_v: 0,
            phr_cc1_pcmax: 0xff,
            ring1_bytes: ev.ring1_bytes,
            rlc_bo_bytes: ev.rlc_bo_bytes,
            seq,
        };
        Some((slot, rec))
    }

    /// Evaluate the end-of-TTI auto-freeze state machine.
    ///
    /// Called at `ScheduleUlData` (`0x842d_8b7a`) when `enable == 1 && freeze == 0 && af_mode != 0`.
    pub fn on_tti_end(&mut self, inp: TtiEndInput) {
        if !self.is_recording() || self.af_mode == 0 || self.af_tti_thresh == 0 {
            return;
        }
        // Once a post-trigger countdown is already armed, let it finish cleanly.
        if self.af_post_countdown > 0 {
            return;
        }

        let got0 = inp.hq0 != 0xff;
        let got1 = inp.hq1 != 0xff;
        let cur_bo = inp.ring1_bytes.saturating_add(inp.rlc_bo_bytes);
        let allow_unseen = (self.af_mode & AF_ALLOW_UNSEEN) != 0;

        if got0 {
            self.cc0_nogrant_streak = 0;
            self.cc_seen_mask |= 1;
        }
        if got1 {
            self.cc1_nogrant_streak = 0;
            self.cc_seen_mask |= 2;
        }
        if got0 || got1 {
            self.last_grant_tti = inp.tti_ms;
        }

        let mut reason = FREEZE_NONE;

        if cur_bo >= self.af_bo_thresh {
            // 1. SCell drop: PCell got a grant, SCell did not.
            if got0
                && !got1
                && inp.ul_ca_configured
                && (self.af_mode & AF_SCELL_DROP) != 0
                && ((self.cc_seen_mask & 2) != 0 || allow_unseen)
            {
                self.cc1_nogrant_streak = self.cc1_nogrant_streak.saturating_add(1);
                if self.cc1_nogrant_streak >= self.af_tti_thresh {
                    reason = FREEZE_SCELL_DROP;
                }
            }
            // 2. PCell drop: SCell got a grant, PCell did not.
            if reason == FREEZE_NONE
                && got1
                && !got0
                && (self.af_mode & AF_PCELL_DROP) != 0
                && ((self.cc_seen_mask & 1) != 0 || allow_unseen)
            {
                self.cc0_nogrant_streak = self.cc0_nogrant_streak.saturating_add(1);
                if self.cc0_nogrant_streak >= self.af_tti_thresh {
                    reason = FREEZE_PCELL_DROP;
                }
            }
            // 3. Total UL stall: neither CC granted for `af_tti_thresh * 5` ms while buffered.
            if reason == FREEZE_NONE
                && !got0
                && !got1
                && (self.af_mode & AF_BOTH_STALL) != 0
                && (self.cc_seen_mask != 0 || allow_unseen)
            {
                let stall_ms = self.af_tti_thresh.saturating_mul(5);
                if inp.tti_ms.wrapping_sub(self.last_grant_tti) >= stall_ms {
                    reason = FREEZE_BOTH_STALL;
                }
            }
        } else {
            self.cc0_nogrant_streak = 0;
            self.cc1_nogrant_streak = 0;
        }

        if reason != FREEZE_NONE {
            self.af_trigger_reason = reason;
            self.af_trigger_seq = self.wr_idx;
            self.af_trigger_tti = inp.tti_ms;
            self.af_trigger_sti = inp.air_sti as u32;
            if self.af_post_events == 0 {
                self.freeze = reason;
            } else {
                self.af_post_countdown = self.af_post_events;
            }
        }
    }
}
