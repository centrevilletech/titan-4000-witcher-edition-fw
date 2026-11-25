//! Pure-Rust `no_std` behavioural model of the GDM7243A PDCP UL & LLCE0 pipeline:
//! - `do_tc` (`0x842e_5adc`) 250 ms submission cap tiers
//! - `l2_proc_pdcp_ul` (`0x842d_cbf4`) Ring 0 priority + staging cap + `/1500` vs byte-accurate pacing
//! - `proc_pdcp_ul` (`0x842d_c968`) SDU window & 64-descriptor LLCE0 batching
//! - `ul_cipher_submit` (`0x842d_9a48`) 2-slot LLCE0 pipeline (`busy` + `pending`)
//! - `ScheduleUlData` LLCE0 completion (`0x842d_8b86..0x842d_8d5a`)
//! - `pdcp_proc_tmr_discard` (`0x842d_d074`) & `pdcp_ul_proc_drb_cnf` (`0x842d_cf60`)

use modem_atlas::l2::{
    DO_TC_CAP_HIGH, DO_TC_CAP_LOW, DO_TC_CAP_MID, L2_PDCP_UL_DIVISOR_DEFAULT,
    UL_CIPHER_BATCH_MAX_DESCS,
};

/// Ring capacity for the host/`no_std` model (power of 2; matches stock 1024-slot `pdcp_to_rlc_ring`
/// and supports up to 512 in-flight packets per ring in simulations without heap allocation).
pub const MODEL_RING_CAP: usize = 512;
pub const MODEL_RING_MASK: usize = MODEL_RING_CAP - 1;
/// PDCP 12-bit SN window size (`0..4095`).
pub const PDCP_SN_MAX: u16 = 4096;
pub const PDCP_SN_MASK: u16 = PDCP_SN_MAX - 1;
/// Maximum packets in one LLCE0 hardware cipher batch (`0x842d_cae0`).
pub const LLCE_BATCH_CAP: usize = UL_CIPHER_BATCH_MAX_DESCS as usize;

/// Exact behavioural model of stock `do_tc` (`0x842e_5adc..0x842e_5b28`).
///
/// Computes the 250 ms PDCP/RLC staging cap (`L2_PDCP_UL_LIMIT_VA`):
/// - `tier = (ul_250ms_bytes >> 15) & 0xfff`
/// - `tier <= 8` (`<= 8.39 Mbps`): `32_768 B`
/// - `9..=32` (`8.39..=33.55 Mbps`): `65_536 B`
/// - `> 32` (`> 33.55 Mbps`): `131_072 B`
#[inline]
pub const fn do_tc_stock_cap(ul_250ms_bytes: u32) -> u32 {
    let tier = (ul_250ms_bytes >> 15) & 0x0fff;
    if tier <= 8 {
        DO_TC_CAP_LOW
    } else if tier <= 32 {
        DO_TC_CAP_MID
    } else {
        DO_TC_CAP_HIGH
    }
}

/// Tuned `do_tc` staging cap behind `N2OptState` (`FLAG_DO_TC_CAP`):
/// targets `target_ms` of staging queue at the measured 250 ms UL rate,
/// clamped to `[cap_min, cap_max]`.
#[inline]
pub const fn do_tc_tuned_cap(
    ul_250ms_bytes: u32,
    target_ms: u32,
    cap_min: u32,
    cap_max: u32,
) -> u32 {
    let desired = ((ul_250ms_bytes as u64) * (target_ms as u64) / 250) as u32;
    if desired < cap_min {
        cap_min
    } else if desired > cap_max {
        cap_max
    } else {
        desired
    }
}

/// Staging-cap admission policy in `l2_proc_pdcp_ul` (`0x842d_cca2..0x842d_ccdc`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum StagingPolicy {
    /// Stock `do_tc` (`32 / 64 / 128 KB`) with `/ 1500` integer floor division.
    StockDoTc,
    /// Tuned `do_tc` target-ms clamp with optional byte-accurate packet admission.
    TunedDoTc {
        target_ms: u32,
        cap_min: u32,
        cap_max: u32,
        byte_accurate: bool,
    },
    /// N4/N5 Hook 3 (`0x842d_cca2`): `clamp(g_ema_bytes + headroom_bytes, min_bytes, max_bytes)`.
    DynamicGrantCap {
        min_bytes: u32,
        max_bytes: u32,
        headroom_bytes: u32,
        byte_accurate: bool,
    },
}

/// Configuration for [`PdcpUlState`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PdcpConfig {
    /// PDCP `discardTimer` in ms (`750` on Nokia `pdcpProf2`; `0` = infinity / disabled).
    pub discard_timer_ms: u16,
    /// `L2_PDCP_UL_DIVISOR_VA` (`1500` in stock).
    pub divisor: u32,
    /// Staging limit policy.
    pub staging: StagingPolicy,
    /// Post-HARQ LLCE0 harvest latency in ms (stock `ScheduleUlData` harvests on the
    /// next 1 ms TTI after `HandleHarqProc`, so `1` ms nominal).
    pub llce_harvest_delay_ms: u32,
}

impl Default for PdcpConfig {
    fn default() -> Self {
        Self {
            discard_timer_ms: 750,
            divisor: L2_PDCP_UL_DIVISOR_DEFAULT,
            staging: StagingPolicy::StockDoTc,
            llce_harvest_delay_ms: 1,
        }
    }
}

/// Packet metadata tracked across Ring 0/1, PDCP SDU window, LLCE0, and RLC AM.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct IngressPkt {
    /// Unique monotonic packet ID for end-to-end latency attribution.
    pub id: u32,
    /// IP payload length in bytes (PDCP adds 2 B header for 12-bit SN).
    pub ip_len: u16,
    /// TTI (ms) when the packet entered Ring 0 or Ring 1.
    pub ring_enqueue_ms: u32,
}

/// One entry in the PDCP UL SDU tracking window (`PdcpUlSduEntry`).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PdcpSduRecord {
    pub active: bool,
    pub discarded: bool,
    pub pdcp_count: u32,
    pub pkt_id: u32,
    pub ip_len: u16,
    pub ring_enqueue_ms: u32,
    /// Exact `enqueue_tti_and_flags & !1` stored by `proc_pdcp_ul` (`0x842d_c98e`).
    pub pdcp_submit_ms: u32,
    /// Actual unmasked submit ms for sub-2 ms latency accounting.
    pub submit_exact_ms: u32,
    /// TTI (ms) when LLCE0 completed and committed this SDU to RLC.
    pub llce_done_ms: u32,
}

/// One ciphered PDCP PDU waiting in `pdcp_to_rlc_ring` (`PdcpToRlcEntry`).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PdcpToRlcPdu {
    pub pdcp_sn: u16,
    pub len: u16,
    pub pkt_id: u32,
    pub discarded: bool,
}

/// One hardware LLCE0 UL cipher batch (`UlCipherBatch`, max 64 descriptors).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct LlceBatch {
    pub in_use: bool,
    pub pkt_count: u32,
    pub byte_count: u32,
    pub submit_ms: u32,
    pub ready_ms: u32,
}

/// Result of a single `l2_proc_pdcp_ul` pass.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PdcpSubmitResult {
    pub ring0_submitted: u32,
    pub ring1_submitted: u32,
    pub effective_limit: u32,
    pub batch_kicked: bool,
    pub llce_full_stall: bool,
}

/// Result of an LLCE0 harvest pass (`ScheduleUlData` `0x842d_8b86..0x842d_8d5a`).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct LlceHarvestResult {
    pub harvested_pkts: u32,
    pub harvested_bytes: u32,
    pub kicked_pending: bool,
}

/// Range of PDCP SNs discarded by `pdcp_proc_tmr_discard` (`0x842d_d074`).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct DiscardRange {
    pub count: u32,
    pub first_sn: u16,
    pub last_sn: u16,
}

/// Fixed-size ring buffer (`no_std`, zero heap allocation).
#[derive(Clone)]
pub struct RingQueue<T: Copy + Default> {
    slots: [T; MODEL_RING_CAP],
    wr: usize,
    rd: usize,
}

impl<T: Copy + Default> RingQueue<T> {
    pub fn new() -> Self {
        Self {
            slots: [T::default(); MODEL_RING_CAP],
            wr: 0,
            rd: 0,
        }
    }

    #[inline]
    pub const fn len(&self) -> usize {
        self.wr.wrapping_sub(self.rd) & MODEL_RING_MASK
    }

    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[inline]
    pub const fn free(&self) -> usize {
        (MODEL_RING_CAP - 1) - self.len()
    }

    #[inline]
    pub fn push(&mut self, item: T) -> bool {
        if self.free() == 0 {
            return false;
        }
        self.slots[self.wr] = item;
        self.wr = (self.wr + 1) & MODEL_RING_MASK;
        true
    }

    #[inline]
    pub fn pop(&mut self) -> Option<T> {
        if self.is_empty() {
            return None;
        }
        let item = self.slots[self.rd];
        self.rd = (self.rd + 1) & MODEL_RING_MASK;
        Some(item)
    }

    #[inline]
    pub fn peek_at(&self, offset: usize) -> Option<&T> {
        if offset >= self.len() {
            return None;
        }
        Some(&self.slots[(self.rd + offset) & MODEL_RING_MASK])
    }
}

impl<T: Copy + Default> Default for RingQueue<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// Complete PDCP UL + LLCE0 state for one DRB (e.g. default QCI 9 bearer).
pub struct PdcpUlState {
    pub cfg: PdcpConfig,
    /// High-priority Ring 0 (`rbc.ring0`).
    pub ring0: RingQueue<IngressPkt>,
    /// Bulk Ring 1 (`rbc.ring1`).
    pub ring1: RingQueue<IngressPkt>,
    /// `rbc.ring_pending_bytes` (`+0x130`): Ring 0 + Ring 1 + in-flight LLCE0 bytes.
    pub ring_pending_bytes: u32,
    /// `rbc.pdcp_tx_count` (`+0xd8`): 32-bit PDCP UL COUNT.
    pub pdcp_tx_count: u32,
    /// `rbc.pdcp_ul_oldest_sn` (`+0xdc`): oldest un-ACKed PDCP SN.
    pub pdcp_ul_oldest_sn: u16,
    /// `rbc.pdcp_ul_win` (`+0xe4`): active un-ACKed SDU count.
    pub sdu_win_active: u32,
    /// 4,096-entry SDU window indexed by `pdcp_count & 0xfff`.
    pub sdu_win: [PdcpSduRecord; PDCP_SN_MAX as usize],

    /// `rbc.pdcp_to_rlc_ring` (`+0xf8`): 3-pointer ring (`wr`, `committed`, `rd`).
    pub pdcp_to_rlc: [PdcpToRlcPdu; MODEL_RING_CAP],
    /// `+0xfc`: write index (advanced by `proc_pdcp_ul` at LLCE0 submit).
    pub pdcp_to_rlc_wr: u16,
    /// `+0xfe`: committed index (advanced on LLCE0 harvest).
    pub pdcp_to_rlc_committed: u16,
    /// `+0x100`: read index (advanced by RLC consumption or discard).
    pub pdcp_to_rlc_rd: u16,
    /// `+0x106`: committed ciphered PDU count waiting for RLC.
    pub pdcp_to_rlc_cnt: u16,
    /// `+0x10a`: header overhead BO (`2 B` per queued ciphered PDU).
    pub pdcp_rlc_hdr_bo: u16,
    /// `+0x10c`: committed ciphered PDCP bytes ready in RLC TX queue.
    pub pdcp_rlc_tx_bo: u32,

    /// Two static LLCE0 batch slots (`0x84d9_5050`), plus `busy` and `pending` indices.
    pub batches: [LlceBatch; 2],
    pub llce_busy: Option<usize>,
    pub llce_pending: Option<usize>,

    /// `L2_PDCP_UL_LIMIT_VA` (`0x84dd_977c`) current limit in bytes.
    pub pdcp_ul_limit: u32,
    /// `L2_UL_250MS_BYTES_VA` (`0x84dd_9774`) accumulator for 250 ms `do_tc`.
    pub ul_250ms_bytes: u32,
    /// Last 250 ms `do_tc` tick timestamp.
    pub last_do_tc_ms: u32,
    /// N4/N5 grant EMA (`G_ema`, bytes per 5 ms UL TTI) for `DynamicGrantCap`.
    pub grant_ema_bytes: u32,

    /// Telemetry counters.
    pub total_submitted_pkts: u64,
    pub total_discarded_pkts: u64,
    pub total_acked_pkts: u64,
    pub llce_busy_stalls: u64,
}

impl PdcpUlState {
    pub fn new(cfg: PdcpConfig) -> Self {
        let initial_limit = match cfg.staging {
            StagingPolicy::StockDoTc => DO_TC_CAP_LOW,
            StagingPolicy::TunedDoTc { cap_min, .. } => cap_min,
            StagingPolicy::DynamicGrantCap { min_bytes, .. } => min_bytes,
        };
        Self {
            cfg,
            ring0: RingQueue::new(),
            ring1: RingQueue::new(),
            ring_pending_bytes: 0,
            pdcp_tx_count: 0,
            pdcp_ul_oldest_sn: 0,
            sdu_win_active: 0,
            sdu_win: [PdcpSduRecord::default(); PDCP_SN_MAX as usize],
            pdcp_to_rlc: [PdcpToRlcPdu::default(); MODEL_RING_CAP],
            pdcp_to_rlc_wr: 0,
            pdcp_to_rlc_committed: 0,
            pdcp_to_rlc_rd: 0,
            pdcp_to_rlc_cnt: 0,
            pdcp_rlc_hdr_bo: 0,
            pdcp_rlc_tx_bo: 0,
            batches: [LlceBatch::default(); 2],
            llce_busy: None,
            llce_pending: None,
            pdcp_ul_limit: initial_limit,
            ul_250ms_bytes: 0,
            last_do_tc_ms: 0,
            grant_ema_bytes: 0,
            total_submitted_pkts: 0,
            total_discarded_pkts: 0,
            total_acked_pkts: 0,
            llce_busy_stalls: 0,
        }
    }

    /// Enqueue a high-priority packet (e.g. TCP ACK / sparse flow) into Ring 0.
    pub fn enqueue_ring0(&mut self, pkt: IngressPkt) -> bool {
        if !self.ring0.push(pkt) {
            return false;
        }
        // PDCP PDU length = IP payload + 2 B (12-bit SN header)
        self.ring_pending_bytes = self.ring_pending_bytes.saturating_add(pkt.ip_len as u32 + 2);
        true
    }

    /// Enqueue a bulk data packet into Ring 1.
    pub fn enqueue_ring1(&mut self, pkt: IngressPkt) -> bool {
        if !self.ring1.push(pkt) {
            return false;
        }
        self.ring_pending_bytes = self.ring_pending_bytes.saturating_add(pkt.ip_len as u32 + 2);
        true
    }

    /// Number of free slots in `pdcp_to_rlc_ring`, matching `0x842d_cc60..0x842d_cc82`:
    /// `(rd - (wr + 1)) & (size - 1)`.
    #[inline]
    pub const fn pdcp_to_rlc_free_slots(&self) -> usize {
        (self
            .pdcp_to_rlc_rd
            .wrapping_sub(self.pdcp_to_rlc_wr.wrapping_add(1)) as usize)
            & MODEL_RING_MASK
    }

    /// Record transmitted bytes toward the 250 ms `do_tc` accumulator and N4/N5 grant EMA.
    pub fn record_ul_tx_bytes(&mut self, bytes: u32) {
        self.ul_250ms_bytes = self.ul_250ms_bytes.saturating_add(bytes);
    }

    /// Update N4/N5 grant EMA (`G_ema = (3 * G_ema + grant) >> 2` per UL grant).
    pub fn update_grant_ema(&mut self, grant_bytes: u32) {
        if self.grant_ema_bytes == 0 {
            self.grant_ema_bytes = grant_bytes;
        } else {
            self.grant_ema_bytes = (self.grant_ema_bytes * 3 + grant_bytes) >> 2;
        }
    }

    /// Run the 250 ms `do_tc` (`0x842e_5adc`) cap update if `now_ms - last_do_tc_ms >= 250`.
    pub fn maybe_run_do_tc(&mut self, now_ms: u32) -> bool {
        if now_ms.wrapping_sub(self.last_do_tc_ms) < 250 {
            return false;
        }
        self.last_do_tc_ms = now_ms;
        let bytes = self.ul_250ms_bytes;
        self.ul_250ms_bytes = 0;
        match self.cfg.staging {
            StagingPolicy::StockDoTc => {
                self.pdcp_ul_limit = do_tc_stock_cap(bytes);
            }
            StagingPolicy::TunedDoTc {
                target_ms,
                cap_min,
                cap_max,
                ..
            } => {
                self.pdcp_ul_limit = do_tc_tuned_cap(bytes, target_ms, cap_min, cap_max);
            }
            StagingPolicy::DynamicGrantCap { .. } => {
                // Stock do_tc still updates 0x84dd_97bc, though Hook 3 overrides it on read.
                self.pdcp_ul_limit = do_tc_stock_cap(bytes);
            }
        }
        true
    }

    /// Effective PDCP staging limit returned at `0x842d_cca2` (either `pdcp_ul_limit`
    /// or N4/N5 Hook 3 dynamic cap).
    pub fn effective_staging_limit(&self) -> u32 {
        match self.cfg.staging {
            StagingPolicy::StockDoTc | StagingPolicy::TunedDoTc { .. } => self.pdcp_ul_limit,
            StagingPolicy::DynamicGrantCap {
                min_bytes,
                max_bytes,
                headroom_bytes,
                ..
            } => {
                let raw = self.grant_ema_bytes.saturating_add(headroom_bytes);
                if raw < min_bytes {
                    min_bytes
                } else if raw > max_bytes {
                    max_bytes
                } else {
                    raw
                }
            }
        }
    }

    #[inline]
    fn byte_accurate_staging(&self) -> bool {
        match self.cfg.staging {
            StagingPolicy::StockDoTc => false,
            StagingPolicy::TunedDoTc { byte_accurate, .. }
            | StagingPolicy::DynamicGrantCap { byte_accurate, .. } => byte_accurate,
        }
    }

    /// Allocate a free LLCE0 batch slot (`0x842d_cb16..0x842d_cb48`), returning `None` if both
    /// slots are occupied (`bitmap == 3`).
    fn alloc_batch(&mut self) -> Option<usize> {
        for (i, b) in self.batches.iter_mut().enumerate() {
            if !b.in_use {
                *b = LlceBatch {
                    in_use: true,
                    pkt_count: 0,
                    byte_count: 0,
                    submit_ms: 0,
                    ready_ms: 0,
                };
                return Some(i);
            }
        }
        None
    }

    /// Submit a populated batch to `LLCE0` (`ul_cipher_submit` `0x842d_9a48`).
    fn submit_batch(&mut self, slot: usize, now_ms: u32) -> bool {
        self.batches[slot].submit_ms = now_ms;
        if self.llce_busy.is_none() {
            self.batches[slot].ready_ms = now_ms.saturating_add(self.cfg.llce_harvest_delay_ms);
            self.llce_busy = Some(slot);
            true
        } else {
            // Hardware busy: park in L2_CIPHER_PEND_VA until next harvest kicks it.
            self.llce_pending = Some(slot);
            false
        }
    }

    /// Exact model of `proc_pdcp_ul` (`0x842d_c968`) draining `max_pkts` from `from_ring0`.
    fn proc_pdcp_ul_ring(
        &mut self,
        from_ring0: bool,
        max_pkts: usize,
        cur_batch: &mut Option<usize>,
        now_ms: u32,
    ) -> (u32, bool) {
        let mut submitted = 0u32;
        let mut llce_stalled = false;
        let ts_even = now_ms & !1; // exact 0x842d_c98e: bic r3, r1, #1

        for _ in 0..max_pkts {
            // Check SDU window slot collision (0x842d_caf0..0x842d_cb0e)
            let sn = (self.pdcp_tx_count as u16) & PDCP_SN_MASK;
            if self.sdu_win[sn as usize].active {
                // Slot still occupied (window full / wrap): skip SN just like 0x842d_cb66.
                self.pdcp_tx_count = self.pdcp_tx_count.wrapping_add(1);
                continue;
            }

            if cur_batch.is_none() {
                match self.alloc_batch() {
                    Some(slot) => *cur_batch = Some(slot),
                    None => {
                        llce_stalled = true;
                        self.llce_busy_stalls += 1;
                        break;
                    }
                }
            }

            let pkt = if from_ring0 {
                match self.ring0.pop() {
                    Some(p) => p,
                    None => break,
                }
            } else {
                match self.ring1.pop() {
                    Some(p) => p,
                    None => break,
                }
            };

            let pdu_len = pkt.ip_len.saturating_add(2); // 12-bit PDCP SN header = 2 B
            let count = self.pdcp_tx_count;
            self.pdcp_tx_count = self.pdcp_tx_count.wrapping_add(1);

            // Record in PDCP UL SDU window (+0x00..+0x0c)
            self.sdu_win[sn as usize] = PdcpSduRecord {
                active: true,
                discarded: false,
                pdcp_count: count,
                pkt_id: pkt.id,
                ip_len: pkt.ip_len,
                ring_enqueue_ms: pkt.ring_enqueue_ms,
                pdcp_submit_ms: ts_even,
                submit_exact_ms: now_ms,
                llce_done_ms: 0,
            };
            self.sdu_win_active = self.sdu_win_active.saturating_add(1);

            // Append to pdcp_to_rlc_ring at wr (0x842d_ca5e..0x842d_ca7a)
            let wr = self.pdcp_to_rlc_wr as usize;
            self.pdcp_to_rlc[wr] = PdcpToRlcPdu {
                pdcp_sn: sn,
                len: pdu_len,
                pkt_id: pkt.id,
                discarded: false,
            };
            self.pdcp_to_rlc_wr = ((wr + 1) & MODEL_RING_MASK) as u16;

            // Accumulate into active LLCE0 batch (0x842d_ca3c..0x842d_cae2)
            let slot = cur_batch.unwrap();
            self.batches[slot].pkt_count += 1;
            self.batches[slot].byte_count += pdu_len as u32;
            submitted += 1;
            self.total_submitted_pkts += 1;

            // Flush batch immediately at 64 descriptors (0x842d_cae0)
            if self.batches[slot].pkt_count as usize >= LLCE_BATCH_CAP {
                self.submit_batch(slot, now_ms);
                *cur_batch = None;
            }
        }
        (submitted, llce_stalled)
    }

    /// Exact behavioural model of `l2_proc_pdcp_ul` (`0x842d_cbf4..0x842d_cd80`).
    ///
    /// 1. Drains Ring 0 first up to `pdcp_to_rlc_free_slots()`.
    /// 2. Computes `cur_bo = ring0_submitted * 64 + pdcp_rlc_hdr_bo + pdcp_rlc_tx_bo`.
    /// 3. Reads `limit = effective_staging_limit()`.
    /// 4. If `limit > cur_bo`:
    ///    - Stock mode: `pkts = min(free_rem, ring1.len(), (limit - cur_bo) / divisor)`.
    ///    - Byte-accurate mode (`N2OptState` bit 2): counts exact head packets in Ring 1
    ///      whose `(ip_len + 2)` bytes fit within `limit - cur_bo`.
    /// 5. Kicks any non-empty LLCE0 batch via `ul_cipher_submit`.
    pub fn proc_pdcp_ul(&mut self, now_ms: u32) -> PdcpSubmitResult {
        let free_slots = self.pdcp_to_rlc_free_slots();
        let r0_occ = self.ring0.len();
        let (r0_take, free_rem) = if free_slots < r0_occ {
            (free_slots, 0)
        } else {
            (r0_occ, free_slots - r0_occ)
        };

        let mut cur_batch: Option<usize> = None;
        let mut r0_submitted = 0u32;
        let mut r1_submitted = 0u32;
        let mut llce_stalled = false;

        if r0_take > 0 {
            let (n, stalled) = self.proc_pdcp_ul_ring(true, r0_take, &mut cur_batch, now_ms);
            r0_submitted = n;
            llce_stalled |= stalled;
        }

        // Exact 0x842d_cc86 + 0x842d_cd1a + 0x842d_cca0:
        // cur_bo = (r0_take << 6) + pdcp_rlc_hdr_bo + pdcp_rlc_tx_bo
        let cur_bo = (r0_take as u32)
            .wrapping_shl(6)
            .wrapping_add(self.pdcp_rlc_hdr_bo as u32)
            .wrapping_add(self.pdcp_rlc_tx_bo);
        let limit = self.effective_staging_limit();

        if limit > cur_bo && free_rem > 0 && !self.ring1.is_empty() {
            let headroom = limit - cur_bo;
            let max_r1 = free_rem.min(self.ring1.len());
            let r1_take = if self.byte_accurate_staging() {
                let mut acc = 0u32;
                let mut cnt = 0usize;
                while cnt < max_r1 {
                    let pkt = self.ring1.peek_at(cnt).unwrap();
                    let bytes = pkt.ip_len as u32 + 2;
                    if acc + bytes > headroom {
                        break;
                    }
                    acc += bytes;
                    cnt += 1;
                }
                cnt
            } else {
                let div = self.cfg.divisor.max(1);
                ((headroom / div) as usize).min(max_r1)
            };

            if r1_take > 0 {
                let (n, stalled) = self.proc_pdcp_ul_ring(false, r1_take, &mut cur_batch, now_ms);
                r1_submitted = n;
                llce_stalled |= stalled;
            }
        }

        let mut batch_kicked = false;
        if let Some(slot) = cur_batch {
            if self.batches[slot].pkt_count > 0 {
                batch_kicked = self.submit_batch(slot, now_ms);
            } else {
                self.batches[slot].in_use = false;
            }
        }

        PdcpSubmitResult {
            ring0_submitted: r0_submitted,
            ring1_submitted: r1_submitted,
            effective_limit: limit,
            batch_kicked,
            llce_full_stall: llce_stalled,
        }
    }

    /// Exact model of `ScheduleUlData` LLCE0 completion (`0x842d_8b86..0x842d_8d5a`).
    ///
    /// Called once per 1 ms TTI (after `HandleHarqProc`). When the active LLCE0 batch
    /// has reached `ready_ms`:
    /// - Advances `pdcp_to_rlc_committed`, `pdcp_to_rlc_cnt`, `pdcp_rlc_hdr_bo (+2/pkt)`,
    ///   and `pdcp_rlc_tx_bo (+byte_count)`.
    /// - Subtracts `byte_count` (saturating at 0) from `ring_pending_bytes`.
    /// - If a `pending` batch is waiting, promotes and kicks it to `LLCE0` immediately.
    pub fn harvest_llce(&mut self, now_ms: u32) -> LlceHarvestResult {
        let Some(busy_slot) = self.llce_busy else {
            return LlceHarvestResult::default();
        };
        if now_ms < self.batches[busy_slot].ready_ms {
            return LlceHarvestResult::default();
        }

        let pkts = self.batches[busy_slot].pkt_count;
        let bytes = self.batches[busy_slot].byte_count;
        self.batches[busy_slot] = LlceBatch::default();
        self.llce_busy = None;

        // Stamp llce_done_ms on newly committed SDUs
        for k in 0..(pkts as usize) {
            let idx = (self.pdcp_to_rlc_committed as usize + k) & MODEL_RING_MASK;
            let sn = self.pdcp_to_rlc[idx].pdcp_sn;
            self.sdu_win[sn as usize].llce_done_ms = now_ms;
        }

        // Exact 0x842d_8cfa..0x842d_8d3c updates
        self.pdcp_to_rlc_committed =
            ((self.pdcp_to_rlc_committed as usize + pkts as usize) & MODEL_RING_MASK) as u16;
        self.pdcp_to_rlc_cnt = self.pdcp_to_rlc_cnt.wrapping_add(pkts as u16);
        self.pdcp_rlc_hdr_bo = self
            .pdcp_rlc_hdr_bo
            .wrapping_add((pkts as u16).wrapping_shl(1));
        self.pdcp_rlc_tx_bo = self.pdcp_rlc_tx_bo.wrapping_add(bytes);
        self.ring_pending_bytes = self.ring_pending_bytes.saturating_sub(bytes);

        let mut kicked_pending = false;
        if let Some(pend_slot) = self.llce_pending.take() {
            self.batches[pend_slot].ready_ms =
                now_ms.saturating_add(self.cfg.llce_harvest_delay_ms);
            self.llce_busy = Some(pend_slot);
            kicked_pending = true;
        }

        LlceHarvestResult {
            harvested_pkts: pkts,
            harvested_bytes: bytes,
            kicked_pending,
        }
    }

    /// Exact model of `pdcp_proc_tmr_discard` (`0x842d_d074..0x842d_d132`).
    ///
    /// Walks from `pdcp_ul_oldest_sn` forward while entries are active and
    /// `(now_ms - entry.pdcp_submit_ms) >= discard_timer_ms`, marking bit 0 (`discarded`)
    /// and returning the `[first_sn..=last_sn]` range to pass to RLC `rlc_ul_proc_discard_req`.
    pub fn proc_discard_timer(&mut self, now_ms: u32) -> DiscardRange {
        let tmr = self.cfg.discard_timer_ms as u32;
        if tmr == 0 || self.sdu_win_active == 0 {
            return DiscardRange::default();
        }

        let mut sn = self.pdcp_ul_oldest_sn;
        let next_sn = (self.pdcp_tx_count as u16) & PDCP_SN_MASK;
        let mut first_sn = 0u16;
        let mut last_sn = 0u16;
        let mut count = 0u32;

        while sn != next_sn {
            let entry = &mut self.sdu_win[sn as usize];
            if !entry.active {
                sn = (sn + 1) & PDCP_SN_MASK;
                continue;
            }
            if entry.discarded {
                sn = (sn + 1) & PDCP_SN_MASK;
                continue;
            }
            let age = now_ms.wrapping_sub(entry.pdcp_submit_ms);
            if age < tmr {
                break;
            }
            entry.discarded = true;
            if count == 0 {
                first_sn = sn;
            }
            last_sn = sn;
            count += 1;
            self.total_discarded_pkts += 1;
            sn = (sn + 1) & PDCP_SN_MASK;
        }

        DiscardRange {
            count,
            first_sn,
            last_sn,
        }
    }

    /// Exact model of `rlc_ul_proc_discard_req` (`0x842d_cd90`) on `pdcp_to_rlc_ring`:
    /// removes un-transmitted committed PDCP PDUs whose SN lies in `[first_sn..=last_sn]`,
    /// freeing their SDU window entries and subtracting their BO.
    pub fn discard_untransmitted(&mut self, range: DiscardRange) -> u32 {
        if range.count == 0 || self.pdcp_to_rlc_cnt == 0 {
            return 0;
        }
        let mut removed = 0u32;
        while self.pdcp_to_rlc_cnt > 0 && self.pdcp_to_rlc_rd != self.pdcp_to_rlc_committed {
            let rd = self.pdcp_to_rlc_rd as usize;
            let pdu = self.pdcp_to_rlc[rd];
            let span = range.last_sn.wrapping_sub(range.first_sn) & PDCP_SN_MASK;
            let off = pdu.pdcp_sn.wrapping_sub(range.first_sn) & PDCP_SN_MASK;
            if off > span {
                break;
            }
            self.pdcp_to_rlc[rd].discarded = true;
            self.pdcp_to_rlc_rd = ((rd + 1) & MODEL_RING_MASK) as u16;
            self.pdcp_to_rlc_cnt -= 1;
            self.pdcp_rlc_hdr_bo = self.pdcp_rlc_hdr_bo.saturating_sub(2);
            self.pdcp_rlc_tx_bo = self.pdcp_rlc_tx_bo.saturating_sub(pdu.len as u32);
            if self.sdu_win[pdu.pdcp_sn as usize].active {
                self.sdu_win[pdu.pdcp_sn as usize].active = false;
                self.sdu_win_active = self.sdu_win_active.saturating_sub(1);
            }
            removed += 1;
        }
        self.advance_oldest_sn();
        removed
    }

    /// Exact model of `pdcp_ul_proc_drb_cnf` (`0x842d_cf60`): releases confirmed PDCP SNs
    /// `[start_sn..=end_sn]` from `pdcp_ul_win` and advances `pdcp_ul_oldest_sn`.
    pub fn proc_drb_cnf(&mut self, start_sn: u16, end_sn: u16) -> u32 {
        let span = end_sn.wrapping_sub(start_sn) & PDCP_SN_MASK;
        let mut freed = 0u32;
        for step in 0..=span {
            let sn = start_sn.wrapping_add(step) & PDCP_SN_MASK;
            let entry = &mut self.sdu_win[sn as usize];
            if entry.active {
                entry.active = false;
                self.sdu_win_active = self.sdu_win_active.saturating_sub(1);
                self.total_acked_pkts += 1;
                freed += 1;
            }
        }
        self.advance_oldest_sn();
        freed
    }

    fn advance_oldest_sn(&mut self) {
        let next_sn = (self.pdcp_tx_count as u16) & PDCP_SN_MASK;
        while self.pdcp_ul_oldest_sn != next_sn
            && !self.sdu_win[self.pdcp_ul_oldest_sn as usize].active
        {
            self.pdcp_ul_oldest_sn = (self.pdcp_ul_oldest_sn + 1) & PDCP_SN_MASK;
        }
    }

    /// Pop the next committed ciphered PDCP PDU for RLC AM transmission.
    pub fn pop_committed_to_rlc(&mut self) -> Option<PdcpToRlcPdu> {
        if self.pdcp_to_rlc_cnt == 0 || self.pdcp_to_rlc_rd == self.pdcp_to_rlc_committed {
            return None;
        }
        let rd = self.pdcp_to_rlc_rd as usize;
        let pdu = self.pdcp_to_rlc[rd];
        self.pdcp_to_rlc_rd = ((rd + 1) & MODEL_RING_MASK) as u16;
        self.pdcp_to_rlc_cnt -= 1;
        self.pdcp_rlc_hdr_bo = self.pdcp_rlc_hdr_bo.saturating_sub(2);
        Some(pdu)
    }

    /// Peek at the next committed ciphered PDCP PDU without removing it.
    pub fn peek_committed_to_rlc(&self) -> Option<PdcpToRlcPdu> {
        if self.pdcp_to_rlc_cnt == 0 || self.pdcp_to_rlc_rd == self.pdcp_to_rlc_committed {
            return None;
        }
        Some(self.pdcp_to_rlc[self.pdcp_to_rlc_rd as usize])
    }
}
