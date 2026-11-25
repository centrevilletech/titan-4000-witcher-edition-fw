//! 1 ms TDD Config 2 end-to-end uplink simulator producing packet-level latency budgets
//! split across Ring 1, LLCE0 harvest, PDCP/RLC staging, TDD framing, HARQ retx, and RLC retx.

use crate::bsr::{calc_lcg_bo, search_bsr_idx};
use crate::pdcp::{IngressPkt, PdcpConfig, PdcpUlState, StagingPolicy};
use crate::rlc::{GeneratedPduKind, RlcAmConfig, RlcAmUlState, RLC_AM_SN_MASK};

/// Maximum HARQ in-flight processes tracked across up to 2 UL carriers.
const HARQ_SLOTS: usize = 32;
/// Maximum in-flight peer RLC STATUS reports queued for DL return.
const STATUS_Q_CAP: usize = 16;
/// Maximum packets traced for percentile latency budget computation (zero-heap `no_std`).
pub const MAX_TRACED_PKTS: usize = 4096;

/// Link & scheduler configuration for TDD Config 2 (`DSUDDDSUDD`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct LinkConfig {
    /// Number of UL carriers (`1` or `2`).
    pub num_ccs: u8,
    /// PHY grant bytes per UL subframe (every 5 ms) **per carrier**.
    /// - 1CC 7.3 Mbps TCP / ~8.0 Mbps PHY -> `5000` B/UL-TTI (`1 CC`)
    /// - 2CC 14.9 Mbps TCP / ~17.5 Mbps PHY -> `5500` B/UL-TTI per CC (`11,000` B total)
    pub grant_bytes_per_cc: u32,
    /// UL HARQ first-attempt BLER in permille (`100` = 10% target BLER).
    pub harq_bler_permille: u16,
    /// `maxHARQ-Tx` (`7` on Nokia CBRS).
    pub max_harq_tx: u8,
    /// TDD Config 2 synchronous UL HARQ RTT in ms (`10` ms exact).
    pub harq_rtt_ms: u32,
    /// Peer eNodeB RLC STATUS return delay after a polled AMD PDU is received (ms).
    pub status_rtt_ms: u32,
    /// Enable N4 `TRUE_BO` in BSR reporting.
    pub n4_true_bo: bool,
    /// Extended BSR table enabled (`MacUlCfg.ext_bsr == 2`).
    pub ext_bsr: bool,
    /// Offered bulk arrival rate in bytes/ms (e.g. `1000` = 8 Mbps, `2190` = 17.5 Mbps).
    /// Set to `0` to saturate Ring 1 continuously to `target_ring1_bytes`.
    pub arrival_bytes_per_ms: u32,
    /// Packet IP payload size in bytes (`1500` for MTU bulk TCP, or smaller for mixed traffic).
    pub pkt_ip_len: u16,
    /// Optional steady Ring-1 backlog maintained by an upstream AQM/CC loop (bytes).
    /// When non-zero, arrivals top Ring 1 up to this level each ms so post-Ring-1 behaviour
    /// can be measured cleanly at any chosen Ring-1 depth.
    pub target_ring1_bytes: u32,
    /// Deterministic PRNG seed for HARQ loss simulation.
    pub seed: u64,
}

impl Default for LinkConfig {
    fn default() -> Self {
        Self {
            num_ccs: 2,
            grant_bytes_per_cc: 5500,
            harq_bler_permille: 100,
            max_harq_tx: 7,
            harq_rtt_ms: 10,
            status_rtt_ms: 12,
            n4_true_bo: true,
            ext_bsr: false,
            arrival_bytes_per_ms: 0,
            pkt_ip_len: 1480,
            target_ring1_bytes: 0,
            seed: 0x5EED_C0DE_2026_1125,
        }
    }
}

/// Per-packet time split across every stage of the uplink pipeline (ms).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PacketTrace {
    pub pkt_id: u32,
    /// Wait inside Ring 1 before `l2_proc_pdcp_ul` admission.
    pub ring1_ms: u16,
    /// Wait from `proc_pdcp_ul` submit to LLCE0 completion harvest (`ScheduleUlData`).
    pub llce_harvest_ms: u16,
    /// Wait inside `pdcp_to_rlc_ring` / RLC AM TX queue until first MAC TB transmission,
    /// minus the TDD UL subframe alignment component.
    pub rlc_queue_ms: u16,
    /// Residual TDD Config 2 UL subframe alignment (`0..=4` ms).
    pub tdd_align_ms: u16,
    /// Delay added by UL HARQ retransmissions (`10` ms per retry) + eNB in-order HoL blocking.
    pub harq_retx_ms: u16,
    /// Delay added by RLC AM retransmission after HARQ failure (`0` on normal packets).
    pub rlc_retx_ms: u16,
    /// Total post-Ring-1 delivery time (`llce + rlc_queue + tdd + harq + rlc_retx`).
    pub post_ring1_ms: u16,
    /// End-to-end sojourn (`ring1_ms + post_ring1_ms`).
    pub total_ms: u16,
}

/// Summary statistics (p50, p90, p99, mean × 10 in tenths of ms) for one metric.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct StageStats {
    pub p50_ms: u16,
    pub p90_ms: u16,
    pub p99_ms: u16,
    /// Mean latency in tenths of a millisecond (`127` = `12.7 ms`).
    pub mean_tenths_ms: u32,
}

/// Complete simulated latency budget and counters.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct BudgetSummary {
    pub delivered_pkts: u32,
    /// Achieved delivered payload throughput in kbps.
    pub throughput_kbps: u32,
    pub ring1: StageStats,
    pub llce_harvest: StageStats,
    pub rlc_queue: StageStats,
    pub tdd_align: StageStats,
    pub harq_retx: StageStats,
    pub rlc_retx: StageStats,
    pub post_ring1: StageStats,
    /// `post_ring1` relative to minimum observed packet (comparable to `tsq.py` with zero Ring 1).
    pub post_ring1_above_min: StageStats,
    pub total: StageStats,
    /// `total` relative to minimum observed packet (comparable directly to `tsq.py`!).
    pub total_above_min: StageStats,
    pub harq_retx_events: u32,
    pub harq_fail_events: u32,
    pub rlc_retx_pdus: u32,
    pub rlc_win_stalls: u32,
    pub pdcp_discards: u32,
    pub last_bsr_idx: u8,
    pub mean_staging_bytes: u32,
}

#[derive(Copy, Clone, Default)]
struct HarqInFlight {
    active: bool,
    sn: u16,
    poll_bit: bool,
    tx_count: u8,
    next_event_ms: u32,
}

#[derive(Copy, Clone, Default)]
struct PeerStatusEvent {
    valid: bool,
    deliver_ms: u32,
    ack_sn: u16,
    nack_cnt: u8,
    nacks: [u16; 8],
}

#[derive(Copy, Clone, Default)]
struct PktRecord {
    valid: bool,
    delivered: bool,
    ring_in_ms: u32,
    pdcp_sub_ms: u32,
    llce_done_ms: u32,
    first_tx_ms: u32,
    rlc_sn: u16,
    had_rlc_retx: bool,
}

/// Small deterministic xorshift64* PRNG (`no_std`).
struct Rng(u64);
impl Rng {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn hit_permille(&mut self, permille: u16) -> bool {
        if permille == 0 {
            return false;
        }
        (self.next_u64() % 1000) < (permille as u64)
    }
}

/// End-to-end 1 ms TDD Config 2 uplink pipeline simulator.
pub struct UplinkSim {
    pub pdcp: PdcpUlState,
    pub rlc: RlcAmUlState,
    pub link: LinkConfig,
    rng: Rng,
    harq: [HarqInFlight; HARQ_SLOTS],
    status_q: [PeerStatusEvent; STATUS_Q_CAP],
    /// eNodeB RLC AM RX reorder state (`VR(R)` and received SN bitmap).
    enb_vr_r: u16,
    enb_rx_bitmap: [bool; 1024],
    /// Per-packet timestamp table indexed by `pkt_id % MAX_TRACED_PKTS`.
    pkts: [PktRecord; MAX_TRACED_PKTS],
    next_pkt_id: u32,
    arrival_credit_bytes: u32,
    traces: [PacketTrace; MAX_TRACED_PKTS],
    trace_cnt: usize,
    harq_retx_events: u32,
    harq_fail_events: u32,
    last_bsr_idx: u8,
    staging_bytes_sum: u64,
    staging_samples: u64,
    delivered_bytes: u64,
}

impl UplinkSim {
    pub fn new(pdcp_cfg: PdcpConfig, rlc_cfg: RlcAmConfig, link: LinkConfig) -> Self {
        let seed = if link.seed == 0 { 1 } else { link.seed };
        Self {
            pdcp: PdcpUlState::new(pdcp_cfg),
            rlc: RlcAmUlState::new(rlc_cfg),
            link,
            rng: Rng(seed),
            harq: [HarqInFlight::default(); HARQ_SLOTS],
            status_q: [PeerStatusEvent::default(); STATUS_Q_CAP],
            enb_vr_r: 0,
            enb_rx_bitmap: [false; 1024],
            pkts: [PktRecord::default(); MAX_TRACED_PKTS],
            next_pkt_id: 1,
            arrival_credit_bytes: 0,
            traces: [PacketTrace::default(); MAX_TRACED_PKTS],
            trace_cnt: 0,
            harq_retx_events: 0,
            harq_fail_events: 0,
            last_bsr_idx: 0,
            staging_bytes_sum: 0,
            staging_samples: 0,
            delivered_bytes: 0,
        }
    }

    /// Run `duration_ms` of 1 ms TDD Config 2 ticks and return the [`BudgetSummary`],
    /// optionally discarding the first `warmup_ms` from latency percentiles.
    pub fn run(&mut self, duration_ms: u32, warmup_ms: u32) -> BudgetSummary {
        for t in 0..duration_ms {
            self.step_1ms(t, warmup_ms);
        }
        self.summarize(duration_ms.saturating_sub(warmup_ms))
    }

    /// Advance the entire uplink stack by one 1 ms TTI.
    pub fn step_1ms(&mut self, now_ms: u32, warmup_ms: u32) {
        // 1. 250 ms do_tc timer
        self.pdcp.maybe_run_do_tc(now_ms);

        // 2. Deliver any scheduled peer RLC STATUS PDUs arriving on DL
        for i in 0..STATUS_Q_CAP {
            if self.status_q[i].valid && now_ms >= self.status_q[i].deliver_ms {
                let ev = self.status_q[i];
                self.status_q[i].valid = false;
                let nacks = &ev.nacks[..ev.nack_cnt as usize];
                let _ = self.rlc.proc_status_rpt(&mut self.pdcp, ev.ack_sn, nacks);
            }
        }

        // 3. PDCP discardTimer & RLC t-PollRetransmit expiry
        let disc = self.pdcp.proc_discard_timer(now_ms);
        if disc.count > 0 {
            let _ = self.pdcp.discard_untransmitted(disc);
            self.rlc.notify_pdcp_bo(&self.pdcp);
        }
        let _ = self.rlc.tick_poll_retx_timer(now_ms);

        // 4. Packet arrivals into Ring 1
        self.generate_arrivals(now_ms);

        // 5. l2_proc_pdcp_ul submits from Ring 0/1 to LLCE0
        let _ = self.pdcp.proc_pdcp_ul(now_ms);

        // 6. Advance in-flight HARQ processes (deliver ACKed TBs to eNB or retry after 10 ms)
        self.step_harq(now_ms, warmup_ms);

        // 7. TDD Config 2 UL subframe (`t % 5 == 2`): HandleHarqProc + GenerateMacUlPdu + BSR
        if now_ms % 5 == 2 {
            let total_grant = self.link.grant_bytes_per_cc * (self.link.num_ccs as u32);
            self.pdcp.update_grant_ema(total_grant);

            for _cc in 0..self.link.num_ccs {
                let grant = self.link.grant_bytes_per_cc;
                let pdu_out = self.rlc.gen_pdu(&mut self.pdcp, grant, now_ms);
                self.pdcp.record_ul_tx_bytes(pdu_out.bytes_consumed);

                for k in 0..(pdu_out.pdu_count as usize) {
                    let pdu = pdu_out.pdus[k];
                    if matches!(
                        pdu.kind,
                        GeneratedPduKind::NewTx | GeneratedPduKind::RetxFull | GeneratedPduKind::RetxSeg
                    ) {
                        self.enqueue_harq(pdu.sn, pdu.poll_bit, now_ms);
                        // Stamp first_tx_ms on packets completed inside this AMD PDU
                        let tx_idx = (pdu.sn as usize) & 511;
                        let cnt = self.rlc.tx_buf[tx_idx].completed_sdu_cnt as usize;
                        for j in 0..cnt {
                            let psn = self.rlc.tx_buf[tx_idx].completed_sdu_sns[j];
                            let sdu = self.pdcp.sdu_win[psn as usize];
                            if sdu.pkt_id > 0 {
                                let pi = (sdu.pkt_id as usize) % MAX_TRACED_PKTS;
                                if self.pkts[pi].valid && self.pkts[pi].first_tx_ms == 0 {
                                    self.pkts[pi].pdcp_sub_ms = sdu.submit_exact_ms;
                                    self.pkts[pi].llce_done_ms = sdu.llce_done_ms;
                                    self.pkts[pi].first_tx_ms = now_ms;
                                    self.pkts[pi].rlc_sn = pdu.sn;
                                }
                                if pdu.kind != GeneratedPduKind::NewTx {
                                    self.pkts[pi].had_rlc_retx = true;
                                }
                            }
                        }
                    }
                }
            }

            // Compute post-TB BSR (matches GenerateMacUlPdu -> GetMacUlBsrValue)
            let snap = self.rlc.bo_snapshot(&self.pdcp, 0);
            let lcg_bo = calc_lcg_bo(&[snap], [0; 4], true, self.link.n4_true_bo);
            self.last_bsr_idx = search_bsr_idx(lcg_bo[self.rlc.cfg.lcg_id as usize], self.link.ext_bsr);
        }

        // 8. Stock ScheduleUlData harvests LLCE0 AFTER HandleHarqProc on every 1 ms TTI!
        let harv = self.pdcp.harvest_llce(now_ms);
        if harv.harvested_pkts > 0 {
            self.rlc.notify_pdcp_bo(&self.pdcp);
        }

        if now_ms >= warmup_ms {
            self.staging_bytes_sum += self.pdcp.pdcp_rlc_tx_bo as u64;
            self.staging_samples += 1;
        }
    }

    fn generate_arrivals(&mut self, now_ms: u32) {
        let pdu_bytes = self.link.pkt_ip_len as u32 + 2;
        if self.link.arrival_bytes_per_ms > 0 {
            self.arrival_credit_bytes += self.link.arrival_bytes_per_ms;
            while self.arrival_credit_bytes >= pdu_bytes && self.pdcp.ring1.free() > 0 {
                self.arrival_credit_bytes -= pdu_bytes;
                self.push_ring1_pkt(now_ms);
            }
        } else {
            // Saturated source holding Ring 1 at target_ring1_bytes (plus 1 full cap burst)
            let target = self.link.target_ring1_bytes;
            let min_pkts = target.div_ceil(pdu_bytes).max(16) as usize;
            while self.pdcp.ring1.len() < min_pkts && self.pdcp.ring1.free() > 0 {
                self.push_ring1_pkt(now_ms);
            }
        }
    }

    fn push_ring1_pkt(&mut self, now_ms: u32) {
        let id = self.next_pkt_id;
        self.next_pkt_id = self.next_pkt_id.wrapping_add(1);
        let pkt = IngressPkt {
            id,
            ip_len: self.link.pkt_ip_len,
            ring_enqueue_ms: now_ms,
        };
        if self.pdcp.enqueue_ring1(pkt) {
            let pi = (id as usize) % MAX_TRACED_PKTS;
            self.pkts[pi] = PktRecord {
                valid: true,
                delivered: false,
                ring_in_ms: now_ms,
                pdcp_sub_ms: 0,
                llce_done_ms: 0,
                first_tx_ms: 0,
                rlc_sn: 0,
                had_rlc_retx: false,
            };
        }
    }

    fn enqueue_harq(&mut self, sn: u16, poll_bit: bool, now_ms: u32) {
        for slot in &mut self.harq {
            if !slot.active {
                // First attempt arrives at eNB at now_ms + 1 (air propagation/decode)
                *slot = HarqInFlight {
                    active: true,
                    sn,
                    poll_bit,
                    tx_count: 1,
                    next_event_ms: now_ms + 1,
                };
                return;
            }
        }
    }

    fn step_harq(&mut self, now_ms: u32, warmup_ms: u32) {
        for i in 0..HARQ_SLOTS {
            if !self.harq[i].active || now_ms < self.harq[i].next_event_ms {
                continue;
            }
            // Subsequent HARQ retx attempts benefit from Chase/IR combining (~1/4 BLER per retry)
            let eff_bler = if self.harq[i].tx_count == 1 {
                self.link.harq_bler_permille
            } else {
                (self.link.harq_bler_permille / 4).max(5)
            };
            let failed = self.rng.hit_permille(eff_bler);
            if failed {
                if self.harq[i].tx_count < self.link.max_harq_tx {
                    self.harq[i].tx_count += 1;
                    self.harq[i].next_event_ms = now_ms + self.link.harq_rtt_ms;
                    self.harq_retx_events += 1;
                    continue;
                } else {
                    // UL HARQ maxRetx failure! TB lost; RLC AM must recover via STATUS NACK.
                    self.harq[i].active = false;
                    self.harq_fail_events += 1;
                    continue;
                }
            }

            // TB decoded cleanly at eNodeB!
            let sn = self.harq[i].sn;
            let poll = self.harq[i].poll_bit;
            self.harq[i].active = false;
            self.enb_rx_bitmap[sn as usize] = true;

            // Advance eNodeB in-order RLC AM VR(R), delivering all unblocked SDUs
            while self.enb_rx_bitmap[self.enb_vr_r as usize] {
                let cur_sn = self.enb_vr_r;
                self.enb_rx_bitmap[cur_sn as usize] = false;
                self.enb_vr_r = (cur_sn + 1) & RLC_AM_SN_MASK;
                self.record_enb_in_order_delivery(cur_sn, now_ms, warmup_ms);
            }

            // If poll bit was set (or hole detected), schedule peer RLC STATUS return
            if poll {
                self.schedule_peer_status(now_ms);
            }
        }
    }

    fn record_enb_in_order_delivery(&mut self, rlc_sn: u16, deliver_ms: u32, warmup_ms: u32) {
        let tx_idx = (rlc_sn as usize) & 511;
        let tx = self.rlc.tx_buf[tx_idx];
        if !tx.occupied || tx.sn != rlc_sn {
            return;
        }
        for j in 0..(tx.completed_sdu_cnt as usize) {
            let psn = tx.completed_sdu_sns[j];
            let sdu = self.pdcp.sdu_win[psn as usize];
            if sdu.pkt_id == 0 {
                continue;
            }
            let pi = (sdu.pkt_id as usize) % MAX_TRACED_PKTS;
            let rec = &mut self.pkts[pi];
            if !rec.valid || rec.delivered {
                continue;
            }
            rec.delivered = true;
            if deliver_ms >= warmup_ms {
                self.delivered_bytes += sdu.ip_len as u64;
                if self.trace_cnt < MAX_TRACED_PKTS {
                    let ring1_ms = rec.pdcp_sub_ms.saturating_sub(rec.ring_in_ms) as u16;
                    let llce_ms = rec.llce_done_ms.saturating_sub(rec.pdcp_sub_ms) as u16;
                    let wait_after_llce = rec.first_tx_ms.saturating_sub(rec.llce_done_ms);
                    // TDD framing alignment: residual time within one 5 ms UL cycle
                    let tdd_align_ms = (wait_after_llce % 5) as u16;
                    let rlc_queue_ms = wait_after_llce.saturating_sub(tdd_align_ms as u32) as u16;
                    // Delivery minus first TX (minus 1 ms nominal air decode) = HARQ + RLC retx
                    let air_extra = deliver_ms
                        .saturating_sub(rec.first_tx_ms)
                        .saturating_sub(1) as u16;
                    let (harq_ms, rlc_retx_ms) = if rec.had_rlc_retx {
                        let harq_part =
                            ((self.link.max_harq_tx.saturating_sub(1) as u16) * (self.link.harq_rtt_ms as u16))
                                .min(air_extra);
                        (harq_part, air_extra.saturating_sub(harq_part))
                    } else {
                        (air_extra, 0)
                    };
                    let post_ring1_ms = llce_ms
                        .saturating_add(rlc_queue_ms)
                        .saturating_add(tdd_align_ms)
                        .saturating_add(harq_ms)
                        .saturating_add(rlc_retx_ms);
                    let total_ms = ring1_ms.saturating_add(post_ring1_ms);

                    self.traces[self.trace_cnt] = PacketTrace {
                        pkt_id: sdu.pkt_id,
                        ring1_ms,
                        llce_harvest_ms: llce_ms,
                        rlc_queue_ms,
                        tdd_align_ms,
                        harq_retx_ms: harq_ms,
                        rlc_retx_ms,
                        post_ring1_ms,
                        total_ms,
                    };
                    self.trace_cnt += 1;
                }
            }
        }
    }

    fn schedule_peer_status(&mut self, now_ms: u32) {
        let mut nacks = [0u16; 8];
        let mut nack_cnt = 0u8;
        let mut sn = self.enb_vr_r;
        let mut ack_sn = self.enb_vr_r;
        // Scan up to VT(S) for holes (missing SNs)
        while sn != self.rlc.vt_s {
            if !self.enb_rx_bitmap[sn as usize] && (nack_cnt as usize) < nacks.len() {
                nacks[nack_cnt as usize] = sn;
                nack_cnt += 1;
            }
            sn = (sn + 1) & RLC_AM_SN_MASK;
            ack_sn = sn;
        }
        if nack_cnt == 0 {
            ack_sn = self.enb_vr_r;
        }
        for slot in &mut self.status_q {
            if !slot.valid {
                *slot = PeerStatusEvent {
                    valid: true,
                    deliver_ms: now_ms + self.link.status_rtt_ms,
                    ack_sn,
                    nack_cnt,
                    nacks,
                };
                return;
            }
        }
    }

    fn summarize(&self, measure_ms: u32) -> BudgetSummary {
        let n = self.trace_cnt;
        if n == 0 {
            return BudgetSummary::default();
        }
        let mut buf = [0u16; MAX_TRACED_PKTS];

        let mut compute = |f: fn(&PacketTrace) -> u16| -> StageStats {
            let mut sum = 0u64;
            for (dst, tr) in buf[..n].iter_mut().zip(self.traces[..n].iter()) {
                let v = f(tr);
                *dst = v;
                sum += v as u64;
            }
            buf[..n].sort_unstable();
            StageStats {
                p50_ms: buf[n / 2],
                p90_ms: buf[(n * 90) / 100],
                p99_ms: buf[(n * 99) / 100],
                mean_tenths_ms: ((sum * 10) / (n as u64)) as u32,
            }
        };

        let ring1 = compute(|t| t.ring1_ms);
        let llce_harvest = compute(|t| t.llce_harvest_ms);
        let rlc_queue = compute(|t| t.rlc_queue_ms);
        let tdd_align = compute(|t| t.tdd_align_ms);
        let harq_retx = compute(|t| t.harq_retx_ms);
        let rlc_retx = compute(|t| t.rlc_retx_ms);
        let post_ring1 = compute(|t| t.post_ring1_ms);
        let total = compute(|t| t.total_ms);

        // Compute `above_min` variants matching `tsq.py` (`latency - flow_min`)
        let min_post = self.traces[..n]
            .iter()
            .map(|t| t.post_ring1_ms)
            .min()
            .unwrap_or(0);
        let min_tot = self.traces[..n]
            .iter()
            .map(|t| t.total_ms)
            .min()
            .unwrap_or(0);

        let mut compute_sub = |min_v: u16, f: fn(&PacketTrace) -> u16| -> StageStats {
            let mut sum = 0u64;
            for (dst, tr) in buf[..n].iter_mut().zip(self.traces[..n].iter()) {
                let v = f(tr).saturating_sub(min_v);
                *dst = v;
                sum += v as u64;
            }
            buf[..n].sort_unstable();
            StageStats {
                p50_ms: buf[n / 2],
                p90_ms: buf[(n * 90) / 100],
                p99_ms: buf[(n * 99) / 100],
                mean_tenths_ms: ((sum * 10) / (n as u64)) as u32,
            }
        };

        let post_ring1_above_min = compute_sub(min_post, |t| t.post_ring1_ms);
        let total_above_min = compute_sub(min_tot, |t| t.total_ms);

        let throughput_kbps = (self.delivered_bytes * 8)
            .checked_div(measure_ms as u64)
            .unwrap_or(0) as u32;
        let mean_staging_bytes = self
            .staging_bytes_sum
            .checked_div(self.staging_samples)
            .unwrap_or(0) as u32;

        BudgetSummary {
            delivered_pkts: n as u32,
            throughput_kbps,
            ring1,
            llce_harvest,
            rlc_queue,
            tdd_align,
            harq_retx,
            rlc_retx,
            post_ring1,
            post_ring1_above_min,
            total,
            total_above_min,
            harq_retx_events: self.harq_retx_events,
            harq_fail_events: self.harq_fail_events,
            rlc_retx_pdus: self.rlc.total_retx_pdus as u32,
            rlc_win_stalls: self.rlc.total_win_stalls as u32,
            pdcp_discards: self.pdcp.total_discarded_pkts as u32,
            last_bsr_idx: self.last_bsr_idx,
            mean_staging_bytes,
        }
    }
}

/// Convenience helper: build a [`PdcpConfig`] for the real shipped v1.0.16 (`N5_FLAGS = 3`,
/// `N5_PDCP_MIN = 8192`, `N5_PDCP_MAX = 12288`) dynamic staging policy.
pub const fn pdcp_cfg_v1_0_16(byte_accurate: bool) -> PdcpConfig {
    PdcpConfig {
        discard_timer_ms: 750,
        divisor: 1500,
        staging: StagingPolicy::DynamicGrantCap {
            min_bytes: 8_192,
            max_bytes: 12_288,
            headroom_bytes: 4_096,
            byte_accurate,
        },
        llce_harvest_delay_ms: 1,
    }
}
