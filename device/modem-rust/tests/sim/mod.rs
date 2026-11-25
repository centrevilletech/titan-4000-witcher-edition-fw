//! A closed-loop, 1 ms model of the Titan 4000 uplink with Linux-like senders.
//!
//! The same model in Python (`lanes-20261125/R1/tests/sim.py`) was calibrated against
//! the 2026-11-25 bench runs (`lanes-20261124/UL/data/runs-20261125-m1/`): with M1's
//! ceiling, 4 BBR flows on one carrier sit on the ceiling (bench: queue p50 63 ms, 1,438
//! ceiling drops against 54 PIE drops in 20 s), and 4 CUBIC flows on two carriers take
//! about 40% of their drops at the ceiling.
//!
//! The link: one uplink subframe per carrier every 5 ms (TDD config 2), two HARQ
//! processes per carrier, 8% BLER with retransmission 10 ms later, grants capped by the
//! buffer report the eNB saw at the last subframe (PCell first), RLC in-order delivery at
//! the eNB, and a modem queue of Ring 1 plus N5's 8-12 KB PDCP staging. The AQM decides
//! at Ring-1 enqueue on Ring 1 + staging bytes and N4's grant EWMA, like hook 4.

pub mod aqm;
pub mod tcp;

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet, VecDeque};

use aqm::{Aqm, Verdict};
use tcp::{AckView, Bbr, Cc, Cubic, Sent};

pub const MSS: u32 = 1328;
pub const PKT: u32 = 1380;
const PROBE_BYTES: u32 = 60;
const DURATION_MS: u32 = 20_000;
const WARMUP_MS: u32 = 3_000;
const BLER: f64 = 0.08;
/// Bytes per uplink subframe: PCell and SCell (bench: ~7.7 and ~17.5 Mbps at the modem).
const CAPACITY: [u32; 2] = [4600, 5400];
const UL_FIXED_MS: u32 = 6;
const DL_DELAY_MS: u32 = 9;

/// xorshift32.
pub struct Rng(u32);

impl Rng {
    pub fn new(seed: u32) -> Self {
        Self(if seed == 0 { 0x9e37_79b9 } else { seed })
    }

    pub fn next(&mut self) -> u32 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.0 = x;
        x
    }

    pub fn unit(&mut self) -> f64 {
        f64::from(self.next()) / 4_294_967_296.0
    }
}

#[derive(Copy, Clone, Debug)]
pub enum Sender {
    Cubic,
    Bbr,
    /// Unresponsive constant rate.
    Udp { kbps: u32 },
}

pub struct Scenario {
    pub senders: Vec<Sender>,
    pub carriers: usize,
    pub seed: u32,
    /// The eNB schedules the SCell only while it saw a buffer report of at least `.0`
    /// bytes within the last `.1` ms (a guess at Nokia's buffer-driven UL CA).
    pub scell_gate: Option<(u32, u32)>,
    /// The SCell stops being scheduled at this time.
    pub scell_off_at: Option<u32>,
}

impl Scenario {
    pub fn new(senders: Vec<Sender>, carriers: usize, seed: u32) -> Self {
        Self { senders, carriers, seed, scell_gate: None, scell_off_at: None }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Outcome {
    pub mbps: f64,
    pub loss_pct: f64,
    /// Ring-1 + staging sojourn plus HARQ and in-order delivery, ms.
    pub qd50: f64,
    pub qd90: f64,
    pub qd99: f64,
    pub qd_max: f64,
    /// The sparse probe's round trip (N5 lane), ms.
    pub probe50: f64,
    pub aqm_drops: u32,
    pub ceiling_drops: u32,
    pub rto: u32,
    pub scell_share: f64,
    pub per_flow_mbps: Vec<f64>,
}

struct Pkt {
    flow: usize,
    seq: u64,
    size: u32,
    sent: Sent,
    retx: bool,
    enqueued: u32,
    left: u32,
    probe: bool,
}

struct Flow {
    cc: Cc,
    tx_next: u64,
    seq_next: u64,
    outstanding: VecDeque<usize>,
    retransmit: VecDeque<u64>,
    delivered: u64,
    delivered_time: u32,
    first_tx: u32,
    tokens: f64,
    srtt: Option<f64>,
    rttvar: f64,
    min_rtt: f64,
    last_progress: u32,
    received: HashSet<u64>,
    goodput_bytes: u64,
}

impl Flow {
    fn new(sender: Sender) -> Self {
        let cc = match sender {
            Sender::Cubic => Cc::Cubic(Cubic::new()),
            Sender::Bbr => Cc::Bbr(Box::new(Bbr::new())),
            Sender::Udp { kbps } => Cc::Udp(f64::from(kbps) / 8.0 / f64::from(PKT)),
        };
        Self {
            cc,
            tx_next: 0,
            seq_next: 0,
            outstanding: VecDeque::new(),
            retransmit: VecDeque::new(),
            delivered: 0,
            delivered_time: 0,
            first_tx: 0,
            tokens: 2.0,
            srtt: None,
            rttvar: 0.0,
            min_rtt: 21.0,
            last_progress: 0,
            received: HashSet::new(),
            goodput_bytes: 0,
        }
    }

    fn rto(&self) -> f64 {
        self.srtt.map_or(1000.0, |srtt| (srtt + 4.0 * self.rttvar).max(200.0))
    }
}

/// A transport block on the air: its packets, HARQ attempts and RLC sequence.
struct Block {
    packets: Vec<usize>,
    attempts: u32,
    seq: u64,
}

pub fn run(scenario: &Scenario, aqm: &mut dyn Aqm) -> Outcome {
    let mut rng = Rng::new(scenario.seed.wrapping_mul(2_654_435_761).wrapping_add(17));
    let mut flows: Vec<Flow> = scenario.senders.iter().map(|&s| Flow::new(s)).collect();
    let carriers = scenario.carriers.clamp(1, 2);
    let mut packets: Vec<Pkt> = Vec::new();

    let mut ring1: VecDeque<usize> = VecDeque::new();
    let mut ring1_bytes = 0u32;
    let mut staging: VecDeque<usize> = VecDeque::new();
    let mut staging_bytes = 0u32;
    let mut g_ema = 370u32;
    let mut reported = 0u32;
    let mut last_big_report: i64 = -1_000_000_000;
    let mut harq: [[Option<Block>; 2]; 2] = Default::default();
    let mut tb_seq = 0u64;
    let mut next_tb = 1u64;
    let mut decoded: HashMap<u64, (u32, Vec<usize>)> = HashMap::new();
    let mut to_receiver: BinaryHeap<Reverse<(u32, u64, usize)>> = BinaryHeap::new();
    let mut to_sender: BinaryHeap<Reverse<(u32, u64, usize, usize)>> = BinaryHeap::new();
    let mut arrival_order = 0u64;

    let mut out = Outcome::default();
    let (mut sent, mut delivered_bytes) = (0u32, 0u64);
    let (mut queue_delays, mut probe_rtts) = (Vec::new(), Vec::new());
    let (mut ul_ttis, mut scell_ttis) = (0u32, 0u32);
    let mut next_probe = 1000u32;

    for t in 0..DURATION_MS {
        let measuring = t >= WARMUP_MS;

        // The receiver: first copies count as goodput; every packet is ACKed.
        while let Some(&Reverse((at, _, idx))) = to_receiver.peek() {
            if at > t {
                break;
            }
            to_receiver.pop();
            let p = &packets[idx];
            if p.probe {
                if measuring {
                    probe_rtts.push(f64::from(t - p.sent.sent + DL_DELAY_MS));
                }
                continue;
            }
            let f = &mut flows[p.flow];
            if f.received.insert(p.seq) && measuring {
                delivered_bytes += u64::from(MSS);
                f.goodput_bytes += u64::from(MSS);
            }
            to_sender.push(Reverse((t + DL_DELAY_MS, p.sent.tx, p.flow, idx)));
        }

        // The senders: an ACK delivers its packet and declares every outstanding packet
        // sent before it lost (the path never reorders).
        while let Some(&Reverse((at, _, fid, idx))) = to_sender.peek() {
            if at > t {
                break;
            }
            to_sender.pop();
            let f = &mut flows[fid];
            let Some(pos) = f.outstanding.iter().position(|&i| i == idx) else {
                continue;
            };
            let lost: Vec<usize> = f.outstanding.drain(..pos).collect();
            f.outstanding.pop_front();
            let p = &packets[idx];
            f.delivered += 1;
            f.delivered_time = t;
            f.first_tx = f.first_tx.max(p.sent.sent);
            f.last_progress = t;
            let rtt = (!p.retx).then(|| f64::from(t - p.sent.sent));
            if let Some(rtt) = rtt {
                match f.srtt {
                    None => {
                        f.srtt = Some(rtt);
                        f.rttvar = rtt / 2.0;
                    }
                    Some(srtt) => {
                        f.rttvar = 0.75 * f.rttvar + 0.25 * (srtt - rtt).abs();
                        f.srtt = Some(0.875 * srtt + 0.125 * rtt);
                    }
                }
                f.min_rtt = if f.delivered > 1 { f.min_rtt.min(rtt) } else { rtt };
            }
            if !lost.is_empty() {
                if f.cc.retransmits() {
                    f.retransmit.extend(lost.iter().map(|&i| packets[i].seq));
                }
                f.cc.on_loss(lost.len() as u32, f.tx_next);
            }
            let view = AckView {
                now: t,
                delivered: f.delivered,
                inflight: f.outstanding.len(),
                tx_next: f.tx_next,
                min_rtt: f.min_rtt,
            };
            let sent_info = p.sent;
            f.cc.on_ack(&sent_info, rtt, &view, &mut rng);
        }

        // Retransmission timeouts.
        for f in &mut flows {
            let Some(&first) = f.outstanding.front() else {
                continue;
            };
            let since = t - f.last_progress.max(packets[first].sent.sent);
            if f64::from(since) > f.rto() {
                if f.cc.retransmits() {
                    f.retransmit.extend(f.outstanding.iter().map(|&i| packets[i].seq));
                }
                f.outstanding.clear();
                f.cc.on_rto();
                f.last_progress = t;
                out.rto += 1;
            }
        }

        // Sending, and the AQM at Ring-1 enqueue.
        for (fid, f) in flows.iter_mut().enumerate() {
            let rate = f.cc.pacing_rate(f.srtt);
            if let Some(rate) = rate {
                f.tokens = (f.tokens + rate).min(2.0 + rate);
            }
            let mut burst = 0;
            while (f.outstanding.len() as f64) < f.cc.cwnd().floor() && burst < 64 {
                if rate.is_some() && f.tokens < 1.0 {
                    break;
                }
                let (seq, retx) = match f.retransmit.pop_front() {
                    Some(seq) => (seq, true),
                    None => {
                        f.seq_next += 1;
                        (f.seq_next - 1, false)
                    }
                };
                if f.outstanding.is_empty() {
                    f.first_tx = t;
                    if f.delivered == 0 {
                        f.delivered_time = t;
                    }
                }
                let idx = packets.len();
                packets.push(Pkt {
                    flow: fid,
                    seq,
                    size: PKT,
                    sent: Sent {
                        tx: f.tx_next,
                        sent: t,
                        delivered_at_send: f.delivered,
                        delivered_time_at_send: f.delivered_time,
                        first_tx_at_send: f.first_tx,
                    },
                    retx,
                    enqueued: t,
                    left: PKT,
                    probe: false,
                });
                f.tx_next += 1;
                f.outstanding.push_back(idx);
                if rate.is_some() {
                    f.tokens -= 1.0;
                }
                burst += 1;
                if measuring {
                    sent += 1;
                }
                match aqm.decide(ring1_bytes + staging_bytes, g_ema, PKT, t) {
                    Verdict::Pass => {
                        ring1.push_back(idx);
                        ring1_bytes += PKT;
                    }
                    Verdict::Drop if measuring => out.aqm_drops += 1,
                    Verdict::Ceiling if measuring => out.ceiling_drops += 1,
                    Verdict::Drop | Verdict::Ceiling => {}
                }
            }
        }
        refill(&mut ring1, &mut ring1_bytes, &mut staging, &mut staging_bytes, &packets, g_ema);

        // A sparse probe every 100 ms, through N5's lane straight to staging.
        if t >= next_probe {
            next_probe += 100;
            let idx = packets.len();
            packets.push(Pkt {
                flow: 0,
                seq: 0,
                size: PROBE_BYTES,
                sent: Sent { tx: 0, sent: t, delivered_at_send: 0, delivered_time_at_send: 0, first_tx_at_send: 0 },
                retx: false,
                enqueued: t,
                left: PROBE_BYTES,
                probe: true,
            });
            staging.push_back(idx);
            staging_bytes += PROBE_BYTES;
        }

        // The uplink subframe: HARQ retransmissions, grants, transport blocks.
        if t % 5 == 2 {
            let process = ((t / 5) % 2) as usize;
            ul_ttis += 1;
            let mut scheduled = carriers;
            if scenario.scell_off_at.is_some_and(|off| t >= off) {
                scheduled = 1;
            }
            if let Some((bytes, hold_ms)) = scenario.scell_gate {
                if reported >= bytes {
                    last_big_report = i64::from(t);
                }
                if i64::from(t) - last_big_report > i64::from(hold_ms) {
                    scheduled = 1;
                }
            }
            // A scheduling request gets a small grant when nothing was reported yet.
            let mut budget = if reported > 0 { reported } else if ring1_bytes + staging_bytes > 0 { 600 } else { 0 };
            let mut granted_tti = 0u32;
            for c in 0..carriers {
                if let Some(block) = harq[c][process].as_mut() {
                    block.attempts += 1;
                    if rng.unit() < BLER && block.attempts < 4 {
                        continue;
                    }
                    let block = harq[c][process].take().expect("checked above");
                    decoded.insert(block.seq, (t + 1, block.packets));
                    continue;
                }
                if c >= scheduled {
                    continue;
                }
                let grant = CAPACITY[c].min(budget);
                if grant == 0 {
                    continue;
                }
                if c == 1 {
                    scell_ttis += 1;
                }
                budget -= grant;
                granted_tti += grant;
                let mut room = grant;
                let mut carried = Vec::new();
                while room > 0 {
                    let Some(&idx) = staging.front() else {
                        break;
                    };
                    let p = &mut packets[idx];
                    let take = room.min(p.left);
                    p.left -= take;
                    room -= take;
                    staging_bytes -= take;
                    if p.left == 0 {
                        staging.pop_front();
                        carried.push(idx);
                    }
                }
                tb_seq += 1;
                if rng.unit() < BLER {
                    harq[c][process] = Some(Block { packets: carried, attempts: 1, seq: tb_seq });
                } else {
                    decoded.insert(tb_seq, (t + 1, carried));
                }
            }
            if granted_tti > 0 {
                g_ema = (3 * g_ema + granted_tti) >> 2;
            }
            refill(&mut ring1, &mut ring1_bytes, &mut staging, &mut staging_bytes, &packets, g_ema);
            reported = ring1_bytes + staging_bytes;
        }

        // RLC delivers in sequence at the eNB.
        while decoded.get(&next_tb).is_some_and(|&(at, _)| at <= t) {
            let (_, carried) = decoded.remove(&next_tb).expect("checked above");
            next_tb += 1;
            for idx in carried {
                if !packets[idx].probe && measuring {
                    queue_delays.push(f64::from(t - packets[idx].enqueued));
                }
                to_receiver.push(Reverse((t + UL_FIXED_MS, arrival_order, idx)));
                arrival_order += 1;
            }
        }
    }

    let seconds = f64::from(DURATION_MS - WARMUP_MS) / 1000.0;
    out.mbps = delivered_bytes as f64 * 8.0 / seconds / 1e6;
    out.loss_pct = 100.0 * f64::from(out.aqm_drops + out.ceiling_drops) / f64::from(sent.max(1));
    queue_delays.sort_by(f64::total_cmp);
    probe_rtts.sort_by(f64::total_cmp);
    out.qd50 = percentile(&queue_delays, 0.50);
    out.qd90 = percentile(&queue_delays, 0.90);
    out.qd99 = percentile(&queue_delays, 0.99);
    out.qd_max = queue_delays.last().copied().unwrap_or(0.0);
    out.probe50 = percentile(&probe_rtts, 0.50);
    out.scell_share = f64::from(scell_ttis) / f64::from(ul_ttis.max(1));
    out.per_flow_mbps = flows.iter().map(|f| f.goodput_bytes as f64 * 8.0 / seconds / 1e6).collect();
    out
}

/// PDCP staging pulls Ring 1 up to N5's limit, `clamp(G_ema + 4 KB, 8 KB, 12 KB)`.
fn refill(
    ring1: &mut VecDeque<usize>,
    ring1_bytes: &mut u32,
    staging: &mut VecDeque<usize>,
    staging_bytes: &mut u32,
    packets: &[Pkt],
    g_ema: u32,
) {
    let limit = (g_ema + 4096).clamp(8192, 12288);
    while *staging_bytes < limit {
        let Some(idx) = ring1.pop_front() else {
            break;
        };
        *ring1_bytes -= packets[idx].size;
        *staging_bytes += packets[idx].size;
        staging.push_back(idx);
    }
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return f64::NAN;
    }
    sorted[((sorted.len() as f64 * p) as usize).min(sorted.len() - 1)]
}
