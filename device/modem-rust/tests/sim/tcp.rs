//! Senders: Linux CUBIC (with HyStart's delay exit), BBRv1 after `tcp_bbr.c`, and an
//! unresponsive UDP source. Windows are in packets, rates in packets per ms.

use std::collections::VecDeque;

use super::Rng;

/// The fields of a sent packet a congestion control looks at.
#[derive(Copy, Clone)]
pub struct Sent {
    /// Transmission order within the flow.
    pub tx: u64,
    pub sent: u32,
    pub delivered_at_send: u64,
    pub delivered_time_at_send: u32,
    pub first_tx_at_send: u32,
}

/// The flow's delivery state when an ACK arrives (after counting it).
#[derive(Copy, Clone)]
pub struct AckView {
    pub now: u32,
    pub delivered: u64,
    pub inflight: usize,
    pub tx_next: u64,
    pub min_rtt: f64,
}

pub enum Cc {
    Cubic(Cubic),
    Bbr(Box<Bbr>),
    /// Constant rate in packets per ms; never backs off, never retransmits.
    Udp(f64),
}

impl Cc {
    pub fn cwnd(&self) -> f64 {
        match self {
            Cc::Cubic(c) => c.cwnd,
            Cc::Bbr(b) => b.cwnd,
            Cc::Udp(_) => 1e9,
        }
    }

    /// Packets per ms, or `None` for ACK-clocked (unpaced) sending.
    pub fn pacing_rate(&self, srtt: Option<f64>) -> Option<f64> {
        match self {
            Cc::Cubic(_) => None,
            Cc::Bbr(b) => Some(b.pacing_rate(srtt)),
            Cc::Udp(rate) => Some(*rate),
        }
    }

    pub fn retransmits(&self) -> bool {
        !matches!(self, Cc::Udp(_))
    }

    pub fn on_ack(&mut self, p: &Sent, rtt: Option<f64>, v: &AckView, rng: &mut Rng) {
        match self {
            Cc::Cubic(c) => c.on_ack(p, rtt, v),
            Cc::Bbr(b) => b.on_ack(p, rtt, v, rng),
            Cc::Udp(_) => {}
        }
    }

    pub fn on_loss(&mut self, lost: u32, tx_next: u64) {
        match self {
            Cc::Cubic(c) => c.on_loss(tx_next),
            Cc::Bbr(b) => b.on_loss(lost, tx_next),
            Cc::Udp(_) => {}
        }
    }

    pub fn on_rto(&mut self) {
        match self {
            Cc::Cubic(c) => c.on_rto(),
            Cc::Bbr(b) => b.on_rto(),
            Cc::Udp(_) => {}
        }
    }
}

pub struct Cubic {
    pub cwnd: f64,
    ssthresh: f64,
    w_max: f64,
    epoch: Option<u32>,
    k: f64,
    origin: f64,
    w_est: f64,
    recovery_until: Option<u64>,
    round_end: u64,
    round_min: f64,
    min_seen: f64,
    samples: u32,
}

impl Cubic {
    const C: f64 = 0.4;
    const BETA: f64 = 0.7;

    pub fn new() -> Self {
        Self {
            cwnd: 10.0,
            ssthresh: 1e9,
            w_max: 0.0,
            epoch: None,
            k: 0.0,
            origin: 0.0,
            w_est: 0.0,
            recovery_until: None,
            round_end: 0,
            round_min: 1e9,
            min_seen: 1e9,
            samples: 0,
        }
    }

    fn on_ack(&mut self, p: &Sent, rtt: Option<f64>, v: &AckView) {
        if let Some(end) = self.recovery_until {
            if p.tx < end {
                return;
            }
            self.recovery_until = None;
        }
        if self.cwnd < self.ssthresh {
            // HyStart: the minimum of a round's first 8 RTT samples against the
            // connection's minimum, threshold clamp(min / 8, 4, 16) ms.
            if p.tx >= self.round_end {
                self.round_end = v.tx_next;
                self.round_min = 1e9;
                self.samples = 0;
            }
            if let Some(rtt) = rtt {
                self.min_seen = self.min_seen.min(rtt);
                if self.samples < 8 {
                    self.round_min = self.round_min.min(rtt);
                    self.samples += 1;
                    if self.samples == 8 && self.cwnd >= 16.0 {
                        let threshold = (self.min_seen / 8.0).clamp(4.0, 16.0);
                        if self.round_min >= self.min_seen + threshold {
                            self.ssthresh = self.cwnd;
                        }
                    }
                }
            }
            if self.cwnd < self.ssthresh {
                self.cwnd += 1.0;
                return;
            }
        }
        let epoch = match self.epoch {
            Some(epoch) => epoch,
            None => {
                if self.cwnd < self.w_max {
                    self.k = ((self.w_max - self.cwnd) / Self::C).cbrt();
                    self.origin = self.w_max;
                } else {
                    self.k = 0.0;
                    self.origin = self.cwnd;
                }
                self.w_est = self.cwnd;
                self.epoch = Some(v.now);
                v.now
            }
        };
        let t = (f64::from(v.now) + v.min_rtt - f64::from(epoch)) / 1000.0;
        let target = self.origin + Self::C * (t - self.k).powi(3);
        let mut count = if target > self.cwnd { self.cwnd / (target - self.cwnd) } else { 100.0 * self.cwnd };
        self.w_est += 3.0 * (1.0 - Self::BETA) / (1.0 + Self::BETA) / self.cwnd;
        if self.w_est > self.cwnd {
            count = count.min(self.cwnd / (self.w_est - self.cwnd));
        }
        if count > 0.0 {
            self.cwnd += 1.0 / count.max(1e-9);
        }
        self.cwnd = self.cwnd.min(2000.0);
    }

    fn on_loss(&mut self, tx_next: u64) {
        if self.recovery_until.is_some() {
            return;
        }
        self.epoch = None;
        self.w_max = if self.cwnd < self.w_max { self.cwnd * (1.0 + Self::BETA) / 2.0 } else { self.cwnd };
        self.cwnd = (self.cwnd * Self::BETA).max(2.0);
        self.ssthresh = self.cwnd;
        self.recovery_until = Some(tx_next);
    }

    fn on_rto(&mut self) {
        self.epoch = None;
        self.w_max = self.cwnd;
        self.ssthresh = (self.cwnd * Self::BETA).max(2.0);
        self.cwnd = 1.0;
        self.recovery_until = None;
    }
}

#[derive(Copy, Clone, PartialEq)]
enum Mode {
    Startup,
    Drain,
    ProbeBw,
    ProbeRtt,
}

/// BBRv1: rate samples with Linux's `interval >= min_rtt` filter, a 10-round max
/// bandwidth filter, ACK-aggregation headroom (`extra_acked`), the gain cycle, PROBE_RTT
/// and packet conservation in recovery.
pub struct Bbr {
    pub cwnd: f64,
    mode: Mode,
    pacing_gain: f64,
    cwnd_gain: f64,
    bw_samples: VecDeque<(u64, f64)>,
    round: u64,
    next_round_delivered: u64,
    round_start: bool,
    full_bw: f64,
    full_bw_count: u32,
    full_bw_reached: bool,
    min_rtt: Option<f64>,
    min_rtt_stamp: u32,
    probe_rtt_done: Option<u32>,
    cycle: usize,
    cycle_stamp: u32,
    prior_cwnd: f64,
    conserve: bool,
    recovery_until: Option<u64>,
    was_in_recovery: bool,
    ack_epoch_stamp: u32,
    ack_epoch_acked: f64,
    extra_acked: [f64; 2],
    extra_slot: usize,
    extra_rounds: u32,
    losses_pending: u32,
}

impl Bbr {
    const HIGH_GAIN: f64 = 2.885;
    const CYCLE: [f64; 8] = [1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0];

    pub fn new() -> Self {
        Self {
            cwnd: 10.0,
            mode: Mode::Startup,
            pacing_gain: Self::HIGH_GAIN,
            cwnd_gain: Self::HIGH_GAIN,
            bw_samples: VecDeque::new(),
            round: 0,
            next_round_delivered: 0,
            round_start: false,
            full_bw: 0.0,
            full_bw_count: 0,
            full_bw_reached: false,
            min_rtt: None,
            min_rtt_stamp: 0,
            probe_rtt_done: None,
            cycle: 0,
            cycle_stamp: 0,
            prior_cwnd: 0.0,
            conserve: false,
            recovery_until: None,
            was_in_recovery: false,
            ack_epoch_stamp: 0,
            ack_epoch_acked: 0.0,
            extra_acked: [0.0; 2],
            extra_slot: 0,
            extra_rounds: 0,
            losses_pending: 0,
        }
    }

    fn bw(&self) -> f64 {
        self.bw_samples.iter().map(|&(_, bw)| bw).fold(0.0, f64::max)
    }

    fn bdp(&self, gain: f64) -> f64 {
        match self.min_rtt {
            Some(rtt) if self.bw() > 0.0 => gain * self.bw() * rtt,
            _ => 10.0,
        }
    }

    fn pacing_rate(&self, srtt: Option<f64>) -> f64 {
        let bw = self.bw();
        if bw == 0.0 {
            return Self::HIGH_GAIN * self.cwnd / srtt.unwrap_or(20.0).max(1.0);
        }
        self.pacing_gain * bw * 0.99
    }

    fn on_loss(&mut self, lost: u32, tx_next: u64) {
        self.losses_pending += lost;
        self.recovery_until.get_or_insert(tx_next);
    }

    fn on_rto(&mut self) {
        self.prior_cwnd = self.prior_cwnd.max(self.cwnd);
        self.cwnd = 1.0;
        self.recovery_until = None;
        self.conserve = false;
    }

    fn on_ack(&mut self, p: &Sent, rtt: Option<f64>, v: &AckView, rng: &mut Rng) {
        let now = v.now;
        let delivered = (v.delivered - p.delivered_at_send) as f64;
        let interval = f64::from(p.sent - p.first_tx_at_send).max(f64::from(now - p.delivered_time_at_send));
        if let Some(rtt) = rtt {
            let expired = now - self.min_rtt_stamp > 10_000;
            if self.min_rtt.is_none_or(|m| rtt < m) || expired {
                self.min_rtt = Some(rtt.max(1.0));
                self.min_rtt_stamp = now;
            }
        }
        self.round_start = false;
        if p.delivered_at_send >= self.next_round_delivered {
            self.next_round_delivered = v.delivered;
            self.round += 1;
            self.round_start = true;
        }
        if let Some(min_rtt) = self.min_rtt {
            if interval >= min_rtt && interval > 0.0 {
                self.bw_samples.push_back((self.round, delivered / interval));
            }
        }
        while self.bw_samples.front().is_some_and(|&(r, _)| r + 10 < self.round) {
            self.bw_samples.pop_front();
        }
        self.update_ack_aggregation(now);
        if self.round_start && !self.full_bw_reached {
            let bw = self.bw();
            if bw >= self.full_bw * 1.25 {
                self.full_bw = bw;
                self.full_bw_count = 0;
            } else {
                self.full_bw_count += 1;
                self.full_bw_reached = self.full_bw_count >= 3;
            }
        }
        if self.mode == Mode::Startup && self.full_bw_reached {
            self.mode = Mode::Drain;
            self.pacing_gain = 1.0 / Self::HIGH_GAIN;
            self.cwnd_gain = Self::HIGH_GAIN;
        }
        if self.mode == Mode::Drain && v.inflight as f64 <= self.bdp(1.0) {
            self.enter_probe_bw(now, rng);
        }
        if self.mode == Mode::ProbeBw {
            self.advance_cycle(now, v.inflight);
        }
        if self.mode != Mode::ProbeRtt && self.min_rtt.is_some() && now - self.min_rtt_stamp > 10_000 {
            self.mode = Mode::ProbeRtt;
            self.pacing_gain = 1.0;
            self.prior_cwnd = self.prior_cwnd.max(self.cwnd);
            self.probe_rtt_done = None;
        }
        if self.mode == Mode::ProbeRtt {
            if self.probe_rtt_done.is_none() && v.inflight <= 4 {
                self.probe_rtt_done = Some(now + 200);
            }
            if self.probe_rtt_done.is_some_and(|done| now >= done) {
                self.min_rtt_stamp = now;
                self.cwnd = self.cwnd.max(self.prior_cwnd);
                if self.full_bw_reached {
                    self.enter_probe_bw(now, rng);
                } else {
                    self.mode = Mode::Startup;
                    self.pacing_gain = Self::HIGH_GAIN;
                    self.cwnd_gain = Self::HIGH_GAIN;
                }
            }
        }
        self.set_cwnd(p, v);
    }

    /// `bbr_update_ack_aggregation`: ACKs arriving faster than the bandwidth estimate
    /// earn cwnd headroom (LTE's TDD frames and HARQ deliver in bursts).
    fn update_ack_aggregation(&mut self, now: u32) {
        if self.round_start {
            self.extra_rounds = (self.extra_rounds + 1).min(31);
            if self.extra_rounds >= 5 {
                self.extra_rounds = 0;
                self.extra_slot ^= 1;
                self.extra_acked[self.extra_slot] = 0.0;
            }
        }
        let mut expected = self.bw() * f64::from(now - self.ack_epoch_stamp);
        if self.ack_epoch_acked <= expected || self.ack_epoch_acked + 1.0 >= f64::from(1u32 << 20) {
            self.ack_epoch_acked = 0.0;
            self.ack_epoch_stamp = now;
            expected = 0.0;
        }
        self.ack_epoch_acked += 1.0;
        let extra = (self.ack_epoch_acked - expected).min(self.cwnd);
        if extra > self.extra_acked[self.extra_slot] {
            self.extra_acked[self.extra_slot] = extra;
        }
    }

    fn enter_probe_bw(&mut self, now: u32, rng: &mut Rng) {
        self.mode = Mode::ProbeBw;
        self.cwnd_gain = 2.0;
        self.cycle = (7 - (rng.next() % 7) as usize) % 8;
        self.cycle_stamp = now;
        self.pacing_gain = Self::CYCLE[self.cycle];
    }

    fn advance_cycle(&mut self, now: u32, inflight: usize) {
        let elapsed = f64::from(now - self.cycle_stamp) > self.min_rtt.unwrap_or(20.0);
        let gain = Self::CYCLE[self.cycle];
        let advance = if gain == 1.0 {
            elapsed
        } else if gain > 1.0 {
            elapsed && (self.losses_pending > 0 || inflight as f64 >= self.bdp(gain))
        } else {
            elapsed || inflight as f64 <= self.bdp(1.0)
        };
        if advance {
            self.cycle = (self.cycle + 1) % 8;
            self.cycle_stamp = now;
            self.pacing_gain = Self::CYCLE[self.cycle];
        }
    }

    fn set_cwnd(&mut self, p: &Sent, v: &AckView) {
        let acked = 1.0;
        let mut cwnd = self.cwnd;
        if self.losses_pending > 0 {
            cwnd = (cwnd - f64::from(self.losses_pending)).max(1.0);
            self.losses_pending = 0;
        }
        let in_recovery = self.recovery_until.is_some_and(|end| p.tx < end);
        if self.recovery_until.is_some_and(|end| p.tx >= end) {
            self.recovery_until = None;
        }
        if in_recovery && !self.was_in_recovery {
            self.prior_cwnd = self.cwnd;
            self.conserve = true;
            self.next_round_delivered = v.delivered;
            cwnd = v.inflight as f64 + acked;
        } else if self.was_in_recovery && !in_recovery {
            cwnd = cwnd.max(self.prior_cwnd);
            self.conserve = false;
        }
        self.was_in_recovery = in_recovery;
        if self.conserve && in_recovery {
            if self.round_start {
                self.conserve = false;
            }
            cwnd = cwnd.max(v.inflight as f64 + acked);
        }
        if self.mode == Mode::ProbeRtt {
            self.cwnd = 4.0;
            return;
        }
        let mut target = self.bdp(self.cwnd_gain) + 3.0 * self.bw().clamp(2.0, 64.0);
        if self.full_bw_reached {
            target += self.extra_acked[0].max(self.extra_acked[1]).min(self.bw() * 100.0);
        }
        if self.mode == Mode::ProbeBw && self.cycle == 0 {
            target += 2.0;
        }
        if self.full_bw_reached {
            cwnd = (cwnd + acked).min(target);
        } else if cwnd < target || v.delivered < 10 {
            cwnd += acked;
        }
        self.cwnd = cwnd.max(4.0);
    }
}
