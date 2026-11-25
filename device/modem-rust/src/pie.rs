//! PIE (RFC 8033, with DOCSIS-PIE's gain scaling from RFC 8034) for the LTE uplink,
//! run at Ring-1 enqueue in integer arithmetic on the control block's words.
//!
//! Three limits shape the queue:
//!
//! - **Target.** The control law moves the drop probability `p` toward the queue delay
//!   that holds `target_ms`.
//! - **Budget.** For responsive senders (CUBIC), `p` is capped at `drop_budget_q24`
//!   (2%). Four CUBIC flows on one carrier would need about 4% to sit at the target;
//!   capped, their queue floats higher instead. The Nokia eNB keeps the second uplink
//!   carrier busy only while the reported backlog stays high, so that float is worth
//!   about half the upload rate.
//! - **Ceiling.** Big packets are tail-dropped above `max(ceiling_floor_bytes, drain
//!   rate x ceiling_ms)`. Responsive senders back off and rarely come back; a sender
//!   that does not respond to loss (BBR, a UDP flood) keeps hitting it.
//!
//! A token bucket polices the ceiling at the budget rate, `ceiling_burst_pkts` deep.
//! When it runs dry, the traffic is not responding to the budget, so the cap is
//! lifted: `p` may rise to whatever holds the target (RFC 8033). This *overload* ends
//! at the first update where `p` is back under the budget. Slow-start overshoot and
//! isolated tail-drop bursts fit in the bucket.
//!
//! The bench result this answers (2026-11-25, `runs-20261125-m1/`): with the budget
//! alone, 4 BBR flows sat on the ceiling, 1,438 ceiling drops against 54 PIE drops in
//! 20 s.
//!
//! No floating point, no 64-bit arithmetic, no allocation, no panic paths.

#![forbid(unsafe_code)]

use crate::block::M1Block;
use crate::ecn;

/// Probability 1.0 in Q24.
pub const P_SCALE: u32 = 1 << 24;

/// Derandomisation bounds on the drop accumulator (RFC 8033 section 5.1 uses 0.85 and
/// 8.5; lower bounds let the first drop come sooner at LTE's small windows).
const ACCU_LOW: u32 = P_SCALE / 2;
const ACCU_HIGH: u32 = P_SCALE * 4;

/// Largest rise of `p` per update (+2%).
const MAX_STEP: i32 = (P_SCALE / 50) as i32;

/// A gap this long between updates resets the controller.
pub const IDLE_RESET_MS: u32 = 200;

/// The xorshift32 state after boot (and whenever it would be zero).
pub const RNG_SEED: u32 = 0x1357_2468;

/// `flags`: packet-size scaling of `p` (RFC 8033 section 5.2).
pub const FLAG_SIZE_SCALE: u32 = 1 << 0;
/// `flags`: derandomised drops (RFC 8033 section 5.1).
pub const FLAG_DERANDOMISE: u32 = 1 << 1;

/// One packet arriving at Ring 1, with the queue and grant state hook 4 sees.
#[derive(Copy, Clone, Debug)]
pub struct Arrival {
    /// IP length.
    pub len: u32,
    /// 1 ms TTI clock.
    pub now: u32,
    /// Bytes waiting in Ring 0 + Ring 1 + the cipher batch + RLC staging.
    pub queue_bytes: u32,
    /// N4's EWMA of granted bytes per uplink TTI.
    pub g_ema: u32,
    /// N4's minimum length for drops and marks (600 B).
    pub min_len: u32,
}

/// What happens to a packet. The discriminant indexes `M1Block::decisions`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Decision {
    Enqueue = 0,
    Drop = 1,
    /// Enqueued with CE set.
    Mark = 2,
    /// Tail-dropped at the ceiling.
    Ceiling = 3,
    /// Enqueued above target: shorter than the AQM's minimum length.
    SparedSmall = 4,
    /// Enqueued above target: inside the burst allowance.
    SparedBurst = 5,
}

impl Decision {
    pub const fn is_drop(self) -> bool {
        matches!(self, Self::Drop | Self::Ceiling)
    }
}

impl M1Block {
    /// Decide one packet and count it. `ip` is the start of its IP header (CE is set in
    /// place).
    pub fn decide(&self, arrival: Arrival, ip: &mut [u8]) -> Decision {
        let rate_bpms = self.drain_rate_bpms(arrival.g_ema);
        let qdelay_us = arrival.queue_bytes.min(4_000_000) * 1000 / rate_bpms;
        self.rate_bpms.set(rate_bpms);
        self.qdelay_us.set(qdelay_us);
        self.max_qdelay_us.raise(qdelay_us);
        self.seen.bump();

        let dt = arrival.now.wrapping_sub(self.last_update_tti.get());
        if dt >= self.t_update_ms.get() {
            self.update(qdelay_us, arrival.now, dt);
        }
        let decision = self.classify(&arrival, qdelay_us, rate_bpms, ip);
        self.count_decision(decision);
        decision
    }

    fn classify(&self, arrival: &Arrival, qdelay_us: u32, rate_bpms: u32, ip: &mut [u8]) -> Decision {
        let above_target = qdelay_us > self.target_us();

        // Small packets (ACKs, DNS, VoIP, handshakes) are never dropped or marked.
        if arrival.len < arrival.min_len {
            return if above_target { Decision::SparedSmall } else { Decision::Enqueue };
        }

        let ceiling = self.ceiling_bytes(rate_bpms);
        if ceiling > 0 && arrival.queue_bytes > ceiling {
            self.accu_q24.set(0);
            self.spend_token();
            return Decision::Ceiling;
        }
        self.earn_token();

        // The burst allowance absorbs TDD framing, HARQ pauses and TCP bursts.
        if self.burst_ms.get() > 0 {
            return if above_target { Decision::SparedBurst } else { Decision::Enqueue };
        }

        // No drops while the queue is short (RFC 8033 section 4.3).
        let p = self.prob_q24.get();
        let mtu = self.mtu_bytes.get().max(1);
        let half_target = self.target_us() / 2;
        let quiet = qdelay_us < half_target && self.qdelay_old_us.get() < half_target && p < P_SCALE / 5;
        if p == 0 || arrival.queue_bytes < mtu.saturating_mul(2) || quiet {
            return Decision::Enqueue;
        }

        let flags = self.flags.get();
        let p_packet = if flags & FLAG_SIZE_SCALE != 0 && arrival.len < mtu {
            ((p >> 8).saturating_mul(arrival.len) / mtu) << 8
        } else {
            p
        };
        if !self.trigger(p_packet, flags & FLAG_DERANDOMISE != 0) {
            return Decision::Enqueue;
        }

        let ecn_max = self.ecn_max_prob_q24.get();
        if (ecn_max == 0 || p <= ecn_max) && ecn::mark_ce(ip) {
            Decision::Mark
        } else {
            Decision::Drop
        }
    }

    /// The control law, every `t_update_ms`.
    #[inline(never)]
    fn update(&self, qdelay_us: u32, now: u32, dt: u32) {
        self.updates.bump();
        if dt > IDLE_RESET_MS {
            self.reset(qdelay_us, now);
            return;
        }

        let overload = self.overload.get() != 0;
        let cap = if overload { P_SCALE } else { self.budget() };
        let p_old = self.prob_q24.get().min(P_SCALE) as i32;
        let mut p = p_old.saturating_add(self.control_delta(qdelay_us)).clamp(0, cap as i32) as u32;

        // Below half the target for two updates: decay p, and re-arm the burst
        // allowance once p reaches zero.
        let half_target = self.target_us() / 2;
        if qdelay_us < half_target && self.qdelay_old_us.get() < half_target {
            p -= p >> 3;
            if p < 16 {
                p = 0;
                self.burst_ms.set(self.max_burst_ms.get());
                self.accu_q24.set(0);
                self.rearms.bump();
            }
        } else {
            self.burst_ms.set(self.burst_ms.get().saturating_sub(dt));
        }

        // The overload ends once the budget is enough again.
        if overload {
            if p >= self.budget() {
                self.overload_updates.bump();
            } else {
                self.overload.set(0);
            }
        }
        self.prob_q24.set(p);
        self.max_prob_q24.raise(p);
        self.qdelay_old_us.set(qdelay_us);
        self.last_update_tti.set(now);
    }

    /// Start over after an idle gap: no drop probability, a full burst allowance and a
    /// full token bucket.
    fn reset(&self, qdelay_us: u32, now: u32) {
        self.prob_q24.set(0);
        self.accu_q24.set(0);
        self.qdelay_old_us.set(qdelay_us);
        self.burst_ms.set(self.max_burst_ms.get());
        self.last_update_tti.set(now);
        self.overload.set(0);
        self.tokens_q24.set(self.token_depth());
        self.rearms.bump();
    }

    /// The PI step `alpha * (qdelay - target) + beta * (qdelay - qdelay_old)` in Q24.
    fn control_delta(&self, qdelay_us: u32) -> i32 {
        // 64 us ticks clamped to 500 ms keep every product inside i32.
        let ticks = |us: u32| (us.min(500_000) >> 6) as i32;
        let error = ticks(qdelay_us) - ticks(self.target_us());
        let trend = ticks(qdelay_us) - ticks(self.qdelay_old_us.get());
        let alpha = (self.alpha_q10.get() & 0x3fff) as i32;
        let beta = (self.beta_q10.get() & 0x3fff) as i32;
        let raw = alpha * error + beta * trend;
        // Gain (1/1024) x tick (1/15625 s) x Q24 = 1.048576 ~ 1 + 1/16 - 1/64.
        let delta = raw + (raw >> 4) - (raw >> 6);
        // DOCSIS-PIE: smaller steps while p is small.
        let p = self.prob_q24.get();
        let shift = if p < P_SCALE / 200 {
            2
        } else if p < P_SCALE / 20 {
            1
        } else {
            0
        };
        (delta >> shift).min(MAX_STEP)
    }

    /// Whether to act on this packet at probability `p_q24`.
    fn trigger(&self, p_q24: u32, derandomise: bool) -> bool {
        if !derandomise {
            return self.random_q24() < p_q24;
        }
        let accu = self.accu_q24.get().saturating_add(p_q24);
        if accu < ACCU_LOW || (accu < ACCU_HIGH && self.random_q24() >= p_q24) {
            self.accu_q24.set(accu);
            return false;
        }
        self.accu_q24.set(0);
        true
    }

    /// Uniform Q24 sample from xorshift32.
    fn random_q24(&self) -> u32 {
        let mut x = match self.rng.get() {
            0 => RNG_SEED,
            x => x,
        };
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.rng.set(x);
        x & (P_SCALE - 1)
    }

    /// A ceiling drop spends one packet of budget; an empty bucket starts an overload.
    fn spend_token(&self) {
        if self.token_depth() == 0 {
            return;
        }
        let tokens = self.tokens_q24.get().saturating_sub(P_SCALE);
        self.tokens_q24.set(tokens);
        if tokens == 0 && self.overload.get() == 0 {
            self.overload.set(1);
            self.overloads.bump();
        }
    }

    /// A packet under the ceiling earns one packet's share of the budget.
    fn earn_token(&self) {
        let depth = self.token_depth();
        if depth == 0 {
            return;
        }
        let tokens = self.tokens_q24.get().saturating_add(self.budget());
        self.tokens_q24.set(tokens.min(depth));
    }

    fn target_us(&self) -> u32 {
        self.target_ms.get().saturating_mul(1000)
    }

    /// The cap on `p` outside overload: 0 or above 1.0 means no cap (plain RFC 8033).
    pub fn budget(&self) -> u32 {
        match self.drop_budget_q24.get() {
            0 => P_SCALE,
            b => b.min(P_SCALE),
        }
    }

    /// Bytes per ms the uplink drains: N4's grant EWMA is bytes per uplink TTI.
    pub fn drain_rate_bpms(&self, g_ema: u32) -> u32 {
        let per_frame = self.ul_subframes_per_frame.get().clamp(1, 10);
        (g_ema.saturating_mul(per_frame) / 10).max(self.min_rate_bpms.get()).max(1)
    }

    /// The ceiling at drain rate `rate_bpms`; 0 means none.
    pub fn ceiling_bytes(&self, rate_bpms: u32) -> u32 {
        self.ceiling_floor_bytes.get().max(rate_bpms.saturating_mul(self.ceiling_ms.get()))
    }

    /// The token bucket's depth (Q24 packets, at most 255); 0 turns overloads off.
    pub fn token_depth(&self) -> u32 {
        self.ceiling_burst_pkts.get().min(255) << 24
    }
}
