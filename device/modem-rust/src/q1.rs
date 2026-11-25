//! Selector 3 (lane Q1): CoDel on the uplink queue, held at or above the floor the
//! second uplink carrier needs, with PIE as the backstop for senders that ignore loss.
//!
//! What it fixes in selector 1 (v1.0.16's PIE), from the 2026-11-25 bench:
//!
//! - **Its queue floats.** PIE caps `p` at a 2% budget so the buffer report stays high
//!   enough for the eNB to keep the second carrier. Four CUBIC flows need about 4%, so
//!   they float at about 45 KB on two carriers: 24 ms median queue against N4's 17.
//!   Here the floor does the budget's job directly, and `p` has no cap.
//! - **It fights the grant pipeline.** The eNB sizes each grant from a buffer report two
//!   uplink TTIs old, so below the link's capacity the queue always holds about two
//!   TTIs of arrivals whatever the AQM does, and `queue / G_ema` reads about 10 ms.
//!   CUBIC x1 runs at N4 (10.8 KB) and PIE (17-19 KB) both sat at 15 ms. Selector 3
//!   measures the queue against the capacity (the decaying peak of N4's grant EWMA),
//!   not the current grant, so it only acts on the part of the queue capacity cannot
//!   explain.
//! - **It is slow for one flow.** PIE's integral lets one CUBIC flow overshoot; CoDel
//!   signals it about once per interval at the target.
//!
//! The pieces:
//!
//! - **Target:** `max(q1_target_ms x capacity rate, floor)` bytes, recomputed every
//!   `t_update_ms` into `q1_target_bytes`.
//! - **Floor:** only while the second carrier is in use (N4's grant EWMA at or above
//!   `q1_two_cc_g_ema` within `q1_two_cc_hold_ms`): `q1_floor_bytes` for many bulk
//!   flows, up to `q1_floor_one_bytes` for one (`crate::flows`). One carrier: no floor.
//! - **CoDel** (`crate::codel`) on bulk packets against the target.
//! - **Backstop:** selector 1's PI law, uncapped, toward `q1_backstop_q8` times the
//!   target. It stays at zero while CoDel holds the queue, and holds BBR and floods.
//! - The ceiling, the burst allowance, ECN and the small-packet rule are selector 1's.
//!
//! Per packet there is no grant bookkeeping and no PDCP walk, and the only division is the
//! backstop's packet-size scaling: the capacity, carrier mode, delay estimate, target and
//! PDCP telemetry move to the update every `t_update_ms`.

#![forbid(unsafe_code)]

use crate::block::M1Block;
use crate::flows;
use crate::pie::{Arrival, Decision, FLAG_DERANDOMISE, P_SCALE};

/// Bulk flows are counted over windows this long.
pub const FLOW_WINDOW_MS: u32 = 100;

/// Each update, the capacity estimate (the peak of N4's grant EWMA) decays by 1/64 toward
/// the current EWMA (half-life about 0.7 s at 15 ms updates), so it follows a lost carrier.
pub const CAPACITY_DECAY_SHIFT: u32 = 6;

impl M1Block {
    /// Selector 3's periodic update, if `t_update_ms` has passed since the last one.
    /// Returns whether it ran. The hook calls it before [`M1Block::decide_q1`].
    pub fn q1_tick(&self, arrival: &Arrival) -> bool {
        let due = arrival.now.wrapping_sub(self.last_update_tti.get()) >= self.t_update_ms.get();
        if due {
            self.q1_update(arrival);
        }
        due
    }

    /// Decide one packet under selector 3 and count it, after [`M1Block::q1_tick`]. `ip`
    /// is the start of its IP header (CE is set in place).
    pub fn decide_q1(&self, arrival: Arrival, ip: &mut [u8]) -> Decision {
        self.seen.bump();
        let bulk = arrival.len >= arrival.min_len;
        if bulk {
            self.q1_flow_bits.set(self.q1_flow_bits.get() | flows::flow_bit(ip));
        }

        // Small packets (ACKs, DNS, VoIP, handshakes) are never dropped or marked.
        let decision = if bulk {
            self.q1_classify(&arrival, ip)
        } else if arrival.queue_bytes > self.q1_target_bytes.get() {
            Decision::SparedSmall
        } else {
            Decision::Enqueue
        };
        self.count_decision(decision);
        decision
    }

    fn q1_classify(&self, arrival: &Arrival, ip: &mut [u8]) -> Decision {
        let queue = arrival.queue_bytes;
        let ceiling = self.ceiling_bytes(self.rate_bpms.get());
        if ceiling > 0 && queue > ceiling {
            self.accu_q24.set(0);
            return Decision::Ceiling;
        }

        let target = self.q1_target_bytes.get();
        let mtu = self.mtu_bytes.get().max(1);
        if self.codel_signals(arrival.now, queue, target, mtu) {
            return if crate::ecn::mark_ce(ip) {
                self.q1_codel_marks.bump();
                Decision::Mark
            } else {
                self.q1_codel_drops.bump();
                Decision::Drop
            };
        }

        // The backstop: selector 1's drop decision on the uncapped `p`, never at or under
        // CoDel's target (the floor the second carrier needs), whatever `p` still holds.
        if queue <= target {
            return Decision::Enqueue;
        }
        if self.burst_ms.get() > 0 {
            return Decision::SparedBurst;
        }
        let p = self.prob_q24.get();
        if p == 0 {
            return Decision::Enqueue;
        }
        let flags = self.flags.get();
        if !self.trigger(Self::packet_prob(p, arrival.len, mtu, flags), flags & FLAG_DERANDOMISE != 0) {
            return Decision::Enqueue;
        }
        self.mark_or_drop(p, ip)
    }

    /// Every `t_update_ms`: the flow count, the capacity, carrier mode and target, the
    /// readings selector 1 keeps per packet, and the backstop's control law. N4's grant
    /// EWMA moves once per uplink TTI and the carrier hold is seconds long, so sampling it
    /// here (every three uplink TTIs at TDD config 2) instead of per packet loses nothing.
    #[inline(never)]
    fn q1_update(&self, arrival: &Arrival) {
        let now = arrival.now;
        if now.wrapping_sub(self.q1_flow_tti.get()) >= FLOW_WINDOW_MS {
            self.q1_flows.set(flows::count(self.q1_flow_bits.get()));
            self.q1_flow_bits.set(0);
            self.q1_flow_tti.set(now);
        }

        let g_ema = arrival.g_ema;
        let capacity = self.q1_capacity.get();
        let capacity = (capacity - (capacity >> CAPACITY_DECAY_SHIFT)).max(g_ema);
        self.q1_capacity.set(capacity);
        let rate_bpms = self.drain_rate_bpms(capacity);

        // Two-carrier mode starts with a two-carrier grant EWMA and ends
        // `q1_two_cc_hold_ms` after the last one. It boots off.
        if g_ema >= self.q1_two_cc_g_ema.get() {
            self.q1_two_cc_tti.set(now);
            self.q1_two_cc.set(1);
        }
        let two_cc = self.q1_two_cc.get() != 0
            && now.wrapping_sub(self.q1_two_cc_tti.get()) <= self.q1_two_cc_hold_ms.get();
        self.q1_two_cc.set(u32::from(two_cc));
        let floor = if two_cc { self.q1_floor(self.q1_flows.get()) } else { 0 };
        let target = self.q1_target_ms.get().saturating_mul(rate_bpms).max(floor);
        self.q1_target_bytes.set(target);

        let qdelay_us = arrival.queue_bytes.min(4_000_000) * 1000 / rate_bpms;
        self.rate_bpms.set(rate_bpms);
        self.qdelay_us.set(qdelay_us);
        self.max_qdelay_us.raise(qdelay_us);

        let target_us = target.min(4_000_000) * 1000 / rate_bpms;
        let backstop_us = target_us.min(500_000).saturating_mul(self.q1_backstop_q8.get()) >> 8;
        let dt = now.wrapping_sub(self.last_update_tti.get());
        self.pi_step(qdelay_us, now, dt, backstop_us, P_SCALE);
    }

    /// The floor for `flows` bulk flows while the second carrier is in use:
    /// `floor + ((floor_one - floor) >> (flows - 1))`.
    pub fn q1_floor(&self, flows: u32) -> u32 {
        let floor = self.q1_floor_bytes.get();
        let extra = self.q1_floor_one_bytes.get().saturating_sub(floor);
        floor.saturating_add(extra >> flows.saturating_sub(1).min(31))
    }
}
