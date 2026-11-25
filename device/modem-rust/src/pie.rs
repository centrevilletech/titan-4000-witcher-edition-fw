//! Burst-tolerant Proportional Integral controller Enhanced (PIE, RFC 8033 / RFC 8034)
//! tailored to an enqueue-time LTE UE uplink hook (GCT GDM7243A TDD Config 2).
//!
//! Pure 32-bit integer / fixed-point `no_std` implementation: zero floating-point,
//! zero 64-bit arithmetic, zero heap allocation, and zero panics.

use crate::ecn::try_mark_ce;

/// Fixed-point probability unity (`1.0 == 1 << 24 = 16_777_216`).
pub const P_SCALE: u32 = 1 << 24;

/// De-randomization thresholds (`0.5` and `4.0`, tuned from RFC 8033 Section 5.1
/// for low-BDP 1CC LTE uplinks so first drops aren't delayed by ~500 ms).
pub const ACCU_LOW: u32 = P_SCALE >> 1;
pub const ACCU_HIGH: u32 = P_SCALE << 2;

/// Identity magic `"M1PI"` (decodes cleanly as Thumb-2 under Capstone).
pub const M1_MAGIC: u32 = 0x4d31_5049;
/// Build version `2026-11-25` (BCD, decodes cleanly as Thumb-2 under Capstone).
pub const M1_VERSION: u32 = 0x2026_1125;

/// Runtime selector values at `M1Block::selector` (`0x841b5908`).
pub const SELECTOR_N4_V2: u32 = 0;
pub const SELECTOR_RUST_PIE: u32 = 1;
pub const SELECTOR_NO_AQM: u32 = 2;

/// Feature flags in `M1Block::flags` (`0x841b5930`).
pub const FLAG_SIZE_SCALE: u32 = 1 << 0;
pub const FLAG_DERAND: u32 = 1 << 1;

/// Outcome of evaluating one Ring-1 uplink packet.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Decision {
    /// Enqueue normally to Ring 1 (Exit B).
    Enqueue = 0,
    /// Enqueue normally to Ring 1 after marking CE in place (Exit B).
    EcnMark = 1,
    /// Probabilistic PIE drop (Exit D).
    Drop = 2,
    /// Hard overload ceiling drop (Exit D).
    HardDrop = 3,
    /// Spared because `pkt_len < min_len` while congested (Exit B).
    SparedSmall = 4,
}

impl Decision {
    #[inline]
    pub const fn is_drop(self) -> bool {
        matches!(self, Decision::Drop | Decision::HardDrop)
    }
}

/// 256-byte (4 x 64 B cache lines) RAM control, parameter, state, and counter block.
///
/// Placed at `0x841b5900..0x841b5a00` inside dead `UMM_DecodeATR` (M2 cave catalog).
/// Every field is a 32-bit little-endian word readable/writable via DM `vm`/`wm`.
#[repr(C)]
#[derive(Clone, Debug)]
pub struct M1Block {
    // --- Header & tunable parameters (+0x00..+0x3f) ---
    pub magic: u32,             // +0x00: 0x4d315049 ("M1PI")
    pub version: u32,           // +0x04: 0x20261125
    pub selector: u32,          // +0x08: 0=old N4 v2 (default/rollback), 1=Rust PIE, 2=no AQM
    pub target_delay_ms: u32,   // +0x0c: target queue delay in ms (default 14)
    pub t_update_ms: u32,       // +0x10: PI control-law update period in ms (default 15)
    pub max_burst_ms: u32,      // +0x14: burst allowance window in ms (default 55)
    pub alpha_q10: u32,         // +0x18: alpha * 1024 in Hz (default 256 = 0.25, DOCSIS-PIE)
    pub beta_q10: u32,          // +0x1c: beta * 1024 in Hz (default 2560 = 2.50, DOCSIS-PIE)
    pub min_rate_bpms: u32,     // +0x20: floor on drain-rate estimate in B/ms (default 500 = 4 Mbps)
    pub hard_cap_bytes: u32,    // +0x24: min overload ceiling in bytes (default 50000 = 50 KB; scales with 10*G_ema)
    pub ecn_max_prob_q24: u32,  // +0x28: max prob_q24 for ECN marking (default 1677722 ~= 10%)
    pub mtu_bytes: u32,         // +0x2c: reference MTU for packet-size scaling (default 1380)
    pub flags: u32,             // +0x30: bit0=size_scale, bit1=accu_prob derand (default 3)
    pub max_drop_prob_q24: u32, // +0x34: cap on probabilistic drop/mark rate in Q24 (default 335544 = 2%; 0=uncapped)
    pub reserved_cfg: [u32; 2], // +0x38..+0x3f

    // --- Live PIE controller state (+0x40..+0x5f) ---
    pub prob_q24: u32,        // +0x40: current drop/mark probability in Q24 (1.0 = 1<<24)
    pub accu_prob_q24: u32,   // +0x44: RFC 8033 Section 5.1 de-randomization accumulator
    pub qdelay_us: u32,       // +0x48: latest estimated total queue sojourn delay (us)
    pub qdelay_old_us: u32,   // +0x4c: previous T_update queue delay (us)
    pub burst_allow_ms: u32,  // +0x50: remaining burst allowance (ms)
    pub last_update_tti: u32, // +0x54: 1 ms TTI clock of last PI update
    pub last_rate_bpms: u32,  // +0x58: latest estimated drain rate (B/ms)
    pub rng_state: u32,       // +0x5c: xorshift32 PRNG state (non-zero)

    // --- Diagnostic counters (+0x60..+0x97) ---
    pub c_pie_seen: u32,          // +0x60: packets evaluated by Rust PIE
    pub c_pie_enq: u32,           // +0x64: packets enqueued (incl. ECN marked & spared)
    pub c_pie_drop: u32,          // +0x68: probabilistic PIE drops
    pub c_pie_mark: u32,          // +0x6c: ECN CE marks applied
    pub c_pie_hard_drop: u32,     // +0x70: hard-cap overload drops
    pub c_pie_spared_small: u32,  // +0x74: packets < min_len spared while congested
    pub c_pie_spared_burst: u32,  // +0x78: packets spared by burst_allow_ms > 0
    pub c_pie_updates: u32,       // +0x7c: PI control-law updates executed
    pub c_pie_max_qdelay_us: u32, // +0x80: peak estimated queue delay (us)
    pub c_pie_max_prob_q24: u32,  // +0x84: peak prob_q24 observed
    pub c_bypass_pkts: u32,       // +0x88: packets bypassed under selector == 2
    pub c_pie_idle_resets: u32,   // +0x8c: idle/quiet burst-allowance resets
    pub pdcp_hol_age_ms: u32,     // +0x90: live PDCP-to-ACK HoL age from rbc->pdcp_ul_win[oldest_sn] (telemetry)
    pub pdcp_max_hol_age_ms: u32, // +0x94: peak PDCP-to-ACK HoL age observed (ms)

    // --- Zero tail to exact 256 B (+0x98..+0xff) ---
    pub reserved_tail: [u32; 26],
}

const _: () = assert!(core::mem::size_of::<M1Block>() == 256);

impl M1Block {
    /// Boot-default `M1Block` with `selector = 0` (old N4 v2 behaviour, off by default).
    pub const fn new_boot_default() -> Self {
        Self {
            magic: M1_MAGIC,
            version: M1_VERSION,
            selector: SELECTOR_N4_V2,
            target_delay_ms: 14,
            t_update_ms: 15,
            max_burst_ms: 55,
            alpha_q10: 256,              // 0.25 Hz (DOCSIS-PIE)
            beta_q10: 2560,              // 2.50 Hz (DOCSIS-PIE)
            min_rate_bpms: 500,          // 4 Mbps drain floor
            hard_cap_bytes: 50_000,      // 50 KB floor (adapts to max(hard_cap_bytes, 10*G_ema); Capstone-clean word 0x0000c350)
            ecn_max_prob_q24: 1_677_722, // ~10% of 2^24
            mtu_bytes: 1380,
            flags: FLAG_SIZE_SCALE | FLAG_DERAND,
            max_drop_prob_q24: 335_544, // 2% probabilistic cap (0 = uncapped)
            reserved_cfg: [0; 2],
            prob_q24: 0,
            accu_prob_q24: 0,
            qdelay_us: 0,
            qdelay_old_us: 0,
            burst_allow_ms: 55,
            last_update_tti: 0,
            last_rate_bpms: 0,
            rng_state: 0x1357_2468,
            c_pie_seen: 0,
            c_pie_enq: 0,
            c_pie_drop: 0,
            c_pie_mark: 0,
            c_pie_hard_drop: 0,
            c_pie_spared_small: 0,
            c_pie_spared_burst: 0,
            c_pie_updates: 0,
            c_pie_max_qdelay_us: 0,
            c_pie_max_prob_q24: 0,
            c_bypass_pkts: 0,
            c_pie_idle_resets: 0,
            pdcp_hol_age_ms: 0,
            pdcp_max_hol_age_ms: 0,
            reserved_tail: [0; 26],
        }
    }

    #[inline(always)]
    fn next_rand_q24(&mut self) -> u32 {
        let mut x = self.rng_state;
        if x == 0 {
            x = 0x1357_2468;
        }
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.rng_state = x;
        x & (P_SCALE - 1)
    }

    /// Run the periodic RFC 8033 / 8034 PI control-law update when `t_update_ms` has elapsed.
    #[inline(never)]
    fn update_pi(&mut self, cur_delay_us: u32, target_us: u32, now_tti: u32, dt: u32) {
        // First packet ever or long idle gap (> 200 ms): reset controller cleanly.
        if self.c_pie_updates == 0 || dt > 200 {
            self.prob_q24 = 0;
            self.accu_prob_q24 = 0;
            self.qdelay_old_us = cur_delay_us;
            self.burst_allow_ms = self.max_burst_ms;
            self.last_update_tti = now_tti;
            self.c_pie_updates = self.c_pie_updates.wrapping_add(1);
            self.c_pie_idle_resets = self.c_pie_idle_resets.wrapping_add(1);
            return;
        }

        let old_delay_us = self.qdelay_old_us;
        // 64 us ticks (1/15625 s), clamped to +-500 ms -> pure 32-bit i32 math.
        let cur_t = (cur_delay_us.min(500_000) >> 6) as i32;
        let ref_t = (target_us.min(500_000) >> 6) as i32;
        let old_t = (old_delay_us.min(500_000) >> 6) as i32;
        let err = cur_t - ref_t;
        let diff = cur_t - old_t;

        // (q10 / 1024) * (ticks / 15625) * 2^24 = q10 * ticks * 1.048576
        // ~= sum + (sum >> 4) - (sum >> 6)  (1.046875, 0.16% accuracy, zero division).
        let a = (self.alpha_q10 & 0x3fff) as i32;
        let b = (self.beta_q10 & 0x3fff) as i32;
        let raw_sum = a * err + b * diff;
        let raw_delta = raw_sum + (raw_sum >> 4) - (raw_sum >> 6);

        let prob = self.prob_q24;
        // DOCSIS-PIE (RFC 8034) gain auto-scaling.
        let shift: u32 = if prob < (P_SCALE / 200) {
            2 // p < 0.5%: 1/4 step
        } else if prob < (P_SCALE / 20) {
            1 // p < 5%: 1/2 step
        } else {
            0
        };
        let mut delta = raw_delta >> shift;
        let max_step = (P_SCALE / 50) as i32; // cap positive jump at +2% per tick
        if delta > max_step {
            delta = max_step;
        }

        let cap = if self.max_drop_prob_q24 > 0 && self.max_drop_prob_q24 < P_SCALE {
            self.max_drop_prob_q24 as i32
        } else {
            P_SCALE as i32
        };
        let mut new_prob = (prob as i32 + delta).clamp(0, cap) as u32;

        // Exponential decay and burst-allowance reset when queue stays below target/2.
        let half_target = target_us >> 1;
        if cur_delay_us < half_target && old_delay_us < half_target {
            new_prob -= new_prob >> 3;
            if new_prob < 16 {
                new_prob = 0;
            }
            if new_prob == 0 {
                self.burst_allow_ms = self.max_burst_ms;
                self.accu_prob_q24 = 0;
                self.c_pie_idle_resets = self.c_pie_idle_resets.wrapping_add(1);
            }
        } else if self.burst_allow_ms > 0 {
            self.burst_allow_ms = self.burst_allow_ms.saturating_sub(dt);
        }

        self.prob_q24 = new_prob;
        if new_prob > self.c_pie_max_prob_q24 {
            self.c_pie_max_prob_q24 = new_prob;
        }
        self.qdelay_old_us = cur_delay_us;
        self.last_update_tti = now_tti;
        self.c_pie_updates = self.c_pie_updates.wrapping_add(1);
    }

    /// Evaluate one Ring-1 uplink packet arriving at `now_tti` (1 ms TTI clock).
    #[inline]
    pub fn evaluate_packet(
        &mut self,
        q_total: u32,
        g_ema: u32,
        min_len: u32,
        pkt_len: u32,
        now_tti: u32,
        ip_hdr: &mut [u8],
    ) -> Decision {
        self.c_pie_seen = self.c_pie_seen.wrapping_add(1);

        // Drain rate in B/ms: TDD Config 2 has 1 UL subframe per 5 ms -> G_ema / 5.
        let rate_bpms = (g_ema / 5).max(self.min_rate_bpms.max(1));
        self.last_rate_bpms = rate_bpms;
        let cur_delay_us = (q_total.min(4_000_000) * 1000) / rate_bpms;
        self.qdelay_us = cur_delay_us;
        if cur_delay_us > self.c_pie_max_qdelay_us {
            self.c_pie_max_qdelay_us = cur_delay_us;
        }

        let target_us = self.target_delay_ms * 1000;
        let dt = now_tti.wrapping_sub(self.last_update_tti);
        if self.c_pie_updates == 0 || dt >= self.t_update_ms {
            self.update_pi(cur_delay_us, target_us, now_tti, dt);
        }

        // Rule 1: Never drop or mark packets shorter than min_len (600 B, N5 fast lane).
        if pkt_len < min_len {
            self.c_pie_enq = self.c_pie_enq.wrapping_add(1);
            if cur_delay_us > target_us {
                self.c_pie_spared_small = self.c_pie_spared_small.wrapping_add(1);
                return Decision::SparedSmall;
            }
            return Decision::Enqueue;
        }

        // Rule 2: Adaptive hard overload ceiling (max(hard_cap_bytes, 10 * G_ema) = ~50 ms on 1CC & 2CC).
        let hard_cap = self.hard_cap_bytes;
        if hard_cap > 0 {
            let scaled_cap = g_ema.saturating_mul(10);
            let eff_cap = if scaled_cap > hard_cap { scaled_cap } else { hard_cap };
            if q_total > eff_cap {
                self.accu_prob_q24 = 0;
                self.c_pie_hard_drop = self.c_pie_hard_drop.wrapping_add(1);
                return Decision::HardDrop;
            }
        }

        // Rule 3: Burst tolerance window absorbs TDD 5 ms framing, HARQ pauses, and TCP GSO bursts.
        if self.burst_allow_ms > 0 {
            if cur_delay_us > target_us {
                self.c_pie_spared_burst = self.c_pie_spared_burst.wrapping_add(1);
            }
            self.c_pie_enq = self.c_pie_enq.wrapping_add(1);
            return Decision::Enqueue;
        }

        // Rule 4: Low-queue drop suppression (RFC 8033 Section 4.3).
        let mtu = self.mtu_bytes.max(1);
        let prob = self.prob_q24;
        let half_target = target_us >> 1;
        if prob == 0
            || q_total < (mtu << 1)
            || (cur_delay_us < half_target && self.qdelay_old_us < half_target && prob < (P_SCALE / 5))
        {
            self.c_pie_enq = self.c_pie_enq.wrapping_add(1);
            return Decision::Enqueue;
        }

        // Rule 5: Packet-size scaling (RFC 8033 Section 5.2, 32-bit udiv only).
        let p_pkt = if (self.flags & FLAG_SIZE_SCALE) != 0 && pkt_len < mtu {
            (((prob >> 8) * pkt_len) / mtu) << 8
        } else {
            prob
        };

        // Rule 6: De-randomized drop/mark decision (RFC 8033 Section 5.1).
        let trigger = if (self.flags & FLAG_DERAND) != 0 {
            let acc = self.accu_prob_q24.saturating_add(p_pkt);
            if acc < ACCU_LOW {
                self.accu_prob_q24 = acc;
                false
            } else if acc >= ACCU_HIGH || self.next_rand_q24() < p_pkt {
                self.accu_prob_q24 = 0;
                true
            } else {
                self.accu_prob_q24 = acc;
                false
            }
        } else {
            self.next_rand_q24() < p_pkt
        };

        if !trigger {
            self.c_pie_enq = self.c_pie_enq.wrapping_add(1);
            return Decision::Enqueue;
        }

        // Rule 7: ECN CE mark for ECT(0)/ECT(1) packets when prob <= ecn_max_prob_q24 (RFC 8033 Section 5.3).
        if (self.ecn_max_prob_q24 == 0 || prob <= self.ecn_max_prob_q24) && try_mark_ce(ip_hdr) {
            self.c_pie_mark = self.c_pie_mark.wrapping_add(1);
            self.c_pie_enq = self.c_pie_enq.wrapping_add(1);
            return Decision::EcnMark;
        }

        self.c_pie_drop = self.c_pie_drop.wrapping_add(1);
        Decision::Drop
    }
}
