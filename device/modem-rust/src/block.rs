//! The 256-byte control block at `0x841b5900`: the ABI between the AQM, the DM
//! console (`vm`/`wm`), the keeper and the image builder.
//!
//! Every field is one little-endian 32-bit word. Readers check `magic` and `version`
//! before touching anything else. Layouts are extended, never reordered: M1's words
//! (version `0x2026_1125`) and R1's (`0x2026_1126`) keep their offsets and defaults,
//! and lane Q1's selector-3 words (`0x2026_1127`) fill the 21 words R1 left reserved.

#![forbid(unsafe_code)]

use core::sync::atomic::{AtomicU32, Ordering::Relaxed};

use crate::pie::{Decision, FLAG_DERANDOMISE, FLAG_SIZE_SCALE, P_SCALE, RNG_SEED};

/// `"M1PI"`.
pub const MAGIC: u32 = 0x4d31_5049;
/// This layout. Every change of layout or meaning gets a new value.
pub const VERSION: u32 = 0x2026_1127;

/// [`M1Block::selector`]: N4 v2's AQM, the boot default. Unknown values do the same.
pub const SELECTOR_N4: u32 = 0;
/// [`M1Block::selector`]: this crate's PIE.
pub const SELECTOR_PIE: u32 = 1;
/// [`M1Block::selector`]: no AQM (N4's backlog report and PDCP limit stay on).
pub const SELECTOR_NONE: u32 = 2;
/// [`M1Block::selector`]: lane Q1's controller ([`crate::q1`]): CoDel on the uplink
/// queue, held at or above the floor the second carrier needs, PIE as the backstop.
pub const SELECTOR_Q1: u32 = 3;
/// The largest selector the hook acts on; anything above it is N4 v2.
pub const SELECTOR_MAX: u32 = SELECTOR_Q1;

/// One 32-bit word that code outside Rust also reads and writes.
///
/// Relaxed atomics are plain `ldr`/`str` on ARMv7: the same single-copy-atomic word
/// access the DM console and the other patches use.
#[repr(transparent)]
pub struct Word(AtomicU32);

impl Word {
    pub const fn new(value: u32) -> Self {
        Self(AtomicU32::new(value))
    }

    #[inline(always)]
    pub fn get(&self) -> u32 {
        self.0.load(Relaxed)
    }

    #[inline(always)]
    pub fn set(&self, value: u32) {
        self.0.store(value, Relaxed)
    }

    /// Count one. A load and a store: the AQM is the only writer, and an increment
    /// lost to a DM reset in between does not matter.
    #[inline(always)]
    pub fn bump(&self) {
        self.set(self.get().wrapping_add(1))
    }

    /// Keep the high-water mark.
    #[inline(always)]
    pub fn raise(&self, value: u32) {
        if value > self.get() {
            self.set(value)
        }
    }
}

/// The control block. `tests/block.rs` pins every offset and default.
#[repr(C)]
pub struct M1Block {
    /// `+0x00` [`MAGIC`].
    pub magic: Word,
    /// `+0x04` [`VERSION`].
    pub version: Word,
    /// `+0x08` [`SELECTOR_N4`], [`SELECTOR_PIE`], [`SELECTOR_NONE`] or [`SELECTOR_Q1`];
    /// boots 0.
    pub selector: Word,

    // Tunables, read as they are used.
    /// `+0x0c` queue delay PIE steers toward.
    pub target_ms: Word,
    /// `+0x10` control-law period.
    pub t_update_ms: Word,
    /// `+0x14` time a new queue may stay above target without drops.
    pub max_burst_ms: Word,
    /// `+0x18` integral gain, Hz x 1024.
    pub alpha_q10: Word,
    /// `+0x1c` proportional gain, Hz x 1024.
    pub beta_q10: Word,
    /// `+0x20` floor on the drain-rate estimate.
    pub min_rate_bpms: Word,
    /// `+0x24` floor under the ceiling (covers a stale rate after idle). M1 called it
    /// `hard_cap_bytes`: the same floor under its `10 x G_ema` rule.
    pub ceiling_floor_bytes: Word,
    /// `+0x28` above this `p`, ECN-capable packets are dropped instead of marked;
    /// 0 marks at any `p`.
    pub ecn_max_prob_q24: Word,
    /// `+0x2c` packet-size scaling reference.
    pub mtu_bytes: Word,
    /// `+0x30` `pie::FLAG_SIZE_SCALE` | `pie::FLAG_DERANDOMISE`.
    pub flags: Word,
    /// `+0x34` cap on `p` outside overload; 0 or above `P_SCALE` means none. M1 called
    /// it `max_drop_prob_q24`.
    pub drop_budget_q24: Word,
    /// `+0x38` the ceiling in ms of queue at the drain rate (M1: `10 x G_ema` = 50 ms).
    pub ceiling_ms: Word,
    /// `+0x3c` TDD uplink subframes per 10 ms frame (config 2: 2, config 1: 4, FDD: 10).
    pub ul_subframes_per_frame: Word,

    // Controller state and live readings.
    /// `+0x40` drop probability, Q24.
    pub prob_q24: Word,
    /// `+0x44` derandomisation accumulator, Q24.
    pub accu_q24: Word,
    /// `+0x48` queue delay of the last packet.
    pub qdelay_us: Word,
    /// `+0x4c` queue delay at the last update.
    pub qdelay_old_us: Word,
    /// `+0x50` burst allowance left.
    pub burst_ms: Word,
    /// `+0x54` TTI of the last update.
    pub last_update_tti: Word,
    /// `+0x58` drain rate of the last packet.
    pub rate_bpms: Word,
    /// `+0x5c` xorshift32 state.
    pub rng: Word,

    // Counters.
    /// `+0x60` packets the AQM saw.
    pub seen: Word,
    /// `+0x64..+0x7b`, indexed by [`Decision`]: enqueued (every kind, CE marks and
    /// spared packets included), dropped, CE-marked, ceiling drops, small packets spared
    /// above target, packets spared by the burst allowance.
    pub decisions: [Word; 6],
    /// `+0x7c` control-law updates.
    pub updates: Word,
    /// `+0x80` peak queue delay.
    pub max_qdelay_us: Word,
    /// `+0x84` peak drop probability.
    pub max_prob_q24: Word,
    /// `+0x88` packets passed under [`SELECTOR_NONE`].
    pub bypassed: Word,
    /// `+0x8c` idle resets and burst-allowance re-arms.
    pub rearms: Word,
    /// `+0x90` age of the oldest unacknowledged PDCP SDU (telemetry).
    pub pdcp_hol_ms: Word,
    /// `+0x94` its peak.
    pub pdcp_max_hol_ms: Word,

    // Overload.
    /// `+0x98` token-bucket depth for ceiling drops, packets (at most 255); 0 turns
    /// overloads off (M1's behaviour).
    pub ceiling_burst_pkts: Word,
    /// `+0x9c` 1 while the budget is lifted.
    pub overload: Word,
    /// `+0xa0` ceiling drops the budget still covers, Q24 packets.
    pub tokens_q24: Word,
    /// `+0xa4` overloads started.
    pub overloads: Word,
    /// `+0xa8` updates spent in overload (x `t_update_ms` = time).
    pub overload_updates: Word,

    // Selector 3 (lane Q1, `crate::q1`). Tunables, read as they are used.
    /// `+0xac` the queue delay CoDel holds at the uplink's capacity.
    pub q1_target_ms: Word,
    /// `+0xb0` CoDel's interval: how long the queue must stay above target before
    /// the first drop, and the spacing of the drops after it (`interval / sqrt(n)`).
    pub q1_interval_ms: Word,
    /// `+0xb4` while the second uplink carrier is in use, CoDel holds at least this
    /// many bytes for many bulk flows ...
    pub q1_floor_bytes: Word,
    /// `+0xb8` ... and this many for one. For `n` flows the floor is
    /// `floor + ((floor_one - floor) >> (n - 1))`.
    pub q1_floor_one_bytes: Word,
    /// `+0xbc` N4's grant EWMA at or above this (bytes per uplink TTI) means two carriers.
    pub q1_two_cc_g_ema: Word,
    /// `+0xc0` how long two-carrier mode outlasts the last two-carrier grant.
    pub q1_two_cc_hold_ms: Word,
    /// `+0xc4` the backstop PIE's target as a multiple of CoDel's, Q8.
    pub q1_backstop_q8: Word,

    // Selector 3 state and readings.
    /// `+0xc8` the uplink's capacity: the peak of N4's grant EWMA, decaying 1/64
    /// per update, bytes per uplink TTI.
    pub q1_capacity: Word,
    /// `+0xcc` TTI of the last two-carrier grant.
    pub q1_two_cc_tti: Word,
    /// `+0xd0` bulk flows in the current window, one bit per hash bucket.
    pub q1_flow_bits: Word,
    /// `+0xd4` TTI the current flow window started.
    pub q1_flow_tti: Word,
    /// `+0xd8` bulk flows in the last window (at least 1).
    pub q1_flows: Word,
    /// `+0xdc` the queue CoDel holds now: `max(target_ms x capacity rate, floor)`.
    pub q1_target_bytes: Word,
    /// `+0xe0` [`crate::codel`] state bits: above target, dropping.
    pub q1_codel_state: Word,
    /// `+0xe4` TTI at which a queue above target becomes a standing queue.
    pub q1_first_above_tti: Word,
    /// `+0xe8` TTI of the next CoDel drop.
    pub q1_drop_next_tti: Word,
    /// `+0xec` drops in this dropping state.
    pub q1_count: Word,
    /// `+0xf0` the count the last dropping state started from.
    pub q1_lastcount: Word,
    /// `+0xf4` CoDel drops (the rest of `decisions[1]` are the backstop's).
    pub q1_codel_drops: Word,
    /// `+0xf8` CoDel CE marks (the rest of `decisions[2]` are the backstop's).
    pub q1_codel_marks: Word,
    /// `+0xfc` 1 in two-carrier mode (the floor applies): set by a two-carrier grant,
    /// cleared by the first update `q1_two_cc_hold_ms` after the last one.
    pub q1_two_cc: Word,
}

const _: () = assert!(core::mem::size_of::<M1Block>() == 256);

impl Default for M1Block {
    fn default() -> Self {
        Self::new()
    }
}

impl M1Block {
    /// The block as the image boots it: selector 0, defaults, a fresh controller and a
    /// full token bucket.
    pub const fn new() -> Self {
        const BURST_PKTS: u32 = 64;
        const MAX_BURST_MS: u32 = 55;
        Self {
            magic: Word::new(MAGIC),
            version: Word::new(VERSION),
            selector: Word::new(SELECTOR_N4),
            target_ms: Word::new(14),
            t_update_ms: Word::new(15),
            max_burst_ms: Word::new(MAX_BURST_MS),
            alpha_q10: Word::new(256),
            beta_q10: Word::new(2560),
            min_rate_bpms: Word::new(500),
            ceiling_floor_bytes: Word::new(50_000),
            ecn_max_prob_q24: Word::new(1_677_722), // 10%, as M1
            mtu_bytes: Word::new(1380),
            flags: Word::new(FLAG_SIZE_SCALE | FLAG_DERANDOMISE),
            drop_budget_q24: Word::new(P_SCALE / 50),
            ceiling_ms: Word::new(50),
            ul_subframes_per_frame: Word::new(2),
            prob_q24: Word::new(0),
            accu_q24: Word::new(0),
            qdelay_us: Word::new(0),
            qdelay_old_us: Word::new(0),
            burst_ms: Word::new(MAX_BURST_MS),
            last_update_tti: Word::new(0),
            rate_bpms: Word::new(0),
            rng: Word::new(RNG_SEED),
            seen: Word::new(0),
            decisions: [const { Word::new(0) }; 6],
            updates: Word::new(0),
            max_qdelay_us: Word::new(0),
            max_prob_q24: Word::new(0),
            bypassed: Word::new(0),
            rearms: Word::new(0),
            pdcp_hol_ms: Word::new(0),
            pdcp_max_hol_ms: Word::new(0),
            ceiling_burst_pkts: Word::new(BURST_PKTS),
            overload: Word::new(0),
            tokens_q24: Word::new(BURST_PKTS << 24),
            overloads: Word::new(0),
            overload_updates: Word::new(0),
            q1_target_ms: Word::new(8),
            q1_interval_ms: Word::new(40),
            q1_floor_bytes: Word::new(16_000),
            q1_floor_one_bytes: Word::new(32_000),
            q1_two_cc_g_ema: Word::new(8000),
            q1_two_cc_hold_ms: Word::new(2000),
            q1_backstop_q8: Word::new(384),
            q1_capacity: Word::new(0),
            q1_two_cc_tti: Word::new(0),
            q1_flow_bits: Word::new(0),
            q1_flow_tti: Word::new(0),
            q1_flows: Word::new(1),
            q1_target_bytes: Word::new(0),
            q1_codel_state: Word::new(0),
            q1_first_above_tti: Word::new(0),
            q1_drop_next_tti: Word::new(0),
            q1_count: Word::new(0),
            q1_lastcount: Word::new(0),
            q1_codel_drops: Word::new(0),
            q1_codel_marks: Word::new(0),
            q1_two_cc: Word::new(0),
        }
    }

    /// The count of one kind of decision.
    pub fn count(&self, decision: Decision) -> u32 {
        self.decisions[decision as usize].get()
    }

    /// The one place decisions become counters: every kind but a drop is also an
    /// enqueue.
    pub(crate) fn count_decision(&self, decision: Decision) {
        if !decision.is_drop() {
            self.decisions[Decision::Enqueue as usize].bump();
        }
        if decision != Decision::Enqueue {
            self.decisions[decision as usize].bump();
        }
    }

    /// Count a packet passed under [`SELECTOR_NONE`].
    pub fn record_bypass(&self) {
        self.bypassed.bump();
    }

    /// Record the age of the oldest unacknowledged PDCP SDU.
    pub fn record_pdcp_hol(&self, age_ms: u32) {
        self.pdcp_hol_ms.set(age_ms);
        self.pdcp_max_hol_ms.raise(age_ms);
    }
}
