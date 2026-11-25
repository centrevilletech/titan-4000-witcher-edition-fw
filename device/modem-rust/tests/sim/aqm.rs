//! The AQMs the traces compare, behind one interface.

// Each trace binary (traces.rs, q1_traces.rs) uses a subset of these.
#![allow(dead_code)]

use witcher_modem_aqm::block::{M1Block, SELECTOR_PIE, SELECTOR_Q1};
use witcher_modem_aqm::pie::{Arrival, Decision};

pub enum Verdict {
    Pass,
    /// A probabilistic (PIE) or paced (N4) drop.
    Drop,
    /// A drop at the ceiling, or in N4's hard region.
    Ceiling,
}

pub trait Aqm {
    /// One bulk packet of `len` bytes from sender `flow` at Ring-1 enqueue.
    fn decide(&mut self, queue_bytes: u32, g_ema: u32, len: u32, now: u32, flow: usize) -> Verdict;
}

fn verdict(decision: Decision) -> Verdict {
    match decision {
        Decision::Drop => Verdict::Drop,
        Decision::Ceiling => Verdict::Ceiling,
        _ => Verdict::Pass,
    }
}

/// This crate's PIE, through the control block as the hook drives it.
pub struct Pie {
    pub block: M1Block,
}

impl Pie {
    /// The shipped defaults.
    pub fn new() -> Self {
        let block = M1Block::new();
        block.selector.set(SELECTOR_PIE);
        Self { block }
    }

    /// Overload detection off: M1's ceiling and 2% budget, the bench state of
    /// 2026-11-25.
    pub fn without_latch() -> Self {
        let pie = Self::new();
        pie.block.ceiling_burst_pkts.set(0);
        pie
    }
}

impl Aqm for Pie {
    fn decide(&mut self, queue_bytes: u32, g_ema: u32, len: u32, now: u32, _flow: usize) -> Verdict {
        let mut ip = [0u8; 40];
        ip[0] = 0x45; // IPv4, not ECN-capable
        let arrival = Arrival { len, now, queue_bytes, g_ema, min_len: 600 };
        verdict(self.block.decide(arrival, &mut ip))
    }
}

/// Lane Q1's selector 3, through the control block as the hook drives it. Each sender
/// is a TCP flow from its own source port, so the flow count sees them apart.
pub struct Q1 {
    pub block: M1Block,
}

impl Q1 {
    pub fn new() -> Self {
        let block = M1Block::new();
        block.selector.set(SELECTOR_Q1);
        Self { block }
    }
}

impl Aqm for Q1 {
    fn decide(&mut self, queue_bytes: u32, g_ema: u32, len: u32, now: u32, flow: usize) -> Verdict {
        let mut ip = [0u8; 44];
        ip[0] = 0x45; // IPv4 + TCP, not ECN-capable
        ip[9] = 6;
        ip[12..16].copy_from_slice(&[192, 0, 2, 1]);
        ip[16..20].copy_from_slice(&[198, 51, 100, 1]);
        ip[20..22].copy_from_slice(&(40_000 + flow as u16).to_be_bytes());
        ip[22..24].copy_from_slice(&5299u16.to_be_bytes());
        let arrival = Arrival { len, now, queue_bytes, g_ema, min_len: 600 };
        self.block.q1_tick(&arrival);
        verdict(self.block.decide_q1(arrival, &mut ip))
    }
}

/// N4 AQM v2 (`n4_ul_engine.s`, `hook4_check_aqm`) for non-ECN packets: the selector-0
/// path. `Q_target = clamp(3 G_ema, 20 KB, 48 KB)`; above it one paced drop per 35 ms,
/// above twice it every big packet.
pub struct N4 {
    last_drop: u32,
}

impl N4 {
    pub fn new() -> Self {
        Self { last_drop: 0 }
    }
}

impl Aqm for N4 {
    fn decide(&mut self, queue_bytes: u32, g_ema: u32, len: u32, now: u32, _flow: usize) -> Verdict {
        let target = (3 * g_ema).clamp(20_480, 49_152);
        if queue_bytes <= target || len < 600 {
            return Verdict::Pass;
        }
        if queue_bytes > 2 * target {
            return Verdict::Ceiling;
        }
        if now.wrapping_sub(self.last_drop) >= 35 {
            self.last_drop = now;
            return Verdict::Drop;
        }
        Verdict::Pass
    }
}
