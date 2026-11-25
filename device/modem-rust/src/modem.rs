//! Hook 4 in the Thumb-2 build: the control block, the naked shim N4 calls, and the
//! safe per-packet glue. All modem-memory access goes through [`hw`].
//!
//! N4 replaces `ldr r0, [r5, #4]; and r0, r0, #5` at `0x847e_d414` with
//! `bl m1_aqm_shim; nop`, in asm N4 (N6H) and in R4's Rust N4 alike. At the shim:
//!
//! - `lr` returns to the `nop` at `0x847e_d418`, before N4's `cmp r0, #5`;
//! - the stack top is N4's `{r0, r1, r3, r5, r6, lr}`, which both exits pop;
//! - `r4` is the IP length, `r5` N4's state block, `r6` the TTI clock, `r9` the bearer
//!   and `sl` the IRB buffer (IP header at `sl + 2`);
//! - `r0`, `r1`, `r3`, `ip` and the flags are free; `r2` must reach Exit B intact
//!   (Exit D reloads it), as must `r4`-`fp` and `sp`.

mod hw;

use core::arch::naked_asm;
use core::panic::PanicInfo;

use modem_atlas::l2::{PdcpUlSduEntry, PdcpUlSduWindow, Rbc};
use modem_atlas::patches::{N4ExtCounters, N4State};

use crate::block::{M1Block, SELECTOR_MAX, SELECTOR_NONE, SELECTOR_Q1};
use crate::pie::{Arrival, Decision};
use hw::{Packet, Shared, field};

/// Exit B: N4 pops its frame and enqueues to Ring 1 (stock `0x842d_a22c`).
const EXIT_ENQUEUE: u32 = 0x847e_d52e | 1;
/// Exit D: N4 loads `r2` = Ring 1, pops its frame and drops (stock `0x842d_a3e0`).
const EXIT_DROP: u32 = 0x847e_d51c | 1;

/// N4's AQM slot runs only with its PDCP limit (bit 0) and AQM (bit 2) on.
const N4_AQM_ON: u32 = 0b101;

// SAFETY (attribute): `.m1blk` is the dead `UMM_DecodeATR` range `0x841b_5900..0x841b_5a00`
// that `link-m1.ld` reserves for this block alone.
#[unsafe(link_section = ".m1blk")]
static M1_BLK: M1Block = M1Block::new();

/// The hook-4 shim, first in `.m1code` at `0x841d_e8dc` (R4's Rust N4 calls that
/// address directly).
///
/// - Selector 0, or any value above 3: N4 v2. Runs the two displaced instructions and
///   returns, using no stack.
/// - Selector 1, 2 or 3: calls `hw::m1_decide` on an 8-byte-aligned stack, keeping
///   `r2`, then takes Exit B or Exit D.
// SAFETY (attributes): exported once under this name so the image builder can find it;
// placed by `link-m1.ld`; naked because hook 4's register contract is not AAPCS.
#[unsafe(no_mangle)]
#[unsafe(naked)]
#[unsafe(link_section = ".text.m1_aqm_shim")]
extern "C" fn m1_aqm_shim() {
    naked_asm!(
        "movw r0, #:lower16:{block}",
        "movt r0, #:upper16:{block}",
        "ldr r1, [r0, #{selector}]",
        "cbz r1, 2f",
        "cmp r1, #{max}",
        "bhi 2f",
        "mov r3, sp",
        "bic r1, r3, #7",
        "mov sp, r1",
        "push {{r2, r3}}",
        "mov r0, r9",
        "mov r1, r4",
        "mov r2, r6",
        "mov r3, sl",
        "bl {decide}",
        "pop {{r2, r3}}",
        "mov sp, r3",
        "cbnz r0, 1f",
        "movw ip, #{enqueue_lo}",
        "movt ip, #{enqueue_hi}",
        "bx ip",
        "1:",
        "movw ip, #{drop_lo}",
        "movt ip, #{drop_hi}",
        "bx ip",
        "2:",
        "ldr r0, [r5, #4]",
        "and r0, r0, #5",
        "bx lr",
        block = sym M1_BLK,
        selector = const core::mem::offset_of!(M1Block, selector),
        max = const SELECTOR_MAX,
        decide = sym hw::m1_decide,
        enqueue_lo = const EXIT_ENQUEUE & 0xffff,
        enqueue_hi = const EXIT_ENQUEUE >> 16,
        drop_lo = const EXIT_DROP & 0xffff,
        drop_hi = const EXIT_DROP >> 16,
    );
}

/// One bulk packet under selector 1, 2 or 3. Returns true to drop it.
fn on_packet(packet: Packet<'_>) -> bool {
    if hw::N4.get(field!(N4State, flags)) & N4_AQM_ON != N4_AQM_ON {
        return false;
    }
    let selector = M1_BLK.selector.get();
    if selector == SELECTOR_NONE {
        M1_BLK.record_bypass();
        return false;
    }
    let rbc = packet.rbc;
    let ring = rbc.get(field!(Rbc, ring_pending_bytes));
    let staged = rbc.get(field!(Rbc, pdcp_rlc_tx_bo));
    let arrival = Arrival {
        len: packet.len,
        now: packet.now,
        queue_bytes: ring.saturating_add(staged),
        g_ema: hw::N4.get(field!(N4State, g_ema)),
        min_len: hw::N4.get(field!(N4State, aqm_minlen)),
    };
    // Selector 1 records the PDCP telemetry on every packet; selector 3 with its
    // periodic update.
    let decision = if selector == SELECTOR_Q1 {
        if M1_BLK.q1_tick(&arrival) {
            M1_BLK.record_pdcp_hol(pdcp_hol_age_ms(rbc, packet.now));
        }
        M1_BLK.decide_q1(arrival, packet.ip)
    } else {
        M1_BLK.record_pdcp_hol(pdcp_hol_age_ms(rbc, packet.now));
        M1_BLK.decide(arrival, packet.ip)
    };
    mirror_in_n4(decision);
    decision.is_drop()
}

/// N4's AQM counters stay meaningful whichever AQM runs; the keeper and the bench
/// tools read them. (Comparisons, not a `match`: a match this dense becomes a branch
/// table, which is PC-relative code the cave audit rejects.)
fn mirror_in_n4(decision: Decision) {
    if decision.is_drop() {
        hw::N4.bump(field!(N4State, cnt_aqm_drop));
        if decision == Decision::Ceiling {
            hw::N4_EXT.bump(field!(N4ExtCounters, cnt_drop_hard));
        }
    } else if decision == Decision::Mark {
        hw::N4.bump(field!(N4State, cnt_aqm_mark));
    } else if decision == Decision::SparedSmall {
        hw::N4.bump(field!(N4State, cnt_spared));
    }
}

/// Age of the bearer's oldest unacknowledged PDCP SDU, for the bench. Not an AQM
/// input: it counts from Ring-1 dequeue and includes HARQ and the RLC status trip.
fn pdcp_hol_age_ms(rbc: Shared<Rbc>, now: u32) -> u32 {
    let Some(window) = hw::pdcp_window(rbc) else {
        return 0;
    };
    if window.get(field!(PdcpUlSduWindow, active_count)) == 0 {
        return 0;
    }
    let sn_max = rbc.get(field!(Rbc, pdcp_sn_max));
    let mask = if sn_max == 0 { 0x0fff } else { sn_max.wrapping_sub(1) & 0x0fff };
    let oldest = usize::from(rbc.get(field!(Rbc, pdcp_ul_oldest_sn)) & mask);
    let entries = field!(PdcpUlSduWindow, entries);
    let enqueued = field!(PdcpUlSduEntry, enqueue_tti_and_flags);
    match window.get_element(entries, oldest, enqueued).unwrap_or(0) & !1 {
        0 => 0,
        tti => now.wrapping_sub(tti),
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
