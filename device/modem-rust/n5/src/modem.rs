//! Bare-metal Cortex-A7 Thumb-2 integration for the Titan 4000 N5 per-flow sparse lane.
//!
//! This is the ONLY module in `witcher-modem-n5` permitted to contain `unsafe` code.
//! Every `unsafe` block carries an explicit `// SAFETY:` justification.
//!
//! Entry points and exact ABI contracts preserved from `n5.s`:
//! - Hook A (`0x8418_f768`, `n5_flow_classify`): called from N4 `hook_gipc_rx` with
//!   `r4 = pkt_len`, `r5 = N4_BASE`, `r6 = now_tti`, `r9 = rbc`, `sl = pkt_buf`;
//!   preserves `r2, r4..r11, ip, sp` on `flags == 0` and Exit A (with exact `cmp r4, #127` NZCV).
//! - Hook B (`0x8418_fc9c`, `n5_pdcp_limit`): tail-called from N4 `hook_pdcp_limit` with
//!   `r4 = N4_BASE` and `{r1, r2, r3, r4, lr}` on stack; returns limit in `r0` via
//!   `pop {r1, r2, r3, r4, pc}`, preserving `r1..r12, sp`.
//! - Hook C (`0x8418_fd0a`, `n5_ring0_submit`, hooked at `0x842d_cd24`): replaces
//!   `bl 0x842d_c968` (`pdcp_ul_cipher_submit`) inside `pdcp_ul_bo`; preserves `r0` (batch)
//!   and `r5..r11, sp`, and replaces `r4` (`count << 6`) with exact summed Ring-0 IRB bytes
//!   when `(flags & 5) == 1`.

use core::arch::naked_asm;
use core::panic::PanicInfo;
use core::ptr::{addr_of, read_volatile};
use core::slice;

use modem_atlas::addr::{N4_STATE_VA, N5_STATE_VA};
use modem_atlas::l2::{Rbc, RbcRing};
use modem_atlas::patches::{N4State, N5State};

use crate::flow::classify_packet;
use crate::pdcp::compute_pdcp_limit;
use crate::ring0::{record_ring0_submit, sum_ring0_bytes};
use crate::state::boot_n5_state;

/// Static boot-default N5 state block (`0x8448_9a64..0x8448_9f13`, 1,200 B).
/// The linker script prepends the 2-byte zero alignment pad at `0x8448_9a62` so the
/// patched site covers `0x8448_9a62..0x8448_9f14` (1,202 B, matching `n5.s` byte for byte).
#[unsafe(no_mangle)]
#[unsafe(link_section = ".n5blk")]
pub static mut N5_STATE_INIT: N5State = boot_n5_state();

/// Build a bounded immutable slice over the IP header starting at `pkt_buf + 2`.
///
/// Caps the slice at `min(pkt_len, 80)` bytes, covering every IPv4 (IHL up to 60 B + 14 B TCP)
/// and IPv6 (40 B + 14 B TCP) field without ever reading past `pkt_len`.
#[inline(always)]
fn ip_slice<'a>(pkt_buf: *const u8, pkt_len: u32) -> &'a [u8] {
    if pkt_buf.is_null() {
        return &[];
    }
    let len = pkt_len.min(80) as usize;
    // SAFETY: In `gipc_rx_loop`, `sl` (`pkt_buf`) points to `[2-byte GCT hdr | IP pkt]`
    // with at least `pkt_len` payload bytes valid at `pkt_buf + 2`.
    unsafe { slice::from_raw_parts(pkt_buf.add(2), len) }
}

/// Obtain a mutable reference to the live N5 state block at `0x8448_9a64`.
///
/// # Safety
/// CPU1 executes uT-Kernel on a single core and N5 hooks do not re-enter themselves.
#[inline(always)]
unsafe fn n5_state_mut() -> &'static mut N5State {
    // SAFETY: `N5_STATE_VA` (`0x8448_9a64`) is 4-byte aligned and holds the live `N5State`.
    unsafe { &mut *(N5_STATE_VA as *mut N5State) }
}

// ============================================================================
// AAPCS `extern "C"` Rust implementations called by the naked shims
// ============================================================================

#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.n5_flow_classify_rust")]
pub extern "C" fn n5_flow_classify_rust(
    rbc: *const Rbc,
    pkt_len: u32,
    now_tti: u32,
    pkt_buf: *const u8,
) -> u32 {
    // SAFETY: `rbc` (`r9`) is the live bearer pointer in `gipc_rx_loop`.
    let bearer_idx = unsafe { read_volatile(addr_of!((*rbc).bearer_idx)) };

    let ip = ip_slice(pkt_buf, pkt_len);
    // SAFETY: Single-core CPU1 access to `N5State`.
    let st = unsafe { n5_state_mut() };

    let decision = classify_packet(
        st,
        bearer_idx,
        || {
            // SAFETY: `rbc` is valid; `ring1` is null-checked before reading `wr`/`rd`.
            unsafe {
                let r1 = read_volatile(addr_of!((*rbc).ring1));
                if r1.is_null() {
                    None
                } else {
                    let p = r1.as_ptr();
                    Some((
                        read_volatile(addr_of!((*p).wr)),
                        read_volatile(addr_of!((*p).rd)),
                    ))
                }
            }
        },
        ip,
        pkt_len,
        now_tti,
        || {
            // SAFETY: `rbc` is valid; `ring0` is null-checked before reading `wr`/`rd`.
            unsafe {
                let r0 = read_volatile(addr_of!((*rbc).ring0));
                if r0.is_null() {
                    None
                } else {
                    let p = r0.as_ptr();
                    let wr = read_volatile(addr_of!((*p).wr));
                    let rd = read_volatile(addr_of!((*p).rd));
                    Some((wr.wrapping_sub(rd) & 0x0fff) as u32)
                }
            }
        },
        || {
            // SAFETY: `N4_STATE_VA` (`0x847e_d600`) is 4-byte aligned and holds `N4State`.
            unsafe {
                let n4 = N4_STATE_VA as *const N4State;
                read_volatile(addr_of!((*n4).g_ema))
            }
        },
    );
    decision as u32
}

#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.n5_pdcp_limit_rust")]
pub extern "C" fn n5_pdcp_limit_rust(n4: *const N4State) -> u32 {
    // SAFETY: `n4` (`r4`) is `N4_STATE_VA` (`0x847e_d600`), 4-byte aligned.
    let g_ema = unsafe { read_volatile(addr_of!((*n4).g_ema)) };
    // SAFETY: Single-core CPU1 access to `N5State`.
    let n5 = unsafe { n5_state_mut() };
    compute_pdcp_limit(n5, g_ema, || {
        // SAFETY: `n4` is `N4_STATE_VA`, valid and 4-byte aligned.
        unsafe {
            (
                read_volatile(addr_of!((*n4).pdcp_min)),
                read_volatile(addr_of!((*n4).pdcp_max)),
            )
        }
    })
}

#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.n5_ring0_sum_rust")]
pub extern "C" fn n5_ring0_sum_rust(ring0: *const RbcRing, count: u32) -> u32 {
    if ring0.is_null() || count == 0 {
        return 0;
    }
    // SAFETY: `ring0` is non-null and points to the live 4096-slot `RbcRing` in `pdcp_ul_bo`.
    let (wr, rd) = unsafe {
        (
            read_volatile(addr_of!((*ring0).wr)),
            read_volatile(addr_of!((*ring0).rd)),
        )
    };
    sum_ring0_bytes(wr, rd, count, |slot| {
        // SAFETY: `slot` is masked to `0..4095` within `ring0.slots`; each IRB pointer is null-checked.
        unsafe {
            let slots_base = addr_of!((*ring0).slots) as *const u32;
            let irb_va = read_volatile(slots_base.add(slot));
            if irb_va == 0 {
                None
            } else {
                let irb = irb_va as *const modem_atlas::gipc::GipcIrb;
                Some(read_volatile(addr_of!((*irb).length)) as u32)
            }
        }
    })
}

#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.n5_ring0_record_rust")]
pub extern "C" fn n5_ring0_record_rust(batch: u32, exact_bytes: u32) -> u32 {
    // SAFETY: Single-core CPU1 access to `N5State`.
    let n5 = unsafe { n5_state_mut() };
    record_ring0_submit(n5, exact_bytes);
    batch
}

// ============================================================================
// Naked Thumb-2 hook entry shims (exact N5/N4/stock register + CPSR + 8-byte SP ABI)
// ============================================================================

/// Hook A (`0x8418_f768`): per-flow sparse classifier entry point.
#[unsafe(no_mangle)]
#[unsafe(naked)]
#[unsafe(link_section = ".text.n5_flow_classify")]
pub unsafe extern "C" fn n5_flow_classify() {
    naked_asm!(
        // Fast path when N5_FLAGS bit 0 == 0: exact IMG4 behaviour, `ip` untouched.
        "movw r0, #0x9a64",
        "movt r0, #0x8448",
        "ldr.w r0, [r0, #8]",
        "tst.w r0, #1",
        "bne 2f",
        "cmp r4, #127",
        "bhi 1f",
        "b.w n4_hook4_exit_a",
        "1:",
        "bx lr",
        "2:",
        "push {{r2, r7, ip, lr}}",
        "mov r7, sp",
        "bic r0, r7, #7",
        "mov sp, r0",
        "mov r0, r9",
        "mov r1, r4",
        "mov r2, r6",
        "mov r3, sl",
        "bl n5_flow_classify_rust",
        "mov sp, r7",
        "pop {{r2, r7, ip, lr}}",
        "cbz r0, 10f",
        "cmp r0, #1",
        "beq 11f",
        // Promote (Exit C): r2 = rbc.ring0, unwind N4's frame, jump to 0x842d_a24a | 1.
        "ldr.w r2, [r9, #0]",
        "pop {{r0, r1, r3, r5, r6, lr}}",
        "movw ip, #0xa24b",
        "movt ip, #0x842d",
        "bx ip",
        // ToRing1: <= 127 B -> Exit B, > 127 B -> N4 AQM.
        "11:",
        "cmp r4, #127",
        "bhi 12f",
        "b.w n4_hook4_exit_b",
        "12:",
        "b.w n4_hook4_aqm",
        // StockR0 (Exit A): exact cmp r4, #127 APSR flags, `ip` preserved.
        "10:",
        "cmp r4, #127",
        "b.w n4_hook4_exit_a",
    );
}

/// Hook B (`0x8418_fc9c`): first-class PDCP staging limit entry point.
#[unsafe(no_mangle)]
#[unsafe(naked)]
#[unsafe(link_section = ".text.n5_pdcp_limit")]
pub unsafe extern "C" fn n5_pdcp_limit() {
    naked_asm!(
        "push {{r5, ip}}",
        "mov r5, sp",
        "bic r0, r5, #7",
        "mov sp, r0",
        "mov r0, r4",
        "bl n5_pdcp_limit_rust",
        "mov sp, r5",
        "pop {{r5, ip}}",
        "pop {{r1, r2, r3, r4, pc}}",
    );
}

/// Hook C (`0x8418_fd0a`, called by `bl n5_ring0_submit` at `0x842d_cd24`): exact Ring-0 feeder byte count.
#[unsafe(no_mangle)]
#[unsafe(naked)]
#[unsafe(link_section = ".text.n5_ring0_submit")]
pub unsafe extern "C" fn n5_ring0_submit() {
    naked_asm!(
        // Fast path when bit 0 == 0 or bit 2 == 1: tail-call stock pdcp_ul_cipher_submit.
        "movw ip, #0x9a64",
        "movt ip, #0x8448",
        "ldr.w ip, [ip, #8]",
        "and.w ip, ip, #5",
        "cmp.w ip, #1",
        "beq 1f",
        "b.w pdcp_ul_cipher_sub",
        "1:",
        "push {{r0, r1, r2, r3, r5, r6, lr}}",
        "mov r5, sp",
        "bic r6, r5, #7",
        "mov sp, r6",
        "mov r0, r2",
        "mov r1, r3",
        "bl n5_ring0_sum_rust",
        "mov r6, r0",
        "ldm r5, {{r0, r1, r2, r3}}",
        "bl pdcp_ul_cipher_sub",
        "cbz r6, 2f",
        "mov r4, r6",
        "mov r1, r6",
        "bl n5_ring0_record_rust",
        "2:",
        "mov sp, r5",
        "add sp, #16",
        "pop {{r5, r6, pc}}",
    );
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
