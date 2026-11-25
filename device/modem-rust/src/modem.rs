//! Bare-metal Cortex-A7 Thumb-2 integration for Titan 4000 `tk.bin` (N4 hook 4 site).
//!
//! Uses verified `#[repr(C)]` types and VAs from Lane M2's `modem-atlas` crate:
//! `Rbc`, `PdcpUlSduWindow`, `N4State`, `N4ExtCounters`, `N4_STATE_VA`, `N4_EXT_CNT_VA`.
//!
//! Hook site: `0x847ed414` (`hook4_check_aqm` inside N4's `hook_gipc_rx` cave).
//! Displaced 6 bytes: `ldr r0, [r5, #4]; and r0, r0, #5` (`6868 00f00500`).
//! Replaced with:     `bl m1_aqm_shim; nop` (jumping into dead `cmd_phy` at `0x841de8dc`).
//!
//! Register contract at `0x847ed414`:
//! - Stack top: `{r0, r1, r3, r5, r6, lr}` (pushed by `hook_gipc_rx` at `0x847ed2f6`).
//! - Live inputs: `r4 = pkt_len`, `r5 = N4_STATE_VA (0x847ed600)`, `r6 = now_tti`,
//!   `r9 = *const Rbc`, `r10 (sl) = pkt_buf` (IP header at `sl + 2`).
//! - Dead on entry: `r0, r1, r3, ip, APSR`.
//! - Preserved on all exits: `r4, r5, r6, r7, r8, r9, sl, fp, sp` (plus `r2` on Exit B;
//!   Exit D loads `r2 = [r9, #4]` at `0x847ed51c`).

use core::arch::naked_asm;
use core::cell::UnsafeCell;
use core::panic::PanicInfo;
use core::ptr::{addr_of, addr_of_mut, read_volatile, write_volatile};

use modem_atlas::addr::{N4_EXT_CNT_VA, N4_STATE_VA};
use modem_atlas::l2::Rbc;
use modem_atlas::patches::{N4ExtCounters, N4State};

use crate::pie::{Decision, M1Block};

/// Wrapper allowing a static mutable RAM block in `.m1blk` on single-threaded CPU1 L2 task.
#[repr(transparent)]
pub struct SyncM1Block(UnsafeCell<M1Block>);

unsafe impl Sync for SyncM1Block {}

/// Static RAM control/parameter/state/counter block linked at `0x841b5900` (256 B).
#[unsafe(no_mangle)]
#[unsafe(link_section = ".m1blk")]
pub static M1_BLK: SyncM1Block = SyncM1Block(UnsafeCell::new(M1Block::new_boot_default()));

#[inline(always)]
unsafe fn bump(p: *mut u32) {
    unsafe { write_volatile(p, read_volatile(p).wrapping_add(1)) };
}

/// Sample live PDCP-to-ACK head-of-line age from stock `rbc->pdcp_ul_win[oldest_sn]`
/// (discovered by Lane M2; written at `0x842dcad0` in `proc_pdcp_ul`).
///
/// Exposed as telemetry only: this age starts after Ring-1 dequeue and includes air HARQ
/// + eNB RLC AM STATUS ACK RTT (~20-40 ms), so it is not Ring-1 queuing delay.
#[inline(always)]
unsafe fn sample_pdcp_hol_age_ms(rbc: *const Rbc, now_tti: u32) -> u32 {
    if rbc.is_null() {
        return 0;
    }
    let win_ptr = unsafe { read_volatile(addr_of!((*rbc).pdcp_ul_win)) };
    if win_ptr.is_null() {
        return 0;
    }
    let win = win_ptr.as_ptr();
    let active = unsafe { read_volatile(addr_of!((*win).active_count)) };
    if active == 0 {
        return 0;
    }
    let sn_max = unsafe { read_volatile(addr_of!((*rbc).pdcp_sn_max)) };
    let mask = if sn_max == 0 { 0x0fff } else { sn_max.wrapping_sub(1) & 0x0fff } as usize;
    let oldest = (unsafe { read_volatile(addr_of!((*rbc).pdcp_ul_oldest_sn)) } as usize) & mask;
    let entry_ptr = unsafe { addr_of!((*win).entries).cast::<modem_atlas::l2::PdcpUlSduEntry>().add(oldest) };
    let tti_and_flags = unsafe { read_volatile(addr_of!((*entry_ptr).enqueue_tti_and_flags)) };
    let enq_tti = tti_and_flags & !1;
    if enq_tti == 0 {
        return 0;
    }
    now_tti.wrapping_sub(enq_tti)
}

/// AAPCS `extern "C"` decision routine called from `m1_aqm_shim` when `selector == 1`
/// and N4 flags `(bit0 | bit2)` are both set.
///
/// Returns `0` for Exit B (enqueue Ring 1) or `1` for Exit D (clean Ring 1 AQM drop).
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.m1_pie_decide")]
pub extern "C" fn m1_pie_decide(
    rbc: *const Rbc,
    pkt_len: u32,
    now_tti: u32,
    pkt_buf: *mut u8,
) -> u32 {
    unsafe {
        let blk = &mut *M1_BLK.0.get();
        let n4 = N4_STATE_VA as *mut N4State;
        let n4_ext = N4_EXT_CNT_VA as *mut N4ExtCounters;

        let ring_b = read_volatile(addr_of!((*rbc).ring_pending_bytes));
        let pdcp_b = read_volatile(addr_of!((*rbc).pdcp_rlc_tx_bo));
        let q_total = ring_b.wrapping_add(pdcp_b);

        let g_ema = read_volatile(addr_of!((*n4).g_ema));
        let min_len = read_volatile(addr_of!((*n4).aqm_minlen));

        // Telemetry: record PDCP-to-ACK HoL age from M2's verified PdcpUlSduWindow layout.
        let hol_age = sample_pdcp_hol_age_ms(rbc, now_tti);
        blk.pdcp_hol_age_ms = hol_age;
        if hol_age > blk.pdcp_max_hol_age_ms {
            blk.pdcp_max_hol_age_ms = hol_age;
        }

        // IP header starts at pkt_buf + 2; cap to 40 B (max bytes inspected for IPv4/IPv6 ECN).
        let ip_hdr = if pkt_buf.is_null() {
            &mut [][..]
        } else {
            core::slice::from_raw_parts_mut(pkt_buf.add(2), pkt_len.min(40) as usize)
        };

        match blk.evaluate_packet(q_total, g_ema, min_len, pkt_len, now_tti, ip_hdr) {
            Decision::Enqueue => 0,
            Decision::SparedSmall => {
                bump(addr_of_mut!((*n4).cnt_spared));
                0
            }
            Decision::EcnMark => {
                bump(addr_of_mut!((*n4).cnt_aqm_mark));
                0
            }
            Decision::Drop => {
                bump(addr_of_mut!((*n4).cnt_aqm_drop));
                1
            }
            Decision::HardDrop => {
                bump(addr_of_mut!((*n4_ext).cnt_drop_hard));
                bump(addr_of_mut!((*n4).cnt_aqm_drop));
                1
            }
        }
    }
}

/// Naked Thumb-2 AAPCS shim entered via `bl m1_aqm_shim` from `0x847ed414`.
///
/// - `selector == 0` (boot default & live rollback): runs the two displaced N4 instructions
///   (`ldr r0, [r5, #4]; and r0, r0, #5`) and returns to `0x847ed41a` with zero stack usage.
/// - N4 `(flags & 5) != 5` (stock kill switch / bit0 off): exits to `0x847ed52e` (Exit B).
/// - `selector == 2` (no AQM): bumps `c_bypass_pkts` and exits to `0x847ed52e` (Exit B).
/// - `selector == 1` (Rust PIE): aligns `sp` to 8 bytes, preserves `r2` (and `r4..r11` per AAPCS),
///   calls `m1_pie_decide(rbc, pkt_len, now_tti, pkt_buf)`, restores `sp` and `r2`, and
///   branches to `0x847ed52e` (Exit B) or `0x847ed51c` (Exit D).
/// - Any other `selector` value: falls back safely to `selector == 0` (old N4 v2).
#[unsafe(no_mangle)]
#[unsafe(naked)]
#[unsafe(link_section = ".text.m1_aqm_shim")]
pub unsafe extern "C" fn m1_aqm_shim() {
    naked_asm!(
        // Load M1_BLK base (0x841b5900) with pure movw/movt (zero literal pools).
        "movw r0, #0x5900",
        "movt r0, #0x841b",
        "ldr r1, [r0, #8]",        // r1 = M1_BLK.selector
        "cbz r1, 1f",              // selector == 0 -> fast path: old N4 v2
        "cmp r1, #2",
        "bhi 1f",                  // unknown selector -> safe fallback to old N4 v2

        // Respect N4 invariant D3: AQM only runs when bit0 (PDCP limit) + bit2 (AQM) are both set.
        "ldr r3, [r5, #4]",
        "and r3, r3, #5",
        "cmp r3, #5",
        "bne 4f",                  // AQM off -> Exit B (0x847ed52e)

        // selector == 2: no AQM (bypass), count and jump to Exit B.
        "cmp r1, #2",
        "bne 2f",
        "ldr.w r3, [r0, #0x88]",   // c_bypass_pkts
        "adds r3, #1",
        "str.w r3, [r0, #0x88]",
        "b 4f",

        // selector == 1: Rust PIE AQM.
        // Align SP to 8 bytes for AAPCS while saving r2 and original SP.
        "2:",
        "mov r3, sp",
        "bic r1, r3, #7",
        "mov sp, r1",
        "push {{r2, r3}}",         // 8 bytes -> SP remains 8-byte aligned

        "mov r0, r9",              // arg0: rbc (*const Rbc)
        "mov r1, r4",              // arg1: pkt_len
        "mov r2, r6",              // arg2: now_tti
        "mov r3, sl",              // arg3: pkt_buf
        "bl m1_pie_decide",

        "pop {{r2, r3}}",
        "mov sp, r3",              // restore exact original SP
        "cbnz r0, 3f",

        // Exit B: enqueue Ring 1 (0x847ed52e | 1 = 0x847ed52f).
        "4:",
        "movw ip, #0xd52f",
        "movt ip, #0x847e",
        "bx ip",

        // Exit D: clean Ring 1 AQM drop (0x847ed51c | 1 = 0x847ed51d).
        // 0x847ed51c executes: ldr.w r2, [r9, #4]; pop {r0,r1,r3,r5,r6,lr}; bx 0x842da3e1
        "3:",
        "movw ip, #0xd51d",
        "movt ip, #0x847e",
        "bx ip",

        // Selector == 0 fast path: execute displaced N4 instructions and return to 0x847ed41a.
        "1:",
        "ldr r0, [r5, #4]",
        "and r0, r0, #5",
        "bx lr",
    );
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
