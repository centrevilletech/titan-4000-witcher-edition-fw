//! Audited bare-metal Thumb-2 FFI shims and MMIO/RAM access for `witcher-modem-ul-opt`.
//!
//! Every `unsafe` block in this crate lives inside this single module.
//! No literal pools (`movw`/`movt` only, enforced by `build-thumb.sh`).

use core::ptr::{read_volatile, write_volatile};

use modem_atlas::addr::{
    MAC_UL_CFG_VA, ROM_EXT_BSR_TABLE_VA, ROM_STD_BSR_TABLE_VA,
};
use modem_atlas::l2::RBC_RING_MASK;

use crate::logic::{
    N2OptState, N2_FLAGS_KNOWN_MASK, N2_FLAG_BYTE_PACING, N2_FLAG_DO_TC_CAP, N2_FLAG_FAST_DIV,
    N2_OPT_BLK_VA, N2_OPT_MAGIC, bsr_idx_from_table, compute_do_tc_cap, count_fitting_packets,
};

/// Boot-off control block placed at `0x841b_b5c0` inside dead `UMM_DisplayUSIMPINInfo`.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".n2blk")]
pub static mut N2_OPT_STATE: N2OptState = N2OptState::boot_default();

#[inline(always)]
fn state_ptr() -> *mut N2OptState {
    N2_OPT_BLK_VA as *mut N2OptState
}

/// Read only `magic` and `flags` (2 words, avoiding a 64-byte struct copy on the stack).
#[inline(always)]
unsafe fn read_active_flags(st_ptr: *mut N2OptState) -> u32 {
    // SAFETY: Caller guarantees `st_ptr` points to the live `N2OptState` at `N2_OPT_BLK_VA`.
    let magic = unsafe { read_volatile(core::ptr::addr_of!((*st_ptr).magic)) };
    if magic != N2_OPT_MAGIC {
        return 0;
    }
    // SAFETY: Same live `N2OptState` block.
    let flags = unsafe { read_volatile(core::ptr::addr_of!((*st_ptr).flags)) };
    if (flags & !N2_FLAGS_KNOWN_MASK) != 0 {
        return 0;
    }
    flags
}

/// Fast Rust body for `SearchMacUlBoIdx` (`0x842c_cf64`) when `FLAG_FAST_BSR` is active
/// and `bo != 0` (magic, flags, and `bo == 0` fast-path are already checked by `hook_bsr_idx`).
#[unsafe(no_mangle)]
#[unsafe(link_section = ".n2opt")]
pub extern "C" fn n2_bsr_idx_impl(bo: u32) -> u32 {
    let st_ptr = state_ptr();
    // SAFETY: `MAC_UL_CFG_VA + 0x152` is `MacUlCfg::ext_bsr` (`1` = std, `2` = ext);
    // `ROM_STD_BSR_TABLE_VA` and `ROM_EXT_BSR_TABLE_VA` are 63-word ROM arrays in `tk.bin`.
    let idx = unsafe {
        let ext_bsr = read_volatile((MAC_UL_CFG_VA + 0x152) as *const u8);
        let tbl_va = if ext_bsr == 2 {
            ROM_EXT_BSR_TABLE_VA
        } else {
            ROM_STD_BSR_TABLE_VA
        };
        let tbl = &*(tbl_va as *const [u32; 63]);
        let p = core::ptr::addr_of_mut!((*st_ptr).cnt_bsr_nonzero_fast);
        write_volatile(p, read_volatile(p).wrapping_add(1));
        bsr_idx_from_table(bo, tbl)
    };
    idx as u32
}

/// Fast Rust body for `l2_proc_pdcp_ul` (`0x842d_ccd0`, replacing `blx __aeabi_uidiv`).
///
/// Arguments forwarded from the naked shim:
/// - `headroom` (`r0`): `limit - cur_bo`
/// - `divisor` (`r1`): `*(u32*)0x84dd_9780` (`1500` in stock)
/// - `ring1_va` (`r2` <- `r4`): `rbc->ring1` pointer
/// - `max_pkts` (`r3` <- `fp`): `min(free_slots, ring1_occ)`
///
/// Returns `u32::MAX` when both `FLAG_FAST_DIV` and `FLAG_BYTE_PACING` are off (or
/// `divisor == 0` under `FLAG_FAST_DIV`), telling the shim to tail-call stock `__aeabi_uidiv`.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".n2opt")]
pub extern "C" fn n2_pdcp_div_impl(
    headroom: u32,
    divisor: u32,
    ring1_va: u32,
    max_pkts: u32,
) -> u32 {
    let st_ptr = state_ptr();
    // SAFETY: `N2_OPT_BLK_VA` (`0x841b_b5c0`) is the valid 64-byte `N2OptState` in CPU1 SDRAM.
    let flags = unsafe { read_active_flags(st_ptr) };
    if (flags & (N2_FLAG_FAST_DIV | N2_FLAG_BYTE_PACING)) == 0 {
        return u32::MAX;
    }
    if max_pkts == 0 {
        // SAFETY: Single-core CPU1 L2 task updates telemetry counter at `N2_OPT_BLK_VA + 0x20`.
        unsafe {
            let p = core::ptr::addr_of_mut!((*st_ptr).cnt_div_empty_skip);
            write_volatile(p, read_volatile(p).wrapping_add(1));
        }
        return 0;
    }
    if (flags & N2_FLAG_BYTE_PACING) != 0 && ring1_va != 0 {
        // SAFETY: `ring1_va` is `rbc->ring1` (`RbcRing`: `+0x02` = `rd: u16`, `+0x04` = `slots[4096]`),
        // and each valid slot holds a non-null `GipcIrb` pointer with `len: u16` at `+0x06`.
        let cnt = unsafe {
            let rd = read_volatile((ring1_va + 2) as *const u16) as u32;
            let slots_base = ring1_va + 4;
            let c = count_fitting_packets(headroom, max_pkts, |i| {
                let idx = (rd.wrapping_add(i)) & (RBC_RING_MASK as u32);
                let irb = read_volatile((slots_base + (idx << 2)) as *const u32);
                if irb == 0 {
                    None
                } else {
                    Some(read_volatile((irb + 6) as *const u16))
                }
            });
            let p = core::ptr::addr_of_mut!((*st_ptr).cnt_byte_paced);
            write_volatile(p, read_volatile(p).wrapping_add(1));
            c
        };
        return cnt;
    }
    if divisor == 0 {
        return u32::MAX;
    }
    // SAFETY: Single-core CPU1 L2 task updates telemetry counter at `N2_OPT_BLK_VA + 0x24`.
    unsafe {
        let p = core::ptr::addr_of_mut!((*st_ptr).cnt_div_fast);
        write_volatile(p, read_volatile(p).wrapping_add(1));
    }
    headroom / divisor
}

/// Fast Rust body for `do_tc` (`0x842e_5b06`, replacing `ubfx r3, r3, #15, #12`).
///
/// Returns `0` when `FLAG_DO_TC_CAP` is off (shim runs stock `ubfx` and returns to `0x842e_5b0a`),
/// or non-zero computed staging cap (bytes) to store to `L2_PDCP_UL_LIMIT_VA` and jump to `0x842e_5b28`.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".n2opt")]
pub extern "C" fn n2_do_tc_cap_impl(ul_250ms_bytes: u32) -> u32 {
    let st_ptr = state_ptr();
    // SAFETY: `N2_OPT_BLK_VA` (`0x841b_b5c0`) is the valid 64-byte `N2OptState` in CPU1 SDRAM.
    let flags = unsafe { read_active_flags(st_ptr) };
    if (flags & N2_FLAG_DO_TC_CAP) == 0 {
        return 0;
    }
    // SAFETY: Single-core CPU1 L2 timer task reads 3 tunables and updates telemetry in `N2OptState`.
    unsafe {
        let target_ms = read_volatile(core::ptr::addr_of!((*st_ptr).cap_target_ms));
        let cap_min = read_volatile(core::ptr::addr_of!((*st_ptr).cap_min_bytes));
        let cap_max = read_volatile(core::ptr::addr_of!((*st_ptr).cap_max_bytes));
        let c = compute_do_tc_cap(ul_250ms_bytes, target_ms, cap_min, cap_max);
        let pc = core::ptr::addr_of_mut!((*st_ptr).cnt_do_tc_clamped);
        write_volatile(pc, read_volatile(pc).wrapping_add(1));
        write_volatile(core::ptr::addr_of_mut!((*st_ptr).last_do_tc_cap), c);
        c
    }
}

// ---------------------------------------------------------------------------
// Naked Thumb-2 entry veneers (compiled only for bare-metal ARM targets)
// ---------------------------------------------------------------------------

/// Hook 1: replaces `push {r4-r7, lr}; sub sp, #12` at `SearchMacUlBoIdx` (`0x842c_cf64`).
///
/// - Fast path (`bo == 0` and `FLAG_FAST_BSR` active): zero stack frame, ~14 instructions!
/// - Non-zero fast path: calls `n2_bsr_idx_impl(r0)`.
/// - Off path (`flags == 0` or unknown bits): runs exact displaced prologue and jumps to `0x842c_cf68`.
#[cfg(target_arch = "arm")]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".n2opt.entry")]
#[unsafe(naked)]
pub unsafe extern "C" fn hook_bsr_idx() {
    core::arch::naked_asm!(
        // Fast inline check for boot-off / bo == 0 without touching callee-saved regs:
        // r1, r2, r3, ip are caller-saved AAPCS scratch registers.
        "movw r1, #0xb5c0",
        "movt r1, #0x841b",
        "ldr r2, [r1, #0]",           // magic
        "movw r3, #0x4f50",
        "movt r3, #0x4e32",
        "cmp r2, r3",
        "bne 2f",
        "ldr r2, [r1, #8]",           // flags
        "lsrs r3, r2, #4",            // any unknown bit above bit 3 -> off
        "bne 2f",
        "tst r2, #1",                 // N2_FLAG_FAST_BSR
        "beq 2f",
        "cbnz r0, 1f",                // bo != 0 -> full fast binary search
        "ldr r3, [r1, #24]",          // cnt_bsr_zero_fast++
        "adds r3, #1",
        "str r3, [r1, #24]",
        "bx lr",                      // return 0 in r0!
        "1:",
        "push {{r4, lr}}",
        "bl {bsr_impl}",
        "pop {{r4, pc}}",
        "2:",
        // OFF path: execute exact displaced 4 bytes of SearchMacUlBoIdx and resume at 0x842ccf68|1
        "push {{r4, r5, r6, r7, lr}}",
        "sub sp, #12",
        "movw ip, #0xcf69",
        "movt ip, #0x842c",
        "bx ip",
        bsr_impl = sym n2_bsr_idx_impl,
    );
}

/// Hook 2: replaces `blx 0x8411_cc14` (`__aeabi_uidiv`) at `l2_proc_pdcp_ul` (`0x842d_ccd0`).
///
/// Entry: `r0 = limit - cur_bo`, `r1 = divisor`, `r4 = ring1`, `fp = max_pkts`.
/// Preserves all callee-saved regs (`r4..r11`); returns `r0 = pkts`.
///
/// Fast-paths `FLAG_FAST_DIV` (`fp == 0` skip and hardware Thumb-2 `udiv`) inline with
/// zero stack frame (~15–17 insns vs ~32–52 insns ARM `__aeabi_uidiv`). Delegates
/// `FLAG_BYTE_PACING` (bit 2) to pure-Rust `n2_pdcp_div_impl`.
#[cfg(target_arch = "arm")]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".n2opt.entry")]
#[unsafe(naked)]
pub unsafe extern "C" fn hook_pdcp_div() {
    core::arch::naked_asm!(
        "movw r2, #0xb5c0",
        "movt r2, #0x841b",
        "ldr r3, [r2, #0]",           // magic
        "movw ip, #0x4f50",
        "movt ip, #0x4e32",
        "cmp r3, ip",
        "bne 3f",                     // bad magic -> stock __aeabi_uidiv
        "ldr r3, [r2, #8]",           // flags
        "lsrs ip, r3, #4",            // unknown bits -> stock
        "bne 3f",
        "tst r3, #6",                 // bit 1 (FAST_DIV) | bit 2 (BYTE_PACING)
        "beq 3f",                     // boot-off -> stock __aeabi_uidiv
        "cmp fp, #0",                 // Ring 1 empty (max_pkts == 0)?
        "bne 1f",
        "ldr r3, [r2, #32]",          // cnt_div_empty_skip++
        "adds r3, #1",
        "str r3, [r2, #32]",
        "movs r0, #0",
        "bx lr",                      // 16 insns total!
        "1:",
        "tst r3, #4",                 // N2_FLAG_BYTE_PACING?
        "bne 2f",
        "cbz r1, 3f",                 // divisor == 0 safety fallback
        "udiv r0, r0, r1",            // single-instruction Cortex-A7 hardware divide!
        "ldr r3, [r2, #36]",          // cnt_div_fast++
        "adds r3, #1",
        "str r3, [r2, #36]",
        "bx lr",                      // 19 insns total!
        "2:",
        "push {{r0, r1, lr}}",
        "mov r2, r4",                 // ring1_va
        "mov r3, fp",                 // max_pkts
        "bl {div_impl}",
        "cmn r0, #1",
        "beq 4f",
        "add sp, #8",
        "pop {{pc}}",
        "4:",
        "pop {{r0, r1, lr}}",
        "3:",
        "movw ip, #0xcc14",           // ARM-mode __aeabi_uidiv (bit 0 = 0!)
        "movt ip, #0x8411",
        "bx ip",
        div_impl = sym n2_pdcp_div_impl,
    );
}

/// Hook 3: replaces `ubfx r3, r3, #15, #12` at `do_tc` (`0x842e_5b06`).
///
/// Entry: `r3 = ul_250ms_bytes`, `r4 = 0x84dd_9000` (`[r4, #0x7bc]` = `L2_PDCP_UL_LIMIT_VA`).
/// - OFF: executes `ubfx r3, r3, #15, #12` and returns to `0x842e_5b0a` (`lr`).
/// - ON (`FLAG_DO_TC_CAP`): writes tuned cap to `[r4, #0x7bc]` and returns to `0x842e_5b28`.
#[cfg(target_arch = "arm")]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".n2opt.entry")]
#[unsafe(naked)]
pub unsafe extern "C" fn hook_do_tc_cap() {
    core::arch::naked_asm!(
        "push {{r0, r1, r2, r3, lr}}",
        "mov r0, r3",
        "bl {cap_impl}",
        "cbz r0, 1f",                 // 0 -> OFF path
        "str.w r0, [r4, #1980]",      // L2_PDCP_UL_LIMIT_VA = cap
        "pop {{r0, r1, r2, r3, lr}}",
        "movw ip, #0x5b29",           // skip stock 3-tier overwrite -> 0x842e_5b28 | 1
        "movt ip, #0x842e",
        "bx ip",
        "1:",
        "pop {{r0, r1, r2, r3, lr}}",
        "ubfx r3, r3, #15, #12",      // exact displaced stock instruction
        "bx lr",
        cap_impl = sym n2_do_tc_cap_impl,
    );
}
