//! Bare-metal Cortex-A7 Thumb-2 integration for the combined MAC/PDCP UL optimizer.
//!
//! This is the ONLY module in `witcher-modem-mac-opt` permitted to contain `unsafe` code.
//! Every `unsafe` block carries an explicit `// SAFETY:` justification.
//!
//! Five 4-byte Thumb-2 hook sites (100% disjoint from IMG4, N4, N5, N6H, R1, C1, N7, M1):
//! 1. `0x842c_cf64` (`SearchMacUlBoIdx`) -> `opt_search_bo_idx_shim` (`.optcode1`)
//!    Stock prologue replaced: `push {r4, r5, r6, r7, lr}; sub sp, #0xc` (4 B -> resume `0x842c_cf68`)
//! 2. `0x842c_fe34` (`CheckLongBsrDowngradeToShort`) -> `opt_check_long_bsr_shim` (`.optcode1`)
//!    Stock prologue replaced: `push.w {r4-r11, lr}` (4 B -> resume `0x842c_fe38`)
//! 3. `0x842d_a60c` (`mac_bsr_pre_work`) -> `opt_mac_bsr_pre_work_shim` (`.optcode1`)
//!    Stock prologue replaced: `push.w {r4-r10, lr}` (4 B -> resume `0x842d_a610`)
//! 4. `0x842d_ccd0` (`l2_proc_pdcp_ul`) -> `opt_pdcp_div_shim` (`.optcode2`)
//!    Stock call replaced: `blx 0x8411_cc14` (`__aeabi_uidiv`, 4 B -> returns via `bx lr`)
//! 5. `0x842e_5b06` (`do_tc`) -> `opt_do_tc_cap_shim` (`.optcode2`)
//!    Stock insn replaced: `ubfx r3, r3, #15, #12` (4 B -> off resumes `lr`, on jumps `0x842e_5b28`)

use core::arch::naked_asm;
use core::panic::PanicInfo;
use core::ptr::{addr_of, read_volatile, write_volatile};

use modem_atlas::addr::{
    L2_BSR_PRE_BO_VA, L2_CIPHER_BUSY_VA, L2_CIPHER_PEND_VA, L2_CTX_VA, MAC_PDCP_OPT_BLK_VA,
    MAC_UL_BSR_CTX_VA, RBC_TABLE_VA, ROM_EXT_BSR_TABLE_VA, ROM_STD_BSR_TABLE_VA,
};
use modem_atlas::l2::{RBC_RING_MASK, Rbc};
use modem_atlas::mac::MacUlBsrCtx;

use crate::block::{
    FLAG_DO_TC_CAP, FLAG_FAST_LONG_BSR_CHECK, FLAG_GUARDED_PRE_BO, MacPdcpOptBlock,
};
use crate::opt::{
    FALLBACK_TO_STOCK, compute_do_tc_cap, count_fitting_packets, fast_bo_idx_nz,
    fast_long_bsr_downgrade, guarded_pre_bo,
};

/// Boot-off 128-byte control block placed in `.optblk` at `0x841b_b5c0` (`UMM_DisplayUSIMPINInfo+2`).
#[unsafe(no_mangle)]
#[unsafe(link_section = ".optblk")]
pub static MAC_PDCP_OPT_BLK: MacPdcpOptBlock = MacPdcpOptBlock::boot_default();

#[inline(always)]
fn blk() -> &'static MacPdcpOptBlock {
    // SAFETY: `MAC_PDCP_OPT_BLK_VA` (`0x841b_b5c0`) is the fixed 128-byte `.optblk` cave on CPU1;
    // all fields are `AtomicU32` (`Word`) accessed via relaxed atomic loads/stores.
    unsafe { &*(MAC_PDCP_OPT_BLK_VA as *const MacPdcpOptBlock) }
}

#[inline(always)]
fn read_u32(va: u32) -> u32 {
    // SAFETY: Caller passes a verified 4-byte-aligned modem RAM/ROM VA from `modem_atlas::addr`.
    unsafe { read_volatile(va as *const u32) }
}

// ============================================================================
// Cave 1 (.optcode1 @ 0x8418_67e4, 852 B): MAC UL hot-path handlers
// ============================================================================

/// Non-zero fast Rust handler for `SearchMacUlBoIdx(bo_bytes)` (`0x842c_cf64`).
///
/// Tail-called ONLY by `opt_search_bo_idx_shim` after `magic`, `version`, `KNOWN_FLAGS_MASK`,
/// `FLAG_FAST_BSR_IDX`, `bo_bytes != 0`, and `ext_bsr_mode in {1, 2}` have already been
/// validated inline (`is_ext = ext_bsr_mode - 1` in `{0, 1}`). Uses zero stack.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".optcode1.search_bo_idx_nz")]
pub extern "C" fn opt_search_bo_idx_nz_rust(
    bo_bytes: u32,
    blk_va: u32,
    is_ext: u32,
) -> u32 {
    // SAFETY: Caller passes `MAC_PDCP_OPT_BLK_VA` (`0x841b_b5c0`), the live static `MacPdcpOptBlock`.
    unsafe { (*(blk_va as *const MacPdcpOptBlock)).cnt_bo_idx_nonzero.bump() };
    let table_va = if is_ext != 0 {
        ROM_EXT_BSR_TABLE_VA
    } else {
        ROM_STD_BSR_TABLE_VA
    };
    // SAFETY: `table_va` is either `0x847f_5b1c` or `0x847f_5c18`, both verified 4-byte-aligned
    // constant `[u32; 63]` tables in `tk.bin` ROM.
    let table = unsafe { &*(table_va as *const [u32; 63]) };
    fast_bo_idx_nz(table, bo_bytes) as u32
}

/// Rust handler for `CheckLongBsrDowngradeToShort(tb_rem)` (`0x842c_fe34`).
///
/// Returns `0` or `1` on O(1) early exit, or `FALLBACK_TO_STOCK` (`2`) to execute stock.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".optcode1.check_long_bsr")]
pub extern "C" fn opt_check_long_bsr_rust(tb_rem: u32) -> u32 {
    let b = blk();
    if !b.feature_enabled(FLAG_FAST_LONG_BSR_CHECK) {
        return FALLBACK_TO_STOCK;
    }
    b.cnt_downgrade_checks.bump();
    let ctx = MAC_UL_BSR_CTX_VA as *const MacUlBsrCtx;
    // SAFETY: `MAC_UL_BSR_CTX_VA` (`0x84d6_2940`) is the live static `MacUlBsrCtx` in CPU1 BSS.
    let (active_cnt, bo0, bo1, bo2, bo3) = unsafe {
        (
            read_volatile(addr_of!((*ctx).retx_bsr_has_data)),
            read_volatile(addr_of!((*ctx).lcg[0].bo_bytes)),
            read_volatile(addr_of!((*ctx).lcg[1].bo_bytes)),
            read_volatile(addr_of!((*ctx).lcg[2].bo_bytes)),
            read_volatile(addr_of!((*ctx).lcg[3].bo_bytes)),
        )
    };
    let decision = fast_long_bsr_downgrade(active_cnt, [bo0, bo1, bo2, bo3], tb_rem);
    if decision != FALLBACK_TO_STOCK {
        b.cnt_downgrade_fast_exit.bump();
    }
    decision
}

/// Rust handler for `mac_bsr_pre_work(active_lc_mask)` (`0x842d_a60c`).
///
/// Returns `1` if handled (fast guarded path), or `0` to fall back to stock `0x842d_a610`.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".optcode1.mac_bsr_pre_work")]
pub extern "C" fn opt_mac_bsr_pre_work_rust(active_lc_mask: u32) -> u32 {
    let b = blk();
    if !b.feature_enabled(FLAG_GUARDED_PRE_BO) {
        return 0;
    }
    b.cnt_pre_work_fast.bump();

    let (mut p0, mut p1, mut p2, mut p3) = (0u32, 0u32, 0u32, 0u32);
    let mut mask = active_lc_mask;
    if mask != 0 {
        let cipher_active = read_u32(L2_CIPHER_BUSY_VA) != 0 || read_u32(L2_CIPHER_PEND_VA) != 0;
        while mask != 0 {
            let lcid = 31 - mask.leading_zeros();
            mask &= !(1u32 << lcid);
            if lcid > 10 {
                continue;
            }
            // SAFETY: `L2_CTX_VA + 0x818 + lcid` is the live LCID->RBC index table (`0..7` or `0xff`).
            let rbc_idx = unsafe { read_volatile((L2_CTX_VA + 0x818 + lcid) as *const u8) };
            if rbc_idx >= 8 {
                continue;
            }
            let rbc = (RBC_TABLE_VA + (rbc_idx as u32) * 0x248) as *const Rbc;
            // SAFETY: `rbc_idx < 8`, so `rbc` points inside the live 8-entry `RBC_TABLE_VA` array.
            let (rb_type, active, lcg_id, pending, r0_ptr, r1_ptr) = unsafe {
                (
                    read_volatile(addr_of!((*rbc).rb_type)),
                    read_volatile(addr_of!((*rbc).active)),
                    read_volatile(addr_of!((*rbc).lcg_id)),
                    read_volatile(addr_of!((*rbc).ring_pending_bytes)),
                    read_volatile(addr_of!((*rbc).ring0)),
                    read_volatile(addr_of!((*rbc).ring1)),
                )
            };
            if rb_type != 0 || active != 1 || lcg_id >= 4 || pending == 0 {
                continue;
            }
            let r0_nonempty = if r0_ptr.is_null() {
                false
            } else {
                let p = r0_ptr.as_ptr();
                // SAFETY: Non-null `RbcRing` pointer owned by active DRB `rbc`.
                unsafe { read_volatile(addr_of!((*p).wr)) != read_volatile(addr_of!((*p).rd)) }
            };
            let r1_nonempty = if r1_ptr.is_null() {
                false
            } else {
                let p = r1_ptr.as_ptr();
                // SAFETY: Non-null `RbcRing` pointer owned by active DRB `rbc`.
                unsafe { read_volatile(addr_of!((*p).wr)) != read_volatile(addr_of!((*p).rd)) }
            };
            let (eff, clamped) = guarded_pre_bo(pending, r0_nonempty, r1_nonempty, cipher_active);
            if clamped {
                b.cnt_pre_work_guarded_zero.bump();
            }
            match lcg_id {
                0 => p0 = p0.wrapping_add(eff),
                1 => p1 = p1.wrapping_add(eff),
                2 => p2 = p2.wrapping_add(eff),
                _ => p3 = p3.wrapping_add(eff),
            }
        }
    }

    let dst = L2_BSR_PRE_BO_VA as *mut u32;
    // SAFETY: `L2_BSR_PRE_BO_VA` (`0x84dd_9d18`) is the live 4-word `lcg_pre_bo[4]` array in L2 BSS.
    unsafe {
        write_volatile(dst, p0);
        write_volatile(dst.add(1), p1);
        write_volatile(dst.add(2), p2);
        write_volatile(dst.add(3), p3);
    }
    1
}

// ============================================================================
// Cave 2 (.optcode2 @ 0x8417_ffd8, 628 B): PDCP UL hot-path handlers
// ============================================================================

/// Byte-accurate Ring-1 packet admission handler for `l2_proc_pdcp_ul` (`0x842d_ccd0`).
///
/// Called ONLY by `opt_pdcp_div_shim` when `FLAG_PDCP_BYTE_PACING` is validated active and
/// `max_pkts != 0`. Returns `u32::MAX` only if `ring1_va == 0` (safety fallback to stock
/// `__aeabi_uidiv`).
#[unsafe(no_mangle)]
#[unsafe(link_section = ".optcode2.pdcp_byte_pace")]
pub extern "C" fn opt_pdcp_byte_pace_rust(
    headroom: u32,
    _divisor: u32,
    ring1_va: u32,
    max_pkts: u32,
) -> u32 {
    if ring1_va == 0 {
        return u32::MAX;
    }
    // SAFETY: `ring1_va` is `rbc->ring1` (`RbcRing`: `+0x02` = `rd: u16`, `+0x04` = `slots[4096]`),
    // and each live slot holds a `GipcIrb` pointer with `length: u16` at `+0x06`.
    let cnt = unsafe {
        let rd = read_volatile((ring1_va + 2) as *const u16) as u32;
        let slots_base = ring1_va + 4;
        count_fitting_packets(headroom, max_pkts, |i| {
            let idx = rd.wrapping_add(i) & (RBC_RING_MASK as u32);
            let irb = read_volatile((slots_base + (idx << 2)) as *const u32);
            if irb == 0 {
                None
            } else {
                Some(read_volatile((irb + 6) as *const u16))
            }
        })
    };
    blk().cnt_byte_paced.bump();
    cnt
}

/// Rust handler for `do_tc` (`0x842e_5b06`, replacing `ubfx r3, r3, #15, #12`).
///
/// Returns `0` when `FLAG_DO_TC_CAP` is off (shim runs stock `ubfx` and returns to `lr`),
/// or non-zero computed staging cap (bytes) to store into `L2_PDCP_UL_LIMIT_VA` and jump
/// past stock's 3-tier ladder to `0x842e_5b28`.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".optcode2.do_tc_cap")]
pub extern "C" fn opt_do_tc_cap_rust(ul_250ms_bytes: u32) -> u32 {
    let b = blk();
    if !b.feature_enabled(FLAG_DO_TC_CAP) {
        return 0;
    }
    let cap = compute_do_tc_cap(
        ul_250ms_bytes,
        b.cap_target_ms.get(),
        b.cap_min_bytes.get(),
        b.cap_max_bytes.get(),
    );
    b.cnt_do_tc_clamped.bump();
    b.last_do_tc_cap.set(cap);
    cap
}

// ============================================================================
// Naked Thumb-2 entry shims (exact AAPCS + stock resume prologues)
// ============================================================================

/// Entry shim patched at `SearchMacUlBoIdx` (`0x842c_cf64`, `.optcode1`).
///
/// Fast-paths `bo == 0` inline with zero stack frame (~21 insns total) after validating
/// `magic`, `version`, `KNOWN_FLAGS_MASK`, and `FLAG_FAST_BSR_IDX`. Delegates `bo > 0`
/// to `opt_search_bo_idx_nz_rust` without re-checking the control block (~52 insns).
///
/// # Safety
/// Must be entered via `b.w` from `0x842c_cf64`. Preserves `r0` across the fallback
/// path and executes stock's displaced `push {r4-r7, lr}; sub sp, #0xc` before resuming
/// `0x842c_cf68`.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".optcode1.entry.search_bo_idx")]
#[unsafe(naked)]
pub unsafe extern "C" fn opt_search_bo_idx_shim() {
    naked_asm!(
        "movw r1, #0xb5c0",           // MAC_PDCP_OPT_BLK_VA = 0x841b_b5c0
        "movt r1, #0x841b",
        "ldrd r2, r3, [r1, #0]",      // r2 = magic, r3 = version
        "movw ip, #0x4f50",           // MAGIC = 0x4d50_4f50 ("MPOP")
        "movt ip, #0x4d50",
        "cmp r2, ip",
        "bne 2f",
        "movw ip, #0x1125",           // VERSION = 0x2026_1125
        "movt ip, #0x2026",
        "cmp r3, ip",
        "bne 2f",
        "ldr r2, [r1, #8]",           // flags
        "lsrs r3, r2, #6",            // any unknown bit above bit 5 -> stock
        "bne 2f",
        "tst r2, #1",                 // FLAG_FAST_BSR_IDX
        "beq 2f",
        "cbnz r0, 1f",                // bo != 0 -> validate ext_bsr_mode and tail-call
        "ldr r3, [r1, #28]",          // cnt_bo_idx_zero++ (+0x1c)
        "adds r3, #1",
        "str r3, [r1, #28]",
        "bx lr",                      // return 0 in r0 (zero stack frame!)
        "1:",
        "movw r2, #0x2aee",           // MAC_UL_CFG_VA + 0x152 (ext_bsr_mode) = 0x84d6_2aee
        "movt r2, #0x84d6",
        "ldrb r2, [r2, #0]",
        "subs r2, #1",                // 1 -> 0 (Std), 2 -> 1 (Ext), other -> > 1
        "cmp r2, #1",
        "bhi 2f",                     // unknown ext_bsr_mode -> stock fallback
        "b {nz_impl}",                // tail-call leaf Rust search (zero stack frame!)
        "2:",
        "push {{r4, r5, r6, r7, lr}}",
        "sub sp, #0xc",
        "movw ip, #0xcf69",
        "movt ip, #0x842c",
        "bx ip",
        nz_impl = sym opt_search_bo_idx_nz_rust,
    );
}

/// Entry shim patched at `CheckLongBsrDowngradeToShort` (`0x842c_fe34`, `.optcode1`).
///
/// # Safety
/// Must be entered via `b.w` from `0x842c_fe34`. Preserves `r0` across fallback and
/// executes stock's displaced `push.w {r4-r11, lr}` before resuming `0x842c_fe38`.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".optcode1.entry.check_long_bsr")]
#[unsafe(naked)]
pub unsafe extern "C" fn opt_check_long_bsr_shim() {
    naked_asm!(
        "push {{r0, lr}}",
        "bl {downgrade_impl}",
        "cmp r0, #2",
        "beq 1f",
        "add sp, #4",
        "pop {{pc}}",
        "1:",
        "pop {{r0, lr}}",
        "push.w {{r4, r5, r6, r7, r8, r9, r10, r11, lr}}",
        "movw ip, #0xfe39",
        "movt ip, #0x842c",
        "bx ip",
        downgrade_impl = sym opt_check_long_bsr_rust,
    );
}

/// Entry shim patched at `mac_bsr_pre_work` (`0x842d_a60c`, `.optcode1`).
///
/// # Safety
/// Must be entered via `b.w` from `0x842d_a60c`. Preserves `r0` across fallback and
/// executes stock's displaced `push.w {r4-r10, lr}` before resuming `0x842d_a610`.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".optcode1.entry.mac_bsr_pre_work")]
#[unsafe(naked)]
pub unsafe extern "C" fn opt_mac_bsr_pre_work_shim() {
    naked_asm!(
        "push {{r0, lr}}",
        "bl {pre_work_impl}",
        "cbz r0, 1f",
        "add sp, #4",
        "pop {{pc}}",
        "1:",
        "pop {{r0, lr}}",
        "push.w {{r4, r5, r6, r7, r8, r9, r10, lr}}",
        "movw ip, #0xa611",
        "movt ip, #0x842d",
        "bx ip",
        pre_work_impl = sym opt_mac_bsr_pre_work_rust,
    );
}

/// Entry shim patched at `l2_proc_pdcp_ul` (`0x842d_ccd0`, `.optcode2`),
/// replacing `blx 0x8411_cc14` (`__aeabi_uidiv`).
///
/// Entry: `r0 = limit - cur_bo`, `r1 = divisor`, `r4 = ring1`, `fp = max_pkts`.
/// Preserves all callee-saved regs (`r4..r11`); returns `r0 = pkts`.
///
/// # Safety
/// Must be entered via `bl` from `0x842d_ccd0`. Validates `magic`, `version`, and
/// `KNOWN_FLAGS_MASK`; falls back via tail-call `bx` to ARM-mode `__aeabi_uidiv`
/// (`0x8411_cc14`, bit 0 clear) when disabled or `divisor == 0`.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".optcode2.entry.pdcp_div")]
#[unsafe(naked)]
pub unsafe extern "C" fn opt_pdcp_div_shim() {
    naked_asm!(
        "movw r2, #0xb5c0",           // MAC_PDCP_OPT_BLK_VA = 0x841b_b5c0
        "movt r2, #0x841b",
        "ldr r3, [r2, #0]",           // magic
        "movw ip, #0x4f50",           // MAGIC = 0x4d50_4f50 ("MPOP")
        "movt ip, #0x4d50",
        "cmp r3, ip",
        "bne 3f",
        "ldr r3, [r2, #4]",           // version
        "movw ip, #0x1125",           // VERSION = 0x2026_1125
        "movt ip, #0x2026",
        "cmp r3, ip",
        "bne 3f",
        "ldr r3, [r2, #8]",           // flags
        "lsrs ip, r3, #6",            // any unknown bit above bit 5 -> stock
        "bne 3f",
        "tst r3, #0x18",              // FLAG_FAST_PDCP_DIV (0x08) | FLAG_PDCP_BYTE_PACING (0x10)
        "beq 3f",
        "cmp fp, #0",                 // Ring 1 empty (max_pkts == 0)?
        "bne 1f",
        "ldr r3, [r2, #48]",          // cnt_div_empty_skip++ (+0x30)
        "adds r3, #1",
        "str r3, [r2, #48]",
        "movs r0, #0",
        "bx lr",
        "1:",
        "tst r3, #0x10",              // FLAG_PDCP_BYTE_PACING?
        "bne 2f",
        "cbz r1, 3f",                 // divisor == 0 safety fallback
        "udiv r0, r0, r1",            // single-instruction Cortex-A7 hardware divide!
        "ldr r3, [r2, #52]",          // cnt_div_fast++ (+0x34)
        "adds r3, #1",
        "str r3, [r2, #52]",
        "bx lr",
        "2:",
        "push {{r0, r1, lr}}",
        "mov r2, r4",                 // ring1_va
        "mov r3, fp",                 // max_pkts
        "bl {pace_impl}",
        "cmn r0, #1",
        "beq 4f",
        "add sp, #8",
        "pop {{pc}}",
        "4:",
        "pop {{r0, r1, lr}}",
        "3:",
        "movw ip, #0xcc14",           // ARM-mode __aeabi_uidiv (bit 0 MUST be 0!)
        "movt ip, #0x8411",
        "bx ip",
        pace_impl = sym opt_pdcp_byte_pace_rust,
    );
}

/// Entry shim patched at `do_tc` (`0x842e_5b06`, `.optcode2`),
/// replacing `ubfx r3, r3, #15, #12`.
///
/// Entry: `r3 = ul_250ms_bytes`, `r4 = 0x84dd_9000` (`[r4, #0x7bc]` = `L2_PDCP_UL_LIMIT_VA`).
///
/// # Safety
/// Must be entered via `bl` from `0x842e_5b06`. When OFF, executes `ubfx r3, r3, #15, #12`
/// and returns to `lr` (`0x842e_5b0a`). When ON (`FLAG_DO_TC_CAP`), stores tuned cap to
/// `[r4, #1980]` and resumes `do_tc` at `0x842e_5b28` past the stock 3-tier ladder.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".optcode2.entry.do_tc_cap")]
#[unsafe(naked)]
pub unsafe extern "C" fn opt_do_tc_cap_shim() {
    naked_asm!(
        "push {{r0, r1, r2, r3, lr}}",
        "mov r0, r3",
        "bl {cap_impl}",
        "cbz r0, 1f",
        "str.w r0, [r4, #1980]",      // L2_PDCP_UL_LIMIT_VA = cap
        "pop {{r0, r1, r2, r3, lr}}",
        "movw ip, #0x5b29",           // resume 0x842e_5b28 | 1
        "movt ip, #0x842e",
        "bx ip",
        "1:",
        "pop {{r0, r1, r2, r3, lr}}",
        "ubfx r3, r3, #15, #12",      // exact displaced stock instruction
        "bx lr",
        cap_impl = sym opt_do_tc_cap_rust,
    );
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
