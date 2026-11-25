//! Bare-metal Cortex-A7 Thumb-2 integration for Lane N3 MAC UL hot-path optimizations.
//!
//! This is the ONLY module in `witcher-modem-mac-opt` permitted to contain `unsafe` code.
//! Every `unsafe` block carries an explicit `// SAFETY:` justification.
//!
//! Hook sites (all 4-byte Thumb-2 `b.w` at function entry, 100% disjoint from N4/N5/N6H/C1/M1):
//! 1. `0x842c_cf64` (`SearchMacUlBoIdx`) -> `n3_search_bo_idx_shim`
//!    Stock prologue replaced: `push {r4, r5, r6, r7, lr}; sub sp, #0xc` (4 B -> resume `0x842c_cf68`)
//! 2. `0x842c_fe34` (`CheckLongBsrDowngradeToShort`) -> `n3_check_long_bsr_shim`
//!    Stock prologue replaced: `push.w {r4-r11, lr}` (4 B -> resume `0x842c_fe38`)
//! 3. `0x842d_a60c` (`mac_bsr_pre_work`) -> `n3_mac_bsr_pre_work_shim`
//!    Stock prologue replaced: `push.w {r4-r10, lr}` (4 B -> resume `0x842d_a610`)

use core::arch::naked_asm;
use core::panic::PanicInfo;
use core::ptr::{addr_of, read_volatile, write_volatile};

use modem_atlas::addr::{
    L2_BSR_PRE_BO_VA, L2_CIPHER_BUSY_VA, L2_CIPHER_PEND_VA, L2_CTX_VA, MAC_UL_BSR_CTX_VA,
    MAC_UL_CFG_VA, N3_OPT_BLK_VA, RBC_TABLE_VA, ROM_EXT_BSR_TABLE_VA, ROM_STD_BSR_TABLE_VA,
};
use modem_atlas::l2::Rbc;
use modem_atlas::mac::{MacUlBsrCtx, MacUlCfg};

use crate::block::{
    FLAG_FAST_BSR_IDX, FLAG_FAST_LONG_BSR_CHECK, FLAG_GUARDED_PRE_BO, N3OptBlock,
};
use crate::opt::{FALLBACK_TO_STOCK, fast_bo_idx, fast_long_bsr_downgrade, guarded_pre_bo};

/// Boot-off 128-byte control block placed in `.n3blk` at `0x8449_a2a0` (`ATM_decodePCO`).
#[unsafe(no_mangle)]
#[unsafe(link_section = ".n3blk")]
pub static N3_OPT_BLK: N3OptBlock = N3OptBlock::boot_default();

#[inline(always)]
fn blk() -> &'static N3OptBlock {
    // SAFETY: `N3_OPT_BLK_VA` (`0x8449_a2a0`) is the fixed 128-byte `.n3blk` cave on CPU1;
    // all fields are `AtomicU32` (`Word`) accessed via relaxed atomic loads/stores.
    unsafe { &*(N3_OPT_BLK_VA as *const N3OptBlock) }
}

#[inline(always)]
fn read_u32(va: u32) -> u32 {
    // SAFETY: Caller passes a verified 4-byte-aligned modem RAM/ROM VA from `modem_atlas::addr`.
    unsafe { read_volatile(va as *const u32) }
}

/// Rust handler for `SearchMacUlBoIdx(bo_bytes)` (`0x842c_cf64`).
///
/// Returns `0..=63` when handled on the fast path, or `0xff` to fall back to stock
/// (when `FLAG_FAST_BSR_IDX` is off or `ext_bsr_mode` is neither 1 nor 2).
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.n3_search_bo_idx_rust")]
pub extern "C" fn n3_search_bo_idx_rust(bo_bytes: u32) -> u32 {
    let b = blk();
    if !b.feature_enabled(FLAG_FAST_BSR_IDX) {
        return 0xff;
    }
    b.cnt_bo_idx_fast.bump();
    if bo_bytes == 0 {
        b.cnt_bo_idx_zero.bump();
        return 0;
    }
    let cfg = MAC_UL_CFG_VA as *const MacUlCfg;
    // SAFETY: `MAC_UL_CFG_VA` (`0x84d6_299c`) is the live static `MacUlCfg` in CPU1 BSS.
    let mode = unsafe { read_volatile(addr_of!((*cfg).ext_bsr_mode)) };
    let table_va = match mode {
        1 => ROM_STD_BSR_TABLE_VA,
        2 => ROM_EXT_BSR_TABLE_VA,
        _ => return 0xff,
    };
    // SAFETY: `table_va` is either `0x847f_5b1c` or `0x847f_5c18`, both verified 4-byte-aligned
    // constant `[u32; 63]` tables in `tk.bin` ROM.
    let table = unsafe { &*(table_va as *const [u32; 63]) };
    fast_bo_idx(table, bo_bytes) as u32
}

/// Rust handler for `CheckLongBsrDowngradeToShort(tb_rem)` (`0x842c_fe34`).
///
/// Returns `0` or `1` on O(1) early exit, or `FALLBACK_TO_STOCK` (`2`) to execute stock.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.n3_check_long_bsr_rust")]
pub extern "C" fn n3_check_long_bsr_rust(tb_rem: u32) -> u32 {
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
#[unsafe(link_section = ".text.n3_mac_bsr_pre_work_rust")]
pub extern "C" fn n3_mac_bsr_pre_work_rust(active_lc_mask: u32) -> u32 {
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
// Naked Thumb-2 entry shims (preserve exact AAPCS + stock resume prologues)
// ============================================================================

/// Entry shim patched at `SearchMacUlBoIdx` (`0x842c_cf64`).
///
/// # Safety
/// Must be entered via `b.w` from `0x842c_cf64`. Preserves `r0` across the fallback
/// path and executes stock's displaced `push {r4-r7, lr}; sub sp, #0xc` before resuming
/// `0x842c_cf68`.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.n3_search_bo_idx_shim")]
#[unsafe(naked)]
pub unsafe extern "C" fn n3_search_bo_idx_shim() {
    naked_asm!(
        "push {{r0, lr}}",
        "bl n3_search_bo_idx_rust",
        "cmp r0, #0xff",
        "beq 1f",
        "add sp, #4",
        "pop {{pc}}",
        "1:",
        "pop {{r0, lr}}",
        "push {{r4, r5, r6, r7, lr}}",
        "sub sp, #0xc",
        "movw ip, #0xcf69",
        "movt ip, #0x842c",
        "bx ip",
    );
}

/// Entry shim patched at `CheckLongBsrDowngradeToShort` (`0x842c_fe34`).
///
/// # Safety
/// Must be entered via `b.w` from `0x842c_fe34`. Preserves `r0` across fallback and
/// executes stock's displaced `push.w {r4-r11, lr}` before resuming `0x842c_fe38`.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.n3_check_long_bsr_shim")]
#[unsafe(naked)]
pub unsafe extern "C" fn n3_check_long_bsr_shim() {
    naked_asm!(
        "push {{r0, lr}}",
        "bl n3_check_long_bsr_rust",
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
    );
}

/// Entry shim patched at `mac_bsr_pre_work` (`0x842d_a60c`).
///
/// # Safety
/// Must be entered via `b.w` from `0x842d_a60c`. Preserves `r0` across fallback and
/// executes stock's displaced `push.w {r4-r10, lr}` before resuming `0x842d_a610`.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.n3_mac_bsr_pre_work_shim")]
#[unsafe(naked)]
pub unsafe extern "C" fn n3_mac_bsr_pre_work_shim() {
    naked_asm!(
        "push {{r0, lr}}",
        "bl n3_mac_bsr_pre_work_rust",
        "cbz r0, 1f",
        "add sp, #4",
        "pop {{pc}}",
        "1:",
        "pop {{r0, lr}}",
        "push.w {{r4, r5, r6, r7, r8, r9, r10, lr}}",
        "movw ip, #0xa611",
        "movt ip, #0x842d",
        "bx ip",
    );
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
