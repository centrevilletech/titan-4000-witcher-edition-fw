//! Bare-metal Cortex-A7 Thumb-2 integration for the Titan 4000 N4 v2 uplink engine.
//!
//! This is the ONLY module in `witcher-modem-n4` permitted to contain `unsafe` code.
//! Every `unsafe` block carries an explicit `// SAFETY:` justification.
//!
//! All five N4 hook sites preserve the exact stock/N4 register and CPSR flag contracts:
//! - Hook 1 (`0x842d_0914`): `n4_hook_mac_tb`   — replaces `ldr.w r8, [r3, #8]`
//! - Hook 2 (`0x842d_d21c` / `0x847e_d0ee`): `n4_hook_calc_lcg_bo` — replaces `ldr.w r2, [sl, #580]`
//! - Hook 2b (`0x842c_d5f4`): `n4_hook_short_bsr` — replaces `bl 0x842d_d194` (`calc_lcg_bo`)
//! - Hook 3 (`0x842d_cca2`): `n4_hook_pdcp_limit` — replaces `ldr.w r0, [r2, #1980]`
//! - Hook 4 (`0x842d_a210`): `n4_hook_gipc_rx`  — replaces `cmp r4, #127; bhi 0x842d_a22c`

use core::arch::naked_asm;
use core::panic::PanicInfo;
use core::ptr::{addr_of, read_volatile};
use core::slice;

use modem_atlas::addr::{
    L2_CIPHER_BUSY_VA, L2_CIPHER_PEND_VA, N4_EXT_CNT_VA, N4_STATE_VA, TTI_CLK_VA,
};
#[cfg(feature = "stack-hooks")]
use modem_atlas::addr::N5_STATE_VA;
use modem_atlas::l2::Rbc;
use modem_atlas::mac::MacTbBuildFrame;
use modem_atlas::patches::{N4ExtCounters, N4State};

use crate::aqm::{AqmOutcome, evaluate_aqm};
use crate::bsr::{calc_lcg_bo, rescue_short_bsr};
use crate::pdcp::pdcp_limit;
use crate::rx::{record_arrival, try_legacy_sparse};
use crate::state::{N4_SPARSE_TBL_VA, SparseBucket};
#[cfg(feature = "stack-hooks")]
use crate::state::{FLAG_TRUE_BO_PDCP, N4_V3_HANDSHAKE_CNT_VA, N4HandshakeCounters};
use crate::tb::{DrbRefillInfo, TbInputs, on_mac_tb};

/// Read a volatile `u32` from a fixed 4-byte-aligned modem address.
#[inline(always)]
fn read_mmio_u32(va: u32) -> u32 {
    // SAFETY: Caller passes a verified 4-byte-aligned modem RAM/MMIO VA from `modem_atlas::addr`.
    unsafe { read_volatile(va as *const u32) }
}

/// Obtain mutable references to the disjoint N4 state regions (`N4State` at `0x847e_d600`
/// and `N4ExtCounters` at `0x847e_d780`).
///
/// # Safety
/// CPU1 runs uT-Kernel on a single core and hooks do not re-enter themselves; `N4State`
/// (`0x847e_d600..0x847e_d680`) and `N4ExtCounters` (`0x847e_d780..0x847e_d79c`) are
/// strictly non-overlapping fixed PRACH-tail RAM allocations.
#[inline(always)]
unsafe fn n4_state_and_ext() -> (&'static mut N4State, &'static mut N4ExtCounters) {
    // SAFETY: Non-overlapping fixed addresses verified in `modem_atlas::patches`.
    unsafe {
        (
            &mut *(N4_STATE_VA as *mut N4State),
            &mut *(N4_EXT_CNT_VA as *mut N4ExtCounters),
        )
    }
}

/// Read `rbc.ring_pending_bytes` with the N4 empty-ring & idle-cipher defensive guard.
///
/// Mirrors `n4_ul_engine.s` lines 288..315: if `ring_pending_bytes != 0` while Ring 0,
/// Ring 1, and both hardware cipher queues are all empty, returns `0` to clear residual drift.
#[inline(always)]
fn read_guarded_ring_pending(rbc: *const Rbc) -> u32 {
    // SAFETY: `rbc` is the live bearer pointer in `sl` passed by stock `rlc_upd_cur_bo`.
    let pending = unsafe { read_volatile(addr_of!((*rbc).ring_pending_bytes)) };
    if pending == 0 {
        return 0;
    }

    // SAFETY: `rbc` is valid; ring pointers are null-checked before dereferencing `wr`/`rd`.
    unsafe {
        let r0 = read_volatile(addr_of!((*rbc).ring0));
        if !r0.is_null() {
            let r0p = r0.as_ptr();
            if read_volatile(addr_of!((*r0p).wr)) != read_volatile(addr_of!((*r0p).rd)) {
                return pending;
            }
        }
        let r1 = read_volatile(addr_of!((*rbc).ring1));
        if !r1.is_null() {
            let r1p = r1.as_ptr();
            if read_volatile(addr_of!((*r1p).wr)) != read_volatile(addr_of!((*r1p).rd)) {
                return pending;
            }
        }
    }

    if read_mmio_u32(L2_CIPHER_BUSY_VA) != 0 || read_mmio_u32(L2_CIPHER_PEND_VA) != 0 {
        return pending;
    }
    0
}

/// Build a bounded mutable slice over the IP header starting at `pkt_buf + 2`.
///
/// Caps the slice at `min(pkt_len, 128)` bytes, which covers every IPv4/IPv6 ECN,
/// legacy sparse-hash, and IMG4 v3 handshake-spare access without ever crossing `pkt_len`.
#[inline(always)]
fn ip_slice_mut<'a>(pkt_buf: *mut u8, pkt_len: u32) -> &'a mut [u8] {
    if pkt_buf.is_null() {
        return &mut [];
    }
    let len = if pkt_len > 128 { 128 } else { pkt_len } as usize;
    // SAFETY: In `gipc_rx_loop`, `sl` (`pkt_buf`) points to `[2-byte GCT hdr | IP pkt]`
    // with at least `pkt_len` payload bytes valid at `pkt_buf + 2`.
    unsafe { slice::from_raw_parts_mut(pkt_buf.add(2), len) }
}

// ============================================================================
// AAPCS `extern "C"` Rust implementations called by the naked shims
// ============================================================================

#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.n4_mac_tb_rust")]
pub extern "C" fn n4_mac_tb_rust(frame: *const MacTbBuildFrame) {
    // SAFETY: `frame` (`r7`) is the live `GenerateMacUlPdu` stack frame at `0x842d_0914`.
    let (tb_size, used_bytes, has_pad) = unsafe {
        (
            read_volatile(addr_of!((*frame).tb_size)),
            read_volatile(addr_of!((*frame).used_bytes)),
            read_volatile(addr_of!((*frame).has_trailing_pad)) != 0,
        )
    };
    let now_tti = read_mmio_u32(TTI_CLK_VA);

    // SAFETY: Single-core CPU1 access to `N4State`.
    let st = unsafe { &mut *(N4_STATE_VA as *mut N4State) };
    on_mac_tb(
        st,
        TbInputs {
            tb_size,
            used_bytes,
            has_trailing_pad: has_pad,
            now_tti,
        },
        |rbc_va| {
            let rbc = rbc_va as *const Rbc;
            // SAFETY: `rbc_va` was recorded from a live `Rbc*` in `hook_gipc_rx` and checked non-null.
            unsafe {
                DrbRefillInfo {
                    active: read_volatile(addr_of!((*rbc).active)),
                    ring_pending_bytes: read_volatile(addr_of!((*rbc).ring_pending_bytes)),
                    pdcp_rlc_tx_bo: read_volatile(addr_of!((*rbc).pdcp_rlc_tx_bo)),
                }
            }
        },
    );
}

#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.n4_calc_lcg_bo_rust")]
pub extern "C" fn n4_calc_lcg_bo_rust(
    rbc: *const Rbc,
    lcg_id: u32,
    actual_bo: u32,
    hdr_bo: u32,
) -> u32 {
    // SAFETY: `rbc` (`sl`) is the live bearer pointer in `rlc_upd_cur_bo` at `0x842d_d21c`.
    let bo_margin = unsafe { read_volatile(addr_of!((*rbc).bo_margin_bytes)) };
    // SAFETY: Single-core CPU1 access to disjoint `N4State` and `N4ExtCounters`.
    let (st, ext) = unsafe { n4_state_and_ext() };
    calc_lcg_bo(
        st,
        ext,
        lcg_id,
        rbc as u32,
        bo_margin,
        actual_bo,
        hdr_bo,
        || read_guarded_ring_pending(rbc),
        || read_mmio_u32(TTI_CLK_VA),
    )
}

#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.n4_short_bsr_rust")]
pub extern "C" fn n4_short_bsr_rust(lcg_bo_ptr: *const [u32; 4], selected_lcg: u32) -> u32 {
    // SAFETY: `lcg_bo_ptr` (`r4`, originally `r0`) points to `u32[4]` on `GetMacUlBsrValue`'s stack,
    // freshly populated by stock `calc_lcg_bo` immediately prior to this call.
    let lcg_bo = unsafe { &*lcg_bo_ptr };
    // SAFETY: Single-core CPU1 access to disjoint `N4State` and `N4ExtCounters`.
    let (st, ext) = unsafe { n4_state_and_ext() };
    rescue_short_bsr(st, ext, lcg_bo, selected_lcg)
}

#[cfg(not(feature = "stack-hooks"))]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.n4_pdcp_limit_rust")]
pub extern "C" fn n4_pdcp_limit_rust(stock_cap: u32) -> u32 {
    // SAFETY: Single-core CPU1 access to `N4State`.
    let st = unsafe { &mut *(N4_STATE_VA as *mut N4State) };
    pdcp_limit(st, stock_cap)
}

#[cfg(feature = "stack-hooks")]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.n4_pdcp_limit_rust")]
pub extern "C" fn n4_pdcp_limit_rust(stock_cap: u32) -> u64 {
    // SAFETY: Single-core CPU1 access to `N4State`.
    let st = unsafe { &mut *(N4_STATE_VA as *mut N4State) };
    let lim = pdcp_limit(st, stock_cap);
    // If N4 bit 0 is enabled and N5 PDCP limit (N5_FLAGS bit 1) is armed, tell the shim
    // to tail-call N5's `n5_pdcp_limit` so N5 Hook B behavior is preserved unmodified.
    if (st.flags & FLAG_TRUE_BO_PDCP) != 0 && (read_mmio_u32(N5_STATE_VA + 8) & 2) != 0 {
        return 1u64 << 32;
    }
    lim as u64
}

#[cfg(not(feature = "stack-hooks"))]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.n4_gipc_rx_rust")]
pub extern "C" fn n4_gipc_rx_rust(rbc: *const Rbc, pkt_len: u32, pkt_buf: *mut u8) -> u32 {
    let now_tti = read_mmio_u32(TTI_CLK_VA);
    // SAFETY: Single-core CPU1 access to disjoint N4 state regions.
    let (st, ext) = unsafe { n4_state_and_ext() };
    record_arrival(st, rbc as u32, pkt_len, now_tti);

    if pkt_len <= 127 {
        return 0; // Exit A
    }

    let ip = ip_slice_mut(pkt_buf, pkt_len);
    // SAFETY: `N4_SPARSE_TBL_VA` (`0x847e_d680`) is disjoint from `N4State` (`0x847e_d600..0x847e_d680`)
    // and `N4ExtCounters` (`0x847e_d780..0x847e_d79c`).
    let sparse_tbl = unsafe { &mut *(N4_SPARSE_TBL_VA as *mut [SparseBucket; 64]) };
    if try_legacy_sparse(st, sparse_tbl, pkt_len, now_tti, ip, || {
        // SAFETY: `rbc` (`r9`) is the live bearer pointer in `gipc_rx_loop`.
        unsafe {
            let r0 = read_volatile(addr_of!((*rbc).ring0));
            if r0.is_null() {
                None
            } else {
                let r0p = r0.as_ptr();
                let wr = read_volatile(addr_of!((*r0p).wr));
                let rd = read_volatile(addr_of!((*r0p).rd));
                Some(wr.wrapping_sub(rd) & 0x0fff)
            }
        }
    }) {
        return 2; // Exit C
    }

    // SAFETY: `rbc` (`r9`) is valid; queue counters are read only when AQM is active or harmlessly.
    let q_total = unsafe {
        read_volatile(addr_of!((*rbc).ring_pending_bytes))
            .wrapping_add(read_volatile(addr_of!((*rbc).pdcp_rlc_tx_bo)))
    };
    match evaluate_aqm(st, ext, q_total, pkt_len, now_tti, ip, None) {
        AqmOutcome::Enqueue => 1, // Exit B
        AqmOutcome::Drop => 3,    // Exit D
    }
}

#[cfg(feature = "stack-hooks")]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.n4_ingress_rust")]
pub extern "C" fn n4_ingress_rust(rbc: *const Rbc, pkt_len: u32) -> u64 {
    let now_tti = read_mmio_u32(TTI_CLK_VA);
    // SAFETY: Single-core CPU1 access to `N4State`.
    let st = unsafe { &mut *(N4_STATE_VA as *mut N4State) };
    record_arrival(st, rbc as u32, pkt_len, now_tti);
    let n5_active = read_mmio_u32(N5_STATE_VA + 8) & 1;
    ((n5_active as u64) << 32) | (now_tti as u64)
}

#[cfg(feature = "stack-hooks")]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.n4_sparse_rust")]
pub extern "C" fn n4_sparse_rust(
    rbc: *const Rbc,
    pkt_len: u32,
    now_tti: u32,
    pkt_buf: *mut u8,
) -> u32 {
    // SAFETY: Single-core CPU1 access to disjoint `N4State` and `N4_SPARSE_TBL_VA`.
    let (st, sparse_tbl) = unsafe {
        (
            &mut *(N4_STATE_VA as *mut N4State),
            &mut *(N4_SPARSE_TBL_VA as *mut [SparseBucket; 64]),
        )
    };
    let ip = ip_slice_mut(pkt_buf, pkt_len);
    let promoted = try_legacy_sparse(st, sparse_tbl, pkt_len, now_tti, ip, || {
        // SAFETY: `rbc` (`r9`) is the live bearer pointer in `gipc_rx_loop`.
        unsafe {
            let r0 = read_volatile(addr_of!((*rbc).ring0));
            if r0.is_null() {
                None
            } else {
                let r0p = r0.as_ptr();
                let wr = read_volatile(addr_of!((*r0p).wr));
                let rd = read_volatile(addr_of!((*r0p).rd));
                Some(wr.wrapping_sub(rd) & 0x0fff)
            }
        }
    });
    u32::from(promoted)
}

#[cfg(feature = "stack-hooks")]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.n4_aqm_rust")]
pub extern "C" fn n4_aqm_rust(
    rbc: *const Rbc,
    pkt_len: u32,
    now_tti: u32,
    pkt_buf: *mut u8,
) -> u32 {
    // SAFETY: Single-core CPU1 access to disjoint N4 state, ext counters, and IMG4 handshake counters.
    let (st, ext, hc) = unsafe {
        let (st, ext) = n4_state_and_ext();
        (st, ext, &mut *(N4_V3_HANDSHAKE_CNT_VA as *mut N4HandshakeCounters))
    };
    // SAFETY: `rbc` (`r9`) is the live bearer pointer in `gipc_rx_loop`.
    let q_total = unsafe {
        read_volatile(addr_of!((*rbc).ring_pending_bytes))
            .wrapping_add(read_volatile(addr_of!((*rbc).pdcp_rlc_tx_bo)))
    };
    let ip = ip_slice_mut(pkt_buf, pkt_len);
    match evaluate_aqm(st, ext, q_total, pkt_len, now_tti, ip, Some(hc)) {
        AqmOutcome::Enqueue => 0,
        AqmOutcome::Drop => 1,
    }
}

// ============================================================================
// Naked Thumb-2 hook entry shims (exact stock/N4 register + CPSR + 8-byte SP ABI)
// ============================================================================

/// Hook 1 (`0x842d_0914`): executes displaced `ldr.w r8, [r3, #8]`, aligns SP to 8 bytes,
/// invokes `n4_mac_tb_rust(r7)`, and preserves all other registers (`r0..r7, r9..r12, sp`).
#[unsafe(no_mangle)]
#[unsafe(naked)]
#[unsafe(link_section = ".text.n4_shims")]
pub unsafe extern "C" fn hook_mac_tb() {
    naked_asm!(
        "ldr.w r8, [r3, #8]",
        "push {{r0, r1, r2, r3, r4, ip, lr}}",
        "mov r4, sp",
        "bic r0, r4, #7",
        "mov sp, r0",
        "mov r0, r7",
        "bl n4_mac_tb_rust",
        "mov sp, r4",
        "pop {{r0, r1, r2, r3, r4, ip, pc}}",
    );
}

/// Hook 2 (`0x842d_d21c` / IMG3 HRB tail target `0x847e_d0ee`): computes augmented `bo_margin`
/// into `r2` via `n4_calc_lcg_bo_rust(sl, r1, [r7], [r7+4])`, preserving `r0, r1, r3..r12, sp`.
#[unsafe(no_mangle)]
#[unsafe(naked)]
#[unsafe(link_section = ".text.n4_shims")]
pub unsafe extern "C" fn hook_calc_lcg_bo() {
    naked_asm!(
        "push {{r0, r1, r3, r4, ip, lr}}",
        "mov r4, sp",
        "bic r0, r4, #7",
        "mov sp, r0",
        "mov r0, sl",
        "ldr r2, [r7, #0]",
        "ldr r3, [r7, #4]",
        "bl n4_calc_lcg_bo_rust",
        "mov r2, r0",
        "mov sp, r4",
        "pop {{r0, r1, r3, r4, ip, pc}}",
    );
}

/// Hook 2b (`0x842c_d5f4`): calls stock `calc_lcg_bo` (`0x842d_d194 | 1`), then invokes
/// `n4_short_bsr_rust(&lcg_bo[0], r8)` and updates `r8`.
#[unsafe(no_mangle)]
#[unsafe(naked)]
#[unsafe(link_section = ".text.n4_shims")]
pub unsafe extern "C" fn hook_short_bsr() {
    naked_asm!(
        "push {{r4, r5, lr}}",
        "mov r4, r0",
        "mov r5, sp",
        "bic r1, r5, #7",
        "mov sp, r1",
        "movw ip, #0xd195",
        "movt ip, #0x842d",
        "blx ip",
        "mov r0, r4",
        "mov r1, r8",
        "bl n4_short_bsr_rust",
        "mov r8, r0",
        "mov sp, r5",
        "pop {{r4, r5, pc}}",
    );
}

/// Hook 3 (`0x842d_cca2`, standalone): computes PDCP staging cap into `r0`, preserving `r1..r12, sp`.
#[cfg(not(feature = "stack-hooks"))]
#[unsafe(no_mangle)]
#[unsafe(naked)]
#[unsafe(link_section = ".text.n4_shims")]
pub unsafe extern "C" fn hook_pdcp_limit() {
    naked_asm!(
        "push {{r1, r2, r3, r4, ip, lr}}",
        "mov r4, sp",
        "bic r1, r4, #7",
        "mov sp, r1",
        "ldr.w r0, [r2, #1980]",
        "bl n4_pdcp_limit_rust",
        "mov sp, r4",
        "pop {{r1, r2, r3, r4, ip, pc}}",
    );
}

/// Hook 3 (`0x842d_cca2`, stack-hooks): runs Rust `pdcp_limit` when N5 bit 1 is off, or
/// delegates to N5 `n5_pdcp_limit` (`0x8418_fc9c`) with the exact `{r1,r2,r3,r4,lr}` frame.
#[cfg(feature = "stack-hooks")]
#[unsafe(no_mangle)]
#[unsafe(naked)]
#[unsafe(link_section = ".text.n4_shims")]
pub unsafe extern "C" fn hook_pdcp_limit() {
    naked_asm!(
        "push {{r1, r2, r3, r4, lr}}",
        "push {{r5, ip}}",
        "mov r5, sp",
        "bic r1, r5, #7",
        "mov sp, r1",
        "ldr.w r0, [r2, #1980]",
        "bl n4_pdcp_limit_rust",
        "mov sp, r5",
        "pop {{r5, ip}}",
        "cbnz r1, 1f",
        "pop {{r1, r2, r3, r4, pc}}",
        "1:",
        "movw r4, #0xd600",
        "movt r4, #0x847e",
        // Use r0 (dead on entry to n5_pdcp_limit) so ip (r12) remains strictly preserved.
        "movw r0, #0xfc9d", // 0x8418_fc9c | 1 (n5_pdcp_limit)
        "movt r0, #0x8418",
        "bx r0",
    );
}

/// Hook 4 (`0x842d_a210`, standalone): pure N4 v2 ingress, legacy sparse, and AQM v2.
#[cfg(not(feature = "stack-hooks"))]
#[unsafe(no_mangle)]
#[unsafe(naked)]
#[unsafe(link_section = ".text.n4_shims")]
pub unsafe extern "C" fn hook_gipc_rx() {
    naked_asm!(
        "push {{r0, r1, r3, r5, r6, lr}}",
        "push {{r2, ip}}",
        "mov r5, sp",
        "bic r0, r5, #7",
        "mov sp, r0",
        "mov r0, r9",
        "mov r1, r4",
        "mov r2, sl",
        "bl n4_gipc_rx_rust",
        "mov sp, r5",
        "mov r3, r0",
        "pop {{r2, ip}}",
        "cbz r3, 10f",
        "cmp r3, #1",
        "beq 11f",
        "cmp r3, #2",
        "beq 12f",
        // Exit D: Ring 1 AQM drop
        "ldr.w r2, [r9, #4]",
        "pop {{r0, r1, r3, r5, r6, lr}}",
        "movw ip, #0xa3e1",
        "movt ip, #0x842d",
        "bx ip",
        // Exit C: Ring 0 sparse promotion
        "12:",
        "ldr.w r2, [r9, #0]",
        "pop {{r0, r1, r3, r5, r6, lr}}",
        "movw ip, #0xa24b",
        "movt ip, #0x842d",
        "bx ip",
        // Exit B: stock Ring 1 enqueue
        "11:",
        "pop {{r0, r1, r3, r5, r6, lr}}",
        "movw ip, #0xa22d",
        "movt ip, #0x842d",
        "bx ip",
        // Exit A: stock <= 127 B Ring 0 check (exact cmp r4, #127 flags + all regs preserved)
        "10:",
        "cmp r4, #127",
        "pop {{r0, r1, r3, r5, r6, pc}}",
    );
}

/// Hook 4 (`0x842d_a210`, stack-hooks): Rust N4 ingress + N5 flow-lane / M1 PIE / IMG4 v3 ABI.
#[cfg(feature = "stack-hooks")]
#[unsafe(no_mangle)]
#[unsafe(naked)]
#[unsafe(link_section = ".text.n4_shims")]
pub unsafe extern "C" fn hook_gipc_rx() {
    naked_asm!(
        "push {{r0, r1, r3, r5, r6, lr}}",
        "push {{r2, ip}}",
        "mov r5, sp",
        "bic r0, r5, #7",
        "mov sp, r0",
        "mov r0, r9",
        "mov r1, r4",
        "bl n4_ingress_rust",
        "mov sp, r5",
        "mov r6, r0",       // r6 = now_tti
        "mov r3, r1",       // r3 = N5_FLAGS & 1
        "pop {{r2, ip}}",
        "movw r5, #0xd600",
        "movt r5, #0x847e", // r5 = N4_STATE_VA
        "cbz r3, 1f",
        "movw r0, #0xf769", // 0x8418_f768 | 1 (n5_flow_classify)
        "movt r0, #0x8418",
        "blx r0",
        "1:",
        "cmp r4, #127",
        "bls.w n4_abi_exit_a",
        "ldr r0, [r5, #4]",
        "tst r0, #8",
        "beq.w n4_abi_check_aqm",
        "push {{r2, r7}}",
        "mov r7, sp",
        "bic r0, r7, #7",
        "mov sp, r0",
        "mov r0, r9",
        "mov r1, r4",
        "mov r2, r6",
        "mov r3, sl",
        "bl n4_sparse_rust",
        "mov sp, r7",
        "pop {{r2, r7}}",
        "cbz r0, 2f",
        "ldr.w r2, [r9, #0]",
        "pop {{r0, r1, r3, r5, r6, lr}}",
        "movw ip, #0xa24b",
        "movt ip, #0x842d",
        "bx ip",
        "2:",
        "b.w n4_abi_check_aqm",
    );
}

// ============================================================================
// Fixed-VA ABI veneers inside 0x847e_d000..0x847e_d540 (stack-hooks mode only)
// Preserves binary compatibility with IMG3 HRB, IMG4 n4v3_spare, N5, and M1.
// ============================================================================

/// Fixed VA `0x847e_d0ee`: tail-called by IMG3's HRB hook at `0x842d_d21c`.
#[cfg(feature = "stack-hooks")]
#[unsafe(no_mangle)]
#[unsafe(naked)]
#[unsafe(link_section = ".text.n4_abi_0ee")]
pub unsafe extern "C" fn n4_abi_calc_lcg_bo() {
    naked_asm!("b.w hook_calc_lcg_bo");
}

/// Fixed VA `0x847e_d414`: entered by N5 `n5_flow_classify` and `hook_gipc_rx`.
/// First invokes M1's `m1_aqm_shim` (`0x841d_e8dc`); when `M1 selector == 0`,
/// `m1_aqm_shim` returns `r0 = N4_FLAGS & 5` and execution enters Rust N4 AQM v2.
#[cfg(feature = "stack-hooks")]
#[unsafe(no_mangle)]
#[unsafe(naked)]
#[unsafe(link_section = ".text.n4_abi_414")]
pub unsafe extern "C" fn n4_abi_check_aqm() {
    naked_asm!(
        // Exact Thumb-2 `bl 0x841de8dc` (m1_aqm_shim) from fixed VA 0x847ed414.
        ".inst.w 0xf5f1f262",
        "nop",
        "cmp r0, #5",
        "bne.w n4_abi_exit_b",
        "push {{r2, r7}}",
        "mov r7, sp",
        "bic r0, r7, #7",
        "mov sp, r0",
        "mov r0, r9",
        "mov r1, r4",
        "mov r2, r6",
        "mov r3, sl",
        "bl n4_aqm_rust",
        "mov sp, r7",
        "pop {{r2, r7}}",
        "cbnz r0, 1f",
        "b.w n4_abi_exit_b",
        "1:",
        "b.w n4_abi_exit_d",
    );
}

/// Fixed VA `0x847e_d458`: `bl n4v3_spare` preserved for IMG4 T1 direct-site audit.
#[cfg(feature = "stack-hooks")]
#[unsafe(no_mangle)]
#[unsafe(naked)]
#[unsafe(link_section = ".text.n4_abi_458")]
pub unsafe extern "C" fn n4_abi_n4v3_word() {
    naked_asm!(
        // Exact Thumb-2 `bl 0x8448a6de` (IMG4 n4v3_spare) from fixed VA 0x847ed458.
        ".inst.w 0xf49df941",
    );
}

/// Fixed VA `0x847e_d51c`: Exit D (clean Ring 1 drop), targeted by M1 `m1_aqm_shim`.
#[cfg(feature = "stack-hooks")]
#[unsafe(no_mangle)]
#[unsafe(naked)]
#[unsafe(link_section = ".text.n4_abi_51c")]
pub unsafe extern "C" fn n4_abi_exit_d() {
    naked_asm!(
        "ldr.w r2, [r9, #4]",
        "pop {{r0, r1, r3, r5, r6, lr}}",
        "movw ip, #0xa3e1",
        "movt ip, #0x842d",
        "bx ip",
    );
}

/// Fixed VA `0x847e_d52e`: Exit B (normal Ring 1 enqueue), targeted by IMG4, N5, and M1.
#[cfg(feature = "stack-hooks")]
#[unsafe(no_mangle)]
#[unsafe(naked)]
#[unsafe(link_section = ".text.n4_abi_52e")]
pub unsafe extern "C" fn n4_abi_exit_b() {
    naked_asm!(
        "pop {{r0, r1, r3, r5, r6, lr}}",
        "movw ip, #0xa22d",
        "movt ip, #0x842d",
        "bx ip",
    );
}

/// Fixed VA `0x847e_d53c`: Exit A (stock <= 127 B Ring 0), targeted by N5 `n5_flow_classify`.
#[cfg(feature = "stack-hooks")]
#[unsafe(no_mangle)]
#[unsafe(naked)]
#[unsafe(link_section = ".text.n4_abi_53c")]
pub unsafe extern "C" fn n4_abi_exit_a() {
    naked_asm!("pop {{r0, r1, r3, r5, r6, pc}}");
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
