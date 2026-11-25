//! Bare-metal Cortex-A7 Thumb-2 integration for the G1 MAC UL timeline tracer.
//!
//! This is the ONLY module in `witcher-modem-g1` permitted to contain `unsafe` code.
//! Every `unsafe` block carries an explicit `// SAFETY:` justification and performs
//! at most one unsafe operation (`clippy::multiple_unsafe_ops_per_block`).
//!
//! Five 4-byte `bl` hook sites, all strictly disjoint from N6H, R4, R1, M1, C1, N7, U14, N1, N2, N3, and Q1:
//! - Hook 1 (`0x842d_0918`, `GenerateMacUlPdu`): `g1_hook_pre_ce`  — replaces `ldr.w sb, [r5, #0x810]`
//! - Hook 2 (`0x842d_098a`, `GenerateMacUlPdu`): `g1_hook_newtx`   — replaces `mov.w r1, #0x3c0`
//! - Hook 3 (`0x842c_ed8c`, `L1A_L2_SendTxPdu`): `g1_hook_send_tx` — replaces `movw r5, #0xd07c`
//! - Hook 4 (`0x842d_4cd4`, `GetMacUlSR`):       `g1_hook_sr`      — replaces `ldr.w r3, [r4, #0xf0]`
//! - Hook 5 (`0x842d_8b7a`, `ScheduleUlData`):   `g1_hook_tti_end` — replaces `bl SchedRa` (`0x842d_3d10`)

use core::arch::naked_asm;
use core::mem::offset_of;
use core::panic::PanicInfo;
use core::ptr::{read_volatile, write_volatile};

use modem_atlas::addr::{
    AIR_STI_VA, L2_BSR_PRE_BO_VA, MAC_HARQ_PROC_TBL_VA, MAC_PHR_STATE_VA, MAC_UL_BSR_CTX_VA,
    MAC_UL_CFG_VA, TTI_CLK_VA,
};
use modem_atlas::mac::{MacHarqProc, MacTbBuildFrame, MacUlBsrCtx, MacUlCfg, MacUlLcgState};

use crate::block::{G1Block, RING_BASE, TtiEndInput};
use crate::record::{BsrFormat, EventKind, PhrSample, TraceRecord};

/// Control block placed at `0x8412_a340` inside dead `ossDupWorld` (`0x8412_a308..0x8412_a538`).
#[unsafe(no_mangle)]
#[unsafe(link_section = ".g1blk")]
pub static mut G1_BLK: G1Block = G1Block::boot_default();

#[inline(always)]
fn read_u32_va(va: u32) -> u32 {
    // SAFETY: Caller supplies a verified 4-byte-aligned modem RAM/MMIO VA from `modem_atlas`.
    unsafe { read_volatile(va as *const u32) }
}

#[inline(always)]
fn read_u8_va(va: u32) -> u8 {
    // SAFETY: Caller supplies a verified byte-accessible modem RAM VA from `modem_atlas`.
    unsafe { read_volatile(va as *const u8) }
}

/// Sum Ring-1 pending bytes (`L2_BSR_PRE_BO_VA`) and cached RLC BO (`MacUlBsrCtx::lcg[0..4]`).
#[inline(never)]
fn read_bo_pair() -> (u32, u32) {
    const LCG_BASE: u32 = MAC_UL_BSR_CTX_VA
        + offset_of!(MacUlBsrCtx, lcg) as u32
        + offset_of!(MacUlLcgState, bo_bytes) as u32;
    const STRIDE: u32 = core::mem::size_of::<MacUlLcgState>() as u32;
    let mut r1 = 0u32;
    let mut rlc = 0u32;
    let mut i = 0u32;
    while i < 4 {
        r1 = r1.wrapping_add(read_u32_va(L2_BSR_PRE_BO_VA + i * 4));
        rlc = rlc.wrapping_add(read_u32_va(LCG_BASE + i * STRIDE));
        i += 1;
    }
    (r1, rlc)
}

/// Read one carrier's PHR entry from `MacPhrState` (`0x84d9_3f84`, per-CC stride `0x10`).
#[inline(never)]
fn read_phr_cell(cc: u32, is_ext: bool) -> PhrSample {
    let base = MAC_PHR_STATE_VA + cc * 0x10;
    let active = read_u8_va(base + 0x10) == 1;
    if !active {
        return PhrSample::ABSENT;
    }
    let ph = (read_u32_va(base + 0x14) & 0x3f) as u8;
    let v_byte = read_u8_va(base + 0x1c);
    let virtual_phr = v_byte != 0;
    let pcmax = if is_ext && !virtual_phr {
        read_u8_va(base + 0x1d) & 0x3f
    } else {
        0xff
    };
    PhrSample {
        active: true,
        virtual_phr,
        ph,
        pcmax,
    }
}

/// Fill common tail fields (`tti_ms`, `ring1_bytes`, `rlc_bo_bytes`, `seq`), advance `wr_idx`,
/// enforce any post-trigger countdown, and store `rec` into `G1_RING`.
#[inline(never)]
fn emit_record(blk: &mut G1Block, rec: &mut TraceRecord) {
    let Some((slot, seq)) = blk.alloc_slot() else {
        return;
    };
    let (r1, rlc) = read_bo_pair();
    rec.tti_ms = read_u32_va(TTI_CLK_VA);
    rec.ring1_bytes = r1;
    rec.rlc_bo_bytes = rlc;
    rec.seq = seq;
    let dst = (RING_BASE as usize + (slot << 5)) as *mut u32;
    let src = (rec as *const TraceRecord).cast::<u32>();
    let mut i = 0usize;
    while i < 8 {
        let sp = src.wrapping_add(i);
        // SAFETY: `rec` is an aligned 32-byte (8 x u32) `TraceRecord` on the stack; `i < 8`.
        let word = unsafe { *sp };
        let dp = dst.wrapping_add(i);
        // SAFETY: `RING_BASE` (`0x87f7_0000..0x87f9_0000`, 128 KiB) is Normal Non-Cacheable SDRAM
        // strictly inside the proven-dead `srch_run_pss_*` buffer (`0x87f6_ed40..0x87f9_4540`),
        // `slot` is masked to `0..4095`, and `i < 8`.
        unsafe { write_volatile(dp, word) };
        i += 1;
    }
}

/// Mutable reference to `G1_BLK` on single-core CPU1 (`l2_hp_task` / L1U non-reentrant hooks).
#[inline(always)]
fn g1_blk_mut() -> &'static mut G1Block {
    // SAFETY: CPU1 runs uT-Kernel on a single core; hooks run sequentially in L2/MAC/L1U context
    // without re-entering each other.
    unsafe { &mut *core::ptr::addr_of_mut!(G1_BLK) }
}

// ============================================================================
// AAPCS `extern "C"` Rust handlers called by the naked shims
// ============================================================================

#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.g1_on_newtx_rust")]
pub extern "C" fn g1_on_newtx_rust(
    cc: u32,
    hq_id: u32,
    frame_va: u32,
    _total_ce_size: u32,
) {
    let blk = g1_blk_mut();
    if !blk.is_recording() {
        return;
    }

    let cc_u = cc & 3;
    let hq_u = hq_id & 7;
    let hp_va = MAC_HARQ_PROC_TBL_VA + cc_u * 0x3c0 + hq_u * 0x78;
    let air_sti = (read_u32_va(hp_va) & 0xffff) as u16;
    let ce_mask = (read_u32_va(hp_va + 8) & 0x1f) as u8;

    let tb_size = read_u32_va(frame_va + offset_of!(MacTbBuildFrame, tb_size) as u32);
    let used_bytes = read_u32_va(frame_va + offset_of!(MacTbBuildFrame, used_bytes) as u32);
    let bsr_lcid = read_u8_va(frame_va + offset_of!(MacTbBuildFrame, bsr_lcid) as u32);
    let has_trailing_pad =
        read_u8_va(frame_va + offset_of!(MacTbBuildFrame, has_trailing_pad) as u32) != 0;
    // `MacTbBuildFrame::bsr_type` at `+0x68`: `1` = Padding BSR, `0` = Regular/Periodic.
    let bsr_is_padding = read_u32_va(frame_va + 0x68) == 1;

    let ext_bsr_mode =
        read_u8_va(MAC_UL_CFG_VA + offset_of!(MacUlCfg, ext_bsr_mode) as u32) == 2;

    let mut bsr_ce = [0u8; 3];
    if (ce_mask & 0x02) != 0 && blk.snap_ce_buf != 0 {
        let p = blk.snap_ce_buf;
        bsr_ce[0] = read_u8_va(p);
        if bsr_lcid == modem_atlas::mac::MAC_LCID_LONG_BSR {
            bsr_ce[1] = read_u8_va(p + 1);
            bsr_ce[2] = read_u8_va(p + 2);
        }
    }

    let mut phr_cc0 = PhrSample::ABSENT;
    let mut phr_cc1 = PhrSample::ABSENT;
    if (ce_mask & 0x1c) != 0 {
        let is_ext = (ce_mask & 0x18) != 0;
        phr_cc0 = read_phr_cell(0, is_ext);
        if !phr_cc0.active && (ce_mask & 0x04) != 0 {
            phr_cc0 = PhrSample {
                active: true,
                virtual_phr: read_u8_va(MAC_PHR_STATE_VA + 0x1c) != 0,
                ph: (read_u32_va(MAC_PHR_STATE_VA + 0x14) & 0x3f) as u8,
                pcmax: 0xff,
            };
        }
        if is_ext {
            let mut s = 1u32;
            while s < 8 {
                let sample = read_phr_cell(s, true);
                if sample.active {
                    phr_cc1 = sample;
                    break;
                }
                s += 1;
            }
        }
    }

    if (cc & 1) == 0 {
        blk.cnt_newtx_cc0 = blk.cnt_newtx_cc0.wrapping_add(1);
    } else {
        blk.cnt_newtx_cc1 = blk.cnt_newtx_cc1.wrapping_add(1);
    }
    let has_bsr = (ce_mask & 0x02) != 0;
    let has_phr = (ce_mask & 0x1c) != 0;
    if has_bsr {
        blk.cnt_bsr = blk.cnt_bsr.wrapping_add(1);
    }
    if has_phr {
        blk.cnt_phr = blk.cnt_phr.wrapping_add(1);
    }
    let bsr_fmt = if has_bsr {
        BsrFormat::from_lcid(bsr_lcid)
    } else {
        BsrFormat::None
    };

    let mut rec = TraceRecord {
        tti_ms: 0,
        air_sti,
        flags0: TraceRecord::pack_flags0(EventKind::NewTx, cc as u8, hq_id as u8, ext_bsr_mode),
        flags1: TraceRecord::pack_flags1(ce_mask, has_trailing_pad, bsr_fmt),
        tbs_bytes: tb_size as u16,
        used_or_retx: used_bytes as u16,
        bsr_trig: TraceRecord::pack_bsr_trig(blk.snap_bsr_trig, bsr_is_padding, blk.snap_phr_evt),
        bsr_ce,
        phr_cc0_ph_v: phr_cc0.pack_ph_v(),
        phr_cc0_pcmax: phr_cc0.pack_pcmax(),
        phr_cc1_ph_v: phr_cc1.pack_ph_v(),
        phr_cc1_pcmax: phr_cc1.pack_pcmax(),
        ring1_bytes: 0,
        rlc_bo_bytes: 0,
        seq: 0,
    };
    emit_record(blk, &mut rec);
}

#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.g1_on_retx_rust")]
pub extern "C" fn g1_on_retx_rust(cc: u32, sub_idx: u32, hp_va: u32, pending_action: u32) {
    let blk = g1_blk_mut();
    if !blk.is_recording() {
        return;
    }
    blk.cnt_retx = blk.cnt_retx.wrapping_add(1);
    let air_sti = (read_u32_va(hp_va) & 0xffff) as u16;
    let mcs = read_u8_va(hp_va + offset_of!(MacHarqProc, mcs) as u32);
    let tx_nb = read_u8_va(hp_va + offset_of!(MacHarqProc, current_tx_nb) as u32);
    let rv = read_u8_va(hp_va + offset_of!(MacHarqProc, rv) as u32);
    let hq_id = (read_u32_va(hp_va + 0x24) & 7) as u8;
    let tbs_bytes = (read_u32_va(hp_va + 0x4c + (sub_idx & 1) * 4) & 0xffff) as u16;
    let kind = if pending_action == modem_atlas::mac::HARQ_ACT_ADAPT_RETX {
        EventKind::AdaptRetx
    } else {
        EventKind::NonAdaptRetx
    };

    let mut rec = TraceRecord {
        tti_ms: 0,
        air_sti,
        flags0: TraceRecord::pack_flags0(kind, cc as u8, hq_id, false),
        flags1: 0,
        tbs_bytes,
        used_or_retx: TraceRecord::pack_retx_meta(mcs, tx_nb, rv),
        bsr_trig: 0,
        bsr_ce: [0; 3],
        phr_cc0_ph_v: 0,
        phr_cc0_pcmax: 0xff,
        phr_cc1_ph_v: 0,
        phr_cc1_pcmax: 0xff,
        ring1_bytes: 0,
        rlc_bo_bytes: 0,
        seq: 0,
    };
    emit_record(blk, &mut rec);
}

#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.g1_on_sr_rust")]
pub extern "C" fn g1_on_sr_rust(old_sr_counter: u32) {
    let blk = g1_blk_mut();
    if !blk.is_recording() {
        return;
    }
    blk.cnt_sr = blk.cnt_sr.wrapping_add(1);
    let cur_sti = read_u32_va(AIR_STI_VA);
    let tx_sti = if cur_sti + 1 >= 10_240 {
        0
    } else {
        (cur_sti + 1) as u16
    };
    let bsr_trigger_mask = read_u32_va(MAC_UL_BSR_CTX_VA + 4);
    let mut rec = TraceRecord {
        tti_ms: 0,
        air_sti: tx_sti,
        flags0: TraceRecord::pack_flags0(EventKind::PucchSr, 0, 0, false),
        flags1: 0,
        tbs_bytes: (old_sr_counter.wrapping_add(1) & 0xffff) as u16,
        used_or_retx: 0,
        bsr_trig: TraceRecord::pack_bsr_trig(bsr_trigger_mask, false, 0),
        bsr_ce: [0; 3],
        phr_cc0_ph_v: 0,
        phr_cc0_pcmax: 0xff,
        phr_cc1_ph_v: 0,
        phr_cc1_pcmax: 0xff,
        ring1_bytes: 0,
        rlc_bo_bytes: 0,
        seq: 0,
    };
    emit_record(blk, &mut rec);
}

#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.g1_on_tti_end_rust")]
pub extern "C" fn g1_on_tti_end_rust(hq0: u32, hq1: u32, feature_flags: u32, air_sti: u32) {
    let blk = g1_blk_mut();
    let (ring1_bytes, rlc_bo_bytes) = read_bo_pair();
    blk.on_tti_end(TtiEndInput {
        tti_ms: read_u32_va(TTI_CLK_VA),
        air_sti: (air_sti & 0xffff) as u16,
        hq0: hq0 as u8,
        hq1: hq1 as u8,
        ul_ca_configured: (feature_flags & 2) != 0,
        ring1_bytes,
        rlc_bo_bytes,
    });
}

// ============================================================================
// Naked Thumb-2 hook entry shims (exact stock register & 8-byte SP ABI)
// ============================================================================

/// Hook 1 (`0x842d_0918` in `GenerateMacUlPdu`): executes displaced `ldr.w sb, [r5, #0x810]`.
/// When enabled & unfrozen, snapshots `ce_buf`, `bsr_trigger_mask`, and `phr_event` into `G1_BLK`
/// before `GetMacUlBsrValue` / `ResetPHREvent` clear them.
///
/// # Safety
/// Invoked solely via a patched 4-byte `bl` at `0x842d_0918` in `GenerateMacUlPdu` with
/// `r5` pointing to the active MAC PDU descriptor and a valid stack in `sp`.
#[unsafe(no_mangle)]
#[unsafe(naked)]
#[unsafe(link_section = ".text.g1_shims")]
pub unsafe extern "C" fn g1_hook_pre_ce() {
    naked_asm!(
        "ldr.w sb, [r5, #0x810]",
        "push {{r0, r1}}",
        "movw r0, #:lower16:G1_BLK",
        "movt r0, #:upper16:G1_BLK",
        "ldr r1, [r0, #8]",
        "cmp r1, #1",
        "bne 1f",
        "ldr r1, [r0, #12]",
        "cbnz r1, 1f",
        "str.w sb, [r0, #0x68]",
        "movw r1, #0x2944",
        "movt r1, #0x84d6",
        "ldr r1, [r1]",
        "str r1, [r0, #0x6c]",
        "movw r1, #0x3f88",
        "movt r1, #0x84d9",
        "ldr r1, [r1]",
        "str r1, [r0, #0x70]",
        "1:",
        "pop {{r0, r1}}",
        "bx lr",
    );
}

/// Hook 2 (`0x842d_098a` in `GenerateMacUlPdu`): replaces `mov.w r1, #0x3c0`.
/// At this site all MAC CEs (BSR, PHR, ExtPHR, DC-PHR, C-RNTI) are finalized; `r1, r2, r3` and
/// CPSR are dead immediately after.
///
/// # Safety
/// Invoked solely via a patched 4-byte `bl` at `0x842d_098a` in `GenerateMacUlPdu` with
/// `r6 = cc`, `sl = hq_id`, `r7 = &MacTbBuildFrame`, `sb = total_ce_size`.
#[unsafe(no_mangle)]
#[unsafe(naked)]
#[unsafe(link_section = ".text.g1_shims")]
pub unsafe extern "C" fn g1_hook_newtx() {
    naked_asm!(
        "movw r1, #:lower16:G1_BLK",
        "movt r1, #:upper16:G1_BLK",
        "ldr r2, [r1, #8]",
        "cmp r2, #1",
        "bne 1f",
        "ldr r2, [r1, #12]",
        "cbnz r2, 1f",
        "push {{r0, r3, r4, ip, lr}}",
        "mov r4, sp",
        "bic r0, r4, #7",
        "mov sp, r0",
        "mov r0, r6",
        "mov r1, sl",
        "mov r2, r7",
        "mov r3, sb",
        "bl g1_on_newtx_rust",
        "mov sp, r4",
        "pop {{r0, r3, r4, ip, lr}}",
        "1:",
        "mov.w r1, #0x3c0",
        "bx lr",
    );
}

/// Hook 3 (`0x842c_ed8c` in `L1A_L2_SendTxPdu`): replaces `movw r5, #0xd07c`.
/// Fast-skips when off, frozen, or NewTx (`pending_action == 0`); captures HARQ retransmissions.
///
/// # Safety
/// Invoked solely via a patched 4-byte `bl` at `0x842c_ed8c` in `L1A_L2_SendTxPdu` with
/// `r0 = cc`, `r1 = sub_idx`, `r3 = &MacHarqProc`.
#[unsafe(no_mangle)]
#[unsafe(naked)]
#[unsafe(link_section = ".text.g1_shims")]
pub unsafe extern "C" fn g1_hook_send_tx() {
    naked_asm!(
        "movw r5, #:lower16:G1_BLK",
        "movt r5, #:upper16:G1_BLK",
        "ldr r4, [r5, #8]",
        "cmp r4, #1",
        "bne 1f",
        "ldr r4, [r5, #12]",
        "cbnz r4, 1f",
        "ldr r4, [r3, #0x20]",
        "cbz r4, 1f",
        "push {{r0, r1, r2, r3, r6, ip, lr}}",
        "mov r6, sp",
        "bic r5, r6, #7",
        "mov sp, r5",
        "mov r2, r3",
        "mov r3, r4",
        "bl g1_on_retx_rust",
        "mov sp, r6",
        "pop {{r0, r1, r2, r3, r6, ip, lr}}",
        "1:",
        "movw r5, #0xd07c",
        "bx lr",
    );
}

/// Hook 4 (`0x842d_4cd4` in `GetMacUlSR`): replaces `ldr.w r3, [r4, #0xf0]`.
/// Strictly disjoint from U14 (`0x842d_4cd8..0x842d_4cdc`).
///
/// # Safety
/// Invoked solely via a patched 4-byte `bl` at `0x842d_4cd4` in `GetMacUlSR` with
/// `r4 = MAC_RA_SR_CTX_VA`.
#[unsafe(no_mangle)]
#[unsafe(naked)]
#[unsafe(link_section = ".text.g1_shims")]
pub unsafe extern "C" fn g1_hook_sr() {
    naked_asm!(
        "ldr.w r3, [r4, #0xf0]",
        "movw r1, #:lower16:G1_BLK",
        "movt r1, #:upper16:G1_BLK",
        "ldr r2, [r1, #8]",
        "cmp r2, #1",
        "bne 1f",
        "ldr r2, [r1, #12]",
        "cbnz r2, 1f",
        "push {{r0, r3, r5, ip, lr}}",
        "mov r5, sp",
        "bic r0, r5, #7",
        "mov sp, r0",
        "mov r0, r3",
        "bl g1_on_sr_rust",
        "mov sp, r5",
        "pop {{r0, r3, r5, ip, lr}}",
        "1:",
        "bx lr",
    );
}

/// Hook 5 (`0x842d_8b7a` in `ScheduleUlData`): replaces `bl SchedRa` (`0x842d_3d10`).
/// Tail-calls `SchedRa` with zero stack when off, frozen, or auto-freeze is disabled (`af_mode == 0`).
///
/// # Safety
/// Invoked solely via a patched 4-byte `bl` at `0x842d_8b7a` in `ScheduleUlData` with
/// `r5 = MAC_UL_CFG_VA`, `r7 = ScheduleUlData frame`, `r8 = MAC_UL_GLOBAL_VA`.
#[unsafe(no_mangle)]
#[unsafe(naked)]
#[unsafe(link_section = ".text.g1_shims")]
pub unsafe extern "C" fn g1_hook_tti_end() {
    naked_asm!(
        "movw r0, #:lower16:G1_BLK",
        "movt r0, #:upper16:G1_BLK",
        "ldr r1, [r0, #8]",
        "cmp r1, #1",
        "bne 1f",
        "ldr r1, [r0, #12]",
        "cbnz r1, 1f",
        "ldr r1, [r0, #0x20]",
        "cbz r1, 1f",
        "push {{r4, lr}}",
        "mov r4, sp",
        "bic r0, r4, #7",
        "mov sp, r0",
        "movw ip, #0x3d11",
        "movt ip, #0x842d",
        "blx ip",
        "ldrb r0, [r7, #0xe]",
        "ldrb r1, [r7, #0xf]",
        "ldr r2, [r5, #0]",
        "ldr.w r3, [r8, #0x490]",
        "cbz r3, 2f",
        "ldr r3, [r3, #0]",
        "2:",
        "bl g1_on_tti_end_rust",
        "mov sp, r4",
        "pop {{r4, pc}}",
        "1:",
        "movw ip, #0x3d11",
        "movt ip, #0x842d",
        "bx ip",
    );
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
