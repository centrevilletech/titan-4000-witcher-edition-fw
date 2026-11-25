//! `extern "C"` signatures for stock `tk.bin` functions that a Rust modem patch
//! may call (via linker symbol table / `PROVIDE` or typed function pointers) or
//! replace via hook trampolines.
//!
//! Calling convention: ARMv7 AAPCS (`r0..r3` args, `r0` return, `r4..r11` callee-saved).
//! All L2/MAC/GIPC functions below are **Thumb-2** (`va | 1` for indirect `blx`),
//! **except** the three CP15 cache maintenance primitives (`dma_*_range`), which are
//! **ARM mode** (even address, bit 0 MUST be `0`).

use crate::gipc::GipcIrb;
use crate::l2::{Rbc, RbcRing, RlcAmTxEntry};
use crate::mac::MacHarqProc;

// Linker-resolved external symbols (`PROVIDE(sym = 0x84xxxxxx | 1);` for Thumb).
//
// A Rust bare-metal crate targeting `tk.bin` can link against a generated linker
// script providing these exact VAs, or invoke them via `fn_ptr`.
extern "C" {
    // -----------------------------------------------------------------------
    // ARM-mode CP15 cache maintenance (even VAs: 0x8411_4e64 / 4eac / 4ee0)
    // -----------------------------------------------------------------------

    /// `0x8411_4e64` (ARM): Invalidate D-cache `[start, end)` (`DCIMVAC` + `dsb st`).
    pub fn dma_inv_range(start: *mut u8, end: *mut u8);
    /// `0x8411_4eac` (ARM): Clean D-cache `[start, end)` (`DCCMVAC` + `dsb st`).
    pub fn dma_clean_range(start: *const u8, end: *const u8);
    /// `0x8411_4ee0` (ARM): Clean + invalidate D-cache `[start, end)` (`DCCIMVAC` + `dsb st`).
    pub fn dma_flush_range(start: *mut u8, end: *mut u8);

    // -----------------------------------------------------------------------
    // GIPC shared-ring primitives (Thumb-2)
    // -----------------------------------------------------------------------

    /// `0x8411_6228` (Thumb): Pop one H->M (uplink) IRB from channel `ch` (`1` = LTE SDU).
    pub fn get_rx_ch_irb(ch: u32) -> *mut GipcIrb;
    /// `0x8411_6330` (Thumb): Push one M->H (downlink) IRB to host CPU0 + SGI #10.
    pub fn gipc_send(irb: *mut GipcIrb) -> i32;
    /// `0x8411_63e4` (Thumb): Pop one pre-posted free M->H (downlink) IRB from channel `ch`.
    pub fn gipc_get_tx_irb(ch: u32) -> *mut GipcIrb;
    /// `0x8411_6564` (Thumb): Release a finished H->M (uplink) IRB back to host CPU0 + SGI #10.
    pub fn gipc_rel_rx_irb(irb: *mut GipcIrb);
    /// `0x8411_6220` (Thumb): Fatal GIPC IRB state/overflow abort handler.
    pub fn gipc_irb_abort(irb: *mut GipcIrb, file: *const u8, line: u32, func: *const u8) -> !;

    // -----------------------------------------------------------------------
    // L2 scheduler, timers & bearer lookup (Thumb-2)
    // -----------------------------------------------------------------------

    /// `0x842d_a5d8` (Thumb): Lookup [`Rbc`] by MAC logical channel ID (`lcid`), NULL if unmapped.
    pub fn rbc_by_lcid(lcid: u32) -> *mut Rbc;
    /// `0x842d_a530` (Thumb): Schedule a deferred L2 callback (`prio`: 1=HP, 2=normal).
    pub fn l2_sched_event(callback: unsafe extern "C" fn(*mut core::ffi::c_void), arg: *mut core::ffi::c_void, prio: u32);
    /// `0x842d_9e5c` (Thumb): Start L2 software timer slot `tmr_id` (`0..63`).
    pub fn l2_timer_start(tmr_id: u32);
    /// `0x842d_9ef4` (Thumb): Stop L2 software timer slot `tmr_id` (`0..63`).
    pub fn l2_timer_stop(tmr_id: u32);
    /// `0x842d_9fa8` (Thumb): Poll expired L2 timers (`is_hp`: 1=slots 0..23, 0=slots 24..63).
    pub fn l2_proc_timer(l2_ctx: *mut core::ffi::c_void, is_hp: u32);

    // -----------------------------------------------------------------------
    // PDCP UL & RLC UL (Thumb-2)
    // -----------------------------------------------------------------------

    /// `0x842d_c968` (Thumb): Submit up to `count` IRBs from `ring` into hardware `LLCE0` UL cipher batch.
    pub fn proc_pdcp_ul(
        batch: *mut core::ffi::c_void,
        rbc: *mut Rbc,
        ring: *mut RbcRing,
        count: u32,
    ) -> *mut core::ffi::c_void;
    /// `0x842d_cbf4` (Thumb): Per-TTI PDCP UL feeder (drains Ring 0 then Ring 1 up to staging cap).
    pub fn l2_proc_pdcp_ul(l2_ctx: *mut core::ffi::c_void);
    /// `0x842d_cf60` (Thumb): Release ACKed PDCP UL SDUs `[start_sn..=end_sn]` and return IRBs to GIPC.
    pub fn pdcp_ul_proc_drb_cnf(rbc: *mut Rbc, start_sn: u32, end_sn: u32);
    /// `0x842d_d074` (Thumb): Scan PDCP UL window for expired `discardTimer` SDUs.
    pub fn pdcp_proc_tmr_discard(rbc: *mut Rbc);
    /// `0x842d_d134` (Thumb): Compute per-bearer `(actual_bo, hdr_bo)` for RLC AM/UM/TM.
    pub fn get_rlc_cur_bo(rbc: *const Rbc, out_actual_bo: *mut u32, out_hdr_bo: *mut u32);
    /// `0x842d_d194` (Thumb): Aggregate per-LCG BO into `lcg_bo[4]` (includes `bo_margin` + N4 `TRUE_BO`).
    pub fn rlc_upd_cur_bo(lcg_bo: *mut [u32; 4]);
    /// `0x842d_d794` (Thumb): Enqueue an RLC AM TX entry into the UL retransmission ring (returns 1 on maxRetx).
    pub fn process_pdu_retx(rbc: *mut Rbc, tx_entry: *mut RlcAmTxEntry, flags: u32) -> u32;
    /// `0x842d_dbc0` (Thumb): Refresh RLC retx BO and notify MAC UL BO.
    pub fn upd_retx_bo(rbc: *mut Rbc);
    /// `0x842d_eb44` (Thumb): Process an incoming peer RLC AM STATUS PDU (ACKs + NACKs).
    pub fn rlc_ul_am_proc_status_rpt(rbc: *mut Rbc);
    /// `0x842d_f4f4` (Thumb): Build UL RLC AM PDU(s) for a MAC grant allocation.
    pub fn rlc_ul_am_gen_pdu(rbc: *mut Rbc, alloc_packed: u32, allow_retx: u32, out_buf: *mut u8) -> u32;
    /// `0x8452_c9e8` (Thumb): Set `DP_BO_MARGIN_VA = margin_kb << 10`.
    pub fn tc_set_hp_bo_margin(margin_kb: u32);

    // -----------------------------------------------------------------------
    // MAC UL: BSR, SR, LCP, TB build, HARQ (Thumb-2)
    // -----------------------------------------------------------------------

    /// `0x842c_cf64` (Thumb): Map `bo_bytes` to 3GPP 6-bit BSR index (`0..=63`).
    pub fn search_mac_ul_bo_idx(bo_bytes: u32) -> u8;
    /// `0x842c_d080` (Thumb): Restart `periodicBSR-Timer`.
    pub fn restart_bsr_timer();
    /// `0x842c_d298` (Thumb): Update MAC UL BO for `lcid`, triggering Regular BSR / SR if needed.
    pub fn update_mac_ul_bo(lcid: u32, new_bo: u32, extra: u32);
    /// `0x842c_d46c` (Thumb): Select BSR format LCID (`28` Truncated, `29` Short, `30` Long, `255` None).
    pub fn get_mac_ul_bsr_format(bsr_kind: u32, rem_bytes: u32) -> u8;
    /// `0x842c_d54c` (Thumb): Populate BSR MAC CE payload into `out_bsr_ce` for `lcid` (28/29/30).
    pub fn get_mac_ul_bsr_value(bsr_lcid: u32, out_bsr_ce: *mut u32, active_lc_mask: u32);
    /// `0x842c_fb34` (Thumb): MAC LCP Step 2 (remaining TB bytes distributed by priority).
    pub fn second_step_pbr(ctx: *mut core::ffi::c_void, rem_bytes: u32);
    /// `0x842c_fd40` (Thumb): MAC LCP Step 1 (allocate up to each LC's PBR token bucket `Bj`).
    pub fn assign_schedule_size_2lc(ctx: *mut core::ffi::c_void, rem_bytes: u32);
    /// `0x842d_3abc` (Thumb): Trigger PUCCH Scheduling Request or fallback to contention RACH.
    pub fn access_ra();
    /// `0x842d_4a78` (Thumb): Cancel pending SR when `cancel_flag != 0` (NewTx grant).
    pub fn handle_ra_ulgrant(cc: u32, hq_id: u32, cancel_flag: u32);
    /// `0x842d_4ca4` (Thumb): Poll MAC SR state machine on a PUCCH SR occasion (returns 1 to TX SR).
    pub fn get_mac_ul_sr() -> u32;
    /// `0x842d_54fc` (Thumb): Free HARQ TB buffer and reset `MacHarqProc` fields.
    pub fn clear_mac_ul_buffer(proc_ptr: *mut MacHarqProc);
    /// `0x842d_556c` (Thumb): Handle PHICH ACK without DCI-0 (suspends HARQ process).
    pub fn harq_proc_ack(cc: u32, hq_id: u32, proc_ptr: *mut MacHarqProc);

    // -----------------------------------------------------------------------
    // Downlink key functions (Thumb-2)
    // -----------------------------------------------------------------------

    /// `0x842c_9ccc` (Thumb): MAC DL TB entry (dispatches to `HandleSCHTrCh` `0x842c_935c`).
    pub fn process_mac_dl_data(dl_ind: *mut core::ffi::c_void);
    /// `0x842d_af3c` (Thumb): RLC AM DL PDU receive & in-sequence release (`VR(R)`).
    /// `pdu_desc` holds `len` at `+0x04` and `buf` at `+0x0c`.
    pub fn rlc_dl_am_proc_pdu(pdu_desc: *mut core::ffi::c_void, rbc: *mut Rbc);
    /// `0x842d_9c70` (Thumb): Post-LLCE1 hardware decipher completion -> GIPC M->H send loop.
    pub fn l2_proc_decip_done(l2_ctx: *mut core::ffi::c_void);

    // -----------------------------------------------------------------------
    // Built-in diagnostics (Thumb-2)
    // -----------------------------------------------------------------------

    /// `0x8454_5048` (Thumb): Record max UL PDCP-to-ACK sojourn ms into `rbc.stats[bank].ul_max_lat_ms`.
    pub fn l2_tr_ul_latency(rbc: *mut Rbc, pdcp_sn: u32);
    /// `0x8454_52e8` (Thumb): Track Ring-1 IRB sojourn (`stage`: 0=enqueue, 1=PDCP submit).
    pub fn l2_tr_irb_latency(irb: *mut GipcIrb, stage: u32);
}

/// Typed 32-bit function-pointer constructors for calling stock `tk.bin` routines
/// without a custom linker script. Automatically sets the Thumb interworking bit
/// (`va | 1`) for Thumb functions and preserves bit 0 = `0` for ARM-mode helpers.
#[cfg(target_pointer_width = "32")]
pub mod fn_ptr {
    use super::*;
    use crate::addr::*;

    #[inline]
    pub fn rbc_by_lcid() -> unsafe extern "C" fn(u32) -> *mut Rbc {
        unsafe { core::mem::transmute((FN_RBC_BY_LCID | 1) as usize) }
    }

    #[inline]
    pub fn gipc_rel_rx_irb() -> unsafe extern "C" fn(*mut GipcIrb) {
        unsafe { core::mem::transmute((FN_GIPC_REL_RX_IRB | 1) as usize) }
    }

    #[inline]
    pub fn rlc_upd_cur_bo() -> unsafe extern "C" fn(*mut [u32; 4]) {
        unsafe { core::mem::transmute((FN_RLC_UPD_CUR_BO | 1) as usize) }
    }

    #[inline]
    pub fn search_mac_ul_bo_idx() -> unsafe extern "C" fn(u32) -> u8 {
        unsafe { core::mem::transmute((FN_SEARCH_MAC_UL_BO_IDX | 1) as usize) }
    }

    #[inline]
    pub fn clear_mac_ul_buffer() -> unsafe extern "C" fn(*mut MacHarqProc) {
        unsafe { core::mem::transmute((FN_CLEAR_MAC_UL_BUFFER | 1) as usize) }
    }

    #[inline]
    pub fn dma_clean_range_arm() -> unsafe extern "C" fn(*const u8, *const u8) {
        // ARM mode: bit 0 MUST remain 0.
        unsafe { core::mem::transmute(FN_DMA_CLEAN_RANGE_ARM as usize) }
    }
}
