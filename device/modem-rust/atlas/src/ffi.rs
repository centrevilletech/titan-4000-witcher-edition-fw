//! `extern "C"` signatures and verified behavioural contracts for stock `tk.bin`
//! functions that a Rust modem patch may call (resolved at link time with
//! `PROVIDE(sym = va | 1);`) or replace via hook trampolines.
//!
//! Calling convention: ARMv7 AAPCS (`r0..r3` args, `r0` return, `r4..r11` callee-saved).
//! All L2/MAC/GIPC functions below are **Thumb-2** (`va | 1` for indirect `blx`),
//! **except** the three CP15 cache maintenance primitives (`dma_*_range`), which are
//! **ARM mode** (even address, bit 0 MUST be `0`).

use crate::gipc::GipcIrb;
use crate::l2::{Rbc, RbcRing, RlcAmTxEntry, UlCipherBatch};
use crate::mac::{MacHarqProc, MacUlLcpTbl, MacUlSchedInfo};

// Linker-resolved external symbols (`PROVIDE(sym = 0x84xxxxxx | 1);` for Thumb).
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
    pub fn l2_sched_event(
        callback: extern "C" fn(*mut core::ffi::c_void),
        arg: *mut core::ffi::c_void,
        prio: u32,
    );
    /// `0x842d_9e5c` (Thumb): Start stopped L2 software timer slot `tmr_id` (`0..63`) under `cpsid i`.
    /// Traps (`udf #255`) if `tmr_id > 63` or `entry.state != 1`.
    pub fn l2_timer_start(tmr_id: u32);
    /// `0x842d_9ef4` (Thumb): Stop L2 software timer slot `tmr_id` (`0..63`) under `cpsid i`.
    /// Removes from active list if `state == 2`, leaves `state = 1`.
    pub fn l2_timer_stop(tmr_id: u32);
    /// `0x842d_a0a4` (Thumb): Restart L2 timer `tmr_id` (`0..63`): stops first if running (`state == 2`), then starts.
    pub fn l2_timer_restart(tmr_id: u32);
    /// `0x842d_a0ec` (Thumb): Return `1` if L2 timer `tmr_id` is running (`state == 2`), else `0`.
    pub fn l2_timer_is_running(tmr_id: u32) -> u32;
    /// `0x842d_9fa8` (Thumb): Poll expired L2 timers (`is_hp`: 1=slots 0..23, 0=slots 24..63).
    pub fn l2_proc_timer(l2_ctx: *mut core::ffi::c_void, is_hp: u32);
    /// `0x842e_1fb0` (Thumb): Create an RLC one-shot timer; subtracts `*(u32*)0x8410_ea00` (`2 ms`)
    /// when `duration_ms > offset`, and writes allocated slot ID into `*out_tmr_id`.
    pub fn rlc_timer_create(
        out_tmr_id: *mut u16,
        callback: u32,
        arg: *mut core::ffi::c_void,
        duration_ms: u32,
    );
    /// `0x842e_1fe0` (Thumb): Modify (or delete if `duration_ms == 0`) an RLC timer slot;
    /// subtracts `*(u32*)0x8410_ea00` (`2 ms`) when `duration_ms > offset`.
    pub fn rlc_timer_modify(
        tmr_id_ptr: *mut u16,
        callback: u32,
        arg: *mut core::ffi::c_void,
        duration_ms: u32,
    );

    // -----------------------------------------------------------------------
    // PDCP UL & LLCE0 hardware ciphering (Thumb-2, runs in `wk-dp` P(63))
    // -----------------------------------------------------------------------

    /// `0x842d_9a48` (Thumb): Finalize and submit a populated [`UlCipherBatch`] to `LLCE0` (`0x1212_0000`).
    ///
    /// Contract:
    /// - Terminates the last `LlceDesc::next_desc_be` with `rev(0x84a0_cec0)` and calls `dma_flush_range`.
    /// - Under `cpsid i`: if `L2_CIPHER_BUSY != NULL`, stores `batch` in `L2_CIPHER_PEND`;
    ///   else sets `L2_CIPHER_BUSY = batch`, writes `batch.desc_ring` to `0x1212_0004`, `dsb sy`,
    ///   and kicks `*(u32*)0x1212_0000 |= 0x41`.
    pub fn ul_cipher_submit(l2_ctx: *mut core::ffi::c_void, batch: *mut UlCipherBatch);

    /// `0x842d_c968` (Thumb): Pop up to `count` IRBs from `ring` into an `LLCE0` UL cipher batch.
    ///
    /// Contract:
    /// - Runs in `wk-dp`; wraps `pdcp_to_rlc_ring`, `LlceDesc`, `pdcp_tx_count`, and `PdcpUlSduEntry`
    ///   updates in `cpsid i`.
    /// - Writes 2-byte 12-bit PDCP DRB header (or 1-byte 7-bit if `rbc.pdcp_sn_mode == 1`),
    ///   cleans source buffer via `dma_clean_range`, allocates cipher destination via `0x842d_9914`,
    ///   records `enqueue_tti_and_flags = TTI_CLK_VA & !1`, and flushes batch at 64 descriptors.
    /// - Stops early and returns current `batch` (possibly NULL) if both static `UlCipherBatch`
    ///   slots (`L2_UL_CIPHER_BMAP_VA == 3`) are busy.
    pub fn proc_pdcp_ul(
        batch: *mut UlCipherBatch,
        rbc: *mut Rbc,
        ring: *mut RbcRing,
        count: u32,
    ) -> *mut UlCipherBatch;

    /// `0x842d_cbf4` (Thumb): Per-pass PDCP UL feeder called via `L2_PDCP_UL_FN_VA` in `l2_task`.
    ///
    /// Contract:
    /// - Iterates set bits of `L2_UL_ACTIVE_BEARER_MASK_VA` (`l2_ctx + 0x930`).
    /// - Computes `free_slots = (pdcp_to_rlc_rd - (pdcp_to_rlc_wr + 1)) & (size - 1)` and
    ///   `cur_bo = pdcp_rlc_hdr_bo + pdcp_rlc_tx_bo`.
    /// - Always drains `ring0` first (capped by `free_slots`; stock estimates `ring0_cnt * 64` B,
    ///   replaced by N5 Hook C at `0x842d_cd24`).
    /// - Reads `limit = *(u32*)L2_PDCP_UL_LIMIT_VA` at `0x842d_cca2` (hooked by N4 Hook 3 / N5 Hook B).
    /// - If `limit > cur_bo + ring0_est_bytes`, submits
    ///   `min((limit - cur_bo) / *(u32*)L2_PDCP_UL_DIVISOR_VA, min(ring1_occ, rem_free_slots))`
    ///   packets from `ring1` (divisor = `1500` B at boot).
    /// - Kicks any remaining partial `UlCipherBatch` via `ul_cipher_submit` on exit.
    pub fn l2_proc_pdcp_ul(l2_ctx: *mut core::ffi::c_void);

    /// `0x842d_c8ec` (Thumb): Enqueue confirmed/discarded PDCP SN range `[start_sn..=end_sn]`
    /// into `rbc.pdcp_cnf_ring` (coalescing contiguous ranges) and set `rbc.bearer_idx` bit
    /// in `L2_PDCP_CNF_MASK_VA` under `cpsid i`.
    pub fn pdcp_cnf_enqueue(rbc: *mut Rbc, start_sn: u32, end_sn: u32);

    /// `0x842d_cd90` (Thumb): Deferred RLC UL discard handler scheduled by `pdcp_proc_tmr_discard`.
    ///
    /// Contract:
    /// - Under `cpsid i`, scans un-transmitted entries `[pdcp_to_rlc_rd..pdcp_to_rlc_committed)`
    ///   whose SN falls in `[L2_DISCARD_FIRST_SN_VA..=L2_DISCARD_LAST_SN_VA]`.
    /// - Decrements `pdcp_to_rlc_cnt`, `pdcp_rlc_tx_bo`, `pdcp_rlc_hdr_bo` (`2 B/pkt`), invokes
    ///   `rbc.rlc_ul_bo_notify_fn`, and enqueues discarded SNs via `pdcp_cnf_enqueue`.
    pub fn rlc_ul_proc_discard_req(rbc: *mut Rbc);

    /// `0x842d_cf60` (Thumb): Release ACKed/discarded PDCP UL SDUs `[start_sn..=end_sn]`,
    /// freeing `cipher_buf` (`0x842d_993c`), returning `GipcIrb` via `gipc_rel_rx_irb`,
    /// decrementing `pdcp_ul_win.active_count`, and advancing `rbc.pdcp_ul_oldest_sn`.
    pub fn pdcp_ul_proc_drb_cnf(rbc: *mut Rbc, start_sn: u32, end_sn: u32);

    /// `0x842d_d074` (Thumb): Periodic PDCP `discardTimer` scanner (`rbc.pdcp_discard_timer_ms`).
    ///
    /// Contract:
    /// - Walks `pdcp_ul_win` from `pdcp_ul_oldest_sn` while `(i32)(entry.enqueue_tti_and_flags - (now - discard_ms)) < 0`.
    /// - Marks un-discarded live entries with bit 0 (`|= 1`), writes `[first_sn, last_sn]` to
    ///   `L2_DISCARD_FIRST_SN_VA`/`LAST_SN_VA`, schedules `rlc_ul_proc_discard_req` (prio 2),
    ///   and restarts `rbc.t_discard_tmr_id`.
    pub fn pdcp_proc_tmr_discard(rbc: *mut Rbc);

    /// `0x842e_5adc` (Thumb): 250 ms UL rate monitor setting stock `L2_PDCP_UL_LIMIT_VA` (`0x84dd_977c`).
    ///
    /// Contract:
    /// - Consumes and zeroes `L2_UL_250MS_BYTES_VA`, computes `tier = (bytes >> 15) & 0xfff`:
    ///   `<= 8` -> `32_768 B`, `9..=32` -> `65_536 B`, `> 32` -> `131_072 B`.
    /// - Chains into `do_ic` (`0x8452_c8cc`) and `do_bo` (`0x8452_c95c`).
    pub fn do_tc(l2_ctx: *mut core::ffi::c_void);

    /// `0x842e_5b40` (Thumb): Return current global `DP_BO_MARGIN_VA` (`0x84f9_3008`) in bytes.
    pub fn get_hp_bo_margin() -> u32;

    /// `0x8452_c95c` (Thumb): 250 ms Ring-0 activity check updating `rbc.bo_margin_bytes` (`+0x244`)
    /// from `DP_BO_MARGIN_VA` whenever `rbc.ring0_last_tx_cnt > rbc.bo_hold_last_cnt`.
    pub fn do_bo();

    /// `0x8452_c9e8` (Thumb): Store `margin_bytes` into `DP_BO_MARGIN_VA` (`0x84f9_3008`).
    pub fn tc_set_hp_bo_margin(margin_bytes: u32);

    // -----------------------------------------------------------------------
    // RLC AM UL & BSR reporting (Thumb-2, runs in `l2_hp_task` HP context)
    // -----------------------------------------------------------------------

    /// `0x842d_d134` (Thumb): Compute per-bearer `(actual_bo, hdr_bo)` for RLC AM/UM/TM.
    ///
    /// Contract for AM (`rbc.rlc_mode == 3`):
    /// - `*out_actual_bo = rlc_am_newtx_bo (+0x154) + rlc_am_retx_bo (+0x158) + rlc_status_bo (+0x144)`
    /// - `*out_hdr_bo = pdcp_rlc_hdr_bo (+0x10a) + rlc_reest_hdr_bo (+0x126) + retx_hdr_bo (+0x1d6) + am_extra_hdr_bo (+0x1f2)`
    /// - Does NOT include `rbc.ring_pending_bytes` (`+0x130`).
    pub fn get_rlc_cur_bo(rbc: *const Rbc, out_actual_bo: *mut u32, out_hdr_bo: *mut u32);

    /// `0x842d_d194` (Thumb): Aggregate per-LCG BO into `lcg_bo[4]` for `GetMacUlBsrValue`.
    ///
    /// Contract:
    /// - Seeds `lcg_bo[0..3]` from `L2_BSR_PRE_BO_VA` (`0x84dd_9d18`).
    /// - For each set bit in `MacUlCfg::active_lc_mask`, if `rbc.active == 1`, calls `get_rlc_cur_bo`
    ///   and adds `actual_bo + (L2_TIMER_OFFSET_VA != 0 ? bo_margin_bytes + hdr_bo : 0)` to `lcg_bo[rbc.lcg_id]`.
    /// - N4 Hook 2 (`0x842d_d21c`) replaces the `bo_margin_bytes` load to add `ring_pending_bytes`.
    pub fn rlc_upd_cur_bo(lcg_bo: *mut [u32; 4]);

    /// `0x842d_d238` (Thumb): Refresh one LC's MAC BO via `rbc_by_lcid` -> `get_rlc_cur_bo` -> `update_mac_ul_bo`.
    pub fn upd_lcid_bo_to_mac(lcid: u32);

    /// `0x842d_d360` (Thumb): Query RLC AM/UM/TM whether `alloc_bytes` fits into `out_info` (`[u32; 3]`).
    pub fn rlc_check_size(lcid: u32, alloc_bytes: u32, out_info: *mut [u32; 3]) -> u32;

    /// `0x842d_a60c` (Thumb): Populate `L2_BSR_PRE_BO_VA[0..3]` from active DRBs' `ring_pending_bytes`.
    pub fn mac_bsr_pre_work(active_lc_mask: u32);

    /// `0x842d_d404` (Thumb): RLC SDU/segment fit classifier (`0` = segment, `1` = fits exact/final, `2` = fits with room for LI+more).
    ///
    /// Exact formula: `if rem == 0 || rem < sdu_len { 0 } else if rem > sdu_len + li_bytes { 2 } else { 1 }`.
    pub fn rlc_can_fit(rem_budget: u32, sdu_len: u32, li_bytes: u32) -> u32;

    /// `0x842d_d794` (Thumb): Enqueue an `RlcAmTxEntry` into `rbc.ul_am_retx_ring` (`+0x1cc`).
    ///
    /// Contract:
    /// - Traps (`udf #255`) if `((retx_wr + 1) & 0x1ff) == retx_rd` (ring full).
    /// - If `tx_entry.was_nacked == 1`, increments `tx_entry.retx_count`; else sets `retx_count = 0`.
    /// - Returns `1` (maxRetxThreshold RLF) immediately if `retx_count >= rbc.max_retx_threshold`.
    /// - Otherwise clears `P` bit (`0x20`) in `tx_entry.pdu_desc[0]` header byte 0, sets
    ///   `tx_entry.in_retx_queue = 1`, pops an `RlcAmRetxNode`, initializes the `RlcAmRetxEntry`,
    ///   adds `total_len - hdr_len` to `rbc.retx_bytes` and `hdr_len` to `rbc.retx_hdr_bo`,
    ///   advances `retx_wr`/`retx_cnt`, and returns `0`.
    pub fn process_pdu_retx(rbc: *mut Rbc, tx_entry: *mut RlcAmTxEntry, flags: u32) -> u32;

    /// `0x842d_d89c` (Thumb): Check 3GPP TS 36.322 §5.2.2.1 poll-on-empty / poll-on-window-stall.
    ///
    /// Sets `rbc.poll_trigger = 1` if `((vt_s.wrapping_sub(511).wrapping_sub(vt_a)) & 0x3ff) < 512`
    /// (window stalled) OR (`pdcp_rlc_tx_bo == 0 && retx_bytes == 0`).
    pub fn rlc_poll_check(rbc: *mut Rbc);

    /// `0x842d_dbc0` (Thumb): Sync `rbc.rlc_am_retx_bo = rbc.retx_bytes` and call `update_mac_ul_bo`
    /// if changed, immediately arming MAC Regular BSR/SR for retransmissions.
    pub fn upd_retx_bo(rbc: *mut Rbc);

    /// `0x842d_eaec` (Thumb): Sync `rbc.rlc_am_newtx_bo = pdcp_rlc_tx_bo + rlc_reest_tx_bo`
    /// (or `0` if `rbc.active != 1`) and call `update_mac_ul_bo` if changed. Stored in `rbc.rlc_ul_bo_notify_fn`.
    pub fn rlc_am_ul_bo_notify(rbc: *mut Rbc);

    /// `0x842d_eb44` (Thumb): Process an incoming peer RLC AM STATUS PDU (`rbc.status_pdu_ptr`/`len`).
    ///
    /// Contract:
    /// - Validates `active == 1`, `vt_a != vt_s`, `CPT == 0`, `len > 1`, and `vt_a < ACK_SN <= vt_s`.
    /// - Positively ACKed TX entries free cipher buffers and notify PDCP via `pdcp_cnf_enqueue`.
    /// - NACKed SNs (and `SOstart`/`SOend` byte ranges) enqueue into `ul_am_retx_ring`.
    /// - Stops `t-PollRetransmit` (`l2_timer_stop`) and clears `poll_trigger` if `((poll_sn - ack_sn) & 0x3ff) >= 512`.
    /// - Advances `vt_a`, `ul_am_free_win_slots`, `ul_am_tx_head`; calls `upd_retx_bo` if `retx_bytes != 0`.
    pub fn rlc_ul_am_proc_status_rpt(rbc: *mut Rbc);

    /// `0x842d_f4f4` (Thumb): Build UL RLC AM PDU(s) for a MAC grant allocation.
    ///
    /// Contract (verified from `0x842d_f4f4..0x842e_08d8`):
    /// - `alloc_packed`: `(hq_id << 16) | cc_idx` (low16 = CC `0..3`, high16 = HARQ PID `0..7`).
    /// - `grant_bytes`: Remaining MAC TB bytes assigned to this LC by LCP.
    /// - `out_pdu_sizes`: Output array receiving the byte length of each generated RLC PDU.
    /// - Priority order: (1) UL STATUS PDU (`rlc_status_bo != 0`, starts `t-StatusProhibit`),
    ///   (2) RETX queue (`retx_cnt != 0`, full PDU if `total_len + 1 <= grant_bytes`, else re-segments
    ///   if `grant_bytes > 5`), (3) New-TX AMD PDU (`rlc_am_newtx_bo != 0`, `grant_bytes > 3`,
    ///   checks `ul_am_free_win_slots != 0`, concatenates SDUs with 1.5 B LI overhead, applies
    ///   `rlc_poll_check` + `pollPDU` + `pollByte` poll rules, updates `vt_s` and `rlc_am_newtx_bo`).
    /// - Restarts `t-PollRetransmit` on exit if `start_poll_retx_tmr != 0`.
    /// - Returns total count of RLC PDUs emitted (`ul_ctrl_pdu_cnt + ul_data_pdu_cnt`).
    pub fn rlc_ul_am_gen_pdu(
        rbc: *mut Rbc,
        alloc_packed: u32,
        grant_bytes: u32,
        out_pdu_sizes: *mut u32,
    ) -> u8;

    /// `0x8452_b398` (Thumb): `t-PollRetransmit` expiry callback (`arg = rbc`).
    ///
    /// Contract:
    /// - Only acts if `rbc.active == 1` AND **both** `rlc_am_newtx_bo == 0` AND `rlc_am_retx_bo == 0`.
    /// - If `vt_a != vt_s`, enqueues `ul_am_tx_head` (`VT(A)`) via `process_pdu_retx(rbc, head, 1)`,
    ///   calls `upd_retx_bo(rbc)`, and sets `rbc.poll_trigger = 1`.
    pub fn rlc_am_poll_retx_expire(rbc: *mut Rbc);

    // -----------------------------------------------------------------------
    // MAC UL: BSR, SR, LCP, TB build, HARQ (Thumb-2)
    // -----------------------------------------------------------------------

    /// `0x842c_cf64` (Thumb): Map `bo_bytes` to 3GPP 6-bit BSR index (`0..=63`).
    pub fn search_mac_ul_bo_idx(bo_bytes: u32) -> u8;
    /// `0x842c_cff8` (Thumb): Reset `MacUlBsrCtx` (`0x84d6_2940`) to idle defaults.
    pub fn init_mac_ul_bsr_info();
    /// `0x842c_d080` (Thumb): Restart `periodicBSR-Timer`.
    pub fn restart_bsr_timer();
    /// `0x842c_d0e8` (Thumb): Stop `periodicBSR-Timer`.
    pub fn stop_bsr_timer();
    /// `0x842c_d104` (Thumb): `periodicBSR-Timer` expiry callback (sets `bsr_pending=1, mask=0x01`).
    pub fn expire_bsr_timer();
    /// `0x842c_d168` (Thumb): Restart `retxBSR-Timer`.
    pub fn restart_retx_bsr_timer();
    /// `0x842c_d1d0` (Thumb): Stop `retxBSR-Timer`.
    pub fn stop_retx_bsr_timer();
    /// `0x842c_d1ec` (Thumb): `retxBSR-Timer` expiry callback (sets `bsr_pending=1, mask=0x14` if data).
    pub fn expire_retx_bsr_timer();
    /// `0x842c_d254` (Thumb): Clear `bsr_pending`, `sr_triggered_flag`, and `bsr_trigger_mask`.
    pub fn reset_mac_ul_bsr_event();
    /// `0x842c_d298` (Thumb): Update MAC UL BO for `lcid`, triggering Regular BSR (`0x12`) if higher prio.
    pub fn update_mac_ul_bo(lcid: u32, new_bo: u32, hdr_bo: u32);
    /// `0x842c_d46c` (Thumb): Select BSR format LCID (`28` Truncated, `29` Short, `30` Long, `255` None).
    pub fn get_mac_ul_bsr_format(
        bsr_kind: u32,
        tb_size: u32,
        used_bytes: u32,
        deferred_bsr_flag: u32,
    ) -> u8;
    /// `0x842c_d54c` (Thumb): Populate BSR MAC CE payload into `out_bsr_ce` for `bsr_lcid` (28/29/30).
    pub fn get_mac_ul_bsr_value(bsr_lcid: u32, out_bsr_ce: *mut u32, packed_lc_mask: u32);
    /// `0x842c_fad8` (Thumb): Increment every active LC's PBR token bucket `Bj` once per TTI.
    pub fn update_bj(tti_delta: u32);
    /// `0x842c_fb34` (Thumb): MAC LCP Step 2 (remaining TB bytes distributed by priority/equal share).
    pub fn second_step_pbr(rem_bytes: *mut u32, lc_alloc: *mut [u32; 11], lcp_tbl: *mut MacUlLcpTbl);
    /// `0x842c_fd40` (Thumb): MAC LCP Step 1 (allocate up to each LC's PBR token bucket `Bj`, then Step 2).
    pub fn assign_schedule_size_2lc(
        rem_bytes: *mut u32,
        lc_alloc: *mut [u32; 11],
        lcp_tbl: *mut MacUlLcpTbl,
    );
    /// `0x842c_fe34` (Thumb): Simulate TB packing to check if Long BSR (`30`) can downgrade to Short (`29`).
    pub fn check_long_bsr_downgrade_to_short(tb_rem_plus_2: u32) -> u32;
    /// `0x842d_3abc` (Thumb): Trigger PUCCH Scheduling Request or fallback to contention RACH.
    pub fn access_ra();
    /// `0x842d_4a78` (Thumb): Cancel pending SR when `cancel_flag != 0` (NewTx grant).
    pub fn handle_ra_ulgrant(cc: u32, hq_id: u32, cancel_flag: u32);
    /// `0x842d_4ca4` (Thumb): Poll MAC SR state machine on a PUCCH SR occasion (returns 1 to TX SR).
    pub fn get_mac_ul_sr() -> u32;
    /// `0x842d_5258` (Thumb): Reconstruct L1D UL grant & PHICH scheduling fields for one CC.
    pub fn reconstruct_sched_info(sched: *mut MacUlSchedInfo, body_idx: u32);
    /// `0x842d_54fc` (Thumb): Free HARQ TB buffer and reset `MacHarqProc` fields.
    pub fn clear_mac_ul_buffer(proc_ptr: *mut MacHarqProc);
    /// `0x842d_556c` (Thumb): Handle PHICH ACK without DCI-0 (suspends HARQ process).
    pub fn harq_proc_ack(cc: u32, hq_id: u32, proc_ptr: *mut MacHarqProc);
    /// `0x842d_576c` (Thumb): Return TTI-bundling UL index for TDD cfg 0/1/6 (`0xff` for cfg 2).
    pub fn get_tdd_bundle_ul_idx(tdd_cfg: u32, pusch_tti: u32) -> u32;
    /// `0x842d_6d04` (Thumb): Resolve TTI-bundling PHICH HARQ ID for TDD cfg 0/1/6 (`0xff` for cfg 2).
    pub fn get_tdd_bundle_phich_hq(tdd_cfg: u32, phich_tti: u32) -> u32;
    /// `0x842d_89ac` (Thumb): Per-TTI MAC UL top-level scheduler (PCell then SCell, then LLCE0 harvest).
    pub fn schedule_ul_data(sched_msg: *mut MacUlSchedInfo);
    /// `0x842d_95c4` (Thumb): Tick SCell deactivation timers once per TTI.
    pub fn check_scell_deact_timer();

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
