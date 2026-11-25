//! Runtime control and telemetry blocks of the active modem patch stack:
//! IMG2, IMG3, IMG4, N4, N5, N6H, C1 (`TK-2`), and UL-B (`ULB-BSR`).
//!
//! Verified directly against `n4_ul_engine.s`, `n5.s`, `n6.s`, `c1.s`, `ulb_bsr.s`,
//! and `IMG4-SWITCHES.md`.

use crate::gipc::GipcIrb;
use crate::l2::Rbc;
use crate::Ptr32;

/// N4 UL engine runtime state at `0x847e_d600` (`N4_STATE_VA`).
#[repr(C)]
pub struct N4State {
    /// `+0x00`: Magic `"N4V2"` (`0x4e34_5632`).
    pub magic: u32,
    /// `+0x04`: Feature bitmask (`0x01` TrueBO+PDCP, `0x02` PI lead [OFF], `0x04` AQM,
    /// `0x08` old sparse [OFF], `0x10` short-BSR LCG rescue, `0x20` IMG4 v3 TLS/QUIC spare).
    pub flags: u32,
    /// `+0x08`: PDCP staging min (default `16384`).
    pub pdcp_min: u32,
    /// `+0x0c`: PDCP staging max (default `24576`).
    pub pdcp_max: u32,
    /// `+0x10`: PI lead cap (default `0`, keep `0`).
    pub lead_cap: u32,
    /// `+0x14`: Idle timeout ms (default `22`).
    pub idle_ms: u32,
    /// `+0x18`: AQM paced drop interval ms (default `35`).
    pub aqm_ivl_ms: u32,
    /// `+0x1c`: Legacy sparse length gate (default `127`, disabled).
    pub sparse_len: u32,
    /// `+0x20`: Last TB build TTI (`TTI_CLK_VA`).
    pub last_tb_tti: u32,
    /// `+0x24`: Current TTI cumulative granted TB bytes (PCell + SCell).
    pub g_tti: u32,
    /// `+0x28`: Current TTI cumulative MAC padding bytes (`tbSize - used`).
    pub pad_tti: u32,
    /// `+0x2c`: EWMA of granted UL TB bytes per active UL TTI (`(3*G + prev) >> 2`).
    pub g_ema: u32,
    /// `+0x30`: PI integrator state (unused when bit 1 off).
    pub l_int: u32,
    /// `+0x34`: Last PI lead added.
    pub last_lead: u32,
    /// `+0x38`: Last BSR update TTI.
    pub last_bsr_tti: u32,
    /// `+0x3c`: Last UL packet arrival TTI (`l2_task`).
    pub last_arr_tti: u32,
    /// `+0x40`: Current 5 ms arrival window start TTI.
    pub arr_win_tti: u32,
    /// `+0x44`: Current 5 ms arrival window accumulated bytes.
    pub arr_win_b: u32,
    /// `+0x48`: EWMA of UL arrival bytes per 5 ms window.
    pub a_ema: u32,
    /// `+0x4c`: Last AQM paced drop TTI.
    pub last_aqm_tti: u32,
    /// `+0x50`: Pointer to last active DRB [`Rbc`].
    pub last_drb_rbc: Ptr32<Rbc>,
    /// `+0x54`: Last `Q_true` snapshot.
    pub last_q_true: u32,
    /// `+0x58`: Total UL TBs built (`hook_mac_tb`).
    pub cnt_tb: u32,
    /// `+0x5c`: BSR hook invocations with bit0/bit1 active.
    pub cnt_bsr: u32,
    /// `+0x60`: Refill-eligible TTI count.
    pub cnt_refill: u32,
    /// `+0x64`: Total ECN CE marks applied.
    pub cnt_aqm_mark: u32,
    /// `+0x68`: Total AQM packet drops (paced + hard).
    pub cnt_aqm_drop: u32,
    /// `+0x6c`: Legacy N3 sparse promotion counter.
    pub cnt_sparse: u32,
    /// `+0x70`: Short-BSR LCG rescues applied (`hook_short_bsr`).
    pub cnt_sh_fix: u32,
    /// `+0x74`: Smallest packet length AQM may drop/mark (default `600`).
    pub aqm_minlen: u32,
    /// `+0x78`: `Q_target` floor in bytes (default `20480`).
    pub aqm_qmin: u32,
    /// `+0x7c`: Small packets (`< aqm_minlen`) spared above `Q_target`.
    pub cnt_spared: u32,
}

/// N4 extended always-on counters at `0x847e_d780` (`N4_EXT_CNT_VA`).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct N4ExtCounters {
    /// `+0x00`: Total BSR builds across all bearers.
    pub cnt_bsr_all: u32,
    /// `+0x04`: BSR builds with non-zero `bo_margin`.
    pub cnt_bsr_marg: u32,
    /// `+0x08`: Pure hold BSR builds (`bo_margin > 0` and real BO == 0).
    pub cnt_bsr_hold: u32,
    /// `+0x0c`: Last non-zero `rbc.bo_margin_bytes` observed.
    pub last_margin: u32,
    /// `+0x10`: AQM drops above `2 * Q_target` (hard region).
    pub cnt_drop_hard: u32,
    /// `+0x14`: AQM CE marks above `2 * Q_target`.
    pub cnt_ce_hard: u32,
    /// `+0x18`: Short BSRs where selected LCG read 0 while another LCG had bytes.
    pub cnt_sh_zero: u32,
}

/// One bucket in N5's 64-entry per-flow sparse/bulk hash table (`16` bytes).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct N5FlowEntry {
    /// `+0x00`: Flow tag (`0` = empty, `1..=65535` = active).
    pub tag: u16,
    /// `+0x02`: Leaky-bucket byte level (`0..=65535`).
    pub level: u16,
    /// `+0x04`: `TTI_CLK_VA` of last bucket update.
    pub last_tti: u32,
    /// `+0x08`: `0` = sparse; nonzero = TTI until bulk hold expires.
    pub bulk_until: u32,
    /// `+0x0c`: `0` = drained; nonzero = `r1_deq_seq` target before sparse recovery.
    pub r1_drain: u32,
}

/// N5 per-flow sparse lane & PDCP staging control block at `0x8448_9a64` (`N5_STATE_VA`).
#[repr(C)]
pub struct N5State {
    /// `+0x00`: Magic `"N5FL"` (`0x4e35_464c`).
    pub magic: u32,
    /// `+0x04`: Build version (`0x2026_1123`).
    pub version: u32,
    /// `+0x08`: Flags (`bit 0` flow lane + exact R0 feeder, `bit 1` PDCP limit, `bit 2` disable R0 fix).
    pub flags: u32,
    /// `+0x0c`: Sparse leaky-bucket drain rate in B/ms (default `40` = 40 kB/s).
    pub rate_bpms: u32,
    /// `+0x10`: Sparse burst allowance in bytes (default `3072`).
    pub burst_b: u32,
    /// `+0x14`: Bulk hold duration in ms after Ring 1 drain (default `500`).
    pub hold_ms: u32,
    /// `+0x18`: Global Ring 0 budget percentage of `20 * G_ema` per 100 ms (default `10`).
    pub budget_pct: u32,
    /// `+0x1c`: Fixed 100 ms Ring 0 byte budget (`0` = adaptive).
    pub budget_fixed: u32,
    /// `+0x20`: PDCP staging limit floor in bytes (bench `0x2000`, stock N5 `0x4000`).
    pub pdcp_min: u32,
    /// `+0x24`: PDCP staging limit ceiling in bytes (bench `0x3000`, stock N5 `0x6000`).
    pub pdcp_max: u32,
    /// `+0x28`: Adaptive Q4 multiplier (`0` = `G_ema + 4096`, else `(k * G_ema) >> 4`).
    pub pdcp_k_q4: u32,
    /// `+0x2c`: Ring 0 occupancy guard (`0` = 128 packets).
    pub r0_max_pkts: u32,
    /// `+0x30`: Current 100 ms budget window start TTI.
    pub bud_win_tti: u32,
    /// `+0x34`: Promoted bytes used in current 100 ms window.
    pub bud_used: u32,
    /// `+0x38`: Last computed 100 ms budget cap.
    pub last_bud_cap: u32,
    /// `+0x3c`: Last PDCP staging limit returned by `n5_pdcp_limit`.
    pub last_pdcp_lim: u32,
    /// `+0x40..+0x6f`: Telemetry counters.
    pub c_promo_pkts: u32,
    pub c_promo_bytes: u32,
    pub c_refused_bud: u32,
    pub c_marked_bulk: u32,
    pub c_evictions: u32,
    pub c_held_bulk: u32,
    pub c_stock_r0: u32,
    pub c_bad_hdr: u32,
    pub c_r0_submit: u32,
    pub c_r0_fix_b: u32,
    pub c_seen: u32,
    pub c_r1_nonempty_hold: u32,
    pub _pad0: [u32; 4],
    /// `+0x80`: Last observed `ring1->rd` per bearer index `0..7`.
    pub last_r1_rd: [u16; 8],
    /// `+0x90`: Monotonic Ring 1 dequeue sequence per bearer index `0..7`.
    pub r1_deq_seq: [u32; 8],
    /// `+0xb0..+0x4af`: 64-bucket per-flow hash table (`1024` bytes).
    pub flow_tbl: [N5FlowEntry; 64],
}

/// N6 / N6H U2 HARQ LNK-FIX control block at `0x8418_ff00` (`N6_U2_STATE_VA`, 64 bytes).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct N6U2State {
    /// `+0x00`: Magic `"U2HF"` (`0x5532_4846`).
    pub magic: u32,
    /// `+0x04`: Defaults stamp (`0x4e36_0000` N6, `0x4e36_4803` N6H).
    pub defaults_id: u32,
    /// `+0x08`: Flags (`0` off, `1`/`3` active filter+count, `2` shadow count).
    pub flags: u32,
    /// `+0x0c`: Filtered post-ACK aged buffer flushes (`HARQ_FEEDBACK == 1`).
    pub c_ack_expire: u32,
    /// `+0x10..+0x1f`: True UL HARQ max-retx give-ups per carrier `CC0..CC3`.
    pub c_true_cc: [u32; 4],
    /// `+0x20`: Last true give-up metadata `(cc<<24)|(hq<<16)|(tx_nb<<8)|max_tx`.
    pub last_true_meta: u32,
    /// `+0x24`: Malformed/unexpected HARQ state guard counter.
    pub c_bad_state: u32,
    pub _reserved: [u32; 5],
    /// `+0x3c`: Build date (`0x2026_1123`).
    pub build_ver: u32,
}

/// Lane C1 `TK-2` batched UL RLC-ACK IRB release block at `0x843f_a1c0` (`C1_TK2_STATE_VA`, 256 B).
#[repr(C)]
pub struct C1Tk2State {
    /// `+0x00`: Magic `"TK2B"` (`0x544b_3242`).
    pub magic: u32,
    /// `+0x04`: Version (`0x2026_1124`).
    pub version: u32,
    /// `+0x08`: Flags (`0` stock passthrough, `1` batch ch-1 UL IRB release).
    pub flags: u32,
    /// `+0x0c`: Buffered IRB count (`0..=48`, always `0` outside `pdcp_ul_proc_drb_cnf`).
    pub pending: u32,
    /// `+0x10..+0x27`: Counters.
    pub c_batch: u32,
    pub c_irbs: u32,
    pub c_sgi: u32,
    pub c_fb: u32,
    pub c_max: u32,
    pub c_spill: u32,
    pub _reserved: [u32; 6],
    /// `+0x40..+0xff`: 48-slot IRB pointer batch buffer (`192` bytes).
    pub buf: [Ptr32<GipcIrb>; 48],
}

/// Lane UL-B sustained-upload BSR floor block at `0x8449_db00` (`ULB_BSR_STATE_VA`, 256 B).
#[repr(C)]
pub struct UlbBsrState {
    /// `+0x00`: Magic `"ULB1"` (`0x554c_4231`).
    pub magic: u32,
    /// `+0x04`: Version (`0x2026_1125`).
    pub version: u32,
    /// `+0x08`: Flags (`0` off, `bit 0` boost, `bit 1` rate-prop, `bit 2` 2CC release, `bit 3` observe).
    pub flags: u32,
    /// `+0x0c`: Min `A_ema` in B/5ms to arm (default `2000` = 3.2 Mbps).
    pub a_thresh: u32,
    /// `+0x10`: Min `Q_true` bytes if `Ring 1 == 0` to arm (default `4096`).
    pub q_arm: u32,
    /// `+0x14`: Continuous bulk duration ms before boost engages (default `100`).
    pub sustain_ms: u32,
    /// `+0x18`: Hard idle cutoff ms since `ST_LAST_ARR_TTI` (default `15`).
    pub idle_ms: u32,
    /// `+0x1c`: Suppress boost if `ST_PAD_TTI` exceeds this (default `512`).
    pub pad_cut: u32,
    /// `+0x20`: Fixed/min BSR floor in bytes (default `98304` = 96 KB, Std idx 60).
    pub floor_min: u32,
    /// `+0x24`: Max rate-proportional BSR floor (default `150000`, Std idx 62).
    pub floor_max: u32,
    /// `+0x28`: Multiplier for rate-proportional mode (`20` = 100 ms of `A_ema`).
    pub k_tti: u32,
    /// `+0x2c`: `G_ema` threshold for 2CC release (default `8500` B/5ms).
    pub g_2cc_b: u32,
    /// `+0x30`: Maintenance floor once 2CC release triggers (default `0`).
    pub maint_b: u32,
    /// `+0x34..+0x3f`: Live runtime state.
    pub bulk_start: u32,
    pub last_add: u32,
    pub last_tgt: u32,
    /// `+0x40..+0x5b`: Telemetry counters.
    pub c_calls: u32,
    pub c_armed: u32,
    pub c_boosted: u32,
    pub c_idle_cut: u32,
    pub c_pad_supp: u32,
    pub c_2cc_rel: u32,
    pub c_empty_supp: u32,
    pub _reserved: [u32; 41],
}
