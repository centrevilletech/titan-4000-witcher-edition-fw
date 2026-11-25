//! Verified modem virtual addresses for `tk.bin` V1.6.0.P0 (load VA `0x8410_0000`).
//!
//! File offset for any image-resident VA is `va - TK_LOAD_VA`.

/// Base load VA of `tk.bin` in CPU1 SDRAM (9,553,965 bytes, `.bss` starts at `0x84a1_c840`).
pub const TK_LOAD_VA: u32 = 0x8410_0000;
pub const TK_END_VA: u32 = 0x84a1_c82d;
pub const TK_BSS_START_VA: u32 = 0x84a1_c840;
pub const TK_BSS_END_VA: u32 = 0x8503_81fc;

// ---------------------------------------------------------------------------
// Hardware clocks & MMIO (mapped Device `0x0000_0412` on CPU1)
// ---------------------------------------------------------------------------

/// 32,768 Hz hardware RTC free-running counter (~30.5 us/tick).
pub const HW_RTC_32K_VA: u32 = 0x1002_0004;
/// Hardware LTE cipher/decipher engine (`LLCE0`/`LLCE1`) control register.
pub const HW_LLCE_BASE_VA: u32 = 0x1213_0000;
/// GIC-400 Software Generated Interrupt register (`0x0001_000a` rings SGI #10 on CPU0).
pub const HW_GICD_SGIR_VA: u32 = 0x1a08_1f00;

// ---------------------------------------------------------------------------
// Core L2 / OS globals
// ---------------------------------------------------------------------------

/// 1 ms monotonic L2 TTI clock (`u32`, incremented on every 1 ms tick).
pub const TTI_CLK_VA: u32 = 0x84a1_f860;
/// CPU1 idle percentage updated at 1 Hz by `tmr-trace_perf` (low byte = 0..100).
pub const CPU1_IDLE_PCT_VA: u32 = 0x84a2_0884;
/// Modem-side GIPC controller (`GipcCtrl`).
pub const GIPC_CTRL_VA: u32 = 0x84a2_df9c;
/// Global L2/MAC `-2 ms` timer offset & `bo_margin` enable word (`2` at boot, `0` in test loop).
pub const L2_TIMER_OFFSET_VA: u32 = 0x8410_ea00;
/// Global `dp bo_margin` hold value in bytes (`u32`, e.g. `0x140` = 320 B).
pub const DP_BO_MARGIN_VA: u32 = 0x84f9_3008;
/// Stock `n2d irb-lat` Ring-1 sojourn tracker (`IrbLatTracker`).
pub const IRB_LAT_TRACKER_VA: u32 = 0x84f9_300c;

/// Main L2 context base (`l2_ctx`).
pub const L2_CTX_VA: u32 = 0x84d9_47c0;
/// `wk-dp` workqueue event handle (`l2_ctx + 0x808`).
pub const L2_WK_DP_EVT_VA: u32 = 0x84d9_4fc8;
/// `n2d ul-lat` enable byte (`l2_ctx + 0x86a`).
pub const N2D_UL_LAT_EN_VA: u32 = 0x84d9_502a;
/// `n2d icmp-lat` enable byte (`l2_ctx + 0x86b`).
pub const N2D_ICMP_LAT_EN_VA: u32 = 0x84d9_502b;
/// `n2d irb-lat` enable byte (`l2_ctx + 0x86c`).
pub const N2D_IRB_LAT_EN_VA: u32 = 0x84d9_502c;
/// Pending UL hardware cipher batch pointer (`l2_ctx + 0x924`).
pub const L2_CIPHER_PEND_VA: u32 = 0x84d9_50e4;
/// Active UL hardware cipher batch pointer (`l2_ctx + 0x928`).
pub const L2_CIPHER_BUSY_VA: u32 = 0x84d9_50e8;

/// Array of 8 bearer control blocks (`[Rbc; 8]`, stride `0x248` B).
pub const RBC_TABLE_VA: u32 = 0x84dd_59d8;
/// Active 1-second stats bank index (`u8`, `0` or `1`).
pub const RBC_STATS_BANK_VA: u32 = 0x84dd_9784;
/// Active high-priority L2 timer count (`u16`, slots `0..23`).
pub const L2_TMR_HP_CNT_VA: u32 = 0x84dd_978a;
/// Active normal-priority L2 timer count (`u16`, slots `24..63`).
pub const L2_TMR_NORM_CNT_VA: u32 = 0x84dd_978c;
/// 250 ms UL byte accumulator cleared by `do_tc` (`u32`).
pub const L2_UL_250MS_BYTES_VA: u32 = 0x84dd_97b4;
/// Stock PDCP/RLC UL submission cap (`u32`: 32 KB / 64 KB / 128 KB).
pub const L2_PDCP_UL_LIMIT_VA: u32 = 0x84dd_97bc;
/// Shared bearer IRB headroom limit (`u16`).
pub const L2_IRB_SHARED_LIMIT_VA: u32 = 0x84dd_97c6;
/// Shared bearer IRB occupancy above 32/bearer (`u16`).
pub const L2_IRB_SHARED_USED_VA: u32 = 0x84dd_97c8;
/// Normal L2 timer expiry timestamps (`[u32; 64]`).
pub const L2_TMR_EXPIRY_VA: u32 = 0x84dd_97f0;
/// Flat 64-entry L2 software timer table (`[L2TimerEntry; 64]`, stride 16 B).
pub const L2_TMR_TABLE_VA: u32 = 0x84dd_98d0;
/// `do_ic` overload brake DL drop counter (`u16`).
pub const L2_DO_IC_DROPS_VA: u32 = 0x84dd_9cda;
/// Total UL IRBs seen by `l2_task` (`u32`).
pub const L2_CNT_UL_IRBS_VA: u32 = 0x84dd_9cec;
/// Pure UL TCP ACKs routed to Ring 0 (`u16` / `u32` at `+0x52e`).
pub const L2_CNT_R0_TCP_ACK_VA: u32 = 0x84dd_9cee;
/// Per-LCG pre-RLC DRB pending bytes (`[u32; 4]`) populated by `mac_bsr_pre_work` (`0x842d_a60c`)
/// and copied into `lcg_bo[0..3]` at the top of `rlc_upd_cur_bo` (`0x842d_d1b0`).
pub const L2_BSR_PRE_BO_VA: u32 = 0x84dd_9d18;

// ---------------------------------------------------------------------------
// MAC UL / BSR / SR / HARQ / L1U globals & ROM tables
// ---------------------------------------------------------------------------

/// MAC UL BSR dynamic state (`MacUlBsrCtx`, `0x5c` B).
pub const MAC_UL_BSR_CTX_VA: u32 = 0x84d6_2940;
/// MAC UL RRC configuration & LC-to-LCG table (`MacUlCfg`, `0x160` B).
pub const MAC_UL_CFG_VA: u32 = 0x84d6_299c;
/// MAC UL LCP token-bucket & per-LC BO scheduling table (`MacUlLcpTbl`, `0x110` B).
pub const MAC_UL_LCP_TBL_VA: u32 = 0x84d6_2c70;
/// MAC UL HARQ process table: `4 CCs * 8 processes * 0x78 B` (`0x3c0` per CC).
pub const MAC_HARQ_PROC_TBL_VA: u32 = 0x84d6_3780;
/// MAC PHR state block (`MacPhrState`).
pub const MAC_PHR_STATE_VA: u32 = 0x84d9_3f84;
/// MAC RACH & Scheduling Request context (`MacRaSrCtx`).
pub const MAC_RA_SR_CTX_VA: u32 = 0x84d9_40b8;
/// MAC UL global control block (`MacUlGlobal`, `0x30` B).
pub const MAC_UL_GLOBAL_VA: u32 = 0x84d9_426c;
/// Per-TTI remaining NewTx CC count (`MacUlGlobal + 0x14`, `u8`); non-zero on PCell
/// in a 2CC NewTx TTI so Regular/Periodic BSR defers to SCell.
pub const MAC_UL_PENDING_NEWTX_CNT_VA: u32 = 0x84d9_4280;
/// MAC SCell activation state table (`MacScellEntry`).
pub const MAC_SCELL_TBL_VA: u32 = 0x84d9_4710;
/// Per-CC MAC statistics pointer table (`[Ptr32<u32>; 4]`; `+0x20c..+0x218` holds peak BSR idx).
pub const MAC_STATS_PTR_TBL_VA: u32 = 0x84af_8144;

/// L1U PCell closed-loop TPC accumulator `f_0(i)` (signed 0.1 dB).
pub const L1U_TPC_F0_VA: u32 = 0x84d4_7b34;
/// L1U SCell closed-loop TPC accumulator `f_1(i)` (signed 0.1 dB).
pub const L1U_TPC_F1_VA: u32 = 0x84d4_7d48;
/// L1U SR periodicity & offset (`L1uSrCfg`: `+0x00` period ms, `+0x04` offset).
pub const L1U_SR_CFG_VA: u32 = 0x84d4_9c54;
/// Monotonic 32-bit PHICH ACK/NACK/total counters (`HI_CNT`).
pub const L1D_PHICH_HI_CNT_VA: u32 = 0x84d2_dad8;

/// `dp bsr periodic` override byte (`u8`, 0=off, 1..15=index+1 into timer table).
pub const DP_BSR_PERIODIC_VA: u32 = 0x84b2_6618;
/// `dp bsr fix_boi` floor byte (`u8`, 0=off, 1..63=min BSR index).
pub const DP_BSR_FIX_BOI_VA: u32 = 0x84b2_6619;
/// `l2 mac bsrpe-mar` subtraction byte (`u8`, ms).
pub const L2_MAC_BSRPE_MAR_VA: u32 = 0x84b2_661a;
/// `l2 mac srmax-disable` byte (`u8`, 0=stock).
pub const L2_MAC_SRMAX_DISABLE_VA: u32 = 0x84b2_661d;

/// 3GPP TS 36.211 TDD UL subframe indicator table (`[[u32; 10]; 7]`, cfg 2 = SF 2 & 7).
pub const ROM_TDD_UL_SF_MASK_VA: u32 = 0x847f_5370;
/// 3GPP TS 36.321 Table 6.1.3.1-1 Standard BSR table (`[u32; 63]`, `idx 0..62`).
pub const ROM_STD_BSR_TABLE_VA: u32 = 0x847f_5b1c;
/// 3GPP TS 36.321 Table 6.1.3.1-2 Extended BSR table (`[u32; 63]`, `idx 0..62`).
pub const ROM_EXT_BSR_TABLE_VA: u32 = 0x847f_5c18;
/// 3GPP `periodicBSR-Timer` / `retxBSR-Timer` ms lookup (`[u16; 15]`).
pub const ROM_BSR_TIMER_TABLE_VA: u32 = 0x847f_5d14;
/// 3GPP TS 36.213 Table 9.1.2-1 `k_PHICH` (`[[u8; 10]; 7]`, cfg 2 = 6 ms on SF 2 & 7).
pub const ROM_TDD_K_PHICH_VA: u32 = 0x847f_5dd8;
/// 3GPP TS 36.213 Table 8-2 `k_PUSCH` (`[[u8; 10]; 7]`, cfg 2 = 4 ms on SF 3 & 8).
pub const ROM_TDD_K_PUSCH_VA: u32 = 0x847f_5e20;
/// TDD UL HARQ process ID per subframe (`[[u8; 10]; 7]`, cfg 2 = SF 2 -> 0, SF 7 -> 1).
pub const ROM_TDD_HARQ_ID_VA: u32 = 0x847f_5f18;
/// HARQ Redundancy Version ROM table base (`+0x20` MCS->RV, `+0x40` RV->idx, `+0x6c` idx->RV).
pub const ROM_HARQ_RV_BASE_VA: u32 = 0x847f_8318;

// ---------------------------------------------------------------------------
// Active patch stack control blocks (IMG4 + N4 + N5 + N6H + C1 + UL-B + N3)
// ---------------------------------------------------------------------------

pub const IMG4_CTRL_VA: u32 = 0x847e_cfe8;
pub const IMG3_CTRL_VA: u32 = 0x847e_cf00;
pub const IMG2_CTRL_VA: u32 = 0x847e_d540;
pub const N4_STATE_VA: u32 = 0x847e_d600;
pub const N4_EXT_CNT_VA: u32 = 0x847e_d780;
pub const N5_STATE_VA: u32 = 0x8448_9a64;
pub const N6_U2_STATE_VA: u32 = 0x8418_ff00;
pub const C1_TK2_STATE_VA: u32 = 0x843f_a1c0;
pub const ULB_BSR_STATE_VA: u32 = 0x8449_db00;
/// Lane N3 MAC UL optimizer code cave (`grf_cancellation_rpll_mutual_interference_sd_init`, 852 B).
pub const N3_OPT_CODE_VA: u32 = 0x8418_67e4;
/// Lane N3 MAC UL optimizer boot-off control block (`ATM_decodePCO`, 128 B aligned).
pub const N3_OPT_BLK_VA: u32 = 0x8449_a2a0;

// ---------------------------------------------------------------------------
// Key stock function entry VAs (even addresses; OR with 1 for Thumb BX/BLX)
// ---------------------------------------------------------------------------

pub const FN_DMA_INV_RANGE_ARM: u32 = 0x8411_4e64; // ARM mode! Do NOT OR with 1
pub const FN_DMA_CLEAN_RANGE_ARM: u32 = 0x8411_4eac; // ARM mode! Do NOT OR with 1
pub const FN_DMA_FLUSH_RANGE_ARM: u32 = 0x8411_4ee0; // ARM mode! Do NOT OR with 1

pub const FN_IPC_IRQ_HANDLER: u32 = 0x8411_59fc;
pub const FN_IPC_CPU_ACTIVE_LOCK: u32 = 0x8411_5ce4;
pub const FN_GIPC_IRB_ABORT: u32 = 0x8411_6220;
pub const FN_GET_RX_CH_IRB: u32 = 0x8411_6228;
pub const FN_GIPC_SEND: u32 = 0x8411_6330;
pub const FN_GIPC_GET_TX_IRB: u32 = 0x8411_63e4;
pub const FN_GIPC_REL_RX_IRB: u32 = 0x8411_6564;

pub const FN_L2_ENQUEUE_BULK_TRANS: u32 = 0x842d_9af4;
pub const FN_L2_PROC_DECIP_DONE: u32 = 0x842d_9c70;
pub const FN_L2_TIMER_START: u32 = 0x842d_9e5c;
pub const FN_L2_TIMER_STOP: u32 = 0x842d_9ef4;
pub const FN_L2_PROC_TIMER: u32 = 0x842d_9fa8;
pub const FN_L2_HP_TASK: u32 = 0x842d_a05c;
pub const FN_L2_TASK: u32 = 0x842d_a120;
pub const FN_L2_SCHED_EVENT: u32 = 0x842d_a530;
pub const FN_RBC_BY_LCID: u32 = 0x842d_a5d8;
pub const FN_MAC_BSR_PRE_WORK: u32 = 0x842d_a60c;

pub const FN_PROC_PDCP_UL: u32 = 0x842d_c968;
pub const FN_L2_PROC_PDCP_UL: u32 = 0x842d_cbf4;
pub const FN_RLC_UL_PROC_DISCARD_REQ: u32 = 0x842d_cd90;
pub const FN_PDCP_UL_PROC_DRB_CNF: u32 = 0x842d_cf60;
pub const FN_PDCP_PROC_TMR_DISCARD: u32 = 0x842d_d074;

pub const FN_GET_RLC_CUR_BO: u32 = 0x842d_d134;
pub const FN_RLC_UPD_CUR_BO: u32 = 0x842d_d194;
pub const FN_UPD_LCID_BO_TO_MAC: u32 = 0x842d_d238;
pub const FN_RLC_CHECK_SIZE: u32 = 0x842d_d360;
pub const FN_RLC_GEN_PDU_WRAPPER: u32 = 0x842d_d380;
pub const FN_PROCESS_PDU_RETX: u32 = 0x842d_d794;
pub const FN_UPD_RETX_BO: u32 = 0x842d_dbc0;
pub const FN_RLC_UL_AM_PROC_STATUS_RPT: u32 = 0x842d_eb44;
pub const FN_RLC_UL_AM_GEN_PDU: u32 = 0x842d_f4f4;
pub const FN_DO_TC: u32 = 0x842e_5adc;
pub const FN_GET_HP_BO_MARGIN: u32 = 0x842e_5b40;
pub const FN_DO_IC: u32 = 0x8452_c8cc;
pub const FN_DO_BO: u32 = 0x8452_c95c;
pub const FN_TC_SET_HP_BO_MARGIN: u32 = 0x8452_c9e8;

pub const FN_SEARCH_MAC_UL_BO_IDX: u32 = 0x842c_cf64;
pub const FN_INIT_MAC_UL_BSR_INFO: u32 = 0x842c_cff8;
pub const FN_RESTART_BSR_TIMER: u32 = 0x842c_d080;
pub const FN_STOP_BSR_TIMER: u32 = 0x842c_d0e8;
pub const FN_EXPIRE_BSR_TIMER: u32 = 0x842c_d104;
pub const FN_RESTART_RETX_BSR_TIMER: u32 = 0x842c_d168;
pub const FN_STOP_RETX_BSR_TIMER: u32 = 0x842c_d1d0;
pub const FN_EXPIRE_RETX_BSR_TIMER: u32 = 0x842c_d1ec;
pub const FN_RESET_MAC_UL_BSR_EVENT: u32 = 0x842c_d254;
pub const FN_UPDATE_MAC_UL_BO: u32 = 0x842c_d298;
pub const FN_GET_MAC_UL_BSR_FORMAT: u32 = 0x842c_d46c;
pub const FN_GET_MAC_UL_BSR_VALUE: u32 = 0x842c_d54c;
pub const FN_SET_MAC_UL_BSR_TIMER: u32 = 0x842c_da64;
pub const FN_PACK_MAC_SUBHEADER: u32 = 0x842c_f3b8;
pub const FN_PACK_CCCH_SDU: u32 = 0x842c_f540;
pub const FN_UPDATE_BJ: u32 = 0x842c_fad8;
pub const FN_SECOND_STEP_PBR: u32 = 0x842c_fb34;
pub const FN_ASSIGN_SCHEDULE_SIZE_2LC: u32 = 0x842c_fd40;
pub const FN_CHECK_LONG_BSR_DOWNGRADE: u32 = 0x842c_fe34;
pub const FN_SCHEDULE_AND_BUILD_RLCS: u32 = 0x842d_0030;
pub const FN_GENERATE_MAC_UL_PDU: u32 = 0x842d_0248;
pub const FN_UPDATE_MAC_UL_PH: u32 = 0x842d_1c40;
pub const FN_ACCESS_RA: u32 = 0x842d_3abc;
pub const FN_HANDLE_RA_ULGRANT: u32 = 0x842d_4a78;
pub const FN_GET_MAC_UL_SR: u32 = 0x842d_4ca4;
pub const FN_RECONSTRUCT_SCHED_INFO: u32 = 0x842d_5258;
pub const FN_CLEAR_MAC_UL_BUFFER: u32 = 0x842d_54fc;
pub const FN_HARQ_PROC_ACK: u32 = 0x842d_556c;
pub const FN_GET_TDD_BUNDLE_UL_IDX: u32 = 0x842d_576c;
pub const FN_HANDLE_HARQ_PROC: u32 = 0x842d_5bd4;
pub const FN_CHECK_UL_GR_FALSE_ALARM: u32 = 0x842d_6b20;
pub const FN_GET_TDD_BUNDLE_PHICH_HQ: u32 = 0x842d_6d04;
pub const FN_HANDLE_HARQ_ENTITY: u32 = 0x842d_6d68;
pub const FN_SCHEDULE_UL_DATA: u32 = 0x842d_89ac;
pub const FN_CHECK_SCELL_DEACT_TIMER: u32 = 0x842d_95c4;

pub const FN_HANDLE_SCH_TR_CH: u32 = 0x842c_935c;
pub const FN_PROCESS_MAC_DL_DATA: u32 = 0x842c_9ccc;
pub const FN_SEND_STATUS_REPORT: u32 = 0x842d_a8e8;
pub const FN_RLC_DL_AM_PROC_PDU: u32 = 0x842d_af3c;
pub const FN_RLC_RSM_DECODE_DRB: u32 = 0x842d_c2c4;
pub const FN_GET_HFN: u32 = 0x8452_a94c;
pub const FN_L2_TR_UL_LATENCY: u32 = 0x8454_5048;
pub const FN_L2_TR_ICMP_LATENCY: u32 = 0x8454_5088;
pub const FN_L2_TR_IRB_LATENCY: u32 = 0x8454_52e8;
