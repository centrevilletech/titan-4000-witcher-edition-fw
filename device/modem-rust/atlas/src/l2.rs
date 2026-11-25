//! L2 bearer (`Rbc`), Ring 0 / Ring 1, PDCP UL, RLC AM UL, LLCE hardware cipher
//! descriptors, L2 software timers, and built-in latency trackers.
//!
//! Every offset was verified against disassembly of `l2_task` (`0x842d_a120`),
//! `l2_proc_pdcp_ul` (`0x842d_cbf4`), `proc_pdcp_ul` (`0x842d_c968`),
//! `ul_cipher_submit` (`0x842d_9a48`), `ScheduleUlData` LLCE0 completion (`0x842d_8b86`),
//! `mac_bsr_pre_work` (`0x842d_a60c`), `pdcp_cnf_enqueue` (`0x842d_c8ec`),
//! `pdcp_ul_proc_drb_cnf` (`0x842d_cf60`), `pdcp_proc_tmr_discard` (`0x842d_d074`),
//! `rlc_ul_proc_discard_req` (`0x842d_cd90`), `get_rlc_cur_bo` (`0x842d_d134`),
//! `rlc_upd_cur_bo` (`0x842d_d194`), `ProcessPduRetx` (`0x842d_d794`),
//! `upd_retx_bo` (`0x842d_dbc0`), `rlc_am_ul_bo_notify` (`0x842d_eaec`),
//! `rlc_ul_am_proc_status_rpt` (`0x842d_eb44`), `rlc_ul_am_gen_pdu` (`0x842d_f4f4`),
//! `rlc_am_poll_retx_expire` (`0x8452_b398`), `do_tc` (`0x842e_5adc`),
//! `do_bo.isra.0` (`0x8452_c95c`), and `l2_tr_ul_latency` (`0x8454_5048`),
//! and cross-checked in Unicorn against stock `tk.bin`.

use crate::gipc::GipcIrb;
use crate::Ptr32;

/// Number of bearer slots in `RBC_TABLE_VA` (`0x84dd_59d8`).
pub const RBC_COUNT: usize = 8;
/// Ring 0 / Ring 1 capacity per bearer (12-bit wrap `0..4095`).
pub const RBC_RING_SLOTS: usize = 4096;
pub const RBC_RING_MASK: u16 = 0x0fff;
/// RLC AM TX / RETX window size (10-bit SN, half-window 512).
pub const RLC_AM_WIN_SIZE: usize = 512;
/// Maximum LLCE0 descriptors per UL hardware cipher batch (`proc_pdcp_ul` `0x842d_cae0`).
pub const UL_CIPHER_BATCH_MAX_DESCS: u32 = 64;
/// Stock `L2_PDCP_UL_DIVISOR_VA` (`0x84dd_9780`) initialized at `0x8410_456a`.
pub const L2_PDCP_UL_DIVISOR_DEFAULT: u32 = 1500;
/// Stock `do_tc` (`0x842e_5adc`) PDCP/RLC submission cap tiers (bytes).
pub const DO_TC_CAP_LOW: u32 = 32_768;
pub const DO_TC_CAP_MID: u32 = 65_536;
pub const DO_TC_CAP_HIGH: u32 = 131_072;

/// RLC mode constants in `Rbc::rlc_mode` (`+0x15`).
pub const RLC_MODE_TM: u8 = 1;
pub const RLC_MODE_UM: u8 = 2;
pub const RLC_MODE_AM: u8 = 3;

/// `Rbc::poll_cfg_flags` (`+0x16b`) bitmasks (`0x842e_2468..0x842e_2498`, `0x842e_033e..0x842e_0384`).
pub const RLC_POLL_CFG_PDU: u8 = 0x01;
pub const RLC_POLL_CFG_BYTE: u8 = 0x02;

/// 3GPP TS 36.331 `pollByte` ROM table at `0x847f_8714` (`idx 0..13`; `14` = infinity).
pub const RLC_POLL_BYTE_TABLE: [u32; 14] = [
    25_000, 50_000, 75_000, 100_000, 125_000, 250_000, 375_000, 500_000, 750_000, 1_000_000,
    1_250_000, 1_500_000, 2_000_000, 3_000_000,
];

/// Per-bearer uplink ingress ring (`rbc->ring0` high-priority or `rbc->ring1` bulk).
#[repr(C)]
pub struct RbcRing {
    /// `+0x00`: Write index (`0..4095`, 12-bit wrap).
    pub wr: u16,
    /// `+0x02`: Read index (`0..4095`, 12-bit wrap).
    pub rd: u16,
    /// `+0x04`: Queued `GipcIrb` pointers.
    pub slots: [Ptr32<GipcIrb>; RBC_RING_SLOTS],
}

impl RbcRing {
    /// Current queued packet count in this ring (`0..4095`).
    #[inline]
    pub const fn occupancy(&self) -> u16 {
        self.wr.wrapping_sub(self.rd) & RBC_RING_MASK
    }

    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.occupancy() == 0
    }
}

/// One PDCP UL confirmation range `[start_sn..=end_sn]` inside [`PdcpCnfRing`] (`4` bytes).
///
/// Enqueued by `pdcp_cnf_enqueue` (`0x842d_c8ec`) with contiguous-range coalescing,
/// drained by `pdcp_cnf_drain` (`0x842d_cf00`) -> `rbc.pdcp_cnf_fn` (`pdcp_ul_proc_drb_cnf`).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct PdcpCnfEntry {
    /// `+0x00`: First confirmed PDCP SN.
    pub start_sn: u16,
    /// `+0x02`: Last confirmed PDCP SN (inclusive).
    pub end_sn: u16,
}

/// Per-bearer PDCP confirmation ring pointed to by `Rbc::pdcp_cnf_ring` (`+0x08`, `0x104` bytes).
///
/// Note the firmware's 1-based slot addressing in `0x842d_c930` / `0x842d_cf16`:
/// `[wr, rd]` occupies word 0 (`+0x00..+0x03`), and entries are indexed at `(idx + 1) * 4`
/// for `idx in 0..64` (`+0x04..+0x103`).
#[repr(C)]
pub struct PdcpCnfRing {
    /// `+0x00`: Write index (`0..63`, 6-bit wrap).
    pub wr: u16,
    /// `+0x02`: Read index (`0..63`, 6-bit wrap).
    pub rd: u16,
    /// `+0x04..+0x103`: 64 confirmation range entries.
    pub entries: [PdcpCnfEntry; 64],
}

/// One PDCP UL SDU entry inside [`PdcpUlSduWindow`] (`0x10` = 16 bytes).
///
/// Populated on every UL packet by `proc_pdcp_ul` (`0x842d_cac0..0x842d_cad0`).
/// Freed on RLC AM ACK (`pdcp_ul_proc_drb_cnf`) or `discardTimer` (`pdcp_proc_tmr_discard`).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct PdcpUlSduEntry {
    /// `+0x00`: 32-bit PDCP UL COUNT assigned to this SDU.
    pub pdcp_count: u32,
    /// `+0x04`: Original zero-copy Linux `GipcIrb` pointer (NULL once released).
    pub irb: Ptr32<GipcIrb>,
    /// `+0x08`: Ciphered output buffer pointer in modem pool (freed by `0x842d_993c`).
    pub cipher_buf: Ptr32<u8>,
    /// `+0x0c`: Submission timestamp `*(u32*)0x84a1f860 & !1` (1 ms resolution);
    /// bit 0 is set by `pdcp_proc_tmr_discard` when marked for discard.
    pub enqueue_tti_and_flags: u32,
}

impl PdcpUlSduEntry {
    /// Submission time in 1 ms L2 TTI ticks (bit 0 masked off).
    #[inline]
    pub const fn enqueue_tti_ms(&self) -> u32 {
        self.enqueue_tti_and_flags & !1
    }

    #[inline]
    pub const fn is_discarded(&self) -> bool {
        (self.enqueue_tti_and_flags & 1) != 0
    }
}

/// PDCP UL SDU tracking window pointed to by `Rbc::pdcp_ul_win` (`+0xe4`).
#[repr(C)]
pub struct PdcpUlSduWindow {
    /// `+0x00`: Number of un-ACKed PDCP UL SDUs currently in window.
    pub active_count: u32,
    /// `+0x04`: 4,096 entries indexed by `pdcp_count & (rbc.pdcp_sn_max - 1)`.
    pub entries: [PdcpUlSduEntry; 4096],
}

/// One ciphered PDCP PDU handed to RLC AM/UM inside `Rbc::pdcp_to_rlc_ring` (`+0xf8`, `8` bytes).
///
/// Written by `proc_pdcp_ul` (`0x842d_ca5e..0x842d_ca6a`), committed on LLCE0 completion
/// (`0x842d_8d1e`), discarded if un-transmitted by `rlc_ul_proc_discard_req` (`0x842d_cdde`),
/// and consumed by `rlc_ul_am_gen_pdu` (`0x842e_0256..0x842e_028e`).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct PdcpToRlcEntry {
    /// `+0x00`: 12-bit (or 7-bit) PDCP SN of this SDU.
    pub pdcp_sn: u16,
    /// `+0x02`: Ciphered PDCP PDU byte length (IP payload + 2 B PDCP header).
    pub len: u16,
    /// `+0x04`: Ciphered buffer pointer allocated by `ul_cipher_buf_alloc` (`0x842d_9914`).
    pub cipher_buf: Ptr32<u8>,
}

/// Per-bearer packet/byte accumulator inside [`UlCipherBatch`] (`8` bytes).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct UlCipherBearerAccum {
    /// `+0x00`: Number of packets queued for this bearer in this LLCE0 batch.
    pub pkt_count: u32,
    /// `+0x04`: Total PDCP PDU bytes queued for this bearer in this LLCE0 batch.
    pub byte_count: u32,
}

/// One UL hardware cipher batch (`0x48` = 72 bytes); 2 static slots at `L2_UL_CIPHER_BATCH_VA` (`0x84d9_5050`).
///
/// Filled by `proc_pdcp_ul` (`0x842d_ca3c..0x842d_cae2`), kicked to `LLCE0` by `ul_cipher_submit`
/// (`0x842d_9a48`), and harvested in `ScheduleUlData` (`0x842d_8b86..0x842d_8d5a`).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct UlCipherBatch {
    /// `+0x00..+0x3f`: Per-bearer accumulators indexed by `rbc.bearer_idx` (`0..7`).
    pub bearers: [UlCipherBearerAccum; RBC_COUNT],
    /// `+0x40`: Number of `LlceDesc` descriptors currently populated (`0..=64`).
    pub desc_count: u32,
    /// `+0x44`: Base pointer to the 64-entry `LlceDesc` DMA ring (`64 * 48 = 3072` B).
    pub desc_ring: Ptr32<LlceDesc>,
}

/// 1-second banked RLC/PDCP statistics inside [`Rbc`] (`0x2c` = 44 bytes).
///
/// Active bank index (`0` or `1`) is stored at `RBC_STATS_BANK_VA` (`0x84dd_9784`).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct RbcStatsBank {
    /// `+0x00` (`rbc+0x40`): DL RLC control PDUs.
    pub dl_ctrl_pdus: u16,
    /// `+0x02` (`rbc+0x42`): DL RLC data PDUs.
    pub dl_data_pdus: u16,
    /// `+0x04` (`rbc+0x44`): DL RLC segments.
    pub dl_seg_pdus: u16,
    /// `+0x06` (`rbc+0x46`): DL discarded PDUs.
    pub dl_disc_pdus: u16,
    /// `+0x08` (`rbc+0x48`): DL out-of-window / duplicate PDUs.
    pub dl_oow_dup_pdus: u16,
    pub _rsvd0: [u16; 2],
    /// `+0x0e` (`rbc+0x4e`): UL RLC control PDUs (STATUS).
    pub ul_ctrl_pdus: u16,
    /// `+0x10` (`rbc+0x50`): UL RLC retransmitted PDUs.
    pub ul_retx_pdus: u16,
    /// `+0x12` (`rbc+0x52`): UL RLC new data PDUs.
    pub ul_data_pdus: u16,
    /// `+0x14` (`rbc+0x54`): UL RLC AM window stall events (`ul_am_free_win_slots == 0`).
    pub ul_am_win_stalls: u16,
    /// `+0x16` (`rbc+0x56`): Max UL PDCP-to-ACK sojourn latency in ms (`n2d ul-lat`).
    pub ul_max_lat_ms: u16,
    /// `+0x18` (`rbc+0x58`): `t-Reordering` timer starts.
    pub t_reord_starts: u8,
    /// `+0x19` (`rbc+0x59`): `t-Reordering` timer expiries.
    pub t_reord_expiries: u8,
    pub _pad0: u16,
    /// `+0x1c` (`rbc+0x5c`): Downlink bytes in this 1-second bank.
    pub dl_bytes: u32,
    /// `+0x20` (`rbc+0x60`): Uplink bytes in this 1-second bank.
    pub ul_bytes: u32,
    pub _pad1: [u32; 2],
}

/// One scatter-gather segment descriptor inside `Rbc::ul_am_sdu_desc_pool` (`8` bytes).
///
/// For an [`RlcAmTxEntry`], `pdu_desc[0]` holds `(rlc_hdr_ptr, rlc_hdr_len)` and
/// `pdu_desc[1..seg_count]` hold the payload slices from ciphered PDCP SDUs.
/// Verified against `rlc_am_append_sdu` (`0x842d_dd0a`) and `rlc_ul_am_gen_pdu` (`0x842d_f828`).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct RlcScatterSeg {
    /// `+0x00`: Byte pointer to header or payload slice.
    pub ptr: Ptr32<u8>,
    /// `+0x04`: Byte length of this slice.
    pub len: u32,
}

/// Linked-list node connecting an [`RlcAmTxEntry`] to its pending [`RlcAmRetxEntry`] slots (`0x10` = 16 bytes).
///
/// Pool of 512 nodes at `Rbc::retx_node_pool` (`+0x1c8`, `8192` B), free-list at `+0x1bc..+0x1c4`.
/// Verified against `ProcessPduRetx` (`0x842d_d7e2..0x842d_d824`) and AM setup (`0x842e_2556..0x842e_257c`).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct RlcAmRetxNode {
    /// `+0x00`: Index (`0..511`) of the associated entry in `Rbc::ul_am_retx_ring`.
    pub ring_idx: u32,
    /// `+0x04`: Previous node in owning `RlcAmTxEntry`'s retx list.
    pub prev: Ptr32<RlcAmRetxNode>,
    /// `+0x08`: Next node in owning `RlcAmTxEntry`'s retx list.
    pub next: Ptr32<RlcAmRetxNode>,
    /// `+0x0c`: Next pointer when sitting on `Rbc::retx_node_freelist`.
    pub free_next: Ptr32<RlcAmRetxNode>,
}

/// RLC AM UL transmit buffer entry (`0x40` = 64 bytes), 512 entries at `rbc.ul_am_tx_buf`.
///
/// Indexed by `sn & 0x1ff`. Verified against `ProcessPduRetx` (`0x842d_d794`),
/// `rlc_ul_am_gen_pdu` (`0x842d_fe3c..0x842d_fe4c`), and `rlc_am_poll_retx_expire` (`0x8452_b428`).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct RlcAmTxEntry {
    /// `+0x00`: Starting index in `Rbc::ul_am_sdu_desc_pool` (`+0x19c`).
    pub seg_pool_start_idx: u16,
    /// `+0x02`: Total scatter segment count (`1` header + N SDU payload segments).
    pub seg_count: u16,
    /// `+0x04`: Total AMD PDU byte length (RLC header + payload).
    pub total_len: u32,
    /// `+0x08`: Pointer to scatter segment array (`pdu_desc[0]` = RLC header `(ptr, len)`).
    pub pdu_desc: Ptr32<RlcScatterSeg>,
    /// `+0x0c`: 10-bit RLC AM Sequence Number (`0..1023`).
    pub sn: u16,
    /// `+0x0e`: Length of linked `RlcAmRetxNode` list attached to this TX entry.
    pub retx_list_len: u16,
    /// `+0x10`: `RETX_COUNT` (compared against `rbc.max_retx_threshold` at `+0x169`).
    pub retx_count: u8,
    /// `+0x11`: Framing Info (`FI`) / header metadata byte copied into `RlcAmRetxEntry::fi_flags`.
    pub meta_flags: u8,
    /// `+0x12`: TX entry state flag (checked non-zero in `rlc_am_poll_retx_expire` & `status_rpt`).
    pub tx_state_flags: u8,
    /// `+0x13`: `1` if previously NACKed/retransmitted (controls `ProcessPduRetx` `RETX_COUNT` bump).
    pub was_nacked: u8,
    /// `+0x14`: Duplicate guard (`1` = already queued in `ul_am_retx_ring`).
    pub in_retx_queue: u8,
    pub _pad1: [u8; 0x23],
    /// `+0x38`: Head pointer of linked `RlcAmRetxNode` list.
    pub retx_head: Ptr32<RlcAmRetxNode>,
    /// `+0x3c`: Tail pointer of linked `RlcAmRetxNode` list.
    pub retx_tail: Ptr32<RlcAmRetxNode>,
}

/// RLC AM UL retransmission ring entry (`0x18` = 24 bytes), 512 entries at `rbc.ul_am_retx_ring`.
///
/// Verified against `ProcessPduRetx` (`0x842d_d7d0..0x842d_d856`) and `rlc_ul_am_gen_pdu`
/// (`0x842d_f52e..0x842d_f950`).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct RlcAmRetxEntry {
    /// `+0x00`: 10-bit RLC SN to retransmit.
    pub sn: u16,
    /// `+0x02`: Framing Info (`FI`) bits copied from `tx_entry.meta_flags` (`+0x11`).
    pub fi_flags: u8,
    /// `+0x03`: Retx cause/type flags (`flags` argument to `ProcessPduRetx`).
    pub flags: u8,
    /// `+0x04`: Segment state (`0` = full AMD PDU pending, `1` = re-segmentation in progress).
    pub seg_state: u8,
    /// `+0x05`: Non-zero when created from a byte-range `SOstart`/`SOend` STATUS NACK.
    pub is_so_nack: u8,
    pub _pad0: [u8; 2],
    /// `+0x08`: Back-pointer to the owning [`RlcAmTxEntry`].
    pub tx_entry: Ptr32<RlcAmTxEntry>,
    /// `+0x0c`: Pointer to [`RlcAmRetxNode`] popped from `rbc.retx_node_freelist`.
    pub retx_node: Ptr32<RlcAmRetxNode>,
    /// `+0x10`: Next scatter segment index in `tx_entry.pdu_desc` (starts at `1`).
    pub seg_sdu_idx: u16,
    /// `+0x12`: Byte offset within `tx_entry.pdu_desc[seg_sdu_idx]` (starts at `0`).
    pub seg_sdu_off: u16,
    /// `+0x14`: Remaining un-retransmitted payload bytes (`total_len - hdr_len` initially).
    pub seg_rem_bytes: u16,
    /// `+0x16`: Current 3GPP RLC AM Segment Offset (`SO`, starts at `0`).
    pub seg_so: u16,
}

/// Radio Bearer Context (`Rbc`, `0x248` = 584 bytes).
///
/// 8 contiguous slots live at `RBC_TABLE_VA` (`0x84dd_59d8`). Lookup by LCID
/// uses `rbc_by_lcid(lcid)` (`0x842d_a5d8`).
#[repr(C)]
pub struct Rbc {
    /// `+0x00`: Ring 0 (high-priority: stock pure TCP ACK / small ICMP `<=127 B`, N5 sparse flows).
    pub ring0: Ptr32<RbcRing>,
    /// `+0x04`: Ring 1 (normal bulk queue).
    pub ring1: Ptr32<RbcRing>,
    /// `+0x08`: PDCP UL confirmation range ring (`pdcp_cnf_enqueue` / `pdcp_cnf_drain`).
    pub pdcp_cnf_ring: Ptr32<PdcpCnfRing>,
    pub _pad0: u32,
    /// `+0x10`: Bearer configured flag (`do_bo.isra.0`).
    pub configured: u8,
    /// `+0x11`: Bearer active flag (`1` = active).
    pub active: u8,
    /// `+0x12`: MAC Logical Channel ID (`LCID`, e.g. 3 for default DRB).
    pub lcid: u8,
    /// `+0x13`: Logical Channel Group ID (`0..3`; QCI 9 default DRBs use `3`).
    pub lcg_id: u8,
    /// `+0x14`: Radio Bearer ID (`RB_ID`).
    pub rb_id: u8,
    /// `+0x15`: RLC mode (`3` = AM, `2` = UM, `1` = TM).
    pub rlc_mode: u8,
    pub _pad1: u8,
    /// `+0x17`: PDCP SN length mode (`1` = 7-bit SN, other = 12-bit SN).
    pub pdcp_sn_mode: u8,
    /// `+0x18`: DL valid deciphered packet streak counter (capped at 15).
    pub dl_valid_cnt: u8,
    pub _pad2: u8,
    /// `+0x1a`: Bearer table index (`0..7`).
    pub bearer_idx: u8,
    pub _pad3: u8,
    /// `+0x1c`: Total IRBs currently owned by this bearer (Ring 0 + Ring 1 + PDCP/RLC).
    pub queued_irbs: u16,
    /// `+0x1e`: PDCP SN modulus (`4096` for 12-bit SN).
    pub pdcp_sn_max: u16,
    /// `+0x20`: Next expected PDCP DL RX SN.
    pub next_pdcp_rx_sn: u16,
    pub _pad4: [u8; 6],
    /// `+0x28`: PDCP DL RX Hyper Frame Number (`RX_HFN`).
    pub rx_hfn: u32,
    pub _pad5a: [u8; 4],
    /// `+0x30`: Radio bearer type (`0` = DRB, `1` = MRB/MBMS, `2` = SRB).
    /// Checked by `mac_bsr_pre_work` (`0x842d_a66e`): only DRBs (`rb_type == 0`) add
    /// `ring_pending_bytes` into `L2_BSR_PRE_BO_VA`.
    pub rb_type: u8,
    pub _pad5b: [u8; 0x0f],
    /// `+0x40..+0x97`: Double-buffered 1-second RLC/PDCP statistics (`2 * 0x2c`).
    pub stats: [RbcStatsBank; 2],
    pub _pad6: [u8; 0x10],
    /// `+0xa8`: Cumulative UL bytes enqueued into Ring 0 + Ring 1 (`u64`).
    pub ul_enqueued_bytes_total: u64,
    /// `+0xb0`: Cumulative UL packets enqueued into Ring 0 + Ring 1 (`u64`).
    pub ul_enqueued_pkts_total: u64,
    pub _pad7: [u8; 0x08],
    /// `+0xc0`: RLC-to-PDCP DL delivery ring write index.
    pub rlc_to_pdcp_wr: u16,
    /// `+0xc2`: RLC-to-PDCP DL delivery ring read index.
    pub rlc_to_pdcp_rd: u16,
    /// `+0xc4`: RLC-to-PDCP DL delivery ring pointer (`0x2000` B).
    pub rlc_to_pdcp_ring: u32,
    pub _pad8: [u8; 0x08],
    /// `+0xd0`: Optional DL delivery hook (`dp tcp shp_tgt`).
    pub dl_hold_hook: u32,
    /// `+0xd4`: Monotonic TTI (`TTI_CLK_VA`) stored on Ring 0 drain in `l2_proc_pdcp_ul` (`0x842d_ccfc`).
    /// Stock `do_bo.isra.0` (`0x8452_c976`) compares this against `bo_hold_last_cnt` (`+0x240`),
    /// making stock `bo_margin` Ring 0 ONLY.
    pub ring0_last_tx_cnt: u32,
    /// `+0xd8`: 32-bit PDCP UL TX COUNT (incremented on every UL SDU; A4 `do_bo` source).
    pub pdcp_tx_count: u32,
    /// `+0xdc`: Oldest un-ACKed PDCP UL SN (head of `pdcp_ul_win` for `discardTimer`).
    pub pdcp_ul_oldest_sn: u16,
    /// `+0xde`: Hardware LLCE0 UL descriptor header flags.
    pub llce_ul_hdr_flags: u16,
    /// `+0xe0`: L2 timer table ID for RLC `t-Reordering` (`0x40` = none).
    pub t_reordering_tmr_id: u16,
    /// `+0xe2`: L2 timer table ID for PDCP `discardTimer`.
    pub t_discard_tmr_id: u16,
    /// `+0xe4`: PDCP UL SDU tracking window (`PdcpUlSduWindow`).
    pub pdcp_ul_win: Ptr32<PdcpUlSduWindow>,
    /// `+0xe8`: Callback invoked when LLCE0 UL cipher batch completes (`rlc_am_ul_bo_notify` `0x842d_eaed`).
    pub rlc_ul_bo_notify_fn: u32,
    /// `+0xec`: RLC AM UL secondary handler (`0x842d_e4f9`).
    pub rlc_ul_reest_fn: u32,
    /// `+0xf0`: RLC UL PDU generator (`rlc_ul_am_gen_pdu` `0x842d_f4f5`).
    pub rlc_ul_gen_pdu_fn: u32,
    /// `+0xf4`: PDCP UL confirmation callback (`pdcp_ul_proc_drb_cnf` `0x842d_cf61`).
    pub pdcp_cnf_fn: u32,
    /// `+0xf8`: Ciphered PDCP-to-RLC UL ring pointer (8 bytes/entry: [`PdcpToRlcEntry`]).
    pub pdcp_to_rlc_ring: Ptr32<PdcpToRlcEntry>,
    /// `+0xfc`: `pdcp_to_rlc_ring` write index (advanced by `proc_pdcp_ul` at LLCE0 submit).
    pub pdcp_to_rlc_wr: u16,
    /// `+0xfe`: `pdcp_to_rlc_ring` committed index (advanced at LLCE0 completion `0x842d_8d22`).
    pub pdcp_to_rlc_committed: u16,
    /// `+0x100`: `pdcp_to_rlc_ring` read index (advanced by `rlc_ul_am_gen_pdu` / discard).
    pub pdcp_to_rlc_rd: u16,
    /// `+0x102`: `pdcp_to_rlc_ring` size (power of 2).
    pub pdcp_to_rlc_size: u16,
    /// `+0x104`: PDCP SN of the partially segmented SDU currently at head of RLC AM.
    pub cur_sdu_sn: u16,
    /// `+0x106`: Number of committed ciphered PDCP PDUs waiting in `pdcp_to_rlc_ring`.
    pub pdcp_to_rlc_cnt: u16,
    /// `+0x108`: Remaining unsegmented bytes of the current head PDCP SDU (`0` if none).
    pub cur_sdu_rem: u16,
    /// `+0x10a`: Estimated PDCP/RLC header overhead bytes (`2 B` per queued ciphered SDU).
    pub pdcp_rlc_hdr_bo: u16,
    /// `+0x10c`: Ciphered PDCP bytes ready in RLC TX queue (checked against PDCP staging cap).
    pub pdcp_rlc_tx_bo: u32,
    /// `+0x110`: Byte pointer into remaining bytes of the partially segmented head SDU.
    pub cur_sdu_ptr: Ptr32<u8>,
    /// `+0x114`: Secondary/re-establishment PDCP-to-RLC SDU ring pointer (`8` B/entry).
    pub reest_ring: Ptr32<PdcpToRlcEntry>,
    /// `+0x118`: Re-establishment ring write index.
    pub reest_wr: u16,
    /// `+0x11a`: Re-establishment ring committed index.
    pub reest_committed: u16,
    /// `+0x11c`: Re-establishment ring ACK release read index.
    pub reest_ack_rd: u16,
    /// `+0x11e`: Re-establishment ring size (power of 2, `32` in AM setup).
    pub reest_size: u16,
    /// `+0x120`: Re-establishment ring RLC read index (`0xffff` when uninitialized).
    pub reest_rd: u16,
    /// `+0x122`: Re-establishment ring queued SDU count.
    pub reest_cnt: u16,
    /// `+0x124`: Remaining unsegmented bytes of head re-establishment SDU.
    pub reest_cur_rem: u16,
    /// `+0x126`: Re-establishment/UM additional RLC header BO bytes.
    pub rlc_reest_hdr_bo: u16,
    /// `+0x128`: Re-establishment/UM extra payload BO bytes (summed with `+0x10c` into `+0x154`).
    pub rlc_reest_tx_bo: u32,
    /// `+0x12c`: Byte pointer into remaining bytes of head re-establishment SDU.
    pub reest_cur_ptr: Ptr32<u8>,
    /// `+0x130`: Bytes pending in Ring 0 + Ring 1 + in-flight LLCE0 cipher batch.
    /// Subtracted on LLCE0 completion (`0x842d_8d2e`); added to BSR by N4 `TRUE_BO` (`bit 0`).
    pub ring_pending_bytes: u32,
    pub _pad15: u32,
    /// `+0x138`: RLC AM DL `VR(R)` (next in-sequence SN).
    pub vr_r: u16,
    /// `+0x13a`: RLC AM DL `VR(H)` (highest received SN + 1).
    pub vr_h: u16,
    /// `+0x13c`: RLC AM DL `VR(MS)` (maximum STATUS SN).
    pub vr_ms: u16,
    /// `+0x13e`: RLC AM DL `VR(X)` (`t-Reordering` target SN).
    pub vr_x: u16,
    /// `+0x140`: RLC TM BO bytes (mode 1 only).
    pub rlc_tm_bo: u32,
    /// `+0x144`: Pending UL RLC STATUS PDU bytes (feeds `get_rlc_cur_bo`).
    pub rlc_status_bo: u16,
    pub _pad16: [u8; 6],
    /// `+0x14c`: RLC AM DL receive reorder buffer (`512 * 16 B`).
    pub dl_rx_buf: u32,
    /// `+0x150`: RLC AM DL segment pool (`2048 * 20 B`).
    pub dl_seg_pool: u32,
    /// `+0x154`: RLC AM UL **new-transmission** BO bytes (`pdcp_rlc_tx_bo + rlc_reest_tx_bo`).
    /// Updated by `rlc_am_ul_bo_notify` (`0x842d_eb34`) and `rlc_ul_am_gen_pdu` (`0x842e_044c`).
    pub rlc_am_newtx_bo: u32,
    /// `+0x158`: RLC AM UL **retransmission** BO bytes (`retx_bytes`; UM TX BO in mode 2).
    /// Updated by `upd_retx_bo` (`0x842d_dbee`) and `rlc_ul_am_gen_pdu` (`0x842d_f650`).
    pub rlc_am_retx_bo: u32,
    pub _pad17: [u8; 0x0c],
    /// `+0x168`: Per-call UL RLC control (STATUS) PDU count (`0` or `1`, reset at `0x842d_f510`).
    pub ul_ctrl_pdu_cnt: u8,
    /// `+0x169`: Configured `maxRetxThreshold` (16 on Nokia QCI 9).
    pub max_retx_threshold: u8,
    /// `+0x16a`: RLC AM DL `STATUS_TRIGGER` flag.
    pub status_trigger: u8,
    /// `+0x16b`: RLC AM poll configuration mask (`RLC_POLL_CFG_PDU = 1`, `RLC_POLL_CFG_BYTE = 2`).
    pub poll_cfg_flags: u8,
    /// `+0x16c`: RLC AM UL poll trigger byte (`1` = set `P` bit on next AMD PDU; `rlc_poll_check`).
    pub poll_trigger: u8,
    /// `+0x16d`: Set to `1` during `rlc_ul_am_gen_pdu` when `t-PollRetransmit` must be restarted on exit.
    pub start_poll_retx_tmr: u8,
    /// `+0x16e`: RLC AM UL `POLL_SN` (set to `vt_s - 1` when `P` bit is transmitted).
    pub poll_sn: u16,
    /// `+0x170`: Configured `pollPDU` (64 on Nokia QCI 9).
    pub poll_pdu: u16,
    /// `+0x172`: L2 timer table ID for `t-PollRetransmit` (`40 ms` -> `38 ms` with `-2 ms` offset).
    pub t_poll_retx_tmr_id: u16,
    /// `+0x174`: RLC AM UL `VT(A)` (lowest un-ACKed SN, 10-bit mod 1024).
    pub vt_a: u16,
    /// `+0x176`: RLC AM UL `VT(S)` (next new SN to transmit, 10-bit mod 1024).
    pub vt_s: u16,
    /// `+0x178`: L2 timer table ID for `t-StatusProhibit`.
    pub t_status_prohibit_tmr_id: u16,
    /// `+0x17a`: Incoming peer STATUS PDU length in bytes.
    pub status_pdu_len: u16,
    /// `+0x17c`: `PDU_WITHOUT_POLL` counter (incremented per AMD PDU, compared against `poll_pdu`).
    pub pdu_without_poll: u32,
    /// `+0x180`: Configured `pollByte` (bytes, decoded from `RLC_POLL_BYTE_TABLE`).
    pub poll_byte: u32,
    /// `+0x184`: `BYTE_WITHOUT_POLL` counter (incremented by AMD PDU payload bytes, compared against `poll_byte`).
    pub byte_without_poll: u32,
    /// `+0x188`: Incoming peer STATUS PDU payload pointer.
    pub status_pdu_ptr: Ptr32<u8>,
    /// `+0x18c`: Temporary pointer to stack-local TX PDU builder scratch inside `rlc_ul_am_gen_pdu`.
    pub active_tx_build_ctx: u32,
    /// `+0x190`: `64 KiB` arena buffer for constructing UL RLC AM headers (`0x842e_250a`).
    pub ul_am_hdr_buf: Ptr32<u8>,
    /// `+0x194`: Current write offset inside `ul_am_hdr_buf` (wraps at `0x10000`).
    pub ul_am_hdr_buf_off: u16,
    /// `+0x196`: Current write index inside `ul_am_sdu_desc_pool`.
    pub ul_am_sdu_desc_idx: u16,
    /// `+0x198`: Capacity of `ul_am_sdu_desc_pool` (`512..=16384`).
    pub ul_am_sdu_desc_cap: u16,
    /// `+0x19a`: Remaining free UL RLC AM window slots (initializes to `512`; `0` = window stall).
    pub ul_am_free_win_slots: u16,
    /// `+0x19c`: Scatter-gather descriptor pool (`ul_am_sdu_desc_cap * 8 B`).
    pub ul_am_sdu_desc_pool: Ptr32<RlcScatterSeg>,
    /// `+0x1a0`: RLC AM SDU-to-PDU completion tracking ring (`1024 * 8 B`, indexed by `ul_am_sdu_cnf_wr`).
    pub ul_am_sdu_cnf_pool: u32,
    /// `+0x1a4`: Write index inside `ul_am_sdu_cnf_pool`.
    pub ul_am_sdu_cnf_wr: u32,
    pub _pad22: [u8; 0x08],
    /// `+0x1b0`: RLC AM UL transmit buffer (`512 * 64 B` = `32 KiB`).
    pub ul_am_tx_buf: Ptr32<RlcAmTxEntry>,
    /// `+0x1b4`: Pointer to `VT(A)` entry inside `ul_am_tx_buf` (advanced on STATUS ACK).
    pub ul_am_tx_head: Ptr32<RlcAmTxEntry>,
    /// `+0x1b8`: Pointer to `VT(S)` entry inside `ul_am_tx_buf` (advanced on new AMD PDU TX).
    pub ul_am_tx_tail: Ptr32<RlcAmTxEntry>,
    /// `+0x1bc`: Retx node free-list head.
    pub retx_node_freelist: Ptr32<RlcAmRetxNode>,
    /// `+0x1c0`: Retx node free-list tail.
    pub retx_node_freelist_tail: Ptr32<RlcAmRetxNode>,
    /// `+0x1c4`: Retx node free-list count.
    pub retx_node_free_cnt: u32,
    /// `+0x1c8`: Base pointer of 512-entry `RlcAmRetxNode` pool (`8 KiB`).
    pub retx_node_pool: Ptr32<RlcAmRetxNode>,
    /// `+0x1cc`: RLC AM UL retransmission ring (`512 * 24 B` = `12 KiB`).
    pub ul_am_retx_ring: Ptr32<RlcAmRetxEntry>,
    /// `+0x1d0`: Retx ring write index (9-bit wrap `0..511`).
    pub retx_wr: u16,
    /// `+0x1d2`: Retx ring read index (9-bit wrap `0..511`).
    pub retx_rd: u16,
    /// `+0x1d4`: Retx ring active entry count.
    pub retx_cnt: u16,
    /// `+0x1d6`: Retx RLC header overhead BO bytes.
    pub retx_hdr_bo: u16,
    /// `+0x1d8`: Retx ring total payload bytes (mirrored to `rlc_am_retx_bo` at `+0x158`).
    pub retx_bytes: u32,
    pub _pad26: [u8; 0x10],
    /// `+0x1ec`: Built UL RLC STATUS PDU buffer pointer (`0x842d_f44c`).
    pub tx_status_buf: Ptr32<u8>,
    /// `+0x1f0`: Built UL RLC STATUS PDU length in bytes (`0x842d_f454`).
    pub tx_status_len: u16,
    /// `+0x1f2`: Additional RLC AM STATUS header BO bytes (`1` when STATUS pending).
    pub am_extra_hdr_bo: u16,
    /// `+0x1f4`: `ACK_SN` packed into pending UL STATUS PDU.
    pub tx_status_ack_sn: u16,
    /// `+0x1f6`: Number of NACK entries in pending UL STATUS PDU.
    pub tx_status_nack_cnt: u16,
    /// `+0x1f8`: Pointer to NACK descriptor table for STATUS truncation.
    pub tx_status_nack_list: u32,
    pub _pad27a: u32,
    /// `+0x200`: Per-call UL RLC data PDU count (retx + new TX) inside `rlc_ul_am_gen_pdu`.
    pub ul_data_pdu_cnt: u16,
    /// `+0x202`: Non-zero if UL STATUS PDU was truncated to fit `grant_bytes`.
    pub tx_status_truncated: u16,
    /// `+0x204`: Actual STATUS PDU bytes emitted in this `rlc_ul_am_gen_pdu` call.
    pub tx_status_sent_len: u16,
    /// `+0x206`: Bit length of truncated NACK fields in UL STATUS PDU.
    pub tx_status_nack_bits: u16,
    /// `+0x208`: Scatter descriptor scratch index for AMD PDU re-segmentation.
    pub retx_seg_desc_idx: u16,
    /// `+0x20a`: Header buffer scratch offset for AMD PDU re-segmentation.
    pub retx_seg_hdr_off: u16,
    pub _pad27b: u32,
    /// `+0x210`: ROHC compression enabled flag (`0` on bench).
    pub rohc_enabled: u8,
    pub _pad28: [u8; 0x0b],
    /// `+0x21c`: ROHC per-SN context table pointer.
    pub rohc_ctx_tbl: u32,
    pub _pad29: [u8; 0x16],
    /// `+0x236`: PDCP `discardTimer` duration in ms (`750` on Nokia `pdcpProf2`).
    pub pdcp_discard_timer_ms: u16,
    pub _pad30: [u8; 8],
    /// `+0x240`: Last `ring0_last_tx_cnt` snapshot stored by 250 ms `do_bo.isra.0`.
    pub bo_hold_last_cnt: u32,
    /// `+0x244`: Active `bo_margin` hold bytes added to BSR in `rlc_upd_cur_bo`.
    pub bo_margin_bytes: u32,
}

/// One entry in the flat 64-slot L2 software timer table at `L2_TMR_TABLE_VA` (`0x84dd_98d0`).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct L2TimerEntry {
    /// `+0x00`: Thumb expiry callback pointer (bit 0 set).
    pub callback: u32,
    /// `+0x04`: Callback argument (typically `Ptr32<Rbc>`).
    pub arg: u32,
    /// `+0x08`: Timer duration in ms (live writable via `wm`).
    pub duration_ms: u32,
    /// `+0x0c`: `0` = one-shot, `1` = periodic.
    pub periodic: u8,
    /// `+0x0d`: Priority (`1` = HP slots 0..23, `0` = normal slots 24..63).
    pub prio: u8,
    /// `+0x0e`: State (`0` = free, `1` = stopped, `2` = running).
    pub state: u8,
    /// `+0x0f`: Index in active timer list.
    pub active_idx: u8,
}

/// Hardware LTE Cipher/Decipher Engine (`LLCE0` `0x1212_0000` / `LLCE1` `0x1213_0000`) DMA descriptor (`0x30` = 48 B).
///
/// All multi-byte fields are stored **big-endian** (`rev` instruction in `proc_pdcp_ul`).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct LlceDesc {
    /// `+0x00`: Big-endian `(len << 16) | rbc.llce_ul_hdr_flags`.
    pub hdr_be: u32,
    /// `+0x04`: Big-endian 32-bit PDCP COUNT.
    pub count_be: u32,
    pub _rsvd0: u32,
    /// `+0x0c`: Big-endian physical address of next 48-byte descriptor (`self + 0x30`),
    /// or `rev(LLCE_SENTINEL_VA)` on the last descriptor in a batch.
    pub next_desc_be: u32,
    pub _rsvd1: [u32; 4],
    /// `+0x20`: Big-endian payload byte length.
    pub len_be: u32,
    /// `+0x24`: Big-endian source physical buffer pointer (`skb->data`).
    pub src_be: u32,
    /// `+0x28`: Big-endian destination physical buffer pointer.
    pub dst_be: u32,
    pub _rsvd2: u32,
}

/// Stock `n2d irb-lat` Ring-1 sojourn tracker at `IRB_LAT_TRACKER_VA` (`0x84f9_300c`).
///
/// Active only when `*(u8*)0x84d9_502c != 0` (`n2d irb-lat 1`).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct IrbLatTracker {
    pub _pad0: [u32; 2],
    /// `+0x08`: Currently tracked IPv4 TCP seq / UDP id / ICMP seq (`0` = idle).
    pub tracked_seq: u32,
    /// `+0x0c`: `TTI_CLK_VA` timestamp when tracked packet entered Ring 1.
    pub enqueue_tti: u32,
    /// `+0x10`: `TTI_CLK_VA` timestamp of last 1 Hz console log.
    pub last_print_tti: u32,
    /// `+0x14`: High-water max Ring-1 sojourn time in ms (never auto-cleared).
    pub max_sojourn_ms: u32,
}
