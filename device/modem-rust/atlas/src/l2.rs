//! L2 bearer (`Rbc`), Ring 0 / Ring 1, PDCP UL, RLC AM UL, LLCE hardware cipher
//! descriptors, L2 software timers, and built-in latency trackers.
//!
//! Every offset was verified against disassembly of `l2_task` (`0x842d_a120`),
//! `l2_proc_pdcp_ul` (`0x842d_cbf4`), `proc_pdcp_ul` (`0x842d_c968`),
//! `pdcp_ul_proc_drb_cnf` (`0x842d_cf60`), `pdcp_proc_tmr_discard` (`0x842d_d074`),
//! `get_rlc_cur_bo` (`0x842d_d134`), `rlc_upd_cur_bo` (`0x842d_d194`),
//! `ProcessPduRetx` (`0x842d_d794`), `rlc_ul_am_gen_pdu` (`0x842d_f4f4`),
//! `do_bo.isra.0` (`0x8452_c95c`), and `l2_tr_ul_latency` (`0x8454_5048`).

use crate::gipc::GipcIrb;
use crate::Ptr32;

/// Number of bearer slots in `RBC_TABLE_VA` (`0x84dd_59d8`).
pub const RBC_COUNT: usize = 8;
/// Ring 0 / Ring 1 capacity per bearer (12-bit wrap `0..4095`).
pub const RBC_RING_SLOTS: usize = 4096;
pub const RBC_RING_MASK: u16 = 0x0fff;
/// RLC AM TX / RETX window size (10-bit SN, half-window 512).
pub const RLC_AM_WIN_SIZE: usize = 512;

/// RLC mode constants in `Rbc::rlc_mode` (`+0x15`).
pub const RLC_MODE_TM: u8 = 1;
pub const RLC_MODE_UM: u8 = 2;
pub const RLC_MODE_AM: u8 = 3;

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

/// RLC AM UL transmit buffer entry (`0x40` = 64 bytes), 512 entries at `rbc.ul_am_tx_buf`.
///
/// Indexed by `sn & 0x1ff`. Verified against `ProcessPduRetx` (`0x842d_d794`).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct RlcAmTxEntry {
    pub _pad0: [u32; 2],
    /// `+0x08`: Pointer to RLC PDU buffer descriptor (`[pdu_desc]` points to RLC header byte 0).
    pub pdu_desc: Ptr32<Ptr32<u8>>,
    /// `+0x0c`: 10-bit RLC AM Sequence Number (`0..1023`).
    pub sn: u16,
    /// `+0x0e`: Length of linked retx-info list attached to this TX entry.
    pub retx_list_len: u16,
    /// `+0x10`: `RETX_COUNT` (compared against `rbc.max_retx_threshold` at `+0x169`).
    pub retx_count: u8,
    /// `+0x11`: Flags / segment metadata byte.
    pub meta_flags: u8,
    pub _pad1: u8,
    /// `+0x13`: `1` if previously NACKed (controls whether `ProcessPduRetx` bumps `retx_count`).
    pub was_nacked: u8,
    /// `+0x14`: Duplicate guard (`1` = already queued in `ul_am_retx_ring`).
    pub in_retx_queue: u8,
    pub _pad2: [u8; 0x27],
    /// `+0x3c`: Tail pointer of retx-info list.
    pub retx_tail: u32,
}

/// RLC AM UL retransmission ring entry (`0x18` = 24 bytes), 512 entries at `rbc.ul_am_retx_ring`.
///
/// Verified against `ProcessPduRetx` (`0x842d_d7d0..0x842d_d83e`) and `rlc_ul_am_gen_pdu` (`0x842d_f52e`).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct RlcAmRetxEntry {
    /// `+0x00`: 10-bit RLC SN to retransmit.
    pub sn: u16,
    pub _pad0: u8,
    /// `+0x03`: Segment / retx type flags.
    pub flags: u8,
    /// `+0x04`: Segment state byte (`0` on full PDU retx).
    pub seg_state: u8,
    pub _pad1: [u8; 3],
    /// `+0x08`: Back-pointer to the owning [`RlcAmTxEntry`].
    pub tx_entry: Ptr32<RlcAmTxEntry>,
    /// `+0x0c`: Pointer to retx-info node popped from `rbc.retx_node_freelist`.
    pub retx_node: u32,
    pub _pad2: [u32; 2],
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
    pub _pad0: [u8; 0x08],
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
    pub _pad5: [u8; 0x14],
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
    /// `+0xd4`: Counter incremented on Ring 0 drain (stock `do_bo` activity tracker).
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
    /// `+0xe8`: Callback invoked when LLCE0 UL cipher batch completes to update RLC BO.
    pub rlc_ul_bo_notify_fn: u32,
    pub _pad9: [u8; 0x0c],
    /// `+0xf8`: Ciphered PDCP-to-RLC UL ring pointer (8 bytes/entry).
    pub pdcp_to_rlc_ring: u32,
    /// `+0xfc`: `pdcp_to_rlc_ring` write index (advanced at LLCE0 submit).
    pub pdcp_to_rlc_wr: u16,
    /// `+0xfe`: `pdcp_to_rlc_ring` committed index (advanced at LLCE0 completion).
    pub pdcp_to_rlc_rd_pend: u16,
    pub _pad10: u16,
    /// `+0x102`: `pdcp_to_rlc_ring` size (power of 2).
    pub pdcp_to_rlc_size: u16,
    pub _pad11: u16,
    /// `+0x106`: Number of ciphered PDCP PDUs waiting for RLC segmentation.
    pub pdcp_to_rlc_cnt: u16,
    pub _pad12: u16,
    /// `+0x10a`: Estimated PDCP/RLC header overhead bytes (2 B per ciphered SDU).
    pub pdcp_rlc_hdr_bo: u16,
    /// `+0x10c`: Ciphered PDCP bytes ready in RLC TX queue (checked against PDCP staging cap).
    pub pdcp_rlc_tx_bo: u32,
    pub _pad13: [u8; 0x16],
    /// `+0x126`: RLC UM/AM additional header BO bytes.
    pub rlc_um_hdr_bo: u16,
    /// `+0x128`: RLC UM extra payload BO bytes.
    pub rlc_um_extra_bo: u32,
    pub _pad14: u32,
    /// `+0x130`: Bytes pending in Ring 0 + Ring 1 + in-flight LLCE0 cipher batch.
    /// Added to BSR by N4 `TRUE_BO` (`bit 0`).
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
    /// `+0x144`: Pending UL RLC STATUS PDU bytes.
    pub rlc_status_bo: u16,
    pub _pad16: [u8; 6],
    /// `+0x14c`: RLC AM DL receive reorder buffer (`512 * 16 B`).
    pub dl_rx_buf: u32,
    /// `+0x150`: RLC AM DL segment pool (`2048 * 20 B`).
    pub dl_seg_pool: u32,
    /// `+0x154`: RLC AM UL retransmission queue bytes (feeds `get_rlc_cur_bo`).
    pub rlc_retx_bo: u32,
    /// `+0x158`: RLC AM UL new-transmission bytes (feeds `get_rlc_cur_bo`).
    pub rlc_newtx_bo: u32,
    pub _pad17: [u8; 0x0c],
    /// `+0x168`: RLC AM UL poll trigger byte.
    pub rlc_ul_poll_pending: u8,
    /// `+0x169`: Configured `maxRetxThreshold` (16 on Nokia QCI 9).
    pub max_retx_threshold: u8,
    /// `+0x16a`: RLC AM DL `STATUS_TRIGGER` flag.
    pub status_trigger: u8,
    pub _pad18: [u8; 3],
    /// `+0x16e`: RLC AM UL `POLL_SN`.
    pub poll_sn: u16,
    /// `+0x170`: Configured `pollPDU` (64 on Nokia QCI 9).
    pub poll_pdu: u16,
    /// `+0x172`: L2 timer table ID for `t-PollRetransmit`.
    pub t_poll_retx_tmr_id: u16,
    /// `+0x174`: RLC AM UL `VT(A)` (lowest un-ACKed SN).
    pub vt_a: u16,
    /// `+0x176`: RLC AM UL `VT(S)` (next new SN to transmit).
    pub vt_s: u16,
    /// `+0x178`: L2 timer table ID for `t-StatusProhibit`.
    pub t_status_prohibit_tmr_id: u16,
    /// `+0x17a`: Incoming peer STATUS PDU length in bytes.
    pub status_pdu_len: u16,
    pub _pad19: u32,
    /// `+0x180`: Configured `pollByte`.
    pub poll_byte: u32,
    pub _pad20: u32,
    /// `+0x188`: Incoming peer STATUS PDU payload pointer.
    pub status_pdu_ptr: Ptr32<u8>,
    pub _pad21: [u8; 0x0e],
    /// `+0x19a`: Remaining free UL RLC AM window slots (initializes to `512`).
    pub ul_am_free_win_slots: u16,
    pub _pad22: [u8; 0x14],
    /// `+0x1b0`: RLC AM UL transmit buffer (`512 * 64 B`).
    pub ul_am_tx_buf: Ptr32<RlcAmTxEntry>,
    /// `+0x1b4`: RLC AM UL SDU-to-PDU mapping info table.
    pub ul_am_sdu_info: u32,
    pub _pad23: u32,
    /// `+0x1bc`: Retx info node free-list head.
    pub retx_node_freelist: u32,
    pub _pad24: u32,
    /// `+0x1c4`: Retx info node free-list count.
    pub retx_node_free_cnt: u32,
    pub _pad25: u32,
    /// `+0x1cc`: RLC AM UL retransmission ring (`512 * 24 B`).
    pub ul_am_retx_ring: Ptr32<RlcAmRetxEntry>,
    /// `+0x1d0`: Retx ring write index (9-bit wrap `0..511`).
    pub retx_wr: u16,
    /// `+0x1d2`: Retx ring read index (9-bit wrap `0..511`).
    pub retx_rd: u16,
    /// `+0x1d4`: Retx ring active entry count.
    pub retx_cnt: u16,
    /// `+0x1d6`: Retx RLC header overhead BO bytes.
    pub retx_hdr_bo: u16,
    /// `+0x1d8`: Retx ring total payload bytes.
    pub retx_bytes: u32,
    pub _pad26: [u8; 0x16],
    /// `+0x1f2`: Additional RLC AM header BO bytes.
    pub am_extra_hdr_bo: u16,
    pub _pad27: [u8; 0x1c],
    /// `+0x210`: ROHC compression enabled flag (`0` on bench).
    pub rohc_enabled: u8,
    pub _pad28: [u8; 0x0b],
    /// `+0x21c`: ROHC per-SN context table pointer.
    pub rohc_ctx_tbl: u32,
    pub _pad29: [u8; 0x16],
    /// `+0x236`: PDCP `discardTimer` duration in ms (`750` on Nokia `pdcpProf2`).
    pub pdcp_discard_timer_ms: u16,
    pub _pad30: [u8; 8],
    /// `+0x240`: Last activity counter snapshot stored by 250 ms `do_bo.isra.0`.
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

/// Hardware LTE Cipher/Decipher Engine (`LLCE0`/`LLCE1`, `0x1213_0000`) DMA descriptor (`0x30` = 48 B).
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
    /// `+0x0c`: Big-endian physical address of next 48-byte descriptor (`self + 0x30`).
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
