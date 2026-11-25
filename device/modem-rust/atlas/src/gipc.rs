//! GIPC (Host CPU0 <-> Modem CPU1) shared-memory structures.
//!
//! Verified against `get_rx_ch_irb` (`0x8411_6228`), `gipc_send` (`0x8411_6330`),
//! `gipc_get_tx_irb` (`0x8411_63e4`), `gipc_rel_rx_irb` (`0x8411_6564`),
//! and C1 `tk2_flush_inner`.

use crate::Ptr32;

/// LTE user-plane SDU channel ID (`IPC_CH_LTE_SDU`).
pub const GIPC_CH_LTE_SDU: u8 = 1;
/// IRB direction: Host CPU0 -> Modem CPU1 (uplink).
pub const GIPC_DIR_H2M: u8 = 0;
/// IRB direction: Modem CPU1 -> Host CPU0 (downlink).
pub const GIPC_DIR_M2H: u8 = 1;

/// IRB state: free / owned by producer.
pub const IRB_STATE_FREE: u8 = 0x5c;
/// IRB state: active / in-flight to consumer.
pub const IRB_STATE_ACTIVE: u8 = 0xa5;
/// IRB state: released by consumer, awaiting producer reap.
pub const IRB_STATE_RELEASED: u8 = 0x50;

/// Doorbell suppression sentinel (`'AT'`) in `host_state` / `slave_state`.
pub const GIPC_STATE_ACTIVE_MAGIC: u16 = 0x4154;

/// Channel 1 ring capacity (4,096 IRB pointers, mask `0x0fff`).
pub const GIPC_CH1_RING_SLOTS: usize = 4096;
pub const GIPC_CH1_RING_MASK: u32 = 0x0fff;

/// Single GIPC I/O Request Block (`0x14` = 20 bytes).
///
/// Zero-copy across CPU0/CPU1 via SCU shareable WB-WA mapping (`0x0001_140e`).
/// Note: 20 bytes is not 64-byte cache-line aligned (3.2 IRBs per line).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct GipcIrb {
    /// `+0x00`: Channel ID (`1` = `IPC_CH_LTE_SDU`).
    pub ch: u8,
    /// `+0x01`: Direction (`0` = H->M UL, `1` = M->H DL; bit 7 available on M->H).
    pub dir: u8,
    /// `+0x02`: Ownership sentinel (`0x5c` free, `0xa5` active, `0x50` released).
    pub active: u8,
    /// `+0x03`: Encapsulation header offset (MUST stay `0` for normal IPv4/IPv6).
    pub rsvd: u8,
    /// `+0x04`: Buffer capacity in bytes (stock RX `0x83c` = 2,108 B).
    pub blength: u16,
    /// `+0x06`: Packet length including the 2-byte `{pdn_id, eps_id}` prefix.
    pub length: u16,
    /// `+0x08`: Direct VA==PA pointer to Linux `skb->data`.
    pub buffer: Ptr32<u8>,
    /// `+0x0c`: Linux `struct sk_buff *` opaque handle (untouched by CPU1).
    pub private: u32,
    /// `+0x10`: Linux TX completion callback (`gdm_lte_ipc_tx_done`).
    pub complete_fn: u32,
}

/// Shared-memory lock-protected IRB pointer ring (`0x4008` bytes for ch 1).
#[repr(C)]
pub struct GipcRing {
    /// `+0x00`: Producer monotonic index (masked with `0xfff`).
    pub head: u32,
    /// `+0x04`: Consumer monotonic index (masked with `0xfff`).
    pub tail: u32,
    /// `+0x08`: Circular array of IRB pointers.
    pub slots: [Ptr32<GipcIrb>; GIPC_CH1_RING_SLOTS],
}

/// Shared GIPC protocol control block (`0x680` bytes, allocated by Linux `gipc_init`).
///
/// False-sharing note: `active_lock` (`+0x94`) and `free_lock` (`+0x98`) share
/// cache line 2 (`+0x80..+0xbf`), and `active_ch_h2m/m2h` + `free_ch` share
/// cache line 12 (`+0x300..+0x33f`).
#[repr(C)]
pub struct GipcProto {
    /// `+0x00`: Protocol magic (`0x4054_0106`).
    pub magic: u32,
    /// `+0x04`: CPU0 state (`0x4154` while draining, `0` when idle -> needs SGI #10).
    pub host_state: u16,
    /// `+0x06`: CPU1 state (`0x4154` during active LTE; suppresses H->M ch 1 SGI #10).
    pub slave_state: u16,
    /// `+0x08`: Per-channel M->H doorbell flags (`0xaa` on SGI).
    pub m2h_flags: [u8; 32],
    /// `+0x28`: Per-channel H->M doorbell flags.
    pub h2m_flags: [u8; 32],
    pub _pad0: [u8; 0x4c],
    /// `+0x94`: ARMv7 `ldrex`/`strex` ticket lock for `active_ch` + active ring heads.
    pub active_lock: u32,
    /// `+0x98`: ARMv7 `ldrex`/`strex` ticket lock for `free_ch` + free ring heads.
    pub free_lock: u32,
    pub _pad1: [u8; 0x10],
    /// `+0xac`: Feature bits (`bit 4 = 0x10` selects CPU ticket locks).
    pub config_flags: u32,
    pub _pad2: [u8; 0x284],
    /// `+0x334`: Bitmask of channels with pending H->M (uplink) IRBs.
    pub active_ch_h2m: u32,
    /// `+0x338`: Bitmask of channels with pending M->H (downlink) IRBs.
    pub active_ch_m2h: u32,
    /// `+0x33c`: Bitmask of channels with released IRBs awaiting producer reap.
    pub free_ch: u32,
    pub _pad3: [u8; 0x340],
}

/// Modem-side per-channel GIPC descriptor (`0x58` bytes).
///
/// Channel `n` sits at `GIPC_CTRL_VA + 0x04 + n * 0x58`.
/// For channel 1 (`IPC_CH_LTE_SDU`), base is `0x84a2_dff8`.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct GipcChCtrl {
    pub _pad0: [u32; 2],
    /// `+0x08` (ch1: `gipc+0x64`): H->M active ring (Linux producer, CPU1 consumer).
    pub rx_active_ring: Ptr32<GipcRing>,
    /// `+0x0c` (ch1: `gipc+0x68`): H->M free/release ring (CPU1 returns ACKed UL IRBs).
    pub rx_free_ring: Ptr32<GipcRing>,
    /// `+0x10` (ch1: `gipc+0x6c`): Ring index mask (`0x0fff` for ch 1).
    pub rx_mask: u16,
    pub _pad1: u16,
    /// `+0x14` (ch1: `gipc+0x70`): Outstanding UL IRBs currently held by CPU1.
    pub rx_outstanding: u16,
    /// `+0x16` (ch1: `gipc+0x72`): Max allowed outstanding UL IRBs (4,096 for ch 1).
    pub rx_max: u16,
    pub _pad2: [u32; 6],
    /// `+0x30` (ch1: `gipc+0x8c`): M->H active ring (CPU1 producer, Linux consumer).
    pub tx_active_ring: Ptr32<GipcRing>,
    /// `+0x34` (ch1: `gipc+0x90`): M->H free ring (pre-posted Linux RX IRBs).
    pub tx_free_ring: Ptr32<GipcRing>,
    /// `+0x38` (ch1: `gipc+0x94`): TX ring index mask (`0x0fff` for ch 1).
    pub tx_mask: u16,
    pub _pad3: [u16; 11],
    /// `+0x50` (ch1: `gipc+0xac`): GIC SGI doorbell register VA (`0x1a08_1f00`).
    pub sgi_reg: u32,
    /// `+0x54` (ch1: `gipc+0xb0`): GIC SGI value written to wake CPU0 (`0x0001_000a`).
    pub sgi_val: u32,
}

/// Modem-side top-level GIPC control structure at `0x84a2_df9c`.
#[repr(C)]
pub struct GipcCtrl {
    /// `+0x00`: Shared `GipcProto` pointer.
    pub proto: Ptr32<GipcProto>,
    /// `+0x04`: 32 per-channel descriptors (`32 * 0x58 = 0xb00`).
    pub ch: [GipcChCtrl; 32],
    pub _pad0: [u32; 2],
    /// `+0xb0c`: Total H->M IRBs popped by CPU1 (`get_rx_ch_irb`).
    pub total_rx_popped: u32,
    pub _pad1: [u32; 5],
    /// `+0xb24`: Function pointer `ipc_cpu_active_lock` (`0x8411_5ce5`).
    pub active_lock_fn: u32,
    /// `+0xb28`: Function pointer `ipc_cpu_active_unlock`.
    pub active_unlock_fn: u32,
    pub _pad2: u32,
    /// `+0xb30`: Function pointer `ipc_cpu_free_lock`.
    pub free_lock_fn: u32,
    /// `+0xb34`: Function pointer `ipc_cpu_free_unlock`.
    pub free_unlock_fn: u32,
}
