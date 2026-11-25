//! Verified `#![no_std]` data-path atlas for the Titan 4000 LTE modem
//! (`tk.bin` V1.6.0.P0 R3882-4172, GCT GDM7243A CPU1, uT-Kernel, ARMv7 Thumb-2,
//! load VA `0x8410_0000`).
//!
//! Every struct offset, size, global address, and function entry point in this
//! crate was verified against stock `tk.bin` disassembly (SHA-256
//! `555362d9...82ea`) and the active patch stack (IMG4, N4, N5, N6H, C1, UL-B).
//!
//! All embedded 32-bit pointer fields use [`Ptr32<T>`] so `#[repr(C)]` struct
//! layouts are identical on 32-bit ARMv7 targets and 64-bit host test runners.

#![no_std]
#![allow(dead_code)]

use core::marker::PhantomData;

pub mod addr;
pub mod ffi;
pub mod gipc;
pub mod l2;
pub mod mac;
pub mod mac_model;
pub mod patches;

/// A 32-bit modem virtual address typed as a pointer to `T`.
///
/// Using a `u32` wrapper keeps every `#[repr(C)]` struct byte-exact on both
/// 32-bit ARMv7 Thumb-2 (`tk.bin`) and 64-bit host unit tests.
#[repr(transparent)]
pub struct Ptr32<T: ?Sized>(pub u32, PhantomData<*mut T>);

impl<T: ?Sized> Copy for Ptr32<T> {}
impl<T: ?Sized> Clone for Ptr32<T> {
    #[inline]
    fn clone(&self) -> Self {
        *self
    }
}

impl<T: ?Sized> PartialEq for Ptr32<T> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl<T: ?Sized> Eq for Ptr32<T> {}

impl<T: ?Sized> Ptr32<T> {
    pub const NULL: Self = Self(0, PhantomData);

    #[inline]
    pub const fn new(va: u32) -> Self {
        Self(va, PhantomData)
    }

    #[inline]
    pub const fn addr(self) -> u32 {
        self.0
    }

    #[inline]
    pub const fn is_null(self) -> bool {
        self.0 == 0
    }
}

impl<T> Ptr32<T> {
    /// Convert to a raw const pointer on 32-bit targets.
    #[cfg(target_pointer_width = "32")]
    #[inline]
    pub const fn as_ptr(self) -> *const T {
        self.0 as *const T
    }

    /// Convert to a raw mutable pointer on 32-bit targets.
    #[cfg(target_pointer_width = "32")]
    #[inline]
    pub const fn as_mut_ptr(self) -> *mut T {
        self.0 as *mut T
    }

    /// Create from a raw pointer on 32-bit targets.
    #[cfg(target_pointer_width = "32")]
    #[inline]
    pub fn from_ptr(ptr: *const T) -> Self {
        Self(ptr as u32, PhantomData)
    }
}

#[cfg(test)]
mod tests {
    use core::mem::{offset_of, size_of};

    use crate::gipc::*;
    use crate::l2::*;
    use crate::mac::*;
    use crate::patches::*;

    #[test]
    fn gipc_layouts_match_disassembly() {
        assert_eq!(size_of::<GipcIrb>(), 0x14);
        assert_eq!(offset_of!(GipcIrb, ch), 0x00);
        assert_eq!(offset_of!(GipcIrb, dir), 0x01);
        assert_eq!(offset_of!(GipcIrb, active), 0x02);
        assert_eq!(offset_of!(GipcIrb, rsvd), 0x03);
        assert_eq!(offset_of!(GipcIrb, blength), 0x04);
        assert_eq!(offset_of!(GipcIrb, length), 0x06);
        assert_eq!(offset_of!(GipcIrb, buffer), 0x08);
        assert_eq!(offset_of!(GipcIrb, private), 0x0c);
        assert_eq!(offset_of!(GipcIrb, complete_fn), 0x10);

        assert_eq!(size_of::<GipcRing>(), 0x4008);
        assert_eq!(offset_of!(GipcRing, head), 0x00);
        assert_eq!(offset_of!(GipcRing, tail), 0x04);
        assert_eq!(offset_of!(GipcRing, slots), 0x08);

        assert_eq!(size_of::<GipcProto>(), 0x680);
        assert_eq!(offset_of!(GipcProto, magic), 0x00);
        assert_eq!(offset_of!(GipcProto, host_state), 0x04);
        assert_eq!(offset_of!(GipcProto, slave_state), 0x06);
        assert_eq!(offset_of!(GipcProto, m2h_flags), 0x08);
        assert_eq!(offset_of!(GipcProto, h2m_flags), 0x28);
        assert_eq!(offset_of!(GipcProto, active_lock), 0x94);
        assert_eq!(offset_of!(GipcProto, free_lock), 0x98);
        assert_eq!(offset_of!(GipcProto, config_flags), 0xac);
        assert_eq!(offset_of!(GipcProto, active_ch_h2m), 0x334);
        assert_eq!(offset_of!(GipcProto, active_ch_m2h), 0x338);
        assert_eq!(offset_of!(GipcProto, free_ch), 0x33c);

        assert_eq!(size_of::<GipcChCtrl>(), 0x58);
        assert_eq!(offset_of!(GipcChCtrl, rx_active_ring), 0x08);
        assert_eq!(offset_of!(GipcChCtrl, rx_free_ring), 0x0c);
        assert_eq!(offset_of!(GipcChCtrl, rx_mask), 0x10);
        assert_eq!(offset_of!(GipcChCtrl, rx_outstanding), 0x14);
        assert_eq!(offset_of!(GipcChCtrl, rx_max), 0x16);
        assert_eq!(offset_of!(GipcChCtrl, tx_active_ring), 0x30);
        assert_eq!(offset_of!(GipcChCtrl, tx_free_ring), 0x34);
        assert_eq!(offset_of!(GipcChCtrl, tx_mask), 0x38);
        assert_eq!(offset_of!(GipcChCtrl, sgi_reg), 0x50);
        assert_eq!(offset_of!(GipcChCtrl, sgi_val), 0x54);

        assert_eq!(offset_of!(GipcCtrl, proto), 0x00);
        assert_eq!(offset_of!(GipcCtrl, ch), 0x04);
        assert_eq!(offset_of!(GipcCtrl, total_rx_popped), 0xb0c);
        assert_eq!(offset_of!(GipcCtrl, active_lock_fn), 0xb24);
        assert_eq!(offset_of!(GipcCtrl, active_unlock_fn), 0xb28);
        assert_eq!(offset_of!(GipcCtrl, free_lock_fn), 0xb30);
        assert_eq!(offset_of!(GipcCtrl, free_unlock_fn), 0xb34);
        // Channel 1 absolute offsets from GipcCtrl (0x84a2df9c):
        assert_eq!(
            offset_of!(GipcCtrl, ch)
                + size_of::<GipcChCtrl>()
                + offset_of!(GipcChCtrl, rx_free_ring),
            0x68
        );
        assert_eq!(
            offset_of!(GipcCtrl, ch) + size_of::<GipcChCtrl>() + offset_of!(GipcChCtrl, rx_mask),
            0x6c
        );
        assert_eq!(
            offset_of!(GipcCtrl, ch)
                + size_of::<GipcChCtrl>()
                + offset_of!(GipcChCtrl, rx_outstanding),
            0x70
        );
        assert_eq!(
            offset_of!(GipcCtrl, ch) + size_of::<GipcChCtrl>() + offset_of!(GipcChCtrl, rx_max),
            0x72
        );
        assert_eq!(
            offset_of!(GipcCtrl, ch)
                + size_of::<GipcChCtrl>()
                + offset_of!(GipcChCtrl, tx_active_ring),
            0x8c
        );
        assert_eq!(
            offset_of!(GipcCtrl, ch) + size_of::<GipcChCtrl>() + offset_of!(GipcChCtrl, sgi_reg),
            0xac
        );
        assert_eq!(
            offset_of!(GipcCtrl, ch) + size_of::<GipcChCtrl>() + offset_of!(GipcChCtrl, sgi_val),
            0xb0
        );
    }

    #[test]
    fn l2_pdcp_rlc_layouts_match_disassembly() {
        assert_eq!(size_of::<RbcRing>(), 0x4004);
        assert_eq!(offset_of!(RbcRing, wr), 0x00);
        assert_eq!(offset_of!(RbcRing, rd), 0x02);
        assert_eq!(offset_of!(RbcRing, slots), 0x04);

        assert_eq!(size_of::<PdcpCnfEntry>(), 0x04);
        assert_eq!(offset_of!(PdcpCnfEntry, start_sn), 0x00);
        assert_eq!(offset_of!(PdcpCnfEntry, end_sn), 0x02);
        assert_eq!(size_of::<PdcpCnfRing>(), 0x104);
        assert_eq!(offset_of!(PdcpCnfRing, wr), 0x00);
        assert_eq!(offset_of!(PdcpCnfRing, rd), 0x02);
        assert_eq!(offset_of!(PdcpCnfRing, entries), 0x04);

        assert_eq!(size_of::<PdcpUlSduEntry>(), 0x10);
        assert_eq!(offset_of!(PdcpUlSduEntry, pdcp_count), 0x00);
        assert_eq!(offset_of!(PdcpUlSduEntry, irb), 0x04);
        assert_eq!(offset_of!(PdcpUlSduEntry, cipher_buf), 0x08);
        assert_eq!(offset_of!(PdcpUlSduEntry, enqueue_tti_and_flags), 0x0c);

        assert_eq!(offset_of!(PdcpUlSduWindow, active_count), 0x00);
        assert_eq!(offset_of!(PdcpUlSduWindow, entries), 0x04);

        assert_eq!(size_of::<PdcpToRlcEntry>(), 0x08);
        assert_eq!(offset_of!(PdcpToRlcEntry, pdcp_sn), 0x00);
        assert_eq!(offset_of!(PdcpToRlcEntry, len), 0x02);
        assert_eq!(offset_of!(PdcpToRlcEntry, cipher_buf), 0x04);

        assert_eq!(size_of::<UlCipherBearerAccum>(), 0x08);
        assert_eq!(offset_of!(UlCipherBearerAccum, pkt_count), 0x00);
        assert_eq!(offset_of!(UlCipherBearerAccum, byte_count), 0x04);
        assert_eq!(size_of::<UlCipherBatch>(), 0x48);
        assert_eq!(offset_of!(UlCipherBatch, bearers), 0x00);
        assert_eq!(offset_of!(UlCipherBatch, desc_count), 0x40);
        assert_eq!(offset_of!(UlCipherBatch, desc_ring), 0x44);

        assert_eq!(size_of::<RbcStatsBank>(), 0x2c);
        assert_eq!(offset_of!(RbcStatsBank, dl_ctrl_pdus), 0x00);
        assert_eq!(offset_of!(RbcStatsBank, ul_ctrl_pdus), 0x0e);
        assert_eq!(offset_of!(RbcStatsBank, ul_retx_pdus), 0x10);
        assert_eq!(offset_of!(RbcStatsBank, ul_data_pdus), 0x12);
        assert_eq!(offset_of!(RbcStatsBank, ul_am_win_stalls), 0x14);
        assert_eq!(offset_of!(RbcStatsBank, ul_max_lat_ms), 0x16);
        assert_eq!(offset_of!(RbcStatsBank, t_reord_starts), 0x18);
        assert_eq!(offset_of!(RbcStatsBank, t_reord_expiries), 0x19);
        assert_eq!(offset_of!(RbcStatsBank, dl_bytes), 0x1c);
        assert_eq!(offset_of!(RbcStatsBank, ul_bytes), 0x20);

        assert_eq!(size_of::<RlcScatterSeg>(), 0x08);
        assert_eq!(offset_of!(RlcScatterSeg, ptr), 0x00);
        assert_eq!(offset_of!(RlcScatterSeg, len), 0x04);

        assert_eq!(size_of::<RlcAmRetxNode>(), 0x10);
        assert_eq!(offset_of!(RlcAmRetxNode, ring_idx), 0x00);
        assert_eq!(offset_of!(RlcAmRetxNode, prev), 0x04);
        assert_eq!(offset_of!(RlcAmRetxNode, next), 0x08);
        assert_eq!(offset_of!(RlcAmRetxNode, free_next), 0x0c);

        assert_eq!(size_of::<Rbc>(), 0x248);
        assert_eq!(offset_of!(Rbc, ring0), 0x00);
        assert_eq!(offset_of!(Rbc, ring1), 0x04);
        assert_eq!(offset_of!(Rbc, pdcp_cnf_ring), 0x08);
        assert_eq!(offset_of!(Rbc, configured), 0x10);
        assert_eq!(offset_of!(Rbc, active), 0x11);
        assert_eq!(offset_of!(Rbc, lcid), 0x12);
        assert_eq!(offset_of!(Rbc, lcg_id), 0x13);
        assert_eq!(offset_of!(Rbc, rb_id), 0x14);
        assert_eq!(offset_of!(Rbc, rlc_mode), 0x15);
        assert_eq!(offset_of!(Rbc, pdcp_sn_mode), 0x17);
        assert_eq!(offset_of!(Rbc, dl_valid_cnt), 0x18);
        assert_eq!(offset_of!(Rbc, bearer_idx), 0x1a);
        assert_eq!(offset_of!(Rbc, queued_irbs), 0x1c);
        assert_eq!(offset_of!(Rbc, pdcp_sn_max), 0x1e);
        assert_eq!(offset_of!(Rbc, next_pdcp_rx_sn), 0x20);
        assert_eq!(offset_of!(Rbc, rx_hfn), 0x28);
        assert_eq!(offset_of!(Rbc, rb_type), 0x30);
        assert_eq!(offset_of!(Rbc, stats), 0x40);
        assert_eq!(offset_of!(Rbc, ul_enqueued_bytes_total), 0xa8);
        assert_eq!(offset_of!(Rbc, ul_enqueued_pkts_total), 0xb0);
        assert_eq!(offset_of!(Rbc, dl_hold_hook), 0xd0);
        assert_eq!(offset_of!(Rbc, ring0_last_tx_cnt), 0xd4);
        assert_eq!(offset_of!(Rbc, pdcp_tx_count), 0xd8);
        assert_eq!(offset_of!(Rbc, pdcp_ul_oldest_sn), 0xdc);
        assert_eq!(offset_of!(Rbc, llce_ul_hdr_flags), 0xde);
        assert_eq!(offset_of!(Rbc, t_reordering_tmr_id), 0xe0);
        assert_eq!(offset_of!(Rbc, t_discard_tmr_id), 0xe2);
        assert_eq!(offset_of!(Rbc, pdcp_ul_win), 0xe4);
        assert_eq!(offset_of!(Rbc, rlc_ul_bo_notify_fn), 0xe8);
        assert_eq!(offset_of!(Rbc, rlc_ul_reest_fn), 0xec);
        assert_eq!(offset_of!(Rbc, rlc_ul_gen_pdu_fn), 0xf0);
        assert_eq!(offset_of!(Rbc, pdcp_cnf_fn), 0xf4);
        assert_eq!(offset_of!(Rbc, pdcp_to_rlc_ring), 0xf8);
        assert_eq!(offset_of!(Rbc, pdcp_to_rlc_wr), 0xfc);
        assert_eq!(offset_of!(Rbc, pdcp_to_rlc_committed), 0xfe);
        assert_eq!(offset_of!(Rbc, pdcp_to_rlc_rd), 0x100);
        assert_eq!(offset_of!(Rbc, pdcp_to_rlc_size), 0x102);
        assert_eq!(offset_of!(Rbc, cur_sdu_sn), 0x104);
        assert_eq!(offset_of!(Rbc, pdcp_to_rlc_cnt), 0x106);
        assert_eq!(offset_of!(Rbc, cur_sdu_rem), 0x108);
        assert_eq!(offset_of!(Rbc, pdcp_rlc_hdr_bo), 0x10a);
        assert_eq!(offset_of!(Rbc, pdcp_rlc_tx_bo), 0x10c);
        assert_eq!(offset_of!(Rbc, cur_sdu_ptr), 0x110);
        assert_eq!(offset_of!(Rbc, reest_ring), 0x114);
        assert_eq!(offset_of!(Rbc, reest_wr), 0x118);
        assert_eq!(offset_of!(Rbc, reest_committed), 0x11a);
        assert_eq!(offset_of!(Rbc, reest_ack_rd), 0x11c);
        assert_eq!(offset_of!(Rbc, reest_size), 0x11e);
        assert_eq!(offset_of!(Rbc, reest_rd), 0x120);
        assert_eq!(offset_of!(Rbc, reest_cnt), 0x122);
        assert_eq!(offset_of!(Rbc, reest_cur_rem), 0x124);
        assert_eq!(offset_of!(Rbc, rlc_reest_hdr_bo), 0x126);
        assert_eq!(offset_of!(Rbc, rlc_reest_tx_bo), 0x128);
        assert_eq!(offset_of!(Rbc, reest_cur_ptr), 0x12c);
        assert_eq!(offset_of!(Rbc, ring_pending_bytes), 0x130);
        assert_eq!(offset_of!(Rbc, vr_r), 0x138);
        assert_eq!(offset_of!(Rbc, vr_h), 0x13a);
        assert_eq!(offset_of!(Rbc, vr_ms), 0x13c);
        assert_eq!(offset_of!(Rbc, vr_x), 0x13e);
        assert_eq!(offset_of!(Rbc, rlc_tm_bo), 0x140);
        assert_eq!(offset_of!(Rbc, rlc_status_bo), 0x144);
        assert_eq!(offset_of!(Rbc, dl_rx_buf), 0x14c);
        assert_eq!(offset_of!(Rbc, dl_seg_pool), 0x150);
        assert_eq!(offset_of!(Rbc, rlc_am_newtx_bo), 0x154);
        assert_eq!(offset_of!(Rbc, rlc_am_retx_bo), 0x158);
        assert_eq!(offset_of!(Rbc, ul_ctrl_pdu_cnt), 0x168);
        assert_eq!(offset_of!(Rbc, max_retx_threshold), 0x169);
        assert_eq!(offset_of!(Rbc, status_trigger), 0x16a);
        assert_eq!(offset_of!(Rbc, poll_cfg_flags), 0x16b);
        assert_eq!(offset_of!(Rbc, poll_trigger), 0x16c);
        assert_eq!(offset_of!(Rbc, start_poll_retx_tmr), 0x16d);
        assert_eq!(offset_of!(Rbc, poll_sn), 0x16e);
        assert_eq!(offset_of!(Rbc, poll_pdu), 0x170);
        assert_eq!(offset_of!(Rbc, t_poll_retx_tmr_id), 0x172);
        assert_eq!(offset_of!(Rbc, vt_a), 0x174);
        assert_eq!(offset_of!(Rbc, vt_s), 0x176);
        assert_eq!(offset_of!(Rbc, t_status_prohibit_tmr_id), 0x178);
        assert_eq!(offset_of!(Rbc, status_pdu_len), 0x17a);
        assert_eq!(offset_of!(Rbc, pdu_without_poll), 0x17c);
        assert_eq!(offset_of!(Rbc, poll_byte), 0x180);
        assert_eq!(offset_of!(Rbc, byte_without_poll), 0x184);
        assert_eq!(offset_of!(Rbc, status_pdu_ptr), 0x188);
        assert_eq!(offset_of!(Rbc, active_tx_build_ctx), 0x18c);
        assert_eq!(offset_of!(Rbc, ul_am_hdr_buf), 0x190);
        assert_eq!(offset_of!(Rbc, ul_am_hdr_buf_off), 0x194);
        assert_eq!(offset_of!(Rbc, ul_am_sdu_desc_idx), 0x196);
        assert_eq!(offset_of!(Rbc, ul_am_sdu_desc_cap), 0x198);
        assert_eq!(offset_of!(Rbc, ul_am_free_win_slots), 0x19a);
        assert_eq!(offset_of!(Rbc, ul_am_sdu_desc_pool), 0x19c);
        assert_eq!(offset_of!(Rbc, ul_am_tx_buf), 0x1b0);
        assert_eq!(offset_of!(Rbc, ul_am_tx_head), 0x1b4);
        assert_eq!(offset_of!(Rbc, ul_am_tx_tail), 0x1b8);
        assert_eq!(offset_of!(Rbc, retx_node_freelist), 0x1bc);
        assert_eq!(offset_of!(Rbc, retx_node_freelist_tail), 0x1c0);
        assert_eq!(offset_of!(Rbc, retx_node_free_cnt), 0x1c4);
        assert_eq!(offset_of!(Rbc, retx_node_pool), 0x1c8);
        assert_eq!(offset_of!(Rbc, ul_am_retx_ring), 0x1cc);
        assert_eq!(offset_of!(Rbc, retx_wr), 0x1d0);
        assert_eq!(offset_of!(Rbc, retx_rd), 0x1d2);
        assert_eq!(offset_of!(Rbc, retx_cnt), 0x1d4);
        assert_eq!(offset_of!(Rbc, retx_hdr_bo), 0x1d6);
        assert_eq!(offset_of!(Rbc, retx_bytes), 0x1d8);
        assert_eq!(offset_of!(Rbc, tx_status_buf), 0x1ec);
        assert_eq!(offset_of!(Rbc, tx_status_len), 0x1f0);
        assert_eq!(offset_of!(Rbc, am_extra_hdr_bo), 0x1f2);
        assert_eq!(offset_of!(Rbc, tx_status_ack_sn), 0x1f4);
        assert_eq!(offset_of!(Rbc, tx_status_nack_cnt), 0x1f6);
        assert_eq!(offset_of!(Rbc, tx_status_nack_list), 0x1f8);
        assert_eq!(offset_of!(Rbc, ul_data_pdu_cnt), 0x200);
        assert_eq!(offset_of!(Rbc, tx_status_truncated), 0x202);
        assert_eq!(offset_of!(Rbc, tx_status_sent_len), 0x204);
        assert_eq!(offset_of!(Rbc, tx_status_nack_bits), 0x206);
        assert_eq!(offset_of!(Rbc, retx_seg_desc_idx), 0x208);
        assert_eq!(offset_of!(Rbc, retx_seg_hdr_off), 0x20a);
        assert_eq!(offset_of!(Rbc, rohc_enabled), 0x210);
        assert_eq!(offset_of!(Rbc, rohc_ctx_tbl), 0x21c);
        assert_eq!(offset_of!(Rbc, pdcp_discard_timer_ms), 0x236);
        assert_eq!(offset_of!(Rbc, bo_hold_last_cnt), 0x240);
        assert_eq!(offset_of!(Rbc, bo_margin_bytes), 0x244);

        assert_eq!(size_of::<RlcAmTxEntry>(), 0x40);
        assert_eq!(offset_of!(RlcAmTxEntry, seg_pool_start_idx), 0x00);
        assert_eq!(offset_of!(RlcAmTxEntry, seg_count), 0x02);
        assert_eq!(offset_of!(RlcAmTxEntry, total_len), 0x04);
        assert_eq!(offset_of!(RlcAmTxEntry, pdu_desc), 0x08);
        assert_eq!(offset_of!(RlcAmTxEntry, sn), 0x0c);
        assert_eq!(offset_of!(RlcAmTxEntry, retx_list_len), 0x0e);
        assert_eq!(offset_of!(RlcAmTxEntry, retx_count), 0x10);
        assert_eq!(offset_of!(RlcAmTxEntry, meta_flags), 0x11);
        assert_eq!(offset_of!(RlcAmTxEntry, tx_state_flags), 0x12);
        assert_eq!(offset_of!(RlcAmTxEntry, was_nacked), 0x13);
        assert_eq!(offset_of!(RlcAmTxEntry, in_retx_queue), 0x14);
        assert_eq!(offset_of!(RlcAmTxEntry, retx_head), 0x38);
        assert_eq!(offset_of!(RlcAmTxEntry, retx_tail), 0x3c);

        assert_eq!(size_of::<RlcAmRetxEntry>(), 0x18);
        assert_eq!(offset_of!(RlcAmRetxEntry, sn), 0x00);
        assert_eq!(offset_of!(RlcAmRetxEntry, fi_flags), 0x02);
        assert_eq!(offset_of!(RlcAmRetxEntry, flags), 0x03);
        assert_eq!(offset_of!(RlcAmRetxEntry, seg_state), 0x04);
        assert_eq!(offset_of!(RlcAmRetxEntry, is_so_nack), 0x05);
        assert_eq!(offset_of!(RlcAmRetxEntry, tx_entry), 0x08);
        assert_eq!(offset_of!(RlcAmRetxEntry, retx_node), 0x0c);
        assert_eq!(offset_of!(RlcAmRetxEntry, seg_sdu_idx), 0x10);
        assert_eq!(offset_of!(RlcAmRetxEntry, seg_sdu_off), 0x12);
        assert_eq!(offset_of!(RlcAmRetxEntry, seg_rem_bytes), 0x14);
        assert_eq!(offset_of!(RlcAmRetxEntry, seg_so), 0x16);

        assert_eq!(size_of::<L2TimerEntry>(), 0x10);
        assert_eq!(offset_of!(L2TimerEntry, callback), 0x00);
        assert_eq!(offset_of!(L2TimerEntry, arg), 0x04);
        assert_eq!(offset_of!(L2TimerEntry, duration_ms), 0x08);
        assert_eq!(offset_of!(L2TimerEntry, periodic), 0x0c);
        assert_eq!(offset_of!(L2TimerEntry, prio), 0x0d);
        assert_eq!(offset_of!(L2TimerEntry, state), 0x0e);
        assert_eq!(offset_of!(L2TimerEntry, active_idx), 0x0f);

        assert_eq!(size_of::<LlceDesc>(), 0x30);
        assert_eq!(offset_of!(LlceDesc, hdr_be), 0x00);
        assert_eq!(offset_of!(LlceDesc, count_be), 0x04);
        assert_eq!(offset_of!(LlceDesc, next_desc_be), 0x0c);
        assert_eq!(offset_of!(LlceDesc, len_be), 0x20);
        assert_eq!(offset_of!(LlceDesc, src_be), 0x24);
        assert_eq!(offset_of!(LlceDesc, dst_be), 0x28);

        assert_eq!(size_of::<IrbLatTracker>(), 0x18);
        assert_eq!(offset_of!(IrbLatTracker, tracked_seq), 0x08);
        assert_eq!(offset_of!(IrbLatTracker, enqueue_tti), 0x0c);
        assert_eq!(offset_of!(IrbLatTracker, last_print_tti), 0x10);
        assert_eq!(offset_of!(IrbLatTracker, max_sojourn_ms), 0x14);
    }

    #[test]
    fn mac_layouts_match_disassembly() {
        assert_eq!(size_of::<MacUlLcCfg>(), 0x14);
        assert_eq!(offset_of!(MacUlLcCfg, priority), 0x04);
        assert_eq!(offset_of!(MacUlLcCfg, lcg_id), 0x05);
        assert_eq!(offset_of!(MacUlLcCfg, pbr_bytes_per_tti), 0x08);

        assert_eq!(size_of::<MacUlLcgState>(), 0x08);
        assert_eq!(offset_of!(MacUlLcgState, has_data), 0x00);
        assert_eq!(offset_of!(MacUlLcgState, bo_bytes), 0x04);
        assert_eq!(size_of::<MacUlBsrCtx>(), 0x5c);
        assert_eq!(offset_of!(MacUlBsrCtx, bsr_sent_in_tb), 0x00);
        assert_eq!(offset_of!(MacUlBsrCtx, bsr_pending), 0x01);
        assert_eq!(offset_of!(MacUlBsrCtx, sr_triggered_flag), 0x02);
        assert_eq!(offset_of!(MacUlBsrCtx, bsr_trigger_mask), 0x04);
        assert_eq!(offset_of!(MacUlBsrCtx, highest_prio_with_data), 0x08);
        assert_eq!(offset_of!(MacUlBsrCtx, lc_bo), 0x0c);
        assert_eq!(offset_of!(MacUlBsrCtx, default_lcg), 0x38);
        assert_eq!(offset_of!(MacUlBsrCtx, trigger_lcg), 0x39);
        assert_eq!(offset_of!(MacUlBsrCtx, retx_bsr_has_data), 0x3b);
        assert_eq!(offset_of!(MacUlBsrCtx, lcg), 0x3c);

        assert_eq!(size_of::<MacUlCfg>(), 0x160);
        assert_eq!(offset_of!(MacUlCfg, feature_flags), 0x00);
        assert_eq!(offset_of!(MacUlCfg, duplex_mode), 0x04);
        assert_eq!(offset_of!(MacUlCfg, tdd_ul_dl_cfg), 0x05);
        assert_eq!(offset_of!(MacUlCfg, bsr_timer_flags), 0x1c);
        assert_eq!(offset_of!(MacUlCfg, periodic_bsr_tmr_id), 0x20);
        assert_eq!(offset_of!(MacUlCfg, periodic_bsr_pending_ms), 0x28);
        assert_eq!(offset_of!(MacUlCfg, periodic_bsr_dirty), 0x2a);
        assert_eq!(offset_of!(MacUlCfg, retx_bsr_tmr_id), 0x44);
        assert_eq!(offset_of!(MacUlCfg, retx_bsr_pending_ms), 0x4c);
        assert_eq!(offset_of!(MacUlCfg, retx_bsr_dirty), 0x4e);
        assert_eq!(offset_of!(MacUlCfg, max_harq_tx), 0x5d);
        assert_eq!(offset_of!(MacUlCfg, phr_mode), 0x68);
        assert_eq!(offset_of!(MacUlCfg, active_lc_mask), 0x70);
        assert_eq!(offset_of!(MacUlCfg, lc_cfg), 0x74);
        assert_eq!(
            offset_of!(MacUlCfg, lc_cfg) + offset_of!(MacUlLcCfg, priority),
            0x78
        );
        assert_eq!(
            offset_of!(MacUlCfg, lc_cfg) + offset_of!(MacUlLcCfg, lcg_id),
            0x79
        );
        assert_eq!(
            offset_of!(MacUlCfg, lc_cfg) + offset_of!(MacUlLcCfg, pbr_bytes_per_tti),
            0x7c
        );
        assert_eq!(offset_of!(MacUlCfg, tti_bundling_en), 0x150);
        assert_eq!(offset_of!(MacUlCfg, ext_bsr_mode), 0x152);
        assert_eq!(offset_of!(MacUlCfg, meas_gap_en), 0x15c);

        assert_eq!(size_of::<MacUlLcBoPair>(), 0x08);
        assert_eq!(size_of::<MacUlLcPbr>(), 0x08);
        assert_eq!(size_of::<MacUlLcpTbl>(), 0x110);
        assert_eq!(offset_of!(MacUlLcpTbl, total_bo), 0x00);
        assert_eq!(offset_of!(MacUlLcpTbl, active_prio_mask), 0x04);
        assert_eq!(offset_of!(MacUlLcpTbl, prio_lc_mask), 0x08);
        assert_eq!(offset_of!(MacUlLcpTbl, prio_rr_cursor), 0x4c);
        assert_eq!(offset_of!(MacUlLcpTbl, lc_bo), 0x60);
        assert_eq!(offset_of!(MacUlLcpTbl, lc_pbr), 0xb8);

        assert_eq!(size_of::<MacUlGlobal>(), 0x30);
        assert_eq!(offset_of!(MacUlGlobal, pending_newtx_cnt), 0x14);
        assert_eq!(offset_of!(MacUlGlobal, sfn_wrap_cnt), 0x1c);
        assert_eq!(offset_of!(MacUlGlobal, sps_interval), 0x20);
        assert_eq!(offset_of!(MacUlGlobal, sps_last_tti), 0x24);
        assert_eq!(offset_of!(MacUlGlobal, sps_implicit_rel_after), 0x28);
        assert_eq!(offset_of!(MacUlGlobal, sps_active), 0x2b);
        assert_eq!(offset_of!(MacUlGlobal, sps_zero_sdu_cnt), 0x2c);

        assert_eq!(size_of::<MacUlSchedInfo>(), 0x64);
        assert_eq!(offset_of!(MacUlSchedInfo, tti), 0x00);
        assert_eq!(offset_of!(MacUlSchedInfo, valid), 0x04);
        assert_eq!(offset_of!(MacUlSchedInfo, cc), 0x10);
        assert_eq!(offset_of!(MacUlSchedInfo, tb_size), 0x14);
        assert_eq!(offset_of!(MacUlSchedInfo, mcs), 0x20);
        assert_eq!(offset_of!(MacUlSchedInfo, ndi), 0x21);
        assert_eq!(offset_of!(MacUlSchedInfo, eff_mcs), 0x30);
        assert_eq!(offset_of!(MacUlSchedInfo, eff_ndi), 0x32);
        assert_eq!(offset_of!(MacUlSchedInfo, eff_tb_size), 0x34);
        assert_eq!(offset_of!(MacUlSchedInfo, harq_action), 0x44);
        assert_eq!(offset_of!(MacUlSchedInfo, has_grant), 0x4c);
        assert_eq!(offset_of!(MacUlSchedInfo, phich_ack_raw), 0x50);
        assert_eq!(offset_of!(MacUlSchedInfo, phich_ack), 0x5c);

        assert_eq!(offset_of!(MacTbBuildFrame, packed_lc_mask), 0x2c);
        assert_eq!(offset_of!(MacTbBuildFrame, tb_size), 48);
        assert_eq!(offset_of!(MacTbBuildFrame, tb_idx), 0x38);
        assert_eq!(offset_of!(MacTbBuildFrame, ce_enable_mask), 0x3c);
        assert_eq!(offset_of!(MacTbBuildFrame, used_bytes), 92);
        assert_eq!(offset_of!(MacTbBuildFrame, last_subhdr_ptr), 0x60);
        assert_eq!(offset_of!(MacTbBuildFrame, mac_hdr_len), 0x64);
        assert_eq!(offset_of!(MacTbBuildFrame, bsr_type), 0x68);
        assert_eq!(offset_of!(MacTbBuildFrame, bsr_lcid), 108);
        assert_eq!(offset_of!(MacTbBuildFrame, deferred_bsr_flag), 112);
        assert_eq!(offset_of!(MacTbBuildFrame, has_trailing_pad), 113);

        assert_eq!(offset_of!(MacRaSrCtx, ra_state), 0x00);
        assert_eq!(offset_of!(MacRaSrCtx, sr_configured), 0xec);
        assert_eq!(offset_of!(MacRaSrCtx, sr_pending), 0xed);
        assert_eq!(offset_of!(MacRaSrCtx, sr_pucch_valid), 0xee);
        assert_eq!(offset_of!(MacRaSrCtx, sr_counter), 0xf0);
        assert_eq!(offset_of!(MacRaSrCtx, dsr_trans_max_active), 0xf4);
        assert_eq!(offset_of!(MacRaSrCtx, dsr_trans_max_cfg), 0xf8);
        assert_eq!(offset_of!(MacRaSrCtx, sr_to_rach_cnt), 0x1a4);

        assert_eq!(size_of::<MacHarqProc>(), 0x78);
        assert_eq!(offset_of!(MacHarqProc, harq_feedback), 0x04);
        assert_eq!(offset_of!(MacHarqProc, prev_ndi), 0x0c);
        assert_eq!(offset_of!(MacHarqProc, mcs), 0x0d);
        assert_eq!(offset_of!(MacHarqProc, current_tx_nb), 0x0e);
        assert_eq!(offset_of!(MacHarqProc, max_harq_tx), 0x0f);
        assert_eq!(offset_of!(MacHarqProc, rv_idx), 0x11);
        assert_eq!(offset_of!(MacHarqProc, rv), 0x12);
        assert_eq!(offset_of!(MacHarqProc, pending_action), 0x20);
        assert_eq!(offset_of!(MacHarqProc, tb_buf), 0x68);
        assert_eq!(offset_of!(MacHarqProc, tb_pool_handle), 0x6c);
        assert_eq!(size_of::<[MacHarqProc; 8]>(), 0x3c0);
    }

    #[test]
    fn patch_control_blocks_match_live_memory_map() {
        assert_eq!(offset_of!(N4State, magic), 0x00);
        assert_eq!(offset_of!(N4State, flags), 0x04);
        assert_eq!(offset_of!(N4State, pdcp_min), 0x08);
        assert_eq!(offset_of!(N4State, pdcp_max), 0x0c);
        assert_eq!(offset_of!(N4State, aqm_ivl_ms), 0x18);
        assert_eq!(offset_of!(N4State, pad_tti), 0x28);
        assert_eq!(offset_of!(N4State, g_ema), 0x2c);
        assert_eq!(offset_of!(N4State, last_arr_tti), 0x3c);
        assert_eq!(offset_of!(N4State, a_ema), 0x48);
        assert_eq!(offset_of!(N4State, last_drb_rbc), 0x50);
        assert_eq!(offset_of!(N4State, cnt_tb), 0x58);
        assert_eq!(offset_of!(N4State, cnt_aqm_mark), 0x64);
        assert_eq!(offset_of!(N4State, cnt_aqm_drop), 0x68);
        assert_eq!(offset_of!(N4State, cnt_sh_fix), 0x70);
        assert_eq!(offset_of!(N4State, aqm_minlen), 0x74);
        assert_eq!(offset_of!(N4State, aqm_qmin), 0x78);
        assert_eq!(offset_of!(N4State, cnt_spared), 0x7c);

        assert_eq!(size_of::<N4ExtCounters>(), 0x1c);
        assert_eq!(offset_of!(N4ExtCounters, cnt_bsr_all), 0x00);
        assert_eq!(offset_of!(N4ExtCounters, cnt_drop_hard), 0x10);
        assert_eq!(offset_of!(N4ExtCounters, cnt_sh_zero), 0x18);

        assert_eq!(size_of::<N5FlowEntry>(), 0x10);
        assert_eq!(offset_of!(N5State, magic), 0x00);
        assert_eq!(offset_of!(N5State, flags), 0x08);
        assert_eq!(offset_of!(N5State, pdcp_min), 0x20);
        assert_eq!(offset_of!(N5State, pdcp_max), 0x24);
        assert_eq!(offset_of!(N5State, c_promo_pkts), 0x40);
        assert_eq!(offset_of!(N5State, c_r1_nonempty_hold), 0x6c);
        assert_eq!(offset_of!(N5State, last_r1_rd), 0x80);
        assert_eq!(offset_of!(N5State, r1_deq_seq), 0x90);
        assert_eq!(offset_of!(N5State, flow_tbl), 0xb0);
        assert_eq!(size_of::<N5State>(), 0x4b0);

        assert_eq!(size_of::<N6U2State>(), 0x40);
        assert_eq!(offset_of!(N6U2State, flags), 0x08);
        assert_eq!(offset_of!(N6U2State, c_ack_expire), 0x0c);
        assert_eq!(offset_of!(N6U2State, c_true_cc), 0x10);

        assert_eq!(size_of::<C1Tk2State>(), 0x100);
        assert_eq!(offset_of!(C1Tk2State, flags), 0x08);
        assert_eq!(offset_of!(C1Tk2State, pending), 0x0c);
        assert_eq!(offset_of!(C1Tk2State, buf), 0x40);

        assert_eq!(size_of::<UlbBsrState>(), 0x100);
        assert_eq!(offset_of!(UlbBsrState, flags), 0x08);
        assert_eq!(offset_of!(UlbBsrState, floor_min), 0x20);
        assert_eq!(offset_of!(UlbBsrState, floor_max), 0x24);
        assert_eq!(offset_of!(UlbBsrState, c_calls), 0x40);
    }

    #[test]
    fn bsr_table_lookups_match_3gpp_and_tk_rom() {
        assert_eq!(bsr_index_std(0), 0);
        assert_eq!(bsr_index_std(10), 1);
        assert_eq!(bsr_index_std(11), 2);
        assert_eq!(bsr_index_std(36_304), 53);
        assert_eq!(bsr_index_std(36_305), 54);
        assert_eq!(bsr_index_std(98_304), 60);
        assert_eq!(bsr_index_std(150_000), 62);
        assert_eq!(bsr_index_std(150_001), 63);

        assert_eq!(bsr_index_ext(0), 0);
        assert_eq!(bsr_index_ext(10), 1);
        assert_eq!(bsr_index_ext(39_045), 41);
        assert_eq!(bsr_index_ext(109_774), 46);
        assert_eq!(bsr_index_ext(3_000_000), 62);
        assert_eq!(bsr_index_ext(3_000_001), 63);
    }
}
