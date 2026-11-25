//! Compact 32-byte fixed-size MAC UL timeline record format.
//!
//! Pure `no_std`, `#![forbid(unsafe_code)]`.

#![forbid(unsafe_code)]

use modem_atlas::mac::{MAC_LCID_LONG_BSR, MAC_LCID_SHORT_BSR, MAC_LCID_TRUNCATED_BSR};

/// Event kind stored in `TraceRecord::flags0` bits `0..=2`.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EventKind {
    Empty = 0,
    /// New transmission built by `GenerateMacUlPdu`.
    NewTx = 1,
    /// Adaptive HARQ retransmission (DCI-0 same NDI, `pending_action == 1`).
    AdaptRetx = 2,
    /// Non-adaptive HARQ retransmission (PHICH NACK, `pending_action == 2`).
    NonAdaptRetx = 3,
    /// Scheduling Request transmitted on PUCCH (`GetMacUlSR`).
    PucchSr = 4,
}

/// BSR format code stored in `TraceRecord::flags1` bits `6..=7`.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BsrFormat {
    None = 0,
    Short = 1,
    Truncated = 2,
    Long = 3,
}

impl BsrFormat {
    #[inline]
    pub const fn from_lcid(lcid: u8) -> Self {
        match lcid {
            MAC_LCID_SHORT_BSR => Self::Short,
            MAC_LCID_TRUNCATED_BSR => Self::Truncated,
            MAC_LCID_LONG_BSR => Self::Long,
            _ => Self::None,
        }
    }
}

/// Single-carrier PHR sample captured from `MacPhrState`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PhrSample {
    pub active: bool,
    /// `true` when virtual PHR (`V = 1`, no real PUSCH / `Pcmax,c` omitted).
    pub virtual_phr: bool,
    /// 6-bit Power Headroom index (`0..=63`, 3GPP TS 36.133 Table 9.1.8.4-1).
    pub ph: u8,
    /// 6-bit `Pcmax,c` index (`0..=63`, `0xff` when virtual or absent).
    pub pcmax: u8,
}

impl PhrSample {
    pub const ABSENT: Self = Self {
        active: false,
        virtual_phr: false,
        ph: 0,
        pcmax: 0xff,
    };

    #[inline]
    pub const fn pack_ph_v(self) -> u8 {
        if !self.active {
            return 0;
        }
        0x80 | if self.virtual_phr { 0x40 } else { 0 } | (self.ph & 0x3f)
    }

    #[inline]
    pub const fn pack_pcmax(self) -> u8 {
        if !self.active || self.virtual_phr || self.pcmax == 0xff {
            0xff
        } else {
            self.pcmax & 0x3f
        }
    }
}

/// 32-byte fixed-size MAC timeline event record written to `G1_RING`.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct TraceRecord {
    /// `+0x00`: Monotonic 1 ms L2 TTI clock (`TTI_CLK_VA` `0x84a1_f860`).
    pub tti_ms: u32,
    /// `+0x04`: LTE air timing `sfn * 10 + sf` (`0..10239`; `sfn = sti / 10`, `sf = sti % 10`).
    pub air_sti: u16,
    /// `+0x06`: `kind:3 | cc:2 | hq_id:3`? No: `kind:3 (0..2) | cc:1 (3) | hq_id:3 (4..6) | ext_bsr:1 (7)`.
    /// Keeping `cc` in bit 3 (`0`=PCell, `1`=SCell; `cc & 1`) leaves 3 full bits for `hq_id` (`0..7`).
    pub flags0: u8,
    /// `+0x07`: `ce_mask_lo4:4 (0..3: C-RNTI, BSR, RegPHR, ExtPHR) | dc_phr:1 (4) | has_trailing_pad:1 (5) | bsr_fmt:2 (6..7)`.
    pub flags1: u8,
    /// `+0x08`: UL grant TBS in bytes (NewTx & Retx; `sr_counter` for `PucchSr`).
    pub tbs_bytes: u16,
    /// `+0x0a`: NewTx: bytes used in TB (`pad = tbs_bytes.saturating_sub(used)`).
    /// Retx: low byte = `mcs`, high byte = `(tx_nb << 2) | (rv & 3)`.
    /// PucchSr: `0`.
    pub used_or_retx: u16,
    /// `+0x0c`: `bsr_trig:5 (0..4) | bsr_is_padding:1 (5) | phr_evt_lo2:2 (6..7)`.
    pub bsr_trig: u8,
    /// `+0x0d..+0x0f`: Exact serialized BSR MAC CE bytes from `ce_buf[0..3]`.
    pub bsr_ce: [u8; 3],
    /// `+0x10`: PCell PHR packed as `active:1 (7) | V:1 (6) | PH:6 (0..5)`.
    pub phr_cc0_ph_v: u8,
    /// `+0x11`: PCell `Pcmax,c` (`0..=63`, `0xff` if virtual/absent/regular PHR).
    pub phr_cc0_pcmax: u8,
    /// `+0x12`: SCell PHR packed as `active:1 (7) | V:1 (6) | PH:6 (0..5)`.
    pub phr_cc1_ph_v: u8,
    /// `+0x13`: SCell `Pcmax,c` (`0..=63`, `0xff` if virtual/absent).
    pub phr_cc1_pcmax: u8,
    /// `+0x14`: Total Ring-1 pending bytes at TB build time (`sum(L2_BSR_PRE_BO_VA[0..4])`).
    pub ring1_bytes: u32,
    /// `+0x18`: Total post-TB RLC BO bytes across all 4 LCGs (`sum(MacUlBsrCtx::lcg[0..4].bo_bytes)`).
    pub rlc_bo_bytes: u32,
    /// `+0x1c`: Monotonic write sequence (`wr_idx` at record write time).
    pub seq: u32,
}

const _: () = assert!(core::mem::size_of::<TraceRecord>() == 32);

impl TraceRecord {
    #[inline]
    pub const fn pack_flags0(kind: EventKind, cc: u8, hq_id: u8, ext_bsr_mode: bool) -> u8 {
        ((kind as u8) & 0x07)
            | ((cc & 0x01) << 3)
            | ((hq_id & 0x07) << 4)
            | if ext_bsr_mode { 0x80 } else { 0 }
    }

    #[inline]
    pub const fn pack_flags1(ce_mask: u8, has_trailing_pad: bool, bsr_fmt: BsrFormat) -> u8 {
        (ce_mask & 0x1f)
            | if has_trailing_pad { 0x20 } else { 0 }
            | (((bsr_fmt as u8) & 0x03) << 6)
    }

    #[inline]
    pub const fn pack_bsr_trig(bsr_trigger_mask: u32, bsr_is_padding: bool, phr_event: u32) -> u8 {
        ((bsr_trigger_mask as u8) & 0x1f)
            | if bsr_is_padding { 0x20 } else { 0 }
            | (((phr_event as u8) & 0x03) << 6)
    }

    #[inline]
    pub const fn pack_retx_meta(mcs: u8, tx_nb: u8, rv: u8) -> u16 {
        (mcs as u16) | (((((tx_nb & 0x3f) << 2) | (rv & 0x03)) as u16) << 8)
    }

    #[inline]
    pub const fn kind(&self) -> u8 {
        self.flags0 & 0x07
    }

    #[inline]
    pub const fn cc(&self) -> u8 {
        (self.flags0 >> 3) & 0x01
    }

    #[inline]
    pub const fn hq_id(&self) -> u8 {
        (self.flags0 >> 4) & 0x07
    }

    #[inline]
    pub const fn ext_bsr(&self) -> bool {
        (self.flags0 & 0x80) != 0
    }
}
