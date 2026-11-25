//! Pure-Rust, `#![forbid(unsafe_code)]` logic and control block for the Lane N2
//! PDCP/RLC/BSR uplink hot-path optimizations.

#![forbid(unsafe_code)]

/// Control block VA (`0x841b_b5c0` inside dead `UMM_DisplayUSIMPINInfo` `0x841b_b5be..0x841b_b87c`).
pub const N2_OPT_BLK_VA: u32 = 0x841b_b5c0;
/// Magic word `"N2OP"` (`0x4e32_4f50`).
pub const N2_OPT_MAGIC: u32 = 0x4e32_4f50;
/// Version word (`2026-11-25`).
pub const N2_OPT_VERSION: u32 = 0x2026_1125;

/// Bit 0: fast `SearchMacUlBoIdx` (`0x842c_cf64`) with `bo == 0` early-exit & compact binary search.
pub const N2_FLAG_FAST_BSR: u32 = 1 << 0;
/// Bit 1: fast `l2_proc_pdcp_ul` (`0x842d_ccd0`) division (`fp == 0` early-exit + Cortex-A7 `udiv`).
pub const N2_FLAG_FAST_DIV: u32 = 1 << 1;
/// Bit 2: byte-accurate Ring 1 packet admission at `0x842d_ccd0` (replaces `/ 1500` floor quantization).
pub const N2_FLAG_BYTE_PACING: u32 = 1 << 2;
/// Bit 3: `do_tc` (`0x842e_5b06`) target-ms staging cap clamp (`clamp(ul_250ms * target_ms / 250, min, max)`).
pub const N2_FLAG_DO_TC_CAP: u32 = 1 << 3;
/// Mask of all recognized feature bits; any unknown bit forces all optimizations OFF.
pub const N2_FLAGS_KNOWN_MASK: u32 =
    N2_FLAG_FAST_BSR | N2_FLAG_FAST_DIV | N2_FLAG_BYTE_PACING | N2_FLAG_DO_TC_CAP;

/// Boot-off control block and telemetry counters (`64` bytes, `#[repr(C)]`, live-writable via `wm`).
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct N2OptState {
    /// `+0x00`: Magic `"N2OP"` (`0x4e32_4f50`).
    pub magic: u32,
    /// `+0x04`: Version (`0x2026_1125`).
    pub version: u32,
    /// `+0x08`: Feature bitmask (boots `0` = all off; unknown bits force all off).
    pub flags: u32,
    /// `+0x0c`: Target staging depth in ms for `FLAG_DO_TC_CAP` (default `8` ms).
    pub cap_target_ms: u32,
    /// `+0x10`: Minimum staging cap in bytes for `FLAG_DO_TC_CAP` (default `6_144` B).
    pub cap_min_bytes: u32,
    /// `+0x14`: Maximum staging cap in bytes for `FLAG_DO_TC_CAP` (default `12_288` B).
    pub cap_max_bytes: u32,
    /// `+0x18`: Counter — `SearchMacUlBoIdx` `bo == 0` fast early exits.
    pub cnt_bsr_zero_fast: u32,
    /// `+0x1c`: Counter — `SearchMacUlBoIdx` non-zero fast lookups.
    pub cnt_bsr_nonzero_fast: u32,
    /// `+0x20`: Counter — `l2_proc_pdcp_ul` `fp == 0` empty-Ring-1 division skips.
    pub cnt_div_empty_skip: u32,
    /// `+0x24`: Counter — `l2_proc_pdcp_ul` fast hardware `udiv` calls.
    pub cnt_div_fast: u32,
    /// `+0x28`: Counter — `l2_proc_pdcp_ul` byte-accurate admission calls.
    pub cnt_byte_paced: u32,
    /// `+0x2c`: Counter — `do_tc` cap clamps applied.
    pub cnt_do_tc_clamped: u32,
    /// `+0x30`: Last staging cap computed by `FLAG_DO_TC_CAP`.
    pub last_do_tc_cap: u32,
    /// `+0x34..+0x3f`: Reserved (zero-initialized).
    pub _rsvd: [u32; 3],
}

impl N2OptState {
    pub const fn boot_default() -> Self {
        Self {
            magic: N2_OPT_MAGIC,
            version: N2_OPT_VERSION,
            flags: 0, // Every switch boots OFF!
            cap_target_ms: 8,
            cap_min_bytes: 6_144,
            cap_max_bytes: 12_288,
            cnt_bsr_zero_fast: 0,
            cnt_bsr_nonzero_fast: 0,
            cnt_div_empty_skip: 0,
            cnt_div_fast: 0,
            cnt_byte_paced: 0,
            cnt_do_tc_clamped: 0,
            last_do_tc_cap: 0,
            _rsvd: [0; 3],
        }
    }

    /// Returns validated active flags, or `0` if magic is wrong or any unknown bit is set.
    #[inline]
    pub const fn active_flags(&self) -> u32 {
        if self.magic != N2_OPT_MAGIC {
            return 0;
        }
        if (self.flags & !N2_FLAGS_KNOWN_MASK) != 0 {
            return 0;
        }
        self.flags
    }
}

/// Pure-Rust branchless-friendly 6-step binary search matching stock
/// `SearchMacUlBoIdx` (`0x842c_cf64`) bit-for-bit across all `bo: 0..=u32::MAX`.
#[inline]
pub fn bsr_idx_from_table(bo: u32, table: &[u32; 63]) -> u8 {
    if bo == 0 {
        return 0;
    }
    if bo > table[62] {
        return 63;
    }
    // Invariant: bo > table[0] (0) and bo <= table[62].
    // Find largest k in 0..=61 with bo > table[k]; answer is k + 1.
    let mut k: usize = 0;
    if bo > table[k + 32] {
        k += 32;
    }
    if bo > table[k + 16] {
        k += 16;
    }
    if bo > table[k + 8] {
        k += 8;
    }
    if bo > table[k + 4] {
        k += 4;
    }
    if bo > table[k + 2] {
        k += 2;
    }
    if bo > table[(k + 1).min(62)] {
        k += 1;
    }
    (k + 1) as u8
}

/// Pure-Rust tuned `do_tc` staging cap (`FLAG_DO_TC_CAP`):
/// computes `clamp((ul_250ms_bytes * target_ms) / 250, cap_min, cap_max)` using
/// pure 32-bit arithmetic (zero 64-bit `__aeabi_uldivmod` helpers in Thumb-2!).
///
/// Uses `((ul_250ms_bytes >> 2) * target_ms * 1049) >> 16`:
/// note `1049 / (4 * 65536) = 1049 / 262144 = 0.0040016 ~= 1 / 250` (`+0.04%` accuracy),
/// avoiding any division or 64-bit libcall and clamping safely against overflow.
#[inline]
pub const fn compute_do_tc_cap(
    ul_250ms_bytes: u32,
    target_ms: u32,
    cap_min: u32,
    cap_max: u32,
) -> u32 {
    let min_b = if cap_min == 0 { 6_144 } else { cap_min };
    let max_b = if cap_max < min_b { min_b } else { cap_max };
    let t_ms = if target_ms == 0 {
        8
    } else if target_ms > 50 {
        50
    } else {
        target_ms
    };
    // Cap ul_250ms_bytes at 4 MiB / 250 ms (~134 Mbps) so intermediate never overflows u32:
    // (4_194_304 >> 2) = 1_048_576; * 1049 >> 16 = 16_784; * 50 = 839_200 << u32::MAX.
    let clamped_bytes = if ul_250ms_bytes > 0x0040_0000 {
        0x0040_0000
    } else {
        ul_250ms_bytes
    };
    let bytes_per_ms = ((clamped_bytes >> 2).wrapping_mul(1049)) >> 16;
    let desired = bytes_per_ms.wrapping_mul(t_ms);
    if desired < min_b {
        min_b
    } else if desired > max_b {
        max_b
    } else {
        desired
    }
}

/// Pure-Rust byte-accurate packet counter helper (`FLAG_BYTE_PACING`).
///
/// Walks `max_pkts` packet lengths yielded by `next_len(i)` (adding 2 B PDCP header per packet)
/// and returns how many head packets fit inside `headroom_bytes`.
#[inline]
pub fn count_fitting_packets<F>(headroom_bytes: u32, max_pkts: u32, mut next_len: F) -> u32
where
    F: FnMut(u32) -> Option<u16>,
{
    let mut acc: u32 = 0;
    let mut cnt: u32 = 0;
    while cnt < max_pkts {
        let Some(ip_len) = next_len(cnt) else {
            break;
        };
        let pdu_bytes = (ip_len as u32).saturating_add(2);
        if acc.saturating_add(pdu_bytes) > headroom_bytes {
            break;
        }
        acc += pdu_bytes;
        cnt += 1;
    }
    cnt
}
