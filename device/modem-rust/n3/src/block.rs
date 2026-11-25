//! Unified 128-byte boot-off control block (`MAC_PDCP_OPT_BLK_VA = 0x841b_b5c0`,
//! inside dead `UMM_DisplayUSIMPINInfo`) for the combined MAC/PDCP UL optimizer.
//!
//! Every feature bit boots OFF (`flags == 0`), and any unknown flag bit outside
//! [`KNOWN_FLAGS_MASK`] forces ALL optimizations OFF (stock byte-identical path).
//! All fields are single-copy-atomic relaxed `u32` words accessible via DM `vm`/`wm`.

#![forbid(unsafe_code)]

use core::sync::atomic::{AtomicU32, Ordering::Relaxed};

/// `"MPOP"` (`0x4d50_4f50` — valid Thumb-2 halfwords `0x4f50`, `0x4d50`).
pub const MAGIC: u32 = 0x4d50_4f50;
/// Layout version (`2026-11-25` — valid Thumb-2 halfwords `0x1125`, `0x2026`).
pub const VERSION: u32 = 0x2026_1125;

/// Bit 0 (`0x01`): fast `SearchMacUlBoIdx` (`0x842c_cf64`) — inline zero-stack `bo == 0`
/// early-exit + unrolled 6-step `bsr_index_in` search.
pub const FLAG_FAST_BSR_IDX: u32 = 1 << 0;
/// Bit 1 (`0x02`): O(1) early-exit on `CheckLongBsrDowngradeToShort` (`0x842c_fe34`)
/// when `<= 1` active LCG or `>= 2` LCGs exceed `tb_rem`.
pub const FLAG_FAST_LONG_BSR_CHECK: u32 = 1 << 1;
/// Bit 2 (`0x04`): guarded `mac_bsr_pre_work` (`0x842d_a60c`) — zeroes stale
/// `ring_pending_bytes` when Ring 0, Ring 1, and LLCE0 are all idle.
pub const FLAG_GUARDED_PRE_BO: u32 = 1 << 2;
/// Bit 3 (`0x08`): fast `l2_proc_pdcp_ul` (`0x842d_ccd0`) division — inline `fp == 0`
/// empty-Ring-1 skip + Cortex-A7 hardware `udiv` (replaces ARM `__aeabi_uidiv`).
pub const FLAG_FAST_PDCP_DIV: u32 = 1 << 3;
/// Bit 4 (`0x10`): opt-in byte-accurate Ring-1 packet admission at `0x842d_ccd0`
/// (replaces `/ 1500` floor quantization with exact head-packet length summing).
pub const FLAG_PDCP_BYTE_PACING: u32 = 1 << 4;
/// Bit 5 (`0x20`): `do_tc` (`0x842e_5b06`) 250 ms target-ms staging cap clamp
/// (`clamp(ul_250ms * cap_target_ms / 250, cap_min_bytes, cap_max_bytes)`).
pub const FLAG_DO_TC_CAP: u32 = 1 << 5;

/// Mask of all recognized feature bits (`0x3f`); any bit outside this mask forces all hooks OFF.
pub const KNOWN_FLAGS_MASK: u32 = FLAG_FAST_BSR_IDX
    | FLAG_FAST_LONG_BSR_CHECK
    | FLAG_GUARDED_PRE_BO
    | FLAG_FAST_PDCP_DIV
    | FLAG_PDCP_BYTE_PACING
    | FLAG_DO_TC_CAP;

/// Default target staging depth (ms) for [`FLAG_DO_TC_CAP`].
pub const DEFAULT_CAP_TARGET_MS: u32 = 8;
/// Default minimum staging cap (bytes) for [`FLAG_DO_TC_CAP`].
pub const DEFAULT_CAP_MIN_BYTES: u32 = 6_144;
/// Default maximum staging cap (bytes) for [`FLAG_DO_TC_CAP`].
pub const DEFAULT_CAP_MAX_BYTES: u32 = 12_288;

/// Single 32-bit word shared with DM console (`vm`/`wm`) and offline tooling.
#[repr(transparent)]
pub struct Word(AtomicU32);

impl Word {
    pub const fn new(value: u32) -> Self {
        Self(AtomicU32::new(value))
    }

    #[inline(always)]
    pub fn get(&self) -> u32 {
        self.0.load(Relaxed)
    }

    #[inline(always)]
    pub fn set(&self, value: u32) {
        self.0.store(value, Relaxed)
    }

    #[inline(always)]
    pub fn bump(&self) {
        self.set(self.get().wrapping_add(1))
    }
}

/// 128-byte boot-off control block placed in `.optblk` at `0x841b_b5c0`
/// (`UMM_DisplayUSIMPINInfo + 2`, 4-byte aligned, disjoint from N7 and all other lanes).
#[repr(C, align(4))]
pub struct MacPdcpOptBlock {
    /// `+0x00`: [`MAGIC`] (`0x4d50_4f50`, `"MPOP"`).
    pub magic: Word,
    /// `+0x04`: [`VERSION`] (`0x2026_1125`).
    pub version: Word,
    /// `+0x08`: Feature enable bitmask (`0` at boot = byte-identical stock behaviour).
    pub flags: Word,
    /// `+0x0c`: Target staging depth in ms for `FLAG_DO_TC_CAP` (default `8` ms).
    pub cap_target_ms: Word,
    /// `+0x10`: Minimum staging cap in bytes for `FLAG_DO_TC_CAP` (default `6_144` B).
    pub cap_min_bytes: Word,
    /// `+0x14`: Maximum staging cap in bytes for `FLAG_DO_TC_CAP` (default `12_288` B).
    pub cap_max_bytes: Word,

    /// `+0x18`: Non-zero `SearchMacUlBoIdx` calls handled by the unrolled 6-step fast path.
    pub cnt_bo_idx_nonzero: Word,
    /// `+0x1c`: `SearchMacUlBoIdx` calls taking the inline zero-stack `bo == 0` early-exit.
    pub cnt_bo_idx_zero: Word,
    /// `+0x20`: Total calls inspected by `CheckLongBsrDowngradeToShort` fast-path.
    pub cnt_downgrade_checks: Word,
    /// `+0x24`: `CheckLongBsrDowngradeToShort` calls that exited O(1) without LCP simulation.
    pub cnt_downgrade_fast_exit: Word,
    /// `+0x28`: Total calls handled by guarded `mac_bsr_pre_work`.
    pub cnt_pre_work_fast: Word,
    /// `+0x2c`: Bearers whose stale `ring_pending_bytes` was clamped to 0 by the empty-ring guard.
    pub cnt_pre_work_guarded_zero: Word,
    /// `+0x30`: `l2_proc_pdcp_ul` calls skipping division when Ring 1 is empty (`fp == 0`).
    pub cnt_div_empty_skip: Word,
    /// `+0x34`: `l2_proc_pdcp_ul` calls handled by inline Cortex-A7 hardware `udiv`.
    pub cnt_div_fast: Word,
    /// `+0x38`: `l2_proc_pdcp_ul` calls handled by byte-accurate Ring-1 packet admission.
    pub cnt_byte_paced: Word,
    /// `+0x3c`: `do_tc` 250 ms ticks clamped by `FLAG_DO_TC_CAP`.
    pub cnt_do_tc_clamped: Word,
    /// `+0x40`: Last staging cap (bytes) computed by `FLAG_DO_TC_CAP`.
    pub last_do_tc_cap: Word,
    /// `+0x44..+0x7f`: Reserved zero padding to 128 bytes.
    pub _reserved: [Word; 15],
}

impl MacPdcpOptBlock {
    pub const fn boot_default() -> Self {
        Self {
            magic: Word::new(MAGIC),
            version: Word::new(VERSION),
            flags: Word::new(0),
            cap_target_ms: Word::new(DEFAULT_CAP_TARGET_MS),
            cap_min_bytes: Word::new(DEFAULT_CAP_MIN_BYTES),
            cap_max_bytes: Word::new(DEFAULT_CAP_MAX_BYTES),
            cnt_bo_idx_nonzero: Word::new(0),
            cnt_bo_idx_zero: Word::new(0),
            cnt_downgrade_checks: Word::new(0),
            cnt_downgrade_fast_exit: Word::new(0),
            cnt_pre_work_fast: Word::new(0),
            cnt_pre_work_guarded_zero: Word::new(0),
            cnt_div_empty_skip: Word::new(0),
            cnt_div_fast: Word::new(0),
            cnt_byte_paced: Word::new(0),
            cnt_do_tc_clamped: Word::new(0),
            last_do_tc_cap: Word::new(0),
            _reserved: [const { Word::new(0) }; 15],
        }
    }

    /// Return true iff `magic` and `version` match, no unknown flag bits are set,
    /// and the requested feature `bit` is active.
    #[inline(always)]
    pub fn feature_enabled(&self, bit: u32) -> bool {
        if self.magic.get() != MAGIC || self.version.get() != VERSION {
            return false;
        }
        let f = self.flags.get();
        if (f & !KNOWN_FLAGS_MASK) != 0 {
            return false;
        }
        (f & bit) != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{offset_of, size_of};

    #[test]
    fn block_layout_and_boot_off_contract() {
        assert_eq!(size_of::<MacPdcpOptBlock>(), 128);
        assert_eq!(offset_of!(MacPdcpOptBlock, magic), 0x00);
        assert_eq!(offset_of!(MacPdcpOptBlock, version), 0x04);
        assert_eq!(offset_of!(MacPdcpOptBlock, flags), 0x08);
        assert_eq!(offset_of!(MacPdcpOptBlock, cap_target_ms), 0x0c);
        assert_eq!(offset_of!(MacPdcpOptBlock, cap_min_bytes), 0x10);
        assert_eq!(offset_of!(MacPdcpOptBlock, cap_max_bytes), 0x14);
        assert_eq!(offset_of!(MacPdcpOptBlock, cnt_bo_idx_nonzero), 0x18);
        assert_eq!(offset_of!(MacPdcpOptBlock, cnt_bo_idx_zero), 0x1c);
        assert_eq!(offset_of!(MacPdcpOptBlock, cnt_downgrade_checks), 0x20);
        assert_eq!(offset_of!(MacPdcpOptBlock, cnt_downgrade_fast_exit), 0x24);
        assert_eq!(offset_of!(MacPdcpOptBlock, cnt_pre_work_fast), 0x28);
        assert_eq!(offset_of!(MacPdcpOptBlock, cnt_pre_work_guarded_zero), 0x2c);
        assert_eq!(offset_of!(MacPdcpOptBlock, cnt_div_empty_skip), 0x30);
        assert_eq!(offset_of!(MacPdcpOptBlock, cnt_div_fast), 0x34);
        assert_eq!(offset_of!(MacPdcpOptBlock, cnt_byte_paced), 0x38);
        assert_eq!(offset_of!(MacPdcpOptBlock, cnt_do_tc_clamped), 0x3c);
        assert_eq!(offset_of!(MacPdcpOptBlock, last_do_tc_cap), 0x40);

        let blk = MacPdcpOptBlock::boot_default();
        assert_eq!(blk.magic.get(), MAGIC);
        assert_eq!(blk.version.get(), VERSION);
        assert_eq!(blk.flags.get(), 0);
        for bit in [
            FLAG_FAST_BSR_IDX,
            FLAG_FAST_LONG_BSR_CHECK,
            FLAG_GUARDED_PRE_BO,
            FLAG_FAST_PDCP_DIV,
            FLAG_PDCP_BYTE_PACING,
            FLAG_DO_TC_CAP,
        ] {
            assert!(!blk.feature_enabled(bit));
        }

        // Any unknown bit in flags -> entire block falls back to stock (off).
        blk.flags.set(KNOWN_FLAGS_MASK | (1 << 6));
        assert!(!blk.feature_enabled(FLAG_FAST_BSR_IDX));
        blk.flags.set(KNOWN_FLAGS_MASK | (1 << 31));
        assert!(!blk.feature_enabled(FLAG_DO_TC_CAP));

        // Bad magic or bad version -> all off.
        blk.flags.set(KNOWN_FLAGS_MASK);
        blk.magic.set(0xDEAD_BEEF);
        assert!(!blk.feature_enabled(FLAG_FAST_BSR_IDX));
        blk.magic.set(MAGIC);
        blk.version.set(0x1234_5678);
        assert!(!blk.feature_enabled(FLAG_FAST_BSR_IDX));
        blk.version.set(VERSION);

        // Valid known bits -> enabled.
        for bit in [
            FLAG_FAST_BSR_IDX,
            FLAG_FAST_LONG_BSR_CHECK,
            FLAG_GUARDED_PRE_BO,
            FLAG_FAST_PDCP_DIV,
            FLAG_PDCP_BYTE_PACING,
            FLAG_DO_TC_CAP,
        ] {
            assert!(blk.feature_enabled(bit));
        }
    }
}
