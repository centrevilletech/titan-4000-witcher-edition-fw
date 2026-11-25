//! Control block (`128` bytes at `N3_OPT_BLK_VA = 0x8449_a2a0`) for the Lane N3
//! MAC UL hot-path optimizer.
//!
//! Every feature bit boots OFF (`flags == 0`), and any unknown flag bit is ignored
//! (treated as OFF). All counters are single-copy-atomic relaxed `u32` words.

#![forbid(unsafe_code)]

use core::sync::atomic::{AtomicU32, Ordering::Relaxed};

/// `"N3MO"` (`0x4e33_4d4f` — valid Thumb-2 halfwords `0x4d4f`, `0x4e33`).
pub const MAGIC: u32 = 0x4e33_4d4f;
/// Layout version (`2026-11-25` — valid Thumb-2 halfwords `0x1125`, `0x2026`).
pub const VERSION: u32 = 0x2026_1125;

/// Enable bit 0: fast `SearchMacUlBoIdx` (early-exit on 0 + unrolled 6-step search).
pub const FLAG_FAST_BSR_IDX: u32 = 1 << 0;
/// Enable bit 1: O(1) early-exit on `CheckLongBsrDowngradeToShort` when >= 2 LCGs exceed `tb_rem`.
pub const FLAG_FAST_LONG_BSR_CHECK: u32 = 1 << 1;
/// Enable bit 2: guarded `mac_bsr_pre_work` (zeroes stale `ring_pending_bytes` when rings & LLCE0 idle).
pub const FLAG_GUARDED_PRE_BO: u32 = 1 << 2;
/// Mask of all recognized feature bits; any bit outside this mask is ignored (boots off).
pub const KNOWN_FLAGS_MASK: u32 =
    FLAG_FAST_BSR_IDX | FLAG_FAST_LONG_BSR_CHECK | FLAG_GUARDED_PRE_BO;

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

/// 128-byte boot-off control block placed in `.n3blk` at `0x8449_a2a0` (`ATM_decodePCO`).
#[repr(C, align(4))]
pub struct N3OptBlock {
    /// `+0x00`: [`MAGIC`].
    pub magic: Word,
    /// `+0x04`: [`VERSION`].
    pub version: Word,
    /// `+0x08`: Feature enable bitmask (`0` at boot = byte-identical stock behaviour).
    pub flags: Word,
    /// `+0x0c`: Reserved (0).
    pub reserved0: Word,

    /// `+0x10`: Total calls handled by fast `SearchMacUlBoIdx`.
    pub cnt_bo_idx_fast: Word,
    /// `+0x14`: Calls that took the `bo_bytes == 0` early-exit.
    pub cnt_bo_idx_zero: Word,
    /// `+0x18`: Total calls inspected by `CheckLongBsrDowngradeToShort` fast-path.
    pub cnt_downgrade_checks: Word,
    /// `+0x1c`: Calls that early-exited without running the 855-insn LCP simulation.
    pub cnt_downgrade_fast_exit: Word,
    /// `+0x20`: Total calls handled by guarded `mac_bsr_pre_work`.
    pub cnt_pre_work_fast: Word,
    /// `+0x24`: Bearers whose stale `ring_pending_bytes` was clamped to 0 by the empty-ring guard.
    pub cnt_pre_work_guarded_zero: Word,
    /// `+0x28..+0x7f`: Reserved zero padding to 128 bytes.
    pub _reserved: [Word; 22],
}

impl N3OptBlock {
    pub const fn boot_default() -> Self {
        Self {
            magic: Word::new(MAGIC),
            version: Word::new(VERSION),
            flags: Word::new(0),
            reserved0: Word::new(0),
            cnt_bo_idx_fast: Word::new(0),
            cnt_bo_idx_zero: Word::new(0),
            cnt_downgrade_checks: Word::new(0),
            cnt_downgrade_fast_exit: Word::new(0),
            cnt_pre_work_fast: Word::new(0),
            cnt_pre_work_guarded_zero: Word::new(0),
            _reserved: [const { Word::new(0) }; 22],
        }
    }

    /// Return true iff `magic` and `version` match and the requested known flag is active.
    /// Any unknown flag bit in `flags` is rejected (returns false -> stock path).
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
        assert_eq!(size_of::<N3OptBlock>(), 128);
        assert_eq!(offset_of!(N3OptBlock, magic), 0x00);
        assert_eq!(offset_of!(N3OptBlock, version), 0x04);
        assert_eq!(offset_of!(N3OptBlock, flags), 0x08);
        assert_eq!(offset_of!(N3OptBlock, cnt_bo_idx_fast), 0x10);
        assert_eq!(offset_of!(N3OptBlock, cnt_downgrade_fast_exit), 0x1c);
        assert_eq!(offset_of!(N3OptBlock, cnt_pre_work_guarded_zero), 0x24);

        let blk = N3OptBlock::boot_default();
        assert!(!blk.feature_enabled(FLAG_FAST_BSR_IDX));
        assert!(!blk.feature_enabled(FLAG_FAST_LONG_BSR_CHECK));
        assert!(!blk.feature_enabled(FLAG_GUARDED_PRE_BO));

        // Unknown bit in flags -> entire block falls back to stock (off).
        blk.flags.set(FLAG_FAST_BSR_IDX | (1 << 31));
        assert!(!blk.feature_enabled(FLAG_FAST_BSR_IDX));

        // Valid known bits -> enabled.
        blk.flags.set(KNOWN_FLAGS_MASK);
        assert!(blk.feature_enabled(FLAG_FAST_BSR_IDX));
        assert!(blk.feature_enabled(FLAG_FAST_LONG_BSR_CHECK));
        assert!(blk.feature_enabled(FLAG_GUARDED_PRE_BO));
    }
}
