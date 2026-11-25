//! Verified ARMv7 Thumb-2 FFI entry points into `tk.bin` V1.6.0.P0 TXM routines.
//!
//! Only callable on 32-bit ARMv7 CPU1 inside the `tk.bin` address space. On host
//! targets this module documents the verified ABI and addresses.

use crate::addr;

/// Set `AT%TXPOWLMT` mode and conducted power limit (`mode = 2`, `lim_dbm`).
pub type TxSetTxPowLmtFn = unsafe extern "C" fn(mode: u32, lim_dbm: i32);

/// Set `AT%TXPOWLMTMHZ` PSD limiter (`enable = 0|1`, `lim_dbm_mhz`).
pub type TxSetPsdLimitFn = unsafe extern "C" fn(enable: u32, lim_dbm_mhz: i32);

/// Set `AT%TXTOTMAXPWR` total UE max power (`enable = 0|1`, `lim_dbm` in `24..=33`).
pub type TxSetTotMaxPwrFn = unsafe extern "C" fn(enable: u32, lim_dbm: i32);

/// Linear dual-CC total-power scaler (`0x842a_4828`).
pub type TxDualCcScaleFn =
    unsafe extern "C" fn(p_this: i32, p_other: i32, p_uemax: i32) -> i32;

/// Compute Band 48 CBRS MPR backoff in `0.1 dB` (`0x842a_5e04`).
pub type TxCalcCbrsMprFn = unsafe extern "C" fn(cc_idx: u32, n_rb: u32) -> i32;

/// Convert a Thumb function address in `tk.bin` into an interworking Thumb target (`va | 1`).
#[inline]
pub const fn thumb_addr(va: u32) -> u32 {
    va | 1
}

/// Verified Thumb entry address for `txm_set_txpowlmt`.
pub const THUMB_TXM_SET_TXPOWLMT: u32 = thumb_addr(addr::FN_TXM_SET_TXPOWLMT);
/// Verified Thumb entry address for `txm_set_psd_limit`.
pub const THUMB_TXM_SET_PSD_LIMIT: u32 = thumb_addr(addr::FN_TXM_SET_PSD_LIMIT);
/// Verified Thumb entry address for `txm_set_txtotmaxpwr`.
pub const THUMB_TXM_SET_TXTOTMAXPWR: u32 = thumb_addr(addr::FN_TXM_SET_TXTOTMAXPWR);
/// Verified Thumb entry address for `txm_dual_cc_scale`.
pub const THUMB_TXM_DUAL_CC_SCALE: u32 = thumb_addr(addr::FN_TXM_DUAL_CC_SCALE);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thumb_interworking_bits_are_odd() {
        assert_eq!(THUMB_TXM_SET_TXPOWLMT, 0x842b_0611);
        assert_eq!(THUMB_TXM_SET_PSD_LIMIT, 0x842b_06b5);
        assert_eq!(THUMB_TXM_SET_TXTOTMAXPWR, 0x842b_08a1);
        assert_eq!(THUMB_TXM_DUAL_CC_SCALE, 0x842a_4829);
    }
}
