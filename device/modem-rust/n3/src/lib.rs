//! Combined `#![no_std]` Rust MAC & PDCP uplink hot-path optimizer and BSR
//! empty-ring guard for the Titan 4000 (`tk.bin` V1.6.0.P0).
//!
//! Supersedes the separate Lane N2 (`ul-opt`) and Lane N3 (`n3`) prototypes
//! into one unified boot-off control block (`MAC_PDCP_OPT_BLK_VA = 0x841b_b5c0`,
//! magic `"MPOP"`) across two proven-dead disjoint code caves:
//! - `.optcode1` (`0x8418_67e4..0x8418_6b38`, 852 B): MAC hooks
//!   (`SearchMacUlBoIdx`, `CheckLongBsrDowngradeToShort`, `mac_bsr_pre_work`).
//! - `.optcode2` (`0x8417_ffd8..0x8418_024c`, 628 B): PDCP hooks
//!   (`l2_proc_pdcp_ul` division & byte-accurate pacing, `do_tc` staging cap).
//!
//! Pure-Rust logic lives in [`block`] and [`opt`] (`#![forbid(unsafe_code)]`).
//! Bare-metal ARMv7 Thumb-2 integration lives solely in [`modem`], compiled
//! only on 32-bit ARM targets.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod block;
pub mod opt;

#[cfg(target_arch = "arm")]
pub mod modem;
