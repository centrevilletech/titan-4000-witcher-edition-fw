//! Lane N3 `#![no_std]` Rust MAC uplink hot-path optimizer & BSR empty-ring guard
//! for the Titan 4000 (`tk.bin` V1.6.0.P0).
//!
//! Pure-Rust logic lives in [`block`] and [`opt`] (`#![forbid(unsafe_code)]`).
//! Bare-metal ARMv7 Thumb-2 integration lives solely in [`modem`], compiled only on
//! 32-bit ARM targets.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod block;
pub mod opt;

#[cfg(target_arch = "arm")]
pub mod modem;
