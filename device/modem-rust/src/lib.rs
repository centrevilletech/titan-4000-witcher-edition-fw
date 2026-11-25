//! Witcher's uplink AQM for the Titan 4000 modem (`tk.bin`, GCT GDM7243A CPU1).
//!
//! N4's hook 4 (`0x847e_d414`) calls into this crate for every bulk uplink packet before
//! it enters Ring 1. The selector word picks the AQM: N4 v2 (0, the boot default), this
//! crate's PIE (1), or none (2).
//!
//! - [`block`]: the 256-byte control block at `0x841b_5900`, the ABI shared with the DM
//!   console, the keeper and the image builder.
//! - [`pie`]: the controller. Pure.
//! - [`ecn`]: ECN parsing and CE marking. Pure.
//! - `modem` (Thumb-2 build only): the hook shim and glue; its `hw` submodule holds the
//!   crate's only `unsafe` code.

#![cfg_attr(target_arch = "arm", no_std)]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]

pub mod block;
pub mod ecn;
pub mod pie;

#[cfg(target_arch = "arm")]
mod modem;
