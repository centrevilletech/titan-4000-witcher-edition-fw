//! Witcher's uplink AQM for the Titan 4000 modem (`tk.bin`, GCT GDM7243A CPU1).
//!
//! N4's hook 4 (`0x847e_d414`) calls into this crate for every bulk uplink packet before
//! it enters Ring 1. The selector word picks the AQM: N4 v2 (0, the boot default), this
//! crate's PIE (1), none (2), or lane Q1's CoDel with the second-carrier floor (3).
//!
//! - [`block`]: the 256-byte control block at `0x841b_5900`, the ABI shared with the DM
//!   console, the keeper and the image builder.
//! - [`pie`]: selector 1's controller, whose PI law selector 3 reuses as its backstop.
//! - [`q1`]: selector 3's controller: target, floor, capacity and carrier mode.
//! - [`codel`]: CoDel's control law on the queue in bytes.
//! - [`flows`]: counting bulk flows with a one-word hash sketch.
//! - [`ecn`]: ECN parsing and CE marking.
//! - `modem` (Thumb-2 build only): the hook shim and glue; its `hw` submodule holds the
//!   crate's only `unsafe` code.
//!
//! Everything but `modem` is pure and forbids `unsafe`.

#![cfg_attr(target_arch = "arm", no_std)]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]

pub mod block;
pub mod codel;
pub mod ecn;
pub mod flows;
pub mod pie;
pub mod q1;

#[cfg(target_arch = "arm")]
mod modem;
