//! `#![cfg_attr(target_arch = "arm", no_std)]` Rust port of the Titan 4000 N4 v2 uplink engine.
//!
//! All core logic (`state`, `tb`, `bsr`, `pdcp`, `rx`, `aqm`, `ecn`, `handshake`) is pure
//! safe Rust (`#![forbid(unsafe_code)]` per module) and host-testable via `cargo test`.
//! All hardware pointer dereferences and Thumb-2 hook shims are confined to `modem`.

#![cfg_attr(target_arch = "arm", no_std)]

pub mod aqm;
pub mod bsr;
pub mod ecn;
pub mod handshake;
pub mod pdcp;
pub mod rx;
pub mod state;
pub mod tb;

#[cfg(all(target_arch = "arm", not(test)))]
pub mod modem;
