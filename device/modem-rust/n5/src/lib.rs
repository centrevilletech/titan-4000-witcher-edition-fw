//! `#![cfg_attr(target_arch = "arm", no_std)]` Rust port of the Titan 4000 N5
//! per-flow sparse uplink lane, first-class PDCP staging limit, and exact Ring-0
//! feeder byte accounting.
//!
//! All core logic (`state`, `parse`, `flow`, `pdcp`, `ring0`) is pure safe Rust
//! (`#![forbid(unsafe_code)]` per module) and host-testable via `cargo test`.
//! All hardware pointer dereferences and Thumb-2 hook shims are confined to `modem`.

#![cfg_attr(target_arch = "arm", no_std)]

pub mod flow;
pub mod parse;
pub mod pdcp;
pub mod ring0;
pub mod state;

#[cfg(all(target_arch = "arm", not(test)))]
pub mod modem;
