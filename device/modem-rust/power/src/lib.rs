//! Verified `#![no_std]` uplink power-control atlas and FCC Part 96 / SAS
//! compliance models for the Titan 4000 LTE modem (`tk.bin` V1.6.0.P0
//! R3882-4172, GCT GDM7243AP CPU1, ARMv7 Thumb-2, load VA `0x8410_0000`).
//!
//! Every struct offset, size, global address, ROM lookup table, and function
//! entry point in this crate was verified directly against stock `tk.bin`
//! disassembly (SHA-256 `555362d9...82ea`).

#![no_std]
#![allow(dead_code)]

pub mod addr;
pub mod compliance;
pub mod ffi;
pub mod txm;
