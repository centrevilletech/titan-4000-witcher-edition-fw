//! Boot-off, observation-only MAC UL timeline tracer for the Titan 4000 modem (`tk.bin`, CPU1).
//!
//! Records per-TTI, per-CC UL grants (NewTx, Adaptive Retx, Non-Adaptive Retx), TB used vs
//! padding bytes, BSR MAC CEs (Short/Long/Truncated/Padding + trigger), PHR MAC CEs
//! (per-carrier PH, V bit, `Pcmax,c`), PUCCH SRs, Ring-1 bytes, RLC BO, and LTE SFN/subframe
//! timestamps into a 128 KiB non-cacheable RAM ring (`0x87f7_0000..0x87f9_0000`, 4,096 x 32 B
//! records inside the dead `srch_run_pss_*` buffer).
//!
//! All `unsafe` code is confined to `modem` (Thumb-2 target only).

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(clippy::multiple_unsafe_ops_per_block)]

pub mod block;
pub mod record;

#[cfg(all(target_arch = "arm", not(test)))]
pub mod modem;
