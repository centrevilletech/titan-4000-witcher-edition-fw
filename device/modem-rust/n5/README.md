# Titan 4000 Rust N5 Per-Flow Sparse Uplink Lane (`device/modem-rust/n5`)

`#![no_std]` Rust Thumb-2 port of the N5 per-flow sparse uplink lane, first-class PDCP staging limit, and exact Ring-0 feeder byte accounting (`n5.s`), built on `device/modem-rust`'s bare-metal Cortex-A7 Thumb-2 toolchain and `modem-atlas` (`N5State` at `0x8448_9a64`, `N4State` at `0x847e_d600`).

## Module Structure & `unsafe` Boundary

All flow-lane logic is pure safe Rust (`#![forbid(unsafe_code)]` on every logic module) and host-tested via `cargo test`:

| Module | Safety | Responsibility |
|---|---|---|
| `src/state.rs` | `#![forbid(unsafe_code)]` | `N5_MAGIC` (`"N5FL"`), `N5_VERSION` (`0x2026_1123`), flag bits, defaults, `boot_n5_state`, panic-free `clamp_u32` |
| `src/parse.rs` | `#![forbid(unsafe_code)]` | Bounds-checked IPv4/IPv6 header parser, shared L4 pure-TCP-ACK & port extractor, fragment/truncation validation, 5-tuple + bearer golden-ratio hash |
| `src/flow.rs` | `#![forbid(unsafe_code)]` | Hook A (`classify_packet`): per-bearer monotonic Ring-1 dequeue tracker, 64-bucket leaky-bucket + bulk-hold state machine, active-bulk collision immunity, Ring-0 occupancy & 100 ms byte budget |
| `src/pdcp.rs` | `#![forbid(unsafe_code)]` | Hook B (`compute_pdcp_limit`): first-class PDCP staging limit (`N5_PDCP_MIN/MAX/K_Q4`) and exact N4 fallback when bit 1 is off |
| `src/ring0.rs` | `#![forbid(unsafe_code)]` | Hook C (`sum_ring0_bytes`, `record_ring0_submit`): exact 12-bit wrap Ring-0 IRB byte sum and telemetry counters |
| `src/modem.rs` | Audited `unsafe` only | Single audited module with `// SAFETY:` comments, volatile MMIO/RAM bridges, static `.n5blk` image, and naked Thumb-2 shims enforcing 8-byte SP alignment and exact register/APSR preservation |

## Caves & Fixed Entry Points

All Rust N5 code fits inside N5's already-proven-dead `ChangeCalmodFunc` (`0x8418_f768..0x8418_ff4c`, 2,020 B), keeping N6H's `n6_u2_lnack_filter_code` (`0x8418_fd78..0x8418_fe10`) and `n6_u2_control_block` (`0x8418_ff00..0x8418_ff42`) completely untouched:

- **Primary (`.n5cave_g`):** `0x8418_f768..0x8418_fd78` (`1,552 B`), preserving all three assembly N5 entry VAs verbatim:
  - `n5_flow_classify` = `0x8418_f768` (called by R4 `hook_gipc_rx` / N4 Hook A)
  - `n5_pdcp_limit` = `0x8418_fc9c` (tail-called by R4 `hook_pdcp_limit` / N4 Hook B)
  - `n5_ring0_submit` = `0x8418_fd0a` (called by Hook C at `0x842d_cd24`)
- **Tail (`.n5cave_g_tail`):** `0x8418_fe90..0x8418_ff00` (uses `110 B` of `112 B` post-N7 tail inside `ChangeCalmodFunc`, strictly after both N6H `0x8418_fd78..0x8418_fe10` and N7 `0x8418_fd78..0x8418_fe8a` and before N6H `U2_BLK` `0x8418_ff00..0x8418_ff42`)
- **RAM block (`.n5blk`):** `0x8448_9a62..0x8448_9f14` (`1,202 B`, byte-identical to assembly N5 over dead `FSM_ATM_CMD_LAPI_REGISTRATION_ATTACH_IND`)

## Commands

```bash
# 1. Host unit tests (workspace: modem-atlas + witcher-modem-aqm + witcher-modem-n4 + witcher-modem-n5)
cargo test --locked --workspace --manifest-path device/modem-rust/Cargo.toml

# 2. Bare-metal Cortex-A7 Thumb-2 build + static ELF audit
device/modem-rust/n5/build-thumb.sh /tmp/n5-thumb
```
