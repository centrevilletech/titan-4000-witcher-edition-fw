# Titan 4000 Rust N4 v2 Uplink Engine (`device/modem-rust/n4`)

`#![no_std]` Rust Thumb-2 port of the N4 v2 uplink engine (`n4_ul_engine.s`), built on Lane M1's bare-metal Cortex-A7 Thumb-2 toolchain and Lane M2's verified `modem-atlas` types (`N4State` at `0x847e_d600`, `N4ExtCounters` at `0x847e_d780`).

## Module Structure & `unsafe` Boundary

All uplink logic is pure safe Rust (`#![forbid(unsafe_code)]` on every logic module) and unit-tested on the host via `cargo test`:

| Module | Safety | Responsibility |
|---|---|---|
| `src/state.rs` | `#![forbid(unsafe_code)]` | `N4_MAGIC` (`"N4V2"`), flag bits, defaults, `SparseBucket`, `ensure_init`, panic-free `clamp_u32` |
| `src/tb.rs` | `#![forbid(unsafe_code)]` | Hook 1 (`hook_mac_tb`): per-TTI TB/pad accumulator, `G_ema`, refill-eligible counter (N3R D6) |
| `src/bsr.rs` | `#![forbid(unsafe_code)]` | Hook 2 (`hook_calc_lcg_bo`): always-on BSR counters, true backlog, damped PI lead; Hook 2b (`hook_short_bsr`): short-BSR LCG rescue |
| `src/pdcp.rs` | `#![forbid(unsafe_code)]` | Hook 3 (`hook_pdcp_limit`): dynamic JIT-PDCP staging limit `clamp(G_ema + 4096, pdcp_min, pdcp_max)` |
| `src/rx.rs` | `#![forbid(unsafe_code)]` | Hook 4 ingress: `last_drb_rbc`, 5 ms arrival window (`A_ema`), legacy bit-3 sparse promotion |
| `src/aqm.rs` | `#![forbid(unsafe_code)]` | Hook 4 AQM v2: small-packet sparing, 4x overload ceiling, step ECN CE marking, 35 ms paced drops |
| `src/ecn.rs` | `#![forbid(unsafe_code)]` | RFC 3168 IPv4 (with RFC 1624 incremental checksum) and IPv6 CE marking |
| `src/handshake.rs` | `#![forbid(unsafe_code)]` | IMG4 N4 v3 TLS/QUIC port-443 handshake sparing (bit 5) |
| `src/modem.rs` | Audited `unsafe` only | Single audited module with `// SAFETY:` comments, naked Thumb-2 shims (8-byte SP alignment, exact register/APSR preservation), and fixed-VA ABI veneers (`--cfg feature="stack-hooks"`) |

## Caves

- **Primary (`N4_PRACH`):** `0x847e_d000..0x847e_d540` (`1,344 B`, N4's original PRACH format-4 tail slot)
- **Overflow (`N4_CAVE2`):** `0x8419_4654..0x8419_4a5c` (`1,032 B`, dead `RFFE_PAM_SKY77643_31_NEC`, verified dead with `cavecheck` + `rdcheck`: 0 real references, 1032/1032 B Thumb-2 decode, disjoint from N6H, C1, N7, U14, IMG4, and M1)

## Commands

```bash
# 1. Host unit tests (workspace: modem-atlas + witcher-modem-aqm + witcher-modem-n4)
cargo test --locked --workspace --manifest-path device/modem-rust/Cargo.toml

# 2. Bare-metal Cortex-A7 Thumb-2 build + static ELF audit (standalone & stack-integrated)
device/modem-rust/n4/build-thumb.sh /tmp/n4-standalone --standalone
device/modem-rust/n4/build-thumb.sh /tmp/n4-stack --stack
```
