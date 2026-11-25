# Rust uplink AQM for the Titan 4000 modem (`device/modem-rust`)

`no_std` Rust built into two dead code caves of the modem firmware (`tk.bin`, GCT GDM7243A
CPU1, Thumb-2). N4's hook 4 calls it for every bulk uplink packet before Ring 1. It is built on
lane M2's `modem-atlas` crate (`atlas/`), which describes the modem's structures as `repr(C)`
types.

## Modules

| Module | What it is | `unsafe` |
| --- | --- | --- |
| `block` | The 256-byte control block at `0x841b5900`: layout, boot defaults, counters. The ABI. | forbidden |
| `pie` | The controller: PIE (RFC 8033/8034) with a drop budget, a ceiling and an overload latch. | forbidden |
| `ecn` | ECN parsing and CE marking with the RFC 1624 checksum update. | forbidden |
| `modem` (Thumb-2 only) | The control block's placement, the naked hook shim, and safe per-packet glue. | 4 attributes |
| `modem::hw` (Thumb-2 only) | Typed volatile access to atlas structures; turns hook 4's registers into safe values. | 7 |

The crate denies `unsafe_op_in_unsafe_fn`, `clippy::undocumented_unsafe_blocks` and
`clippy::multiple_unsafe_ops_per_block`. `build-thumb.sh` runs clippy for the Thumb-2 target,
the only build that sees `modem`.

## Selector (`0x841b5908`)

- `0` (boot default) and any unknown value: N4 v2. The shim runs N4's two displaced
  instructions and returns, using no stack.
- `1`: PIE.
- `2`: no AQM (N4's backlog report and PDCP limit stay on).

Switch it live with `wm 0x841b5908 <n>`. Whatever the selector, the AQM slot runs only while N4
flags bits 0 and 2 are both set.

## The controller

- **Target.** PIE moves the drop probability `p` toward the queue delay that holds `target_ms`
  (14 ms). Delay is the queue (Ring 0 + Ring 1 + cipher batch + RLC staging) over the drain rate.
  The drain rate is N4's grant EWMA times `ul_subframes_per_frame` / 10 ms.
- **Budget.** For senders that respond to loss, `p` is capped at `drop_budget_q24` (2%). Four
  CUBIC flows on one carrier would need about 4% to sit at the target. Capped, their queue floats
  higher instead, and the bench shows the Nokia eNB keeps the second uplink carrier only while
  the buffer report stays high.
- **Ceiling.** Big packets are tail-dropped above `max(ceiling_floor_bytes, drain rate x
  ceiling_ms)`, 50 KB / 50 ms (M1's `max(50 KB, 10 x G_ema)` at TDD config 2).
- **Overload.** A token bucket polices the ceiling at the budget rate, 64 packets deep
  (`ceiling_burst_pkts`). When it runs dry, the traffic is not responding to the budget (BBR, a
  UDP flood), so the cap is lifted and `p` rises to whatever holds the target. The overload ends
  when `p` falls back under the budget. `ceiling_burst_pkts = 0` turns it off: M1's behaviour.
- Packets under 600 B (N4's `aqm_minlen`) are never dropped or marked. ECT packets are CE-marked
  instead of dropped while `p` is at most 10%.

The control block layout, defaults and safe live ranges are in lane R1's report and pinned by
`tests/block.rs`.

## Commands

```bash
# Host tests: ECN, the block ABI, the controller, and closed-loop traces of CUBIC and BBR
# on one and two carriers before and after the overload latch (CI runs these).
cargo test --locked --workspace --manifest-path device/modem-rust/Cargo.toml

# Thumb-2 build, clippy for the target, and the audit (also in CI).
device/modem-rust/build-thumb.sh /tmp/m1-out

# tkpatch.py manifest on top of N6H (offline; needs stock tk.bin and N6H's artifacts).
python3 device/modem-rust/make_spec.py \
  --stock /path/to/stock/tk.bin --n6h-spec /path/to/n6h-spec.json --n6h-bin /path/to/n6h/tk.bin \
  /tmp/m1-out/m1_aqm.elf /tmp/m1-out/m1-spec.json
```

`build-thumb.sh` compiles with plain `rustc` for `armv7-unknown-linux-musleabi` (Cortex-A7,
`+thumb-mode,+execute-only`, no FPU), links with `link-m1.ld` (`-nostdlib --gc-sections`), and
fails unless:

- `m1_aqm_shim` is first in `.m1code`, at `0x841de8dc`: N4 and R4's Rust N4 call it there;
- there are no undefined symbols, no ARM-mode code, no data in the code cave, no PC-relative
  operands (literal pools, `adr`, branch tables), no VFP/NEON and no trap instructions;
- no panic machinery survives linking, which proves the hot path cannot panic;
- the hook adds at most 256 B of stack (it adds 124);
- the block decodes as Thumb-2 for `tkpatch.py`, and its magic, version and boot selector match
  `src/block.rs`.

## Caves

| Range | Dead function | Use |
| --- | --- | --- |
| `0x841de8dc..0x841df200` (2,340 B) | `cmd_phy` | code (`.m1code`, shim first) |
| `0x841b5900..0x841b5a00` (256 B) | `UMM_DecodeATR` | control block (`.m1blk`) |
| `0x847ed414..0x847ed41a` (6 B) | in N4's cave | `bl m1_aqm_shim; nop` |

The caves are disjoint from N6H, C1, N7, U14, IMG4's PRACH tail and R4's Rust N4 overflow cave
(`0x84194654..0x84194a5c`).
