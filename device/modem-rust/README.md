# Rust uplink AQM for the Titan 4000 modem (`device/modem-rust`)

`no_std` Rust built into three dead caves of the modem firmware (`tk.bin`, GCT GDM7243A
CPU1, Thumb-2): two for code and one for the control block. N4's hook 4 calls it for every
uplink packet before Ring 1. It is built on
lane M2's `modem-atlas` crate (`atlas/`), which describes the modem's structures as `repr(C)`
types.

## Modules

| Module | What it is | `unsafe` |
| --- | --- | --- |
| `block` | The 256-byte control block at `0x841b5900`: layout, boot defaults, counters. The ABI. | forbidden |
| `pie` | Selector 1's controller: PIE (RFC 8033/8034) with a drop budget, a ceiling and an overload latch. | forbidden |
| `q1` | Selector 3's controller: CoDel held at the second carrier's floor, with an uncapped PIE backstop. | forbidden |
| `codel` | CoDel (RFC 8289) on the queue's bytes at enqueue, in integer TTIs, with no division per packet. | forbidden |
| `flows` | Counts bulk flows: a 32-bit sketch of the 5-tuple, read by linear counting every 100 ms. | forbidden |
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
- `3` (block version `0x20261127` and later): CoDel with the second-carrier floor (lane Q1).
  Earlier builds treat `3` as unknown and run N4 v2.

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

## Selector 3

The bench (2026-11-25) showed why selector 1 cannot beat N4 on queue delay: the eNB sizes
each grant from a buffer report two uplink TTIs old, so below capacity the queue holds about
two TTIs of arrivals whatever the AQM does (about 15 ms at TDD config 2), and PIE's 2% budget
lets four CUBIC flows float at about 45 KB on two carriers. Selector 3 changes what is
controlled and leaves selector 1 untouched:

- **Target.** `max(q1_target_ms x capacity, floor)` bytes, where the capacity is the decaying
  peak of N4's grant EWMA (`q1_capacity`), not the current grant. The queue the grant lag
  explains is left alone.
- **Floor.** Only while the second carrier is in use (grant EWMA at or above
  `q1_two_cc_g_ema` within the last `q1_two_cc_hold_ms`): `q1_floor_bytes` for many bulk flows,
  up to `q1_floor_one_bytes` for one, halving the difference per extra flow. This replaces the
  budget's job of keeping the buffer report high enough for the Nokia eNB to keep the second
  carrier. On one carrier there is no floor.
- **CoDel** on bulk packets against that target (`q1_interval_ms`): one drop or CE mark per
  interval at first, then `interval / sqrt(n)`.
- **Backstop.** Selector 1's PI law with no cap, toward `q1_backstop_q8` times the target. It
  stays at zero while CoDel holds the queue and holds BBR and floods. It never drops at or
  under the target.
- The ceiling, the burst allowance, ECN and the small-packet rule are selector 1's.

Per packet, selector 3 does no division and no grant bookkeeping: the flow count, capacity,
carrier mode, target and delay readings move to the update every `t_update_ms` (15 ms).

| Word | Offset | Boot | What |
| --- | --- | --- | --- |
| `q1_target_ms` | `+0xac` | 8 | delay CoDel holds at capacity |
| `q1_interval_ms` | `+0xb0` | 40 | CoDel interval |
| `q1_floor_bytes` | `+0xb4` | 16000 | floor on two carriers, many flows |
| `q1_floor_one_bytes` | `+0xb8` | 32000 | floor on two carriers, one flow |
| `q1_two_cc_g_ema` | `+0xbc` | 8000 | grant EWMA (B/TTI) that means two carriers |
| `q1_two_cc_hold_ms` | `+0xc0` | 2000 | two-carrier mode outlasts the last such grant |
| `q1_backstop_q8` | `+0xc4` | 384 | backstop target, x target / 256 |
| state and readings | `+0xc8..+0xfc` | 0 (`q1_flows` 1) | capacity, flow sketch, target bytes, CoDel state, CoDel drops and marks, carrier mode |

All of it is read only while the selector is 3.

## Commands

```bash
# Host tests: ECN, the block ABI, both controllers, and closed-loop traces of CUBIC and BBR
# on one and two carriers: selector 1 before and after the overload latch (traces.rs) and
# selector 3 against N4 and selector 1 (q1_traces.rs). CI runs these.
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
- the code that runs once per update or per CoDel drop (`.m1cold`: selector 1's update, the PI
  step both selectors' updates share, CoDel's drop spacing) sits in the cold cave, and every
  branch between the two caves is a `bl`;
- there are no undefined symbols, no ARM-mode code, no data in either code cave, no
  PC-relative operands (literal pools, `adr`, branch tables), no VFP/NEON and no trap
  instructions;
- no panic machinery survives linking, which proves the hot path cannot panic;
- the hook adds at most 256 B of stack (the static bound is 148 B);
- the block decodes as Thumb-2 for `tkpatch.py`, and its magic, version and boot selector match
  `src/block.rs`.

## Caves

| Range | Dead function | Use |
| --- | --- | --- |
| `0x841de8dc..0x841df200` (2,340 B) | `cmd_phy` | code (`.m1code`, shim first) |
| `0x8446e4c8..0x8446e718` (592 B) | `CloseUeTestLoopCnf` | cold code (`.m1cold`, from block version `0x20261127`) |
| `0x841b5900..0x841b5a00` (256 B) | `UMM_DecodeATR` | control block (`.m1blk`) |
| `0x847ed414..0x847ed41a` (6 B) | in N4's cave | `bl m1_aqm_shim; nop` |

The caves are disjoint from N6H, C1, N7, U14, IMG4's PRACH tail, R4's Rust N4 overflow cave
(`0x84194654..0x84194a5c`) and lanes N2's and N3's caves. `CloseUeTestLoopCnf` answers the 3GPP
test loop of conformance test mode; nothing in the image refers to it but its own symbol-table
entry (cavecheck and rdcheck, lane Q1's cave audit).
