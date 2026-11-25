# Titan 4000 Rust Modem Patch Toolchain (`device/modem-rust`)

Reusable `no_std` Rust toolchain for building Thumb-2 Cortex-A7 modem patches (`tk.bin` code caves) on the GCT GDM7243A (CPU1, uT-Kernel), built on Lane M2's verified `modem-atlas` definitions (`device/modem-rust/atlas/`) and starting with Lane M1's burst-tolerant DOCSIS-PIE uplink AQM replacement for N4 hook 4.

## Target Choice and Justification

We compile with `--target=armv7-unknown-linux-musleabi` plus:

- `-C target-cpu=cortex-a7`
- `-C target-feature=+thumb-mode,+thumb2,+execute-only,-neon,-vfp2,-vfp3,-vfp4,-d32`
- `-C relocation-model=static -C panic=abort -C force-unwind-tables=no -C opt-level=s`

and link bare-metal with `-nostdlib --gc-sections -T link-m1.ld`.

Why this target instead of `armv7a-none-eabi` or a custom target JSON:

1. **Already installed offline and in CI:** `rust-std-armv7-unknown-linux-musleabi` is preinstalled on the workstation and already required by Witcher CI (`.github/workflows/firmware.yml`), whereas `armv7a-none-eabi` is not preinstalled and custom target JSONs require unstable `-Z build-std` on nightly.
2. **Identical bare-metal ABI:** Both targets use the ARMv7-A soft-float AAPCS ABI (`r0..r3` args, `r0` return, `r4..r11` callee-saved, 8-byte stack alignment, no VFP/NEON).
3. **Compile-time zero literal pools (`+execute-only`):** Forces LLVM to emit `movw`/`movt` instead of PC-relative constant pools, guaranteeing every byte of `.m1code` decodes as Thumb-2 for `tkpatch.py`.
4. **Strict zero-runtime enforcement:** `build-thumb.sh` links with `-nostdlib` (no musl, no CRT, no `compiler_builtins`, no `libcore` runtime calls) and verifies on every build:
   - `0` undefined symbols,
   - `0` ARM-mode (`$a`) mapping symbols,
   - `0` literal pools (`$d` in `.m1code`) and `0` PC-relative loads,
   - `0` VFP/NEON instructions,
   - 100% valid Thumb-2 disassembly of both `.m1code` and `.m1blk`.

## Cave Allocation (Lane M1, from Lane M2 Cave Catalog)

| Region | Dead Stock Function | VA Range | Size | Purpose |
|---|---|---|---:|---|
| `.m1code` | `cmd_phy` | `0x841de8dc..0x841df200` | 2,340 B | AAPCS shim (`m1_aqm_shim`) + Rust PIE (`m1_pie_decide`) |
| `.m1blk` | `UMM_DecodeATR` | `0x841b5900..0x841b5a00` | 256 B | 4 dedicated 64 B cache lines: selector, tunables, PIE state, counters, PDCP HoL telemetry |
| Hook splice | `hook4_check_aqm` (inside N4 cave) | `0x847ed414..0x847ed41a` | 6 B | `bl m1_aqm_shim; nop` replacing `ldr r0, [r5, #4]; and r0, r0, #5` |

Both caves are independently verified with `cavecheck.py` + `rdcheck.py` (0 real code/data references) and disjoint from all 71 N6H + C1 sites, N7, U14, and IMG4 PRACH-tail RAM. Separating read-only `.m1code` from mutable `.m1blk` prevents I-cache/D-cache line sharing on CPU1.

## Runtime Selector and Live Rollback

`M1_BLK` starts at `0x841b5900` (`magic = 0x4d315049` `"M1PI"`, `version = 0x20261125`).
The selector word at **`0x841b5908`** boots to **`0`**:

- `0` (default & instant rollback): old N4 v2 + IMG4 v3 behaviour (zero stack overhead fast path).
- `1`: Rust burst-tolerant DOCSIS-PIE AQM (RFC 8033 / RFC 8034).
- `2`: no AQM (bypass Ring-1 drops/marks while keeping N4 true backlog, PDCP limit, grant-hold rescue, and N5 flow lane intact).

## Commands

```bash
# 1. Host unit tests (both modem-atlas and witcher-modem-aqm)
cargo test --locked --workspace --manifest-path device/modem-rust/Cargo.toml

# 2. Bare-metal Cortex-A7 Thumb-2 build and static ELF audit
device/modem-rust/build-thumb.sh /tmp/m1-out

# 3. Emit tkpatch.py JSON manifest (offline, requires stock tk.bin and N6H artifacts)
python3 device/modem-rust/make_spec.py \
  --stock /path/to/stock/tk.bin \
  --n6h-spec /path/to/n6h-spec.json \
  --n6h-bin /path/to/n6h/tk.bin \
  /tmp/m1-out/m1_aqm.elf /tmp/m1-out/m1-spec.json
```
