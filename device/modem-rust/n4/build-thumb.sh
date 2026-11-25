#!/usr/bin/env bash
# Reproducible bare-metal Thumb-2 Cortex-A7 build + static audit for witcher-modem-n4.
#
# Usage:
#   device/modem-rust/n4/build-thumb.sh [out_dir] [--stack] [--opt s|z]
#
# Modes:
#   default (--standalone): pure N4 v2 engine matching n4_ul_engine.s
#   --stack:                full IMG4/N5/N6H/M1 stack-integrated build
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
MODEM_RUST_DIR=$(cd "$SCRIPT_DIR/.." && pwd)

OUT=""
MODE="standalone"
OPT="z"

while [ $# -gt 0 ]; do
  case "$1" in
    --stack) MODE="stack"; shift ;;
    --standalone) MODE="standalone"; shift ;;
    --opt) OPT="$2"; shift 2 ;;
    *)
      if [ -z "$OUT" ]; then
        OUT="$1"
      else
        echo "Unexpected argument: $1" >&2
        exit 2
      fi
      shift
      ;;
  esac
done

OUT=${OUT:-"$MODEM_RUST_DIR/target/n4-thumb-$MODE"}
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)

export PATH="$HOME/.cargo/bin:$PATH"

LD_BIN=${LD_BIN:-$(command -v arm-linux-gnueabi-ld || command -v arm-linux-gnueabihf-ld || command -v ld.lld)}
OBJDUMP_BIN=${OBJDUMP_BIN:-$(command -v arm-linux-gnueabi-objdump || command -v arm-linux-gnueabihf-objdump)}
OBJCOPY_BIN=${OBJCOPY_BIN:-$(command -v arm-linux-gnueabi-objcopy || command -v arm-linux-gnueabihf-objcopy)}
NM_BIN=${NM_BIN:-$(command -v arm-linux-gnueabi-nm || command -v arm-linux-gnueabihf-nm)}
READELF_BIN=${READELF_BIN:-$(command -v arm-linux-gnueabi-readelf || command -v arm-linux-gnueabihf-readelf || command -v readelf)}

COMMON_FLAGS=(
  --target=armv7-unknown-linux-musleabi
  -C target-cpu=cortex-a7
  -C target-feature=+thumb-mode,+thumb2,+execute-only,-neon,-vfp2,-vfp3,-vfp4,-d32
  -C relocation-model=static
  -C panic=abort
  -C force-unwind-tables=no
  -C "opt-level=$OPT"
  -C codegen-units=1
  -C embed-bitcode=no
)

EXTRA_FLAGS=()
LD_SCRIPT="$SCRIPT_DIR/link-n4-standalone.ld"
if [ "$MODE" = "stack" ]; then
  EXTRA_FLAGS=(--cfg 'feature="stack-hooks"')
  LD_SCRIPT="$SCRIPT_DIR/link-n4-stack.ld"
fi

echo "mode:    $MODE (opt-level=$OPT)"
echo "rustc:   $(rustc --version)"
echo "linker:  $LD_BIN"
echo "objdump: $OBJDUMP_BIN"

# 1. Compile modem-atlas as Thumb-2 rlib.
rustc \
  --edition=2021 \
  --crate-name modem_atlas \
  --crate-type=rlib \
  "${COMMON_FLAGS[@]}" \
  -o "$OUT/libmodem_atlas.rlib" \
  "$MODEM_RUST_DIR/atlas/src/lib.rs"

# 2. Compile witcher-modem-n4 into a single Thumb-2 object file.
rustc \
  --edition=2024 \
  --crate-name witcher_modem_n4 \
  --crate-type=lib \
  --emit=obj="$OUT/n4_engine.o" \
  --extern modem_atlas="$OUT/libmodem_atlas.rlib" \
  "${COMMON_FLAGS[@]}" \
  "${EXTRA_FLAGS[@]}" \
  "$SCRIPT_DIR/src/lib.rs"

# 3. Strip .ARM.exidx unwind metadata before bare-metal link.
"$OBJCOPY_BIN" -R '.ARM.exidx*' "$OUT/n4_engine.o"

# 4. Link at fixed modem VAs (-nostdlib --gc-sections).
"$LD_BIN" \
  -nostdlib \
  --gc-sections \
  -T "$LD_SCRIPT" \
  -o "$OUT/n4_engine.elf" \
  "$OUT/n4_engine.o"

# 5. Extract raw section binaries and disassembly for audit.
"$OBJCOPY_BIN" -O binary -j .n4prach "$OUT/n4_engine.elf" "$OUT/n4prach.bin"
"$OBJCOPY_BIN" -O binary -j .n4cave2 "$OUT/n4_engine.elf" "$OUT/n4cave2.bin"
"$OBJDUMP_BIN" -d -z "$OUT/n4_engine.elf" > "$OUT/n4_engine.dis"
"$NM_BIN" -n "$OUT/n4_engine.elf" > "$OUT/n4_engine.nm"

# 6. Strict bare-metal Thumb-2 audits (0 undef, 0 ARM, 0 literal pools, 0 VFP/NEON).
python3 - "$OUT" "$READELF_BIN" "$MODE" <<'PY'
import os, re, subprocess, sys

out_dir, readelf, mode = sys.argv[1:4]
elf = os.path.join(out_dir, "n4_engine.elf")
prach = open(os.path.join(out_dir, "n4prach.bin"), "rb").read()
cave2 = open(os.path.join(out_dir, "n4cave2.bin"), "rb").read()
dis = open(os.path.join(out_dir, "n4_engine.dis")).read()

PRACH_LO, PRACH_HI = 0x847ed000, 0x847ed540
CAVE2_LO, CAVE2_HI = 0x84194654, 0x84194a5c

assert len(prach) <= (PRACH_HI - PRACH_LO) and len(prach) % 2 == 0, f".n4prach size {len(prach)}"
assert len(cave2) <= (CAVE2_HI - CAVE2_LO) and len(cave2) % 2 == 0, f".n4cave2 size {len(cave2)}"

syms = subprocess.check_output([readelf, "-sW", elf], text=True)
undef, arm_map, data_map = [], [], []
for line in syms.splitlines():
    parts = line.split()
    if len(parts) < 8 or not parts[0].endswith(":"):
        continue
    val_hex, ndx, name = parts[1], parts[6], parts[7]
    if ndx == "UND" and name != "":
        undef.append(name)
    if name == "$a" or name.startswith("$a."):
        arm_map.append((val_hex, name))
    if name == "$d" or name.startswith("$d."):
        v = int(val_hex, 16)
        if (PRACH_LO <= v < PRACH_HI) or (CAVE2_LO <= v < CAVE2_HI):
            data_map.append((val_hex, name))

assert not undef, f"Undefined symbols in ELF: {undef}"
assert not arm_map, f"ARM-mode mapping symbols found: {arm_map}"
assert not data_map, f"Literal pool ($d) inside code cave: {data_map}"

rows = re.findall(r'^\s*([0-9a-f]+):\s+([0-9a-f]{4}(?:\s+[0-9a-f]{4})?)\s+(.+)$', dis, re.M)
dec_bytes = sum(len(b.replace(" ", "")) // 2 for _, b, _ in rows)
assert dec_bytes == len(prach) + len(cave2), f"objdump decoded {dec_bytes} B != {len(prach) + len(cave2)} B"
for addr, _, ins in rows:
    mnem = ins.split()[0].lower()
    assert not mnem.startswith("."), f"Data directive at 0x{addr}: {ins}"
    assert "undefined" not in ins.lower(), f"Undefined insn at 0x{addr}: {ins}"
    assert not mnem.startswith("v"), f"VFP/NEON insn at 0x{addr}: {ins}"
    assert "[pc" not in ins.lower(), f"PC-relative literal load at 0x{addr}: {ins}"
    if mnem == "blx":
        assert ins.split()[1].startswith(("r", "ip", "lr")), f"blx imm at 0x{addr}: {ins}"

total = len(prach) + len(cave2)
print(
    f"PASS [{mode}]: .n4prach = {len(prach)} / {PRACH_HI - PRACH_LO} B, "
    f".n4cave2 = {len(cave2)} / {CAVE2_HI - CAVE2_LO} B (total {total} B), "
    f"0 undef syms, 0 ARM insns, 0 literal pools, 0 VFP/NEON"
)
PY
