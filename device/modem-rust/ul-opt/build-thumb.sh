#!/usr/bin/env bash
# Reproducible bare-metal Thumb-2 Cortex-A7 build + static audit for witcher-modem-ul-opt.
#
# Usage:
#   device/modem-rust/ul-opt/build-thumb.sh [out_dir]
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
MODEM_RUST_DIR=$(cd "$SCRIPT_DIR/.." && pwd)

OUT=${1:-"$MODEM_RUST_DIR/target/ul-opt-thumb"}
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
  -C opt-level=s
  -C codegen-units=1
  -C embed-bitcode=no
)

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

# 2. Compile witcher-modem-ul-opt into a single Thumb-2 object file.
rustc \
  --edition=2024 \
  --crate-name witcher_modem_ul_opt \
  --crate-type=lib \
  --emit=obj="$OUT/ul_opt.o" \
  --extern modem_atlas="$OUT/libmodem_atlas.rlib" \
  "${COMMON_FLAGS[@]}" \
  "$SCRIPT_DIR/src/lib.rs"

# 3. Strip .ARM.exidx unwind metadata before bare-metal link.
"$OBJCOPY_BIN" -R '.ARM.exidx*' "$OUT/ul_opt.o"

# 4. Link at fixed dead-cave modem VAs (-nostdlib --gc-sections).
"$LD_BIN" \
  -nostdlib \
  --gc-sections \
  -T "$SCRIPT_DIR/link-n2-opt.ld" \
  -o "$OUT/ul_opt.elf" \
  "$OUT/ul_opt.o"

# 5. Extract raw section binaries and disassembly for audit.
"$OBJCOPY_BIN" -O binary -j .n2opt "$OUT/ul_opt.elf" "$OUT/n2opt.bin"
"$OBJCOPY_BIN" -O binary -j .n2blk "$OUT/ul_opt.elf" "$OUT/n2blk.bin"
"$OBJDUMP_BIN" -d -j .n2opt -z "$OUT/ul_opt.elf" > "$OUT/ul_opt.dis"
"$NM_BIN" -n "$OUT/ul_opt.elf" > "$OUT/ul_opt.nm"

# 6. Strict bare-metal Thumb-2 audits (0 undef, 0 ARM, 0 literal pools, 0 VFP/NEON).
python3 - "$OUT" "$READELF_BIN" <<'PY'
import os, re, subprocess, sys

out_dir, readelf = sys.argv[1:3]
elf = os.path.join(out_dir, "ul_opt.elf")
code = open(os.path.join(out_dir, "n2opt.bin"), "rb").read()
blk = open(os.path.join(out_dir, "n2blk.bin"), "rb").read()
dis = open(os.path.join(out_dir, "ul_opt.dis")).read()

OPT_LO, OPT_HI = 0x841867e4, 0x84186b38
BLK_LO, BLK_HI = 0x841bb5c0, 0x841bb87c

assert len(code) <= (OPT_HI - OPT_LO) and len(code) % 2 == 0, f".n2opt size {len(code)}"
assert len(blk) <= (BLK_HI - BLK_LO) and len(blk) == 64, f".n2blk size {len(blk)} (expected 64 B N2OptState)"

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
        if OPT_LO <= v < OPT_HI:
            data_map.append((val_hex, name))

assert not undef, f"Undefined symbols in ELF: {undef}"
assert not arm_map, f"ARM-mode mapping symbols found: {arm_map}"
assert not data_map, f"Literal pool ($d) inside code cave: {data_map}"

rows = re.findall(r'^\s*([0-9a-f]+):\s+([0-9a-f]{4}(?:\s+[0-9a-f]{4})?)\s+(.+)$', dis, re.M)
dec_bytes = sum(len(b.replace(" ", "")) // 2 for _, b, _ in rows)
assert dec_bytes == len(code), f"objdump decoded {dec_bytes} B != {len(code)} B"
for addr, _, ins in rows:
    mnem = ins.split()[0].lower()
    assert not mnem.startswith("."), f"Data directive at 0x{addr}: {ins}"
    assert "undefined" not in ins.lower(), f"Undefined insn at 0x{addr}: {ins}"
    assert not mnem.startswith("v"), f"VFP/NEON insn at 0x{addr}: {ins}"
    assert "[pc" not in ins.lower(), f"PC-relative literal load at 0x{addr}: {ins}"
    if mnem == "blx":
        assert ins.split()[1].startswith(("r", "ip", "lr")), f"blx imm at 0x{addr}: {ins}"

print(
    f"PASS [ul-opt]: .n2opt = {len(code)} / {OPT_HI - OPT_LO} B, "
    f".n2blk = {len(blk)} / {BLK_HI - BLK_LO} B, "
    f"0 undef syms, 0 ARM insns, 0 literal pools, 0 VFP/NEON"
)
PY
