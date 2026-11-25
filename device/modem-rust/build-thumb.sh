#!/usr/bin/env bash
# Reproducible bare-metal Thumb-2 Cortex-A7 build + static audit for witcher-modem-aqm.
#
# Usage:
#   device/modem-rust/build-thumb.sh [out_dir]
#
# Target choice: armv7-unknown-linux-musleabi with -C target-cpu=cortex-a7 and
# +thumb-mode,+thumb2,+execute-only,-neon,-vfp2,-vfp3,-vfp4,-d32, linked with
# link-m1.ld (-nostdlib --gc-sections).
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-"$SCRIPT_DIR/target/m1-thumb"}
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

# 1. Compile Lane M2's modem-atlas crate as a Thumb-2 rlib.
rustc \
  --edition=2021 \
  --crate-name modem_atlas \
  --crate-type=rlib \
  "${COMMON_FLAGS[@]}" \
  -o "$OUT/libmodem_atlas.rlib" \
  "$SCRIPT_DIR/atlas/src/lib.rs"

# 2. Compile witcher-modem-aqm against modem-atlas into a single Thumb-2 object file.
rustc \
  --edition=2024 \
  --crate-name witcher_modem_aqm \
  --crate-type=lib \
  --emit=obj="$OUT/m1_aqm.o" \
  --extern modem_atlas="$OUT/libmodem_atlas.rlib" \
  "${COMMON_FLAGS[@]}" \
  "$SCRIPT_DIR/src/lib.rs"

# 3. Strip unused .ARM.exidx unwind metadata from the object before bare-metal link
#    (prevents GNU ld from keeping an unreferenced __aeabi_unwind_cpp_pr0 symbol).
"$OBJCOPY_BIN" -R '.ARM.exidx*' "$OUT/m1_aqm.o"

# 4. Link at fixed modem VAs using link-m1.ld (no libc, no compiler_builtins, no CRT).
"$LD_BIN" \
  -nostdlib \
  --gc-sections \
  -T "$SCRIPT_DIR/link-m1.ld" \
  -o "$OUT/m1_aqm.elf" \
  "$OUT/m1_aqm.o"

# 4. Extract raw section binaries and disassembly for audit.
"$OBJCOPY_BIN" -O binary -j .m1code "$OUT/m1_aqm.elf" "$OUT/m1code.bin"
"$OBJCOPY_BIN" -O binary -j .m1blk  "$OUT/m1_aqm.elf" "$OUT/m1blk.bin"
"$OBJDUMP_BIN" -d -z "$OUT/m1_aqm.elf" > "$OUT/m1_aqm.dis"
"$NM_BIN" -n "$OUT/m1_aqm.elf" > "$OUT/m1_aqm.nm"

# 5. Strict bare-metal Thumb-2 audits.
python3 - "$OUT" "$READELF_BIN" "$OBJDUMP_BIN" <<'PY'
import os, re, struct, subprocess, sys

out_dir, readelf, objdump = sys.argv[1:4]
elf = os.path.join(out_dir, "m1_aqm.elf")
code = open(os.path.join(out_dir, "m1code.bin"), "rb").read()
blk = open(os.path.join(out_dir, "m1blk.bin"), "rb").read()
dis = open(os.path.join(out_dir, "m1_aqm.dis")).read()

CODE_LO, CODE_HI = 0x841de8dc, 0x841df200
BLK_LO = 0x841b5900

assert len(code) <= (CODE_HI - CODE_LO) and len(code) % 2 == 0, f".m1code size {len(code)} > {CODE_HI - CODE_LO} or odd"
assert len(blk) == 256, f".m1blk size {len(blk)} != 256"

# Check zero undefined symbols and zero ARM-mode ($a) or code-section data ($d) mapping symbols.
syms = subprocess.check_output([readelf, "-sW", elf], text=True)
undef = []
arm_map = []
code_data_map = []
for line in syms.splitlines():
    parts = line.split()
    if len(parts) < 8 or not parts[0].endswith(":"):
        continue
    val_hex, ndx, name = parts[1], parts[6], parts[7]
    if ndx == "UND" and name != "":
        undef.append(name)
    if name == "$a" or name.startswith("$a."):
        arm_map.append((val_hex, name))
    if (name == "$d" or name.startswith("$d.")) and CODE_LO <= int(val_hex, 16) < CODE_HI:
        code_data_map.append((val_hex, name))

assert not undef, f"Undefined symbols in ELF: {undef}"
assert not arm_map, f"ARM-mode mapping symbols found (must be pure Thumb-2): {arm_map}"
assert not code_data_map, f"Literal pool ($d) inside .m1code: {code_data_map}"

# Check disassembly: every byte decoded, zero PC-relative loads, zero VFP/NEON, zero blx imm.
rows = re.findall(r'^\s*([0-9a-f]+):\s+([0-9a-f]{4}(?:\s+[0-9a-f]{4})?)\s+(.+)$', dis, re.M)
dec_bytes = sum(len(b.replace(" ", "")) // 2 for _, b, _ in rows)
assert dec_bytes == len(code), f"objdump decoded {dec_bytes} B != {len(code)} B"
for addr, _, ins in rows:
    mnem = ins.split()[0].lower()
    assert not mnem.startswith("."), f"Data directive in .m1code at 0x{addr}: {ins}"
    assert "undefined" not in ins.lower(), f"Undefined insn at 0x{addr}: {ins}"
    assert not mnem.startswith("v"), f"VFP/NEON insn in .m1code at 0x{addr}: {ins}"
    assert "[pc" not in ins.lower(), f"PC-relative literal load at 0x{addr}: {ins}"
    if mnem == "blx":
        assert ins.split()[1].startswith(("r", "ip", "lr")), f"blx imm at 0x{addr}: {ins}"

# Check Thumb-2 decode of .m1blk via objdump (matching tkpatch.py's check).
raw_blk_dis = subprocess.check_output(
    [objdump, "-D", "-z", "-b", "binary", "-m", "arm", "-M", "force-thumb",
     f"--adjust-vma={BLK_LO:#x}", os.path.join(out_dir, "m1blk.bin")],
    text=True,
)
blk_rows = re.findall(r'^\s*([0-9a-f]+):\s+([0-9a-f]{4}(?: [0-9a-f]{4})?)\s+(.+)$', raw_blk_dis, re.M)
blk_dec = sum(len(b.replace(" ", "")) // 2 for _, b, _ in blk_rows)
assert blk_dec == len(blk), f"objdump decoded {blk_dec} B != {len(blk)} B for .m1blk"
assert not any("undefined" in s.lower() or s.lstrip().startswith(".") for _, _, s in blk_rows), "invalid Thumb-2 in .m1blk"

magic, ver, sel = struct.unpack_from("<III", blk, 0)
assert magic == 0x4d315049, hex(magic)
assert ver == 0x20261125, hex(ver)
assert sel == 0, f"boot selector must be 0, got {sel}"

print(f"PASS: .m1code = {len(code)} / {CODE_HI - CODE_LO} B ({CODE_HI - CODE_LO - len(code)} B free), "
      f".m1blk = {len(blk)} B @ {BLK_LO:#x}, 0 undef syms, 0 ARM insns, 0 literal pools, 0 VFP/NEON")
PY
