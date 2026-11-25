#!/usr/bin/env bash
# Reproducible bare-metal Thumb-2 Cortex-A7 build + static audit for the
# combined MAC/PDCP uplink hot-path optimizer (`witcher-modem-mac-opt`).
#
# Usage:
#   device/modem-rust/n3/build-thumb.sh [out_dir]
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
MODEM_RUST_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
OUT=${1:-"$MODEM_RUST_DIR/target/n3-thumb"}
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

# 2. Clippy audit for Thumb-2 target (-D warnings).
if [ "${SKIP_CLIPPY:-0}" != 1 ]; then
  clippy-driver \
    --edition=2024 \
    --crate-name witcher_modem_mac_opt \
    --crate-type=lib \
    --emit=metadata \
    -o "$OUT/clippy.rmeta" \
    --extern modem_atlas="$OUT/libmodem_atlas.rlib" \
    "${COMMON_FLAGS[@]}" \
    -D warnings \
    "$SCRIPT_DIR/src/lib.rs"
  echo "clippy:  clean for armv7 Thumb-2 (-D warnings)"
fi

# 3. Compile witcher-modem-mac-opt into a single Thumb-2 object.
rustc \
  --edition=2024 \
  --crate-name witcher_modem_mac_opt \
  --crate-type=lib \
  --emit=obj="$OUT/mac_pdcp_opt.o" \
  --extern modem_atlas="$OUT/libmodem_atlas.rlib" \
  "${COMMON_FLAGS[@]}" \
  -D warnings \
  "$SCRIPT_DIR/src/lib.rs"

# 4. Strip unwind metadata and link at fixed dead-cave VAs.
"$OBJCOPY_BIN" -R '.ARM.exidx*' "$OUT/mac_pdcp_opt.o"
"$LD_BIN" \
  -nostdlib \
  --gc-sections \
  -T "$SCRIPT_DIR/link-n3.ld" \
  -o "$OUT/mac_pdcp_opt.elf" \
  "$OUT/mac_pdcp_opt.o"

# 5. Extract raw sections and disassembly.
"$OBJCOPY_BIN" -O binary -j .optcode1 "$OUT/mac_pdcp_opt.elf" "$OUT/optcode1.bin"
"$OBJCOPY_BIN" -O binary -j .optcode2 "$OUT/mac_pdcp_opt.elf" "$OUT/optcode2.bin"
"$OBJCOPY_BIN" -O binary -j .optblk   "$OUT/mac_pdcp_opt.elf" "$OUT/optblk.bin"
"$OBJDUMP_BIN" -d -z "$OUT/mac_pdcp_opt.elf" > "$OUT/mac_pdcp_opt.dis"
"$NM_BIN" -n "$OUT/mac_pdcp_opt.elf" > "$OUT/mac_pdcp_opt.nm"

# 6. Strict bare-metal Thumb-2 audits (0 undef, 0 ARM, 0 literal pools, 0 VFP/NEON, 0 panics, valid Thumb-2 blk).
python3 - "$OUT" "$READELF_BIN" "$OBJDUMP_BIN" "$SCRIPT_DIR/src/block.rs" <<'PY'
import os, re, struct, subprocess, sys

out_dir, readelf, objdump, block_rs = sys.argv[1:5]
elf = os.path.join(out_dir, "mac_pdcp_opt.elf")
code1 = open(os.path.join(out_dir, "optcode1.bin"), "rb").read()
code2 = open(os.path.join(out_dir, "optcode2.bin"), "rb").read()
blk = open(os.path.join(out_dir, "optblk.bin"), "rb").read()
dis = open(os.path.join(out_dir, "mac_pdcp_opt.dis")).read()

C1_LO, C1_HI = 0x841867E4, 0x84186B38
C2_LO, C2_HI = 0x8417FFD8, 0x8418024C
BLK_LO = 0x841BB5C0

def rust_const(name):
    m = re.search(rf"pub const {name}: u32 = (0x[0-9a-f_]+);", open(block_rs).read())
    assert m, f"{name} not found"
    return int(m.group(1).replace("_", ""), 16)

assert 0 < len(code1) <= (C1_HI - C1_LO) and len(code1) % 2 == 0, f".optcode1 size {len(code1)}"
assert 0 < len(code2) <= (C2_HI - C2_LO) and len(code2) % 2 == 0, f".optcode2 size {len(code2)}"
assert len(blk) == 128, f".optblk size {len(blk)} != 128"

syms = subprocess.check_output([readelf, "-sW", elf], text=True)
undef, arm_map, code_data, names = [], [], [], {}
for line in syms.splitlines():
    parts = line.split()
    if len(parts) < 8 or not parts[0].endswith(":") or not re.fullmatch(r"[0-9a-f]{8}", parts[1]):
        continue
    val, size, ndx, name = int(parts[1], 16), int(parts[2], 0), parts[6], parts[7]
    if ndx == "UND" and name:
        undef.append(name)
    if name == "$a" or name.startswith("$a."):
        arm_map.append(name)
    if (name == "$d" or name.startswith("$d.")) and (C1_LO <= val < C1_HI or C2_LO <= val < C2_HI):
        code_data.append(hex(val))
    if parts[3] == "FUNC":
        names[val & ~1] = (name, size)

assert not undef, f"undefined symbols: {undef}"
assert not arm_map, f"ARM-mode code: {arm_map}"
assert not code_data, f"literal pool in code cave: {code_data}"
panics = [n for n, _ in names.values() if re.search(r"panic|unwind|fmt", n)]
assert not panics, f"panic paths survived linking: {panics}"

rows = re.findall(r"^\s*([0-9a-f]+):\s+([0-9a-f]{4}(?:\s+[0-9a-f]{4})?)\s+(.+)$", dis, re.M)
assert sum(len(b.replace(" ", "")) // 2 for _, b, _ in rows) == len(code1) + len(code2), (
    f"partial decode: {sum(len(b.replace(' ', '')) // 2 for _, b, _ in rows)} != {len(code1) + len(code2)}"
)
for addr, _, ins in rows:
    mnem = ins.split()[0].lower()
    assert not mnem.startswith("."), f"data directive at 0x{addr}: {ins}"
    assert "undefined" not in ins.lower(), f"undefined insn at 0x{addr}: {ins}"
    assert not mnem.startswith("v"), f"VFP/NEON at 0x{addr}: {ins}"
    ops = ins[len(mnem):].lower()
    reglist_pop = mnem.startswith(("pop", "ldm")) and re.search(r"\{[^}]*\bpc\b", ops)
    assert not re.search(r"\bpc\b", ops) or reglist_pop, f"PC-relative operand at 0x{addr}: {ins}"
    assert mnem not in ("udf", "bkpt"), f"trap at 0x{addr}: {ins}"

raw = subprocess.check_output(
    [objdump, "-D", "-z", "-b", "binary", "-m", "arm", "-M", "force-thumb",
     f"--adjust-vma={BLK_LO:#x}", os.path.join(out_dir, "optblk.bin")], text=True)
blk_rows = re.findall(r"^\s*([0-9a-f]+):\s+([0-9a-f]{4}(?: [0-9a-f]{4})?)\s+(.+)$", raw, re.M)
assert sum(len(b.replace(" ", "")) // 2 for _, b, _ in blk_rows) == len(blk), "partial .optblk decode"
assert not any("undefined" in s.lower() or s.lstrip().startswith(".") for _, _, s in blk_rows), "invalid Thumb-2 in .optblk"

magic, version, flags = struct.unpack_from("<III", blk, 0)
assert magic == rust_const("MAGIC"), hex(magic)
assert version == rust_const("VERSION"), hex(version)
assert flags == 0, f"boot flags must be 0, got {flags}"

print(f"PASS: .optcode1 {len(code1)}/{C1_HI-C1_LO} B ({C1_HI-C1_LO-len(code1)} B free), "
      f".optcode2 {len(code2)}/{C2_HI-C2_LO} B ({C2_HI-C2_LO-len(code2)} B free), "
      f".optblk 128 B @ {BLK_LO:#x} (magic {magic:#x}, version {version:#x}, flags 0), "
      f"0 undef, 0 ARM, 0 literal pools, 0 VFP/NEON, 0 panics")
PY
