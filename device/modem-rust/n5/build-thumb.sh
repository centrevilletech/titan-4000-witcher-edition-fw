#!/usr/bin/env bash
# Reproducible bare-metal Thumb-2 Cortex-A7 build + static audit for witcher-modem-n5.
#
# Usage:
#   device/modem-rust/n5/build-thumb.sh [out_dir] [--opt z|s|2]
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
MODEM_RUST_DIR=$(cd "$SCRIPT_DIR/.." && pwd)

OUT=""
OPT="2"

while [ $# -gt 0 ]; do
  case "$1" in
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

OUT=${OUT:-"$MODEM_RUST_DIR/target/n5-thumb"}
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)

export PATH="$HOME/.cargo/bin:$PATH"

AS_BIN=${AS_BIN:-$(command -v arm-linux-gnueabi-as || command -v arm-linux-gnueabihf-as)}
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

echo "opt:     $OPT"
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

# 2. Compile witcher-modem-n5 into a single Thumb-2 object file.
rustc \
  --edition=2024 \
  --crate-name witcher_modem_n5 \
  --crate-type=lib \
  --emit=obj="$OUT/n5_flow.o" \
  --extern modem_atlas="$OUT/libmodem_atlas.rlib" \
  "${COMMON_FLAGS[@]}" \
  "$SCRIPT_DIR/src/lib.rs"

# 3. Strip .ARM.exidx unwind metadata before bare-metal link and assemble fixed-VA Thumb target syms.
"$OBJCOPY_BIN" -R '.ARM.exidx*' "$OUT/n5_flow.o"
cat > "$OUT/ext_syms.s" <<'ASM'
    .syntax unified
    .thumb
    .section .note.GNU-stack,"",%progbits
    .global n4_hook4_aqm
    .global n4_hook4_exit_b
    .global n4_hook4_exit_a
    .global pdcp_ul_cipher_sub
    .thumb_set n4_hook4_aqm,       0x847ed414
    .thumb_set n4_hook4_exit_b,    0x847ed52e
    .thumb_set n4_hook4_exit_a,    0x847ed53c
    .thumb_set pdcp_ul_cipher_sub, 0x842dc968
ASM
"$AS_BIN" -mcpu=cortex-a7 -mthumb -o "$OUT/ext_syms.o" "$OUT/ext_syms.s"

# 4. Link at fixed modem VAs (-nostdlib --gc-sections).
"$LD_BIN" \
  -nostdlib \
  --gc-sections \
  -T "$SCRIPT_DIR/link-n5.ld" \
  -o "$OUT/n5_flow.elf" \
  "$OUT/n5_flow.o" "$OUT/ext_syms.o"

# 5. Extract raw section binaries and disassembly for audit.
"$OBJCOPY_BIN" -O binary -j .n5cave_g "$OUT/n5_flow.elf" "$OUT/n5cave_g.bin"
"$OBJCOPY_BIN" -O binary -j .n5cave_g_tail "$OUT/n5_flow.elf" "$OUT/n5cave_g_tail.bin"
"$OBJCOPY_BIN" -O binary -j .n5blk "$OUT/n5_flow.elf" "$OUT/n5blk.bin"
"$OBJDUMP_BIN" -d -z "$OUT/n5_flow.elf" > "$OUT/n5_flow.dis"
"$NM_BIN" -n "$OUT/n5_flow.elf" > "$OUT/n5_flow.nm"

# 6. Strict bare-metal Thumb-2 audits (0 undef, 0 ARM, 0 literal pools, 0 VFP/NEON, exact entry VAs).
python3 - "$OUT" "$READELF_BIN" <<'PY'
import os, re, struct, subprocess, sys

out_dir, readelf = sys.argv[1:3]
elf = os.path.join(out_dir, "n5_flow.elf")
cave_g = open(os.path.join(out_dir, "n5cave_g.bin"), "rb").read()
cave_tail = open(os.path.join(out_dir, "n5cave_g_tail.bin"), "rb").read()
blk = open(os.path.join(out_dir, "n5blk.bin"), "rb").read()
dis = open(os.path.join(out_dir, "n5_flow.dis")).read()
nm = open(os.path.join(out_dir, "n5_flow.nm")).read()

CAVE_G_LO, CAVE_G_HI = 0x8418F768, 0x8418FD78
TAIL_LO, TAIL_HI = 0x8418FE90, 0x8418FF00

assert len(cave_g) == (CAVE_G_HI - CAVE_G_LO) and len(cave_g) % 2 == 0, f".n5cave_g size {len(cave_g)}"
assert len(cave_tail) <= (TAIL_HI - TAIL_LO) and len(cave_tail) % 2 == 0, f".n5cave_g_tail size {len(cave_tail)}"
assert len(blk) == 1202, f".n5blk size {len(blk)}"

# Verify fixed-VA ABI entry points match assembly N5 verbatim.
sym_va = {}
for line in nm.splitlines():
    parts = line.split()
    if len(parts) == 3:
        sym_va[parts[2]] = int(parts[0], 16)
assert sym_va.get("n5_flow_classify") == 0x8418F768, sym_va.get("n5_flow_classify")
assert sym_va.get("n5_pdcp_limit") == 0x8418FC9C, sym_va.get("n5_pdcp_limit")
assert sym_va.get("n5_ring0_submit") == 0x8418FD0A, sym_va.get("n5_ring0_submit")

# Verify boot-default N5 RAM block header (2 B pad + N5FL + version + flags=0 + defaults + zeroed tail).
assert blk[:2] == b"\x00\x00"
words = struct.unpack_from("<12I", blk, 2)
assert words == (0x4E35464C, 0x20261123, 0, 40, 3072, 500, 10, 0, 16384, 24576, 0, 0), words
assert blk[50:] == bytes(1152), "non-zero runtime/counter/table byte in .n5blk"

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
        if (CAVE_G_LO <= v < CAVE_G_HI) or (TAIL_LO <= v < TAIL_HI):
            data_map.append((val_hex, name))

assert not undef, f"Undefined symbols in ELF: {undef}"
assert not arm_map, f"ARM-mode mapping symbols found: {arm_map}"
assert not data_map, f"Literal pool ($d) inside code cave: {data_map}"

rows = re.findall(r'^\s*([0-9a-f]+):\s+([0-9a-f]{4}(?:\s+[0-9a-f]{4})?)\s+(.+)$', dis, re.M)
dec_bytes = sum(len(b.replace(" ", "")) // 2 for _, b, _ in rows)
assert dec_bytes == len(cave_g) + len(cave_tail), f"objdump decoded {dec_bytes} B != {len(cave_g) + len(cave_tail)} B"
for addr, _, ins in rows:
    mnem = ins.split()[0].lower()
    assert not mnem.startswith("."), f"Data directive at 0x{addr}: {ins}"
    assert "undefined" not in ins.lower(), f"Undefined insn at 0x{addr}: {ins}"
    assert not mnem.startswith("v"), f"VFP/NEON insn at 0x{addr}: {ins}"
    assert "[pc" not in ins.lower(), f"PC-relative literal load at 0x{addr}: {ins}"
    if mnem == "blx":
        assert ins.split()[1].startswith(("r", "ip", "lr")), f"blx imm at 0x{addr}: {ins}"

total = len(cave_g) + len(cave_tail)
print(
    f"PASS: .n5cave_g = {len(cave_g)} / {CAVE_G_HI - CAVE_G_LO} B, "
    f".n5cave_g_tail = {len(cave_tail)} / {TAIL_HI - TAIL_LO} B (total {total} B), "
    f".n5blk = {len(blk)} B, 0 undef syms, 0 ARM insns, 0 literal pools, 0 VFP/NEON"
)
PY
