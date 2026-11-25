#!/usr/bin/env bash
# Bare-metal Thumb-2 (Cortex-A7) build and static audit of the uplink AQM patch.
#
# Usage: device/modem-rust/build-thumb.sh [out_dir]
#
# Target: armv7-unknown-linux-musleabi with target-cpu=cortex-a7 and
# +thumb-mode,+thumb2,+execute-only,-neon,-vfp2,-vfp3,-vfp4,-d32, linked with link-m1.ld
# (-nostdlib --gc-sections). Plain rustc, no cargo.
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

# 1. Lane M2's modem-atlas crate as a Thumb-2 rlib.
rustc \
  --edition=2021 \
  --crate-name modem_atlas \
  --crate-type=rlib \
  "${COMMON_FLAGS[@]}" \
  -o "$OUT/libmodem_atlas.rlib" \
  "$SCRIPT_DIR/atlas/src/lib.rs"

# 2. Lint the AQM for the Thumb-2 target. Only this pass sees the `modem` module (the
#    hook and the crate's only unsafe code), which host builds leave out. The crate root
#    denies undocumented unsafe blocks and more than one unsafe operation per block.
if [ "${SKIP_CLIPPY:-0}" != 1 ]; then
  clippy-driver \
    --edition=2024 \
    --crate-name witcher_modem_aqm \
    --crate-type=lib \
    --emit=metadata \
    -o "$OUT/clippy.rmeta" \
    --extern modem_atlas="$OUT/libmodem_atlas.rlib" \
    "${COMMON_FLAGS[@]}" \
    -D warnings \
    "$SCRIPT_DIR/src/lib.rs"
  echo "clippy:  clean for armv7 Thumb-2 (-D warnings)"
fi

# 3. The AQM as one Thumb-2 object.
rustc \
  --edition=2024 \
  --crate-name witcher_modem_aqm \
  --crate-type=lib \
  --emit=obj="$OUT/m1_aqm.o" \
  --extern modem_atlas="$OUT/libmodem_atlas.rlib" \
  "${COMMON_FLAGS[@]}" \
  -D warnings \
  "$SCRIPT_DIR/src/lib.rs"

# 4. Drop unwind tables (unreferenced, but GNU ld would keep __aeabi_unwind_cpp_pr0).
"$OBJCOPY_BIN" -R '.ARM.exidx*' "$OUT/m1_aqm.o"

# 5. Link at the fixed modem addresses: no libc, no compiler_builtins, no CRT.
"$LD_BIN" \
  -nostdlib \
  --gc-sections \
  -T "$SCRIPT_DIR/link-m1.ld" \
  -o "$OUT/m1_aqm.elf" \
  "$OUT/m1_aqm.o"

# 6. Section images and disassembly for the audit.
"$OBJCOPY_BIN" -O binary -j .m1code "$OUT/m1_aqm.elf" "$OUT/m1code.bin"
"$OBJCOPY_BIN" -O binary -j .m1cold "$OUT/m1_aqm.elf" "$OUT/m1cold.bin"
"$OBJCOPY_BIN" -O binary -j .m1blk  "$OUT/m1_aqm.elf" "$OUT/m1blk.bin"
"$OBJDUMP_BIN" -d -z "$OUT/m1_aqm.elf" > "$OUT/m1_aqm.dis"
"$NM_BIN" -n "$OUT/m1_aqm.elf" > "$OUT/m1_aqm.nm"

# 7. Audit.
python3 - "$OUT" "$READELF_BIN" "$OBJDUMP_BIN" "$SCRIPT_DIR/src/block.rs" <<'PY'
import os, re, struct, subprocess, sys

out_dir, readelf, objdump, block_rs = sys.argv[1:5]
elf = os.path.join(out_dir, "m1_aqm.elf")
code = open(os.path.join(out_dir, "m1code.bin"), "rb").read()
cold = open(os.path.join(out_dir, "m1cold.bin"), "rb").read()
blk = open(os.path.join(out_dir, "m1blk.bin"), "rb").read()
dis = open(os.path.join(out_dir, "m1_aqm.dis")).read()

CODE_LO, CODE_HI = 0x841de8dc, 0x841df200
COLD_LO, COLD_HI = 0x8446e4c8, 0x8446e718
BLK_LO = 0x841b5900
in_code = lambda va: CODE_LO <= va < CODE_HI or COLD_LO <= va < COLD_HI
STACK_BUDGET = 256  # bytes the hook may add to l2_task's stack below N4's frame


def rust_const(name):
    m = re.search(rf"pub const {name}: u32 = (0x[0-9a-f_]+);", open(block_rs).read())
    assert m, f"{name} not found in block.rs"
    return int(m.group(1).replace("_", ""), 16)


assert len(code) <= CODE_HI - CODE_LO and len(code) % 2 == 0, f".m1code size {len(code)}"
assert len(cold) <= COLD_HI - COLD_LO and len(cold) % 2 == 0, f".m1cold size {len(cold)}"
assert len(blk) == 256, f".m1blk size {len(blk)} != 256"

# Symbols: nothing undefined, no ARM-mode code, no data in the code cave, no panic machinery.
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
    if (name == "$d" or name.startswith("$d.")) and in_code(val):
        code_data.append(hex(val))
    if parts[3] == "FUNC":
        names[val & ~1] = (name, size)
assert not undef, f"undefined symbols: {undef}"
assert not arm_map, f"ARM-mode code: {arm_map}"
assert not code_data, f"literal pool or jump table in a code cave at {code_data}"
panics = [n for n, _ in names.values() if re.search(r"panic|unwind|fmt", n)]
assert not panics, f"panic paths survived linking: {panics}"
assert names.get(CODE_LO, ("", 0))[0] == "m1_aqm_shim", "m1_aqm_shim must be first in .m1code"

# Disassembly: every byte decodes; no PC-relative operands (literal loads, `adr`, branch
# tables) except `pop {..., pc}`; no VFP/NEON; no traps.
rows = re.findall(r"^\s*([0-9a-f]+):\s+([0-9a-f]{4}(?:\s+[0-9a-f]{4})?)\s+(.+)$", dis, re.M)
assert sum(len(b.replace(" ", "")) // 2 for _, b, _ in rows) == len(code) + len(cold), "partial decode"
for addr, _, ins in rows:
    mnem = ins.split()[0].lower()
    assert not mnem.startswith("."), f"data directive at 0x{addr}: {ins}"
    assert "undefined" not in ins.lower(), f"undefined instruction at 0x{addr}: {ins}"
    assert not mnem.startswith("v"), f"VFP/NEON at 0x{addr}: {ins}"
    ops = ins[len(mnem):].lower()
    reglist_pop = mnem.startswith(("pop", "ldm")) and re.search(r"\{[^}]*\bpc\b", ops)
    assert not re.search(r"\bpc\b", ops) or reglist_pop, f"PC-relative operand at 0x{addr}: {ins}"
    assert mnem not in ("udf", "bkpt"), f"trap at 0x{addr}: {ins}"
    if mnem == "blx":
        assert ins.split()[1].startswith(("r", "ip", "lr")), f"blx immediate at 0x{addr}: {ins}"

# Stack: the deepest frame chain below the shim. Each function's frame is its pushes
# plus any `sub sp`; calls follow `bl`. The shim's own push of {r2, r3} counts too.
funcs = sorted(names)
def owner(a):
    best = None
    for f in funcs:
        if f <= a:
            best = f
    return best
frame, calls = {f: 0 for f in funcs}, {f: set() for f in funcs}
for addr, _, ins in rows:
    a = int(addr, 16)
    f = owner(a)
    if f is None:
        continue
    m = re.match(r"(push|stmdb)(?:\.w)?\s+(?:sp!,\s*)?\{([^}]*)\}", ins)
    if m:
        frame[f] += 4 * len(m.group(2).split(","))
    m = re.match(r"sub(?:\.w)?\s+sp,\s*(?:sp,\s*)?#(\d+)", ins)
    if m:
        frame[f] += int(m.group(1))
    m = re.match(r"bl\s+([0-9a-f]+)", ins)
    if m:
        calls[f].add(int(m.group(1), 16) & ~1)
def depth(f, seen=()):
    assert f not in seen, f"recursion through {names[f][0]}"
    return frame[f] + max((depth(c, seen + (f,)) for c in calls[f] if c in frame), default=0)
stack = depth(CODE_LO)
assert stack <= STACK_BUDGET, f"hook stack {stack} B > budget {STACK_BUDGET} B"

# The block decodes as Thumb-2 (tkpatch.py audits every patched range that way).
raw = subprocess.check_output(
    [objdump, "-D", "-z", "-b", "binary", "-m", "arm", "-M", "force-thumb",
     f"--adjust-vma={BLK_LO:#x}", os.path.join(out_dir, "m1blk.bin")], text=True)
blk_rows = re.findall(r"^\s*([0-9a-f]+):\s+([0-9a-f]{4}(?: [0-9a-f]{4})?)\s+(.+)$", raw, re.M)
assert sum(len(b.replace(" ", "")) // 2 for _, b, _ in blk_rows) == len(blk), "partial .m1blk decode"
assert not any("undefined" in s.lower() or s.lstrip().startswith(".") for _, _, s in blk_rows), "invalid Thumb-2 in .m1blk"

magic, version, selector = struct.unpack_from("<III", blk, 0)
assert magic == rust_const("MAGIC"), hex(magic)
assert version == rust_const("VERSION"), hex(version)
assert selector == 0, f"boot selector must be 0, got {selector}"

print(f"PASS: .m1code {len(code)} / {CODE_HI - CODE_LO} B ({CODE_HI - CODE_LO - len(code)} B free), "
      f".m1cold {len(cold)} / {COLD_HI - COLD_LO} B ({COLD_HI - COLD_LO - len(cold)} B free), "
      f"m1_aqm_shim @ {CODE_LO:#x}, .m1blk 256 B @ {BLK_LO:#x} (magic {magic:#x}, version {version:#x}, selector 0), "
      f"hook stack {stack} B, 0 undefined symbols, 0 ARM code, 0 data in code, 0 VFP/NEON, 0 panic paths")
PY
