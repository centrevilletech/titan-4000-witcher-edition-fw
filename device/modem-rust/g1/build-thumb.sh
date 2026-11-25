#!/usr/bin/env bash
# Bare-metal Thumb-2 (Cortex-A7) build and static audit of the G1 MAC timeline tracer.
#
# Usage: device/modem-rust/g1/build-thumb.sh [out_dir]
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
MODEM_RUST_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
OUT=${1:-"$MODEM_RUST_DIR/target/g1-thumb"}
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
  -C opt-level=z
  -C codegen-units=1
  -C embed-bitcode=no
)

echo "rustc:   $(rustc --version)"
echo "linker:  $LD_BIN"
echo "objdump: $OBJDUMP_BIN"

# 1. Build modem-atlas as a Thumb-2 rlib.
rustc \
  --edition=2021 \
  --crate-name modem_atlas \
  --crate-type=rlib \
  "${COMMON_FLAGS[@]}" \
  -o "$OUT/libmodem_atlas.rlib" \
  "$MODEM_RUST_DIR/atlas/src/lib.rs"

# 2. Clippy for the Thumb-2 target (the only build that compiles `modem.rs`).
if [ "${SKIP_CLIPPY:-0}" != 1 ]; then
  clippy-driver \
    --edition=2024 \
    --crate-name witcher_modem_g1 \
    --crate-type=lib \
    --emit=metadata \
    -o "$OUT/clippy.rmeta" \
    --extern modem_atlas="$OUT/libmodem_atlas.rlib" \
    "${COMMON_FLAGS[@]}" \
    -D warnings \
    "$SCRIPT_DIR/src/lib.rs"
  echo "clippy:  clean for armv7 Thumb-2 (-D warnings)"
fi

# 3. Compile witcher_modem_g1 to a single Thumb-2 object.
rustc \
  --edition=2024 \
  --crate-name witcher_modem_g1 \
  --crate-type=lib \
  --emit=obj="$OUT/g1_tracer.o" \
  --extern modem_atlas="$OUT/libmodem_atlas.rlib" \
  "${COMMON_FLAGS[@]}" \
  -D warnings \
  "$SCRIPT_DIR/src/lib.rs"

# 4. Strip unwind tables.
"$OBJCOPY_BIN" -R '.ARM.exidx*' "$OUT/g1_tracer.o"

# 5. Link at fixed modem addresses: -nostdlib --gc-sections.
"$LD_BIN" \
  -nostdlib \
  --gc-sections \
  -T "$SCRIPT_DIR/link-g1.ld" \
  -o "$OUT/g1_tracer.elf" \
  "$OUT/g1_tracer.o"

# 6. Extract section images and disassembly.
"$OBJCOPY_BIN" -O binary -j .g1code "$OUT/g1_tracer.elf" "$OUT/g1code.bin"
"$OBJCOPY_BIN" -O binary -j .g1cold "$OUT/g1_tracer.elf" "$OUT/g1cold.bin"
"$OBJCOPY_BIN" -O binary -j .g1blk  "$OUT/g1_tracer.elf" "$OUT/g1blk.bin"
"$OBJDUMP_BIN" -d -z "$OUT/g1_tracer.elf" > "$OUT/g1_tracer.dis"
"$NM_BIN" -n "$OUT/g1_tracer.elf" > "$OUT/g1_tracer.nm"

# 7. Static audit.
python3 - "$OUT" "$READELF_BIN" "$OBJDUMP_BIN" "$SCRIPT_DIR/src/block.rs" <<'PY'
import os, re, struct, subprocess, sys

out_dir, readelf, objdump, block_rs = sys.argv[1:5]
elf = os.path.join(out_dir, "g1_tracer.elf")
code = open(os.path.join(out_dir, "g1code.bin"), "rb").read()
cold = open(os.path.join(out_dir, "g1cold.bin"), "rb").read()
blk = open(os.path.join(out_dir, "g1blk.bin"), "rb").read()
dis = open(os.path.join(out_dir, "g1_tracer.dis")).read()

CODE_LO, CODE_HI = 0x8411927c, 0x84119840
COLD_LO, COLD_HI = 0x8450ce94, 0x8450d1e0
BLK_LO = 0x8412a340
STACK_BUDGET = 192  # tight budget inside l2_hp_task / L1U hooks

def rust_const(name):
    m = re.search(rf"pub const {name}: u32 = (0x[0-9a-f_]+|[0-9_]+);", open(block_rs).read())
    assert m, f"{name} not found in block.rs"
    return int(m.group(1).replace("_", ""), 0)

assert len(code) <= CODE_HI - CODE_LO and len(code) % 2 == 0, f".g1code size {len(code)}"
assert len(cold) <= COLD_HI - COLD_LO and len(cold) % 2 == 0, f".g1cold size {len(cold)}"
assert len(blk) == 128, f".g1blk size {len(blk)} != 128"

def in_code(v):
    return (CODE_LO <= v < CODE_HI) or (COLD_LO <= v < COLD_HI)

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
assert not code_data, f"literal pool or jump table in code caves at {code_data}"
panics = [n for n, _ in names.values() if re.search(r"panic|unwind|fmt", n)]
assert not panics, f"panic paths survived linking: {panics}"

required_shims = {"g1_hook_pre_ce", "g1_hook_newtx", "g1_hook_send_tx", "g1_hook_sr", "g1_hook_tti_end"}
present = {n for n, _ in names.values()}
assert required_shims <= present, f"missing shims: {required_shims - present}"

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

funcs = sorted(f for f in names if in_code(f))
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

max_stack = max(depth(f) for f in funcs if names[f][0] in required_shims)
assert max_stack <= STACK_BUDGET, f"hook stack {max_stack} B > budget {STACK_BUDGET} B"

raw = subprocess.check_output(
    [objdump, "-D", "-z", "-b", "binary", "-m", "arm", "-M", "force-thumb",
     f"--adjust-vma={BLK_LO:#x}", os.path.join(out_dir, "g1blk.bin")], text=True)
blk_rows = re.findall(r"^\s*([0-9a-f]+):\s+([0-9a-f]{4}(?: [0-9a-f]{4})?)\s+(.+)$", raw, re.M)
assert sum(len(b.replace(" ", "")) // 2 for _, b, _ in blk_rows) == len(blk), "partial .g1blk decode"
assert not any("undefined" in s.lower() or s.lstrip().startswith(".") for _, _, s in blk_rows), "invalid Thumb-2 in .g1blk"

magic, version, enable, freeze, ring_base, ring_slots, rec_sz, wr_idx, af_mode = struct.unpack_from("<9I", blk, 0)
assert magic == rust_const("MAGIC"), hex(magic)
assert version == rust_const("VERSION"), hex(version)
assert enable == 0, f"boot enable must be 0, got {enable}"
assert freeze == 0, f"boot freeze must be 0, got {freeze}"
assert af_mode == 0, f"boot af_mode must be 0, got {af_mode}"
assert ring_base == rust_const("RING_BASE"), hex(ring_base)
assert ring_slots == rust_const("RING_SLOTS"), ring_slots
assert rec_sz == rust_const("RECORD_SIZE"), rec_sz
assert wr_idx == 0, wr_idx

print(f"PASS: .g1code {len(code)} / {CODE_HI - CODE_LO} B ({CODE_HI - CODE_LO - len(code)} B free), "
      f".g1cold {len(cold)} / {COLD_HI - COLD_LO} B ({COLD_HI - COLD_LO - len(cold)} B free), "
      f".g1blk 128 B @ {BLK_LO:#x} (magic {magic:#x}, version {version:#x}, enable 0, freeze 0), "
      f"max hook stack {max_stack} B, 0 undefined symbols, 0 ARM code, 0 data in code, 0 VFP/NEON, 0 panic paths")
PY
