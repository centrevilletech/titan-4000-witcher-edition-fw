#!/usr/bin/env python3
"""Generate a tkpatch.py JSON manifest for N6H + the Rust uplink AQM.

Consumes the linked Thumb-2 ELF produced by `build-thumb.sh`, stock `tk.bin`,
and N6H's hash-pinned manifest `n6h-spec.json`.

All 68 N6H sites are carried forward unchanged except `n4_ul_engine_cave`
(`0x847ed000..0x847ed540`), where 6 bytes at `0x847ed414..0x847ed41a`
(`ldr r0, [r5, #4]; and r0, r0, #5`) become `bl m1_aqm_shim; nop`.
Two disjoint dead-cave sites are added:
  1. `m1_rust_pie_code`  (`0x841de8dc..0x841df200`, 2,340 B inside dead `cmd_phy`)
  2. `m1_rust_pie_block` (`0x841b5900..0x841b5a00`, 256 B inside dead `UMM_DecodeATR`)

Audits every constraint enforced by `tkpatch.py` and checks zero overlap against
the N6H, C1, N7, U14, IMG4 PRACH-tail and R4 Rust N4 ranges. The block's magic and
version must match `src/block.rs`.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys

BASE = 0x84100000
STOCK_SHA = "555362d9c050862ac462017df54cbcedc00b0963454b332438d70bbef70f82ea"
N6H_BIN_SHA = "a2fc899439b938ec4e16ee2c8519587c4e2fffedee52b8a3bb5cdf33daff8168"

CODE_LO = 0x841de8dc
CODE_HI = 0x841df200  # 2,340 B (dead cmd_phy, Lane M2 cave catalog)
BLK_LO = 0x841b5900
BLK_HI = 0x841b5a00   # 256 B (4 x 64 B cache lines in dead UMM_DecodeATR, M2 cave catalog)

HOOK4_AQM_VA = 0x847ed414
HOOK4_EXPECTED_N4 = bytes.fromhex("686800f00500")  # ldr r0, [r5, #4]; and r0, r0, #5

# Disjointness guard against other lanes (IMG4 PRACH tail, U14, N7, C1, R4)
FORBIDDEN_RANGES = [
    ("R4_RUST_N4_OVERFLOW_CAVE", 0x84194654, 0x84194a5c),
    ("IMG4_PRACH_TAIL", 0x847ece64, 0x847ed954),
    ("U14_HOOK_SR_GUARD", 0x842b8924, 0x842b8928),
    ("U14_HOOK_SRMAX_CAP", 0x842d4cd8, 0x842d4cdc),
    ("U14_CAVE_SERVCELLINFO", 0x842beec4, 0x842bf06c),
    ("N7_ULG_W5", 0x843fc6c0, 0x843fc758),
    ("N7_ULG_A", 0x8449d8bc, 0x8449dcb0),
    ("N7_ULG_B", 0x8449a298, 0x8449a508),
    ("N7_ULG_BLK", 0x84489f40, 0x8448a140),
    ("C1_TK2_REL_HOOK", 0x842dcfb2, 0x842dcfb6),
    ("C1_TK2_FLUSH_HOOK", 0x842dcff6, 0x842dcffa),
    ("C1_TK2_CAVE_AND_BLK", 0x843fa060, 0x843fa2c0),
]


def block_const(name):
    """MAGIC or VERSION from src/block.rs, the single source of the block's identity."""
    src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "src", "block.rs")).read()
    m = re.search(rf"pub const {name}: u32 = (0x[0-9a-f_]+);", src)
    assert m, f"{name} not found in src/block.rs"
    return int(m.group(1).replace("_", ""), 16)


def enc_bl(site, target, link=True):
    off = target - (site + 4)
    assert -(1 << 24) <= off < (1 << 24) and off % 2 == 0, hex(off)
    s = (off >> 24) & 1
    i1 = (off >> 23) & 1
    i2 = (off >> 22) & 1
    j1 = (1 - i1) ^ s
    j2 = (1 - i2) ^ s
    h1 = 0xF000 | (s << 10) | ((off >> 12) & 0x3FF)
    h2 = (0xD000 if link else 0x9000) | (j1 << 13) | (j2 << 11) | ((off >> 1) & 0x7FF)
    return h1.to_bytes(2, "little") + h2.to_bytes(2, "little")


def pick_tool(*names):
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    raise SystemExit(f"missing tool: one of {names}")


def syms(elf):
    nm = pick_tool("arm-linux-gnueabi-nm", "arm-linux-gnueabihf-nm", "nm")
    out = subprocess.check_output([nm, elf], text=True)
    return {l.split()[2]: int(l.split()[0], 16) for l in out.splitlines() if len(l.split()) == 3}


def section(elf, name):
    objdump = pick_tool("arm-linux-gnueabi-objdump", "arm-linux-gnueabihf-objdump")
    objcopy = pick_tool("arm-linux-gnueabi-objcopy", "arm-linux-gnueabihf-objcopy")
    out = subprocess.check_output([objdump, "-h", elf], text=True)
    for l in out.splitlines():
        f = l.split()
        if len(f) > 4 and f[1] == name:
            size, vma = int(f[2], 16), int(f[3], 16)
            data = subprocess.check_output([objcopy, "-O", "binary", "-j", name, elf, "/dev/stdout"])
            assert len(data) == size, (name, len(data), size)
            return vma, data
    raise SystemExit(f"no section {name}")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--stock", required=True, help="Path to stock tk.bin")
    ap.add_argument("--n6h-spec", required=True, help="Path to N6H n6h-spec.json")
    ap.add_argument("--n6h-bin", required=True, help="Path to N6H tk.bin")
    ap.add_argument("--emu-path", default="", help="Optional PYTHONPATH containing Capstone")
    ap.add_argument("elf", help="Path to compiled m1_aqm.elf")
    ap.add_argument("outp", help="Output JSON spec path")
    args = ap.parse_args()

    if args.emu_path:
        sys.path.insert(0, args.emu_path)
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

    raw = open(args.stock, "rb").read()
    assert hashlib.sha256(raw).hexdigest() == STOCK_SHA, "stock tk.bin hash mismatch"

    n6h_bin = open(args.n6h_bin, "rb").read()
    assert hashlib.sha256(n6h_bin).hexdigest() == N6H_BIN_SHA, "N6H tk.bin hash mismatch"

    n6h_spec_raw = open(args.n6h_spec, "rb").read()
    n6h_spec_sha = hashlib.sha256(n6h_spec_raw).hexdigest()
    n6h = json.loads(n6h_spec_raw)
    assert len(n6h["sites"]) == 68, len(n6h["sites"])

    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    md.detail = True
    sy = syms(args.elf)

    def stock(va, n):
        return raw[va - BASE : va - BASE + n]

    # 1. Inspect .m1code
    cvma, code = section(args.elf, ".m1code")
    assert cvma == CODE_LO and CODE_LO + len(code) <= CODE_HI and len(code) % 2 == 0, (hex(cvma), len(code))
    assert sy["m1_aqm_shim"] == CODE_LO, f"m1_aqm_shim must be at {CODE_LO:#x}, got {sy['m1_aqm_shim']:#x}"

    ins = list(md.disasm(code, cvma))
    assert sum(i.size for i in ins) == len(code), "m1code partial Capstone decode"
    for i in ins:
        assert "pc" not in i.op_str.replace("pc}", ""), (hex(i.address), i.mnemonic, i.op_str)
        assert i.mnemonic != "blx" or i.op_str.startswith(("r", "ip", "lr")), (hex(i.address), i.op_str)
        if (
            i.mnemonic.startswith(("b", "cb"))
            and i.mnemonic not in ("bic", "bic.w", "bics", "bfi", "bfc", "bx", "blx")
            and i.operands
            and i.operands[-1].type == 2
        ):
            t = i.operands[-1].imm & 0xFFFFFFFF
            assert CODE_LO <= t < CODE_LO + len(code), f"unexpected branch outside cave: {i.address:#x} {i.mnemonic} -> {t:#x}"

    # Pad with Thumb NOP (00bf) if needed so stock bytes end on an instruction boundary.
    while sum(i.size for i in md.disasm(stock(CODE_LO, len(code)), CODE_LO)) != len(code):
        code += b"\x00\xbf"
        assert CODE_LO + len(code) <= CODE_HI
    assert sum(i.size for i in md.disasm(code, CODE_LO)) == len(code)
    exp_code = stock(CODE_LO, len(code))
    assert n6h_bin[CODE_LO - BASE : CODE_LO - BASE + len(code)] == exp_code, "code cave modified in N6H"

    # 2. Inspect .m1blk
    bvma, blk = section(args.elf, ".m1blk")
    assert bvma == BLK_LO and len(blk) == BLK_HI - BLK_LO == 256, (hex(bvma), len(blk))
    magic, ver, sel = struct.unpack_from("<III", blk, 0)
    assert magic == block_const("MAGIC"), hex(magic)
    assert ver == block_const("VERSION"), hex(ver)
    assert sel == 0, f"boot selector must be 0, got {sel}"
    exp_blk = stock(BLK_LO, len(blk))
    assert n6h_bin[BLK_LO - BASE : BLK_HI - BASE] == exp_blk, "blk cave modified in N6H"
    assert sum(i.size for i in md.disasm(exp_blk, BLK_LO)) == len(blk), "m1blk stock partial decode"
    assert sum(i.size for i in md.disasm(blk, BLK_LO)) == len(blk), "m1blk new partial decode"

    # 3. Copy all 68 N6H sites, splicing the 6-byte hook at 0x847ed414 inside n4_ul_engine_cave.
    sites = []
    hook_patched = False
    new_hook_bytes = enc_bl(HOOK4_AQM_VA, sy["m1_aqm_shim"], link=True) + b"\x00\xbf"
    ins_hk = list(md.disasm(new_hook_bytes, HOOK4_AQM_VA))
    assert len(ins_hk) == 2 and ins_hk[0].mnemonic == "bl" and (ins_hk[0].operands[0].imm & 0xFFFFFFFF) == sy["m1_aqm_shim"]
    assert ins_hk[1].mnemonic == "nop"

    for s in n6h["sites"]:
        s = dict(s)
        if s["name"] == "n4_ul_engine_cave":
            cave_va = int(s["va"], 16)
            cave_new = bytearray(bytes.fromhex(s["new"]))
            rel = HOOK4_AQM_VA - cave_va
            assert bytes(cave_new[rel : rel + 6]) == HOOK4_EXPECTED_N4, bytes(cave_new[rel : rel + 6]).hex()
            cave_new[rel : rel + 6] = new_hook_bytes
            assert sum(i.size for i in md.disasm(bytes(cave_new), cave_va)) == len(cave_new), "patched N4 cave partial decode"
            s["new"] = bytes(cave_new).hex()
            s["reason"] = (
                "M1 hook4_check_aqm splice at 0x847ed414 (bl m1_aqm_shim; nop -> 0x841de8dc). "
                "When M1 selector (0x841b5908) == 0, runs displaced ldr/and and returns to 0x847ed41a "
                "(exact N4 v2 + IMG4 v3). Was: " + s["reason"]
            )
            hook_patched = True
        sites.append(s)
    assert hook_patched, "n4_ul_engine_cave not found in N6H spec"

    new_sites = [
        {
            "name": "m1_rust_pie_code",
            "va": hex(CODE_LO),
            "offset": hex(CODE_LO - BASE),
            "expected": exp_code.hex(),
            "new": code.hex(),
            "reason": (
                f"Rust no_std Thumb-2 uplink PIE AQM and hook-4 shim ({len(code)} B of {CODE_HI - CODE_LO} B, "
                "m1_aqm_shim first at 0x841de8dc, no literal pools, no VFP/NEON, no undefined symbols) "
                "inside proven-dead cmd_phy (0x841de8dc..0x841df200, M2 cave catalog)."
            ),
        },
        {
            "name": "m1_rust_pie_block",
            "va": hex(BLK_LO),
            "offset": hex(BLK_LO - BASE),
            "expected": exp_blk.hex(),
            "new": blk.hex(),
            "reason": (
                f"256 B AQM control block (magic M1PI, version {ver:#010x}, boot selector 0 = N4 v2; "
                "tunables, PIE state, counters) inside proven-dead UMM_DecodeATR "
                "(0x841b5900..0x841b5a00, M2 cave catalog)."
            ),
        },
    ]
    sites.extend(new_sites)

    # 4. Strict pairwise non-overlap and preimage checks across all 70 sites.
    spans = sorted((int(s["offset"], 16), int(s["offset"], 16) + len(s["expected"]) // 2, s["name"]) for s in sites)
    for (a0, a1, an), (b0, b1, bn) in zip(spans, spans[1:]):
        assert a1 <= b0, f"overlap {an} ({BASE+a0:#x}..{BASE+a1:#x}) vs {bn} ({BASE+b0:#x}..{BASE+b1:#x})"
    for s in sites:
        assert stock(int(s["va"], 16), len(s["expected"]) // 2).hex() == s["expected"], s["name"]

    for s in new_sites:
        va0 = int(s["va"], 16)
        va1 = va0 + len(s["expected"]) // 2
        for rname, r0, r1 in FORBIDDEN_RANGES:
            assert va1 <= r0 or va0 >= r1, f"{s['name']} overlaps {rname} {r0:#x}..{r1:#x}"

    spec = {
        "name": f"n6h + rust uplink pie aqm at hook4_check_aqm (block version {ver:#010x})",
        "n6h_spec_sha256": n6h_spec_sha,
        "n6h_bin_sha256": N6H_BIN_SHA,
        "sites": sites,
    }
    with open(args.outp, "w") as f:
        json.dump(spec, f, indent=1)

    print(f"N6H spec sha256:  {n6h_spec_sha}")
    print(f"m1_aqm_shim:      {sy['m1_aqm_shim']:#x}")
    print(f"code size:        {len(code)} / {CODE_HI - CODE_LO} B")
    print(f"M1_BLK:           {BLK_LO:#x}..{BLK_HI-1:#x} ({len(blk)} B)")
    print(f"total sites:      {len(sites)}")


if __name__ == "__main__":
    main()
