#!/usr/bin/env python3
"""Generate tkpatch.py JSON spec and witcher-tk-manifest for v1.0.16 (n6h-r4-r1) + G1 MAC tracer.

Consumes the linked Thumb-2 ELF produced by `device/modem-rust/g1/build-thumb.sh`, stock `tk.bin`,
v1.0.16's `combined-spec.json` (71 sites), and v1.0.16's `tk.bin`.

Adds 8 disjoint sites on top of v1.0.16 (79 sites total):
  1. `g1_tracer_code`  (`0x8411927c..`, inside dead `ihs_keypad_down..is_secure_disable`)
  2. `g1_tracer_cold`  (`0x8450ce94..`, inside dead `lte_agent_bip_control_ind..service`)
  3. `g1_tracer_block` (`0x8412a340..0x8412a3c0`, 128 B inside dead `ossDupWorld`)
  4. `g1_hook_pre_ce`  (`0x842d0918`, 4 B in `GenerateMacUlPdu`, disjoint from R4 `0x842d0914`)
  5. `g1_hook_newtx`   (`0x842d098a`, 4 B in `GenerateMacUlPdu`)
  6. `g1_hook_send_tx` (`0x842ced8c`, 4 B in `L1A_L2_SendTxPdu`)
  7. `g1_hook_sr`      (`0x842d4cd4`, 4 B in `GetMacUlSR`, disjoint from U14 `0x842d4cd8`)
  8. `g1_hook_tti_end` (`0x842d8b7a`, 4 B in `ScheduleUlData`)
"""
import argparse
import gzip
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
V1016_BIN_SHA = "f1aa8add6a4e4e00c17c3cfe90f51e8b31d75c39751c48cf6ffa5c9f159d1f42"

CODE_LO, CODE_HI = 0x8411927c, 0x84119840
COLD_LO, COLD_HI = 0x8450ce94, 0x8450d1e0
BLK_LO, BLK_HI = 0x8412a340, 0x8412a3c0

HOOKS = [
    ("g1_hook_pre_ce", 0x842d0918, "d5f81098", "GenerateMacUlPdu pre-CE snapshot (disjoint from R4 0x842d0914)"),
    ("g1_hook_newtx", 0x842d098a, "4ff47071", "GenerateMacUlPdu post-CE NewTx record"),
    ("g1_hook_send_tx", 0x842ced8c, "4df27c05", "L1A_L2_SendTxPdu HARQ retransmission record"),
    ("g1_hook_sr", 0x842d4cd4, "d4f8f030", "GetMacUlSR PUCCH SR record (disjoint from U14 0x842d4cd8)"),
    ("g1_hook_tti_end", 0x842d8b7a, "fbf7c9f8", "ScheduleUlData end-of-TTI auto-freeze check (wraps SchedRa)"),
]

# Known ranges owned by other lanes (must never overlap our 8 new sites).
FORBIDDEN_RANGES = [
    ("M1_CODE", 0x841de8dc, 0x841df200),
    ("M1_BLK", 0x841b581c, 0x841b5bbc),
    ("Q1_COLD", 0x8446e4c8, 0x8446e718),
    ("R4_CAVE2", 0x84194654, 0x84194a5c),
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
    ("N3_CODE", 0x841867e4, 0x84186b38),
    ("N3_BLK", 0x8449a2a0, 0x8449a320),
    ("N2_BLK", 0x841bb5c0, 0x841bb640),
]


def block_const(name):
    src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "src", "block.rs")).read()
    m = re.search(rf"pub const {name}: u32 = (0x[0-9a-f_]+|[0-9_]+);", src)
    assert m, f"{name} not found in src/block.rs"
    return int(m.group(1).replace("_", ""), 0)


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


def python_gzip(data):
    out = bytearray(gzip.compress(data, compresslevel=9, mtime=0))
    out[9] = 3
    return bytes(out)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def write_manifest(base_manifest_path, new_sites, stock, out_path, spec_name, name="n6h-r4-r1-g1"):
    """Emit a witcher-tk-manifest v1 extending n6h-r4-r1.manifest with G1's 8 sites."""
    lines = open(base_manifest_path).read().splitlines()
    site_lines = {}
    for l in lines:
        if l.startswith("site "):
            va = int(l.split()[1], 16)
            site_lines[va] = l
    for s in new_sites:
        va = int(s["va"], 16)
        exp = bytes.fromhex(s["expected"])
        new = bytes.fromhex(s["new"])
        assert va not in site_lines, f"manifest collision at {va:#x}"
        site_lines[va] = f"site {va:#010x} {len(exp)} {s['name']} {sha(exp)} {new.hex()}"

    # Apply to stock to compute pinned image and gzip hashes.
    img = bytearray(stock)
    for l in site_lines.values():
        f = l.split()
        va, length, sname, orig = int(f[1], 16), int(f[2]), f[3], f[4]
        off = va - BASE
        assert sha(stock[off : off + length]) == orig, f"{sname} orig mismatch"
        parts = []
        for p in f[5:]:
            m = re.fullmatch(r"@0x([0-9a-f]{8}):([0-9]+)", p)
            if m:
                rva, rlen = int(m[1], 16), int(m[2])
                parts.append(stock[rva - BASE : rva - BASE + rlen])
            else:
                parts.append(bytes.fromhex(p))
        repl = b"".join(parts)
        assert len(repl) == length, sname
        img[off : off + length] = repl

    img_bytes = bytes(img)
    gz_bytes = python_gzip(img_bytes)
    header = [
        "# Witcher tk patch manifest: Witcher bytes and hashes only (docs/tk-patch.md).",
        f"# From spec: {spec_name}",
        "witcher-tk-manifest 1",
        f"name {name}",
        f"base {BASE:#010x}",
        f"stock {len(stock)} {sha(stock)}",
        f"image {len(img_bytes)} {sha(img_bytes)}",
        f"gzip {len(gz_bytes)} {sha(gz_bytes)}",
    ]
    body = [site_lines[va] for va in sorted(site_lines)]
    with open(out_path, "w") as f:
        f.write("\n".join(header + body) + "\n")
    return sha(img_bytes), sha(gz_bytes), len(gz_bytes)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--stock", required=True, help="Path to stock tk.bin")
    ap.add_argument("--base-spec", required=True, help="Path to v1.0.16 combined-spec.json")
    ap.add_argument("--base-bin", required=True, help="Path to v1.0.16 tk.bin")
    ap.add_argument("--base-manifest", default="", help="Optional n6h-r4-r1.manifest for manifest output")
    ap.add_argument("--manifest-out", default="", help="Optional output path for n6h-r4-r1-g1.manifest")
    ap.add_argument("--emu-path", default="", help="Optional PYTHONPATH containing Capstone")
    ap.add_argument("elf", help="Path to compiled g1_tracer.elf")
    ap.add_argument("outp", help="Output JSON spec path")
    args = ap.parse_args()

    if args.emu_path:
        sys.path.insert(0, args.emu_path)
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

    raw = open(args.stock, "rb").read()
    assert sha(raw) == STOCK_SHA, "stock tk.bin hash mismatch"

    v1016_bin = open(args.base_bin, "rb").read()
    assert sha(v1016_bin) == V1016_BIN_SHA, "v1.0.16 tk.bin hash mismatch"

    base_spec_raw = open(args.base_spec, "rb").read()
    base_spec = json.loads(base_spec_raw)
    assert len(base_spec["sites"]) == 71, len(base_spec["sites"])

    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    md.detail = True
    sy = syms(args.elf)

    def stock(va, n):
        return raw[va - BASE : va - BASE + n]

    def audit_code_sec(sec_name, lo, hi):
        vma, data = section(args.elf, sec_name)
        assert vma == lo and lo + len(data) <= hi and len(data) % 2 == 0, (sec_name, hex(vma), len(data))
        ins = list(md.disasm(data, vma))
        assert sum(i.size for i in ins) == len(data), f"{sec_name} partial Capstone decode"
        for i in ins:
            assert "pc" not in i.op_str.replace("pc}", ""), (sec_name, hex(i.address), i.mnemonic, i.op_str)
            assert i.mnemonic != "blx" or i.op_str.startswith(("r", "ip", "lr")), (hex(i.address), i.op_str)
        while sum(i.size for i in md.disasm(stock(lo, len(data)), lo)) != len(data):
            data += b"\x00\xbf"
            assert lo + len(data) <= hi
        assert sum(i.size for i in md.disasm(data, lo)) == len(data)
        exp = stock(lo, len(data))
        assert v1016_bin[lo - BASE : lo - BASE + len(data)] == exp, f"{sec_name} modified in v1.0.16"
        return data, exp

    code, exp_code = audit_code_sec(".g1code", CODE_LO, CODE_HI)
    cold, exp_cold = audit_code_sec(".g1cold", COLD_LO, COLD_HI)

    bvma, blk = section(args.elf, ".g1blk")
    assert bvma == BLK_LO and len(blk) == BLK_HI - BLK_LO == 128
    magic, ver, en, frz = struct.unpack_from("<4I", blk, 0)
    assert magic == block_const("MAGIC"), hex(magic)
    assert ver == block_const("VERSION"), hex(ver)
    assert en == 0 and frz == 0
    exp_blk = stock(BLK_LO, len(blk))
    assert v1016_bin[BLK_LO - BASE : BLK_HI - BASE] == exp_blk, "g1blk modified in v1.0.16"
    assert sum(i.size for i in md.disasm(exp_blk, BLK_LO)) == len(blk), "g1blk stock partial decode"
    assert sum(i.size for i in md.disasm(blk, BLK_LO)) == len(blk), "g1blk new partial decode"

    new_sites = [
        {
            "name": "g1_tracer_code",
            "va": hex(CODE_LO),
            "offset": hex(CODE_LO - BASE),
            "expected": exp_code.hex(),
            "new": code.hex(),
            "reason": (
                f"G1 MAC UL timeline tracer shims + NewTx hot path ({len(code)} B of {CODE_HI - CODE_LO} B, "
                "Thumb-2 no literal pools) inside dead ihs_keypad_down..is_secure_disable."
            ),
        },
        {
            "name": "g1_tracer_cold",
            "va": hex(COLD_LO),
            "offset": hex(COLD_LO - BASE),
            "expected": exp_cold.hex(),
            "new": cold.hex(),
            "reason": (
                f"G1 MAC UL timeline tracer Retx/SR/auto-freeze handlers ({len(cold)} B of {COLD_HI - COLD_LO} B) "
                "inside dead lte_agent_bip_control_ind..lte_agent_service_handler."
            ),
        },
        {
            "name": "g1_tracer_block",
            "va": hex(BLK_LO),
            "offset": hex(BLK_LO - BASE),
            "expected": exp_blk.hex(),
            "new": blk.hex(),
            "reason": (
                f"128 B G1 control block (magic G1TR, version {ver:#010x}, boot enable=0, freeze=0, "
                "ring 0x87f70000 x 4096) inside dead ossDupWorld (0x8412a308..0x8412a538)."
            ),
        },
    ]

    for hname, hva, exp_hex, reason in HOOKS:
        assert hname in sy, f"missing symbol {hname}"
        exp_b = bytes.fromhex(exp_hex)
        assert stock(hva, len(exp_b)) == exp_b, f"{hname} stock mismatch"
        assert v1016_bin[hva - BASE : hva - BASE + len(exp_b)] == exp_b, f"{hname} modified in v1.0.16"
        bl_b = enc_bl(hva, sy[hname], link=True)
        ins = list(md.disasm(bl_b, hva))
        assert len(ins) == 1 and ins[0].mnemonic == "bl" and (ins[0].operands[0].imm & 0xFFFFFFFF) == sy[hname]
        new_sites.append({
            "name": hname,
            "va": hex(hva),
            "offset": hex(hva - BASE),
            "expected": exp_hex,
            "new": bl_b.hex(),
            "reason": f"G1 hook: bl {hname} ({sy[hname]:#x}) — {reason}.",
        })

    sites = [dict(s) for s in base_spec["sites"]] + new_sites

    # Strict pairwise non-overlap and stock preimage verification across all 79 sites.
    spans = sorted((int(s["offset"], 16), int(s["offset"], 16) + len(s["expected"]) // 2, s["name"]) for s in sites)
    for (a0, a1, an), (b0, b1, bn) in zip(spans, spans[1:]):
        assert a1 <= b0, f"OVERLAP {an} ({BASE+a0:#x}..{BASE+a1:#x}) vs {bn} ({BASE+b0:#x}..{BASE+b1:#x})"
    for s in sites:
        assert stock(int(s["va"], 16), len(s["expected"]) // 2).hex() == s["expected"], s["name"]

    for s in new_sites:
        va0 = int(s["va"], 16)
        va1 = va0 + len(s["expected"]) // 2
        for rname, r0, r1 in FORBIDDEN_RANGES:
            assert va1 <= r0 or va0 >= r1, f"{s['name']} overlaps {rname} {r0:#x}..{r1:#x}"

    spec = {
        "name": f"n6h-r4-r1 (v1.0.16) + g1 boot-off mac timeline tracer (version {ver:#010x})",
        "base_spec_sha256": sha(base_spec_raw),
        "base_bin_sha256": V1016_BIN_SHA,
        "sites": sites,
    }
    with open(args.outp, "w") as f:
        json.dump(spec, f, indent=1)

    print(f"G1 code:    {CODE_LO:#x}..{CODE_LO+len(code):#x} ({len(code)} / {CODE_HI - CODE_LO} B)")
    print(f"G1 cold:    {COLD_LO:#x}..{COLD_LO+len(cold):#x} ({len(cold)} / {COLD_HI - COLD_LO} B)")
    print(f"G1 block:   {BLK_LO:#x}..{BLK_HI:#x} (128 B)")
    print(f"total sites:{len(sites)}")

    if args.manifest_out:
        assert args.base_manifest, "--base-manifest required with --manifest-out"
        img_sha, gz_sha, gz_sz = write_manifest(
            args.base_manifest, new_sites, raw, args.manifest_out, spec["name"]
        )
        print(f"manifest:   {args.manifest_out}")
        print(f"  tk.bin:   {img_sha}")
        print(f"  tk.gz:    {gz_sha} ({gz_sz} B)")


if __name__ == "__main__":
    main()
