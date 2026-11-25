#!/usr/bin/env python3
"""Generate tkpatch.py JSON manifest for the Lane N2 Rust PDCP/RLC/BSR hot-path optimizations."""
import argparse
import hashlib
import json
import shutil
import subprocess
import sys

BASE = 0x84100000
STOCK_SHA = "555362d9c050862ac462017df54cbcedc00b0963454b332438d70bbef70f82ea"

OPT_LO, OPT_HI = 0x841867E4, 0x84186B38  # dead grf_cancellation_rpll_mutual_interference_sd_init (852 B)
BLK_LO, BLK_HI = 0x841BB5C0, 0x841BB87C  # dead UMM_DisplayUSIMPINInfo (+2 B aligned, 700 B)


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
    ap.add_argument("--emu-path", default="", help="Optional PYTHONPATH containing Capstone")
    ap.add_argument("elf", help="Path to compiled ul_opt.elf")
    ap.add_argument("outp", help="Output JSON spec path")
    args = ap.parse_args()

    if args.emu_path:
        sys.path.insert(0, args.emu_path)
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

    raw = open(args.stock, "rb").read()
    assert hashlib.sha256(raw).hexdigest() == STOCK_SHA, "stock tk.bin hash mismatch"

    def stock(va, n):
        return raw[va - BASE : va - BASE + n]

    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    md.detail = True
    sy = syms(args.elf)

    ovma, code = section(args.elf, ".n2opt")
    bvma, blk = section(args.elf, ".n2blk")
    assert ovma == OPT_LO and OPT_LO + len(code) <= OPT_HI and len(code) % 2 == 0
    assert bvma == BLK_LO and BLK_LO + len(blk) <= BLK_HI and len(blk) == 64

    # Pad code with Thumb NOP (00 bf) to stock instruction boundary
    while sum(i.size for i in md.disasm(stock(OPT_LO, len(code)), OPT_LO)) != len(code):
        code += b"\x00\xbf"
        assert OPT_LO + len(code) <= OPT_HI
    # Pad data block tail if needed to align with stock instruction boundary
    while sum(i.size for i in md.disasm(stock(BLK_LO, len(blk)), BLK_LO)) != len(blk):
        blk += b"\x00\x00"
        assert BLK_LO + len(blk) <= BLK_HI

    hook_defs = [
        ("n2_hook_bsr_idx", 0x842CCF64, "f0b583b0", "hook_bsr_idx", False,
         "N2 Fix A: fast SearchMacUlBoIdx (bo==0 early exit + tight binary search, boot-off)."),
        ("n2_hook_pdcp_div", 0x842DCCD0, "3ff6a0ef", "hook_pdcp_div", True,
         "N2 Fix B: fast l2_proc_pdcp_ul division (fp==0 skip + udiv) & optional byte-accurate pacing (boot-off)."),
        ("n2_hook_do_tc_cap", 0x842E5B06, "c3f3cb33", "hook_do_tc_cap", True,
         "N2 Fix C: do_tc 250 ms target-ms staging cap clamp (boot-off)."),
    ]

    sites = []
    for name, va, exp, sym, link, why in hook_defs:
        assert stock(va, 4).hex() == exp, (name, stock(va, 4).hex(), exp)
        sites.append({
            "name": name,
            "va": hex(va),
            "offset": hex(va - BASE),
            "expected": exp,
            "new": enc_bl(va, sy[sym], link=link).hex(),
            "reason": why,
        })

    sites.append({
        "name": "n2_opt_code_cave",
        "va": hex(OPT_LO),
        "offset": hex(OPT_LO - BASE),
        "expected": stock(OPT_LO, len(code)).hex(),
        "new": code.hex(),
        "reason": f"N2 Rust Thumb-2 optimization code ({len(code)} B, 0 literal pools) in dead grf_cancellation_rpll_mutual_interference_sd_init.",
    })
    sites.append({
        "name": "n2_opt_ctrl_blk",
        "va": hex(BLK_LO),
        "offset": hex(BLK_LO - BASE),
        "expected": stock(BLK_LO, len(blk)).hex(),
        "new": blk.hex(),
        "reason": f"N2 boot-off N2OptState control block ({len(blk)} B, magic N2OP @ 0x841bb5c0, flags=0) in dead UMM_DisplayUSIMPINInfo.",
    })

    # Pairwise non-overlap & stock preimage check
    spans = sorted((int(s["offset"], 16), int(s["offset"], 16) + len(s["expected"]) // 2, s["name"]) for s in sites)
    for (a0, a1, an), (b0, b1, bn) in zip(spans, spans[1:]):
        assert a1 <= b0, f"overlap {an} vs {bn}"
    for s in sites:
        assert stock(int(s["va"], 16), len(s["expected"]) // 2).hex() == s["expected"], s["name"]

    spec = {"name": "n2-pdcp-rlc-bsr-opt", "sites": sites}
    with open(args.outp, "w") as f:
        json.dump(spec, f, indent=1)
    print(f"Wrote {args.outp}: .n2opt={len(code)} B, .n2blk={len(blk)} B, {len(sites)} sites")


if __name__ == "__main__":
    main()
