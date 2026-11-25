#!/usr/bin/env python3
"""Generate tkpatch.py JSON manifest for the combined MAC/PDCP UL optimizer.

Supports two modes:
  --mode standalone
      8 sites on stock tk.bin (5 hooks + .optcode1 + .optcode2 + .optblk).
  --mode combined --base-spec <path>
      Appends the 8 combined optimizer sites onto a base stack spec (e.g.
      N1's 72-site N6H + R4 + N1 N5 + R1 spec -> 80 sites total), asserting
      strict pairwise non-overlap and exact stock preimages.
"""
import argparse
import hashlib
import json
import shutil
import subprocess
import sys

BASE = 0x84100000
STOCK_SHA = "555362d9c050862ac462017df54cbcedc00b0963454b332438d70bbef70f82ea"

C1_LO, C1_HI = 0x841867E4, 0x84186B38  # dead grf_cancellation_rpll_mutual_interference_sd_init (852 B)
C2_LO, C2_HI = 0x8417FFD8, 0x8418024C  # dead restore_valid_check (628 B)
BLK_LO, BLK_HI = 0x841BB5C0, 0x841BB87C  # dead UMM_DisplayUSIMPINInfo+2 (700 B available, 128 B used)


def enc_bl(site: int, target: int, link: bool = True) -> bytes:
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


def pick_tool(*names: str) -> str:
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    raise SystemExit(f"missing tool: one of {names}")


def syms(elf: str) -> dict:
    nm = pick_tool("arm-linux-gnueabi-nm", "arm-linux-gnueabihf-nm", "nm")
    out = subprocess.check_output([nm, elf], text=True)
    return {l.split()[2]: int(l.split()[0], 16) for l in out.splitlines() if len(l.split()) == 3}


def section(elf: str, name: str):
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
    ap.add_argument("--mode", choices=["standalone", "combined"], default="standalone")
    ap.add_argument("--base-spec", default="", help="Base tkpatch JSON spec (required for --mode combined)")
    ap.add_argument("--emu-path", default="", help="Optional PYTHONPATH containing Capstone")
    ap.add_argument("elf", help="Path to compiled mac_pdcp_opt.elf")
    ap.add_argument("outp", help="Output JSON spec path")
    args = ap.parse_args()

    if args.mode == "combined" and not args.base_spec:
        raise SystemExit("--base-spec is required when --mode combined")
    if args.emu_path:
        sys.path.insert(0, args.emu_path)
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

    raw = open(args.stock, "rb").read()
    assert hashlib.sha256(raw).hexdigest() == STOCK_SHA, "stock tk.bin hash mismatch"

    def stock(va: int, n: int) -> bytes:
        return raw[va - BASE : va - BASE + n]

    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    md.detail = True
    sy = syms(args.elf)

    c1_vma, code1 = section(args.elf, ".optcode1")
    c2_vma, code2 = section(args.elf, ".optcode2")
    bvma, blk = section(args.elf, ".optblk")
    assert c1_vma == C1_LO and C1_LO + len(code1) <= C1_HI and len(code1) % 2 == 0
    assert c2_vma == C2_LO and C2_LO + len(code2) <= C2_HI and len(code2) % 2 == 0
    assert bvma == BLK_LO and BLK_LO + len(blk) <= BLK_HI and len(blk) == 128

    # Pad code caves with Thumb NOP (00 bf) to exact stock instruction boundaries.
    while sum(i.size for i in md.disasm(stock(C1_LO, len(code1)), C1_LO)) != len(code1):
        code1 += b"\x00\xbf"
        assert C1_LO + len(code1) <= C1_HI
    while sum(i.size for i in md.disasm(stock(C2_LO, len(code2)), C2_LO)) != len(code2):
        code2 += b"\x00\xbf"
        assert C2_LO + len(code2) <= C2_HI
    while sum(i.size for i in md.disasm(stock(BLK_LO, len(blk)), BLK_LO)) != len(blk):
        blk += b"\x00\x00"
        assert BLK_LO + len(blk) <= BLK_HI

    hook_defs = [
        ("opt_hook_search_bo_idx", 0x842CCF64, "f0b583b0", "opt_search_bo_idx_shim", False,
         "Combined MAC/PDCP opt bit 0: fast SearchMacUlBoIdx (inline zero-stack bo==0 + unrolled 6-step search, boot-off)."),
        ("opt_hook_check_long_bsr", 0x842CFE34, "2de9f04f", "opt_check_long_bsr_shim", False,
         "Combined MAC/PDCP opt bit 1: O(1) CheckLongBsrDowngradeToShort early exit (boot-off)."),
        ("opt_hook_mac_bsr_pre_work", 0x842DA60C, "2de9f047", "opt_mac_bsr_pre_work_shim", False,
         "Combined MAC/PDCP opt bit 2: guarded mac_bsr_pre_work empty-ring & idle-cipher clamp (boot-off)."),
        ("opt_hook_pdcp_div", 0x842DCCD0, "3ff6a0ef", "opt_pdcp_div_shim", True,
         "Combined MAC/PDCP opt bits 3/4: l2_proc_pdcp_ul fp==0 skip + udiv / byte-accurate admission (boot-off)."),
        ("opt_hook_do_tc_cap", 0x842E5B06, "c3f3cb33", "opt_do_tc_cap_shim", True,
         "Combined MAC/PDCP opt bit 5: do_tc 250 ms target-ms staging cap clamp (boot-off)."),
    ]

    opt_sites = []
    for name, va, exp, sym, link, why in hook_defs:
        assert stock(va, 4).hex() == exp, (name, stock(va, 4).hex(), exp)
        opt_sites.append({
            "name": name,
            "va": hex(va),
            "offset": hex(va - BASE),
            "expected": exp,
            "new": enc_bl(va, sy[sym] & ~1, link=link).hex(),
            "reason": why,
        })

    opt_sites.extend([
        {
            "name": "opt_code1_mac_cave",
            "va": hex(C1_LO),
            "offset": hex(C1_LO - BASE),
            "expected": stock(C1_LO, len(code1)).hex(),
            "new": code1.hex(),
            "reason": f"Combined MAC/PDCP Rust Thumb-2 MAC hooks ({len(code1)} B, 0 literal pools) in dead grf_cancellation_rpll_mutual_interference_sd_init.",
        },
        {
            "name": "opt_code2_pdcp_cave",
            "va": hex(C2_LO),
            "offset": hex(C2_LO - BASE),
            "expected": stock(C2_LO, len(code2)).hex(),
            "new": code2.hex(),
            "reason": f"Combined MAC/PDCP Rust Thumb-2 PDCP hooks ({len(code2)} B, 0 literal pools) in dead restore_valid_check.",
        },
        {
            "name": "opt_ctrl_blk",
            "va": hex(BLK_LO),
            "offset": hex(BLK_LO - BASE),
            "expected": stock(BLK_LO, len(blk)).hex(),
            "new": blk.hex(),
            "reason": f"Combined MAC/PDCP boot-off MacPdcpOptBlock ({len(blk)} B, magic MPOP @ 0x841bb5c0, flags=0) in dead UMM_DisplayUSIMPINInfo.",
        },
    ])

    if args.mode == "combined":
        base = json.load(open(args.base_spec))
        sites = list(base["sites"]) + opt_sites
        spec_name = "combined-n6h-r4-n1-r1-mac-pdcp-opt"
    else:
        sites = opt_sites
        spec_name = "standalone-mac-pdcp-opt"

    # Strict pairwise non-overlap & stock preimage verification across ALL sites.
    spans = sorted(
        (int(s["offset"], 16), int(s["offset"], 16) + len(s["expected"]) // 2, s["name"])
        for s in sites
    )
    for (a0, a1, an), (b0, b1, bn) in zip(spans, spans[1:]):
        assert a1 <= b0, f"overlap {an} [{a0:#x}..{a1:#x}) vs {bn} [{b0:#x}..{b1:#x})"
    for s in sites:
        assert stock(int(s["va"], 16), len(s["expected"]) // 2).hex() == s["expected"], s["name"]

    spec = {"name": spec_name, "sites": sites}
    with open(args.outp, "w") as f:
        json.dump(spec, f, indent=1)
    print(
        f"Wrote {args.outp} ({spec_name}): .optcode1={len(code1)} B, "
        f".optcode2={len(code2)} B, .optblk={len(blk)} B, {len(sites)} total sites"
    )


if __name__ == "__main__":
    main()
