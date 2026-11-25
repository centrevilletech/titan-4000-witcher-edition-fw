#!/usr/bin/env python3
"""Generate tkpatch.py JSON manifests for the Rust N5 per-flow sparse uplink lane.

Takes the v1.0.16 combined spec (`N6H + R4 Rust N4 + R1 PIE`, 71 sites) and replaces
assembly N5 (`n5_cave_g_change_calmod_func`, 1,552 B at `0x8418f768..0x8418fd78`) with
Rust `witcher-modem-n5` (`.n5cave_g` + `.n5cave_g_tail` at `0x8418fe10..`, both inside
already-proven-dead `ChangeCalmodFunc` `0x8418f768..0x8418ff4c`), while verifying
`.n5blk` (`0x84489a62..0x84489f14`, 1,202 B) and `n5_ring0_submit_hook` (`0x842dcd24`)
remain byte-identical to assembly N5.

Also supports `--base-spec` pointing to IMG4's `n5-spec.json` (64 sites) for direct
N5-only lockstep comparisons against assembly N5.
"""
import argparse
import hashlib
import json
import shutil
import subprocess
import sys

BASE = 0x84100000
STOCK_SHA = "555362d9c050862ac462017df54cbcedc00b0963454b332438d70bbef70f82ea"

CAVE_G_LO, CAVE_G_HI = 0x8418F768, 0x8418FD78
TAIL_LO, TAIL_HI = 0x8418FE90, 0x8418FF00
N5_BLK_LO, N5_BLK_HI = 0x84489A62, 0x84489F14
R0_SUB_SITE = 0x842DCD24

ALLOWED_EXT = {
    0x847ED414,  # n4 hook4_check_aqm
    0x847ED52E,  # n4 hook4_exit_b
    0x847ED53C,  # n4 hook4_exit_a
    0x842DC968,  # stock pdcp_ul_cipher_submit
}

FORBIDDEN_FOR_TAIL = [
    ("N6_U2_LNACK_FILTER", 0x8418FD78, 0x8418FE10),
    ("N7_U2_LNACK_FILTER", 0x8418FD78, 0x8418FE8A),
    ("N6_U2_CONTROL_BLOCK", 0x8418FF00, 0x8418FF42),
    ("IMG4_PRACH_TAIL", 0x847ECE64, 0x847ED954),
    ("M1_CODE_CAVE", 0x841DE8DC, 0x841DF200),
    ("M1_BLK_CAVE", 0x841B581C, 0x841B5BBC),
    ("N4_RUST_CAVE2", 0x84194654, 0x84194A5C),
    ("U14_HOOK_SR_GUARD", 0x842B8924, 0x842B8928),
    ("U14_HOOK_SRMAX_CAP", 0x842D4CD8, 0x842D4CDC),
    ("U14_CAVE_SERVCELLINFO", 0x842BEEC4, 0x842BF06C),
    ("N7_ULG_W5", 0x843FC6C0, 0x843FC758),
    ("N7_ULG_A", 0x8449D8BC, 0x8449DCB0),
    ("N7_ULG_B", 0x8449A298, 0x8449A508),
    ("N7_ULG_BLK", 0x84489F40, 0x8448A140),
    ("C1_TK2_REL_HOOK", 0x842DCFB2, 0x842DCFB6),
    ("C1_TK2_FLUSH_HOOK", 0x842DCFF6, 0x842DCFFA),
    ("C1_TK2_CAVE_AND_BLK", 0x843FA060, 0x843FA2C0),
]


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


def audit_code(md, code, lo, all_ranges):
    ins = list(md.disasm(code, lo))
    assert sum(i.size for i in ins) == len(code), f"partial Capstone decode at {lo:#x}"
    for i in ins:
        assert "pc" not in i.op_str.replace("pc}", ""), (hex(i.address), i.mnemonic, i.op_str)
        assert i.mnemonic != "blx" or i.op_str.startswith(("r", "ip", "lr")), (hex(i.address), i.op_str)
        if (
            i.mnemonic.startswith(("b", "cb"))
            and not i.mnemonic.startswith(("bic", "bfi", "bfc", "bkpt", "bx", "blx"))
            and i.operands
            and i.operands[-1].type == 2
        ):
            t = i.operands[-1].imm & 0xFFFFFFFF
            in_ours = any(a <= t < b for a, b in all_ranges)
            assert in_ours or t in ALLOWED_EXT, f"unexpected branch target {i.address:#x} {i.mnemonic} -> {t:#x}"
            if not in_ours:
                assert i.mnemonic in ("b.w", "bl"), (hex(i.address), i.mnemonic)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--stock", required=True, help="Path to stock tk.bin")
    ap.add_argument("--base-spec", required=True, help="Base tkpatch JSON spec (e.g. R1 combined-spec.json)")
    ap.add_argument("--emu-path", default="", help="Optional PYTHONPATH containing Capstone")
    ap.add_argument(
        "--name",
        default="n6h + rust n4 (r4) + rust n5 (n1) + rust pie (r1, block version 0x20261126)",
        help="Spec name metadata",
    )
    ap.add_argument("elf", help="Path to compiled n5_flow.elf")
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

    assert sy["n5_flow_classify"] == 0x8418F768, hex(sy["n5_flow_classify"])
    assert sy["n5_pdcp_limit"] == 0x8418FC9C, hex(sy["n5_pdcp_limit"])
    assert sy["n5_ring0_submit"] == 0x8418FD0A, hex(sy["n5_ring0_submit"])

    gvma, cave_g = section(args.elf, ".n5cave_g")
    tvma, cave_tail = section(args.elf, ".n5cave_g_tail")
    bvma, blk = section(args.elf, ".n5blk")

    assert gvma == CAVE_G_LO and len(cave_g) == (CAVE_G_HI - CAVE_G_LO)
    assert tvma == TAIL_LO and TAIL_LO + len(cave_tail) <= TAIL_HI and len(cave_tail) % 2 == 0
    assert bvma == N5_BLK_LO and len(blk) == (N5_BLK_HI - N5_BLK_LO) == 1202

    all_ranges = [(CAVE_G_LO, CAVE_G_HI), (TAIL_LO, TAIL_LO + len(cave_tail))]
    audit_code(md, cave_g, CAVE_G_LO, all_ranges)
    if cave_tail:
        audit_code(md, cave_tail, TAIL_LO, all_ranges)
        # Pad .n5cave_g_tail with Thumb NOP (00 bf) to end on a stock Thumb-2 instruction boundary.
        while sum(i.size for i in md.disasm(stock(TAIL_LO, len(cave_tail)), TAIL_LO)) != len(cave_tail):
            cave_tail += b"\x00\xbf"
            assert TAIL_LO + len(cave_tail) <= TAIL_HI
        assert sum(i.size for i in md.disasm(cave_tail, TAIL_LO)) == len(cave_tail)

    assert sum(i.size for i in md.disasm(stock(CAVE_G_LO, len(cave_g)), CAVE_G_LO)) == len(cave_g)
    assert sum(i.size for i in md.disasm(stock(N5_BLK_LO, len(blk)), N5_BLK_LO)) == len(blk)
    assert sum(i.size for i in md.disasm(blk, N5_BLK_LO)) == len(blk)

    base_raw = open(args.base_spec, "rb").read()
    base_sha = hashlib.sha256(base_raw).hexdigest()
    base_spec = json.loads(base_raw)

    expected_r0_bl = enc_bl(R0_SUB_SITE, sy["n5_ring0_submit"], link=True)

    sites = []
    replaced_cave = False
    verified_blk = False
    verified_r0 = False
    for s in base_spec["sites"]:
        s = dict(s)
        nm = s["name"]
        if nm == "n5_cave_g_change_calmod_func":
            assert int(s["va"], 16) == CAVE_G_LO and len(s["expected"]) // 2 == len(cave_g)
            s["new"] = cave_g.hex()
            s["reason"] = (
                "N1 Rust no_std Thumb-2 N5 primary cave (1,552 B, zero literal pools, zero VFP/NEON) "
                "over dead ChangeCalmodFunc 0x8418f768..0x8418fd77; preserves exact fixed-VA entry points "
                "n5_flow_classify (0x8418f768), n5_pdcp_limit (0x8418fc9c), n5_ring0_submit (0x8418fd0a)."
            )
            replaced_cave = True
        elif nm == "n5_state_and_flow_table":
            assert int(s["va"], 16) == N5_BLK_LO and len(s["expected"]) // 2 == len(blk)
            assert bytes.fromhex(s["new"]) == blk, "Rust .n5blk must be byte-identical to assembly N5 RAM block"
            verified_blk = True
        elif nm == "n5_ring0_submit_hook":
            assert int(s["va"], 16) == R0_SUB_SITE
            assert bytes.fromhex(s["new"]) == expected_r0_bl, "n5_ring0_submit_hook must remain byte-identical"
            verified_r0 = True
        sites.append(s)

    assert replaced_cave and verified_blk and verified_r0

    if cave_tail:
        for rname, r0, r1 in FORBIDDEN_FOR_TAIL:
            assert TAIL_LO + len(cave_tail) <= r0 or TAIL_LO >= r1, f".n5cave_g_tail overlaps {rname}"
        sites.append({
            "name": "n5_rust_cave_g_tail",
            "va": hex(TAIL_LO),
            "offset": hex(TAIL_LO - BASE),
            "expected": stock(TAIL_LO, len(cave_tail)).hex(),
            "new": cave_tail.hex(),
            "reason": (
                f"N1 Rust no_std Thumb-2 N5 PDCP helper ({len(cave_tail)} B of 112 B, zero literal pools, "
                "zero VFP/NEON) in the post-N7 unused tail of already-proven-dead ChangeCalmodFunc "
                "(0x8418fe90..0x8418feff, strictly after N6H/N7 u2_lnack_filter 0x8418fd78..0x8418fe8a and "
                "before N6H U2_BLK 0x8418ff00..0x8418ff41)."
            ),
        })

    # Pairwise non-overlap & stock preimage checks across all sites.
    spans = sorted((int(s["offset"], 16), int(s["offset"], 16) + len(s["expected"]) // 2, s["name"]) for s in sites)
    for (a0, a1, an), (b0, b1, bn) in zip(spans, spans[1:]):
        assert a1 <= b0, f"overlap {an} ({BASE + a0:#x}..{BASE + a1:#x}) vs {bn} ({BASE + b0:#x}..{BASE + b1:#x})"
    for s in sites:
        assert stock(int(s["va"], 16), len(s["expected"]) // 2).hex() == s["expected"], s["name"]

    spec = {
        "name": args.name,
        "base_spec_sha256": base_sha,
        "sites": sites,
    }
    with open(args.outp, "w") as f:
        json.dump(spec, f, indent=1)

    print(f"base spec sha256:  {base_sha}")
    print(f".n5cave_g:         {len(cave_g)} / {CAVE_G_HI - CAVE_G_LO} B @ {CAVE_G_LO:#x}")
    print(f".n5cave_g_tail:    {len(cave_tail)} / {TAIL_HI - TAIL_LO} B @ {TAIL_LO:#x}")
    print(f".n5blk:            {len(blk)} B @ {N5_BLK_LO:#x} (byte-identical to asm N5)")
    print(f"total sites:       {len(sites)}")
    for nm in ("n5_flow_classify", "n5_pdcp_limit", "n5_ring0_submit"):
        print(f"  {nm:18s} {sy[nm]:#x}")


if __name__ == "__main__":
    main()
