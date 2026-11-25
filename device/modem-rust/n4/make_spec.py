#!/usr/bin/env python3
"""Generate tkpatch.py JSON manifests for the Rust N4 v2 uplink engine.

Supports two modes:
  1. --mode standalone: patches stock tk.bin with the 5 N4 hook sites + A4 hold timer +
     Rust N4 code (.n4prach at 0x847ed000 + .n4cave2 at 0x84194654) for direct equivalence
     testing against assembly N4 v2 (n4-aqm2-a4).
  2. --mode stack: takes M1's 70-site manifest (m1-spec.json) and replaces N4's assembly
     inside n4_ul_engine_cave (0x847ed000..0x847ed540) + adds n4_rust_cave2 (0x84194654..)
     and updates hook1/hook2b/hook3/hook4 BL targets to the Rust shims (hook2 stays on
     IMG3 HRB which tail-calls 0x847ed0ee -> hook_calc_lcg_bo).
"""
import argparse
import hashlib
import json
import shutil
import subprocess
import sys

BASE = 0x84100000
STOCK_SHA = "555362d9c050862ac462017df54cbcedc00b0963454b332438d70bbef70f82ea"

PRACH_LO, PRACH_HI = 0x847ED000, 0x847ED540
CAVE2_LO, CAVE2_HI = 0x84194654, 0x84194A5C  # dead RFFE_PAM_SKY77643_31_NEC (1,032 B)

# External targets allowed for B.W/BL out of the Rust N4 caves in stack mode
ALLOWED_STACK_EXT = {
    0x841DE8DC,  # M1 m1_aqm_shim
    0x8448A6DE,  # IMG4 n4v3_spare
}

# Disjointness guard for .n4cave2 against all other lanes
FORBIDDEN_FOR_CAVE2 = [
    ("IMG4_PRACH_TAIL", 0x847ECE64, 0x847ED954),
    ("M1_CODE_CAVE", 0x841DE8DC, 0x841DF200),
    ("M1_BLK_CAVE", 0x841B581C, 0x841B5BBC),
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


def audit_code(md, code, lo, all_ranges, allowed_ext):
    ins = list(md.disasm(code, lo))
    assert sum(i.size for i in ins) == len(code), f"partial Capstone decode at {lo:#x}"
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
            in_ours = any(a <= t < b for a, b in all_ranges)
            assert in_ours or t in allowed_ext, f"unexpected branch target {i.address:#x} {i.mnemonic} -> {t:#x}"


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--mode", choices=["standalone", "stack"], required=True)
    ap.add_argument("--stock", required=True, help="Path to stock tk.bin")
    ap.add_argument("--m1-spec", default="", help="Path to M1 m1-spec.json (required for --mode stack)")
    ap.add_argument("--emu-path", default="", help="Optional PYTHONPATH containing Capstone")
    ap.add_argument("elf", help="Path to compiled n4_engine.elf")
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

    pvma, prach = section(args.elf, ".n4prach")
    cvma, cave2 = section(args.elf, ".n4cave2")
    assert pvma == PRACH_LO and PRACH_LO + len(prach) <= PRACH_HI and len(prach) % 2 == 0
    assert cvma == CAVE2_LO and CAVE2_LO + len(cave2) <= CAVE2_HI and len(cave2) % 2 == 0

    all_ranges = [(PRACH_LO, PRACH_LO + len(prach)), (CAVE2_LO, CAVE2_LO + len(cave2))]
    allowed_ext = ALLOWED_STACK_EXT if args.mode == "stack" else set()
    audit_code(md, prach, PRACH_LO, all_ranges, allowed_ext)
    if cave2:
        audit_code(md, cave2, CAVE2_LO, all_ranges, allowed_ext)

    # Pad .n4prach and .n4cave2 with Thumb NOP (00 bf) to match stock instruction boundaries.
    while len(prach) % 4 != 0 or sum(i.size for i in md.disasm(stock(PRACH_LO, len(prach)), PRACH_LO)) != len(prach):
        prach += b"\x00\xbf"
        assert PRACH_LO + len(prach) <= PRACH_HI
    if cave2:
        while sum(i.size for i in md.disasm(stock(CAVE2_LO, len(cave2)), CAVE2_LO)) != len(cave2):
            cave2 += b"\x00\xbf"
            assert CAVE2_LO + len(cave2) <= CAVE2_HI
        assert sum(i.size for i in md.disasm(cave2, CAVE2_LO)) == len(cave2)

    assert stock(PRACH_LO, len(prach)) == bytes(len(prach)), "PRACH tail expected zero in stock"

    if args.mode == "standalone":
        hook_defs = [
            ("hook1_mac_tb", 0x842D0914, "d3f80880", "hook_mac_tb", "Rust N4 Hook 1: MAC UL TB build tracker."),
            ("hook2_calc_lcg_bo", 0x842DD21C, "daf84422", "hook_calc_lcg_bo", "Rust N4 Hook 2: calc_lcg_bo true backlog + BSR counters."),
            ("hook2b_short_bsr", 0x842CD5F4, "0ff0cefd", "hook_short_bsr", "Rust N4 Hook 2b: short-BSR LCG rescue."),
            ("hook3_pdcp_limit", 0x842DCCA2, "d2f8bc07", "hook_pdcp_limit", "Rust N4 Hook 3: dynamic JIT-PDCP staging cap."),
            ("hook4_gipc_rx", 0x842DA210, "7f2c0bd8", "hook_gipc_rx", "Rust N4 Hook 4: arrival tracker, legacy sparse, and AQM v2."),
        ]
        sites = []
        for name, va, exp, sym, why in hook_defs:
            assert stock(va, 4).hex() == exp, name
            sites.append({
                "name": name,
                "va": hex(va),
                "offset": hex(va - BASE),
                "expected": exp,
                "new": enc_bl(va, sy[sym]).hex(),
                "reason": why,
            })
        sites.append({
            "name": "n4_ul_engine_cave",
            "va": hex(PRACH_LO),
            "offset": hex(PRACH_LO - BASE),
            "expected": "00" * len(prach),
            "new": prach.hex(),
            "reason": f"Rust N4 v2 primary code ({len(prach)} B Thumb-2, zero literal pools) in PRACH format-4 tail.",
        })
        if cave2:
            sites.append({
                "name": "n4_rust_cave2_rffe_pam",
                "va": hex(CAVE2_LO),
                "offset": hex(CAVE2_LO - BASE),
                "expected": stock(CAVE2_LO, len(cave2)).hex(),
                "new": cave2.hex(),
                "reason": f"Rust N4 v2 overflow code ({len(cave2)} B Thumb-2, zero literal pools) in proven-dead RFFE_PAM_SKY77643_31_NEC (0x84194654..0x84194a5c).",
            })
        # Include A4 hold timer sites to match n4-aqm2-a4.json
        sites += [
            {
                "name": "hold_timer_source",
                "va": "0x8452c976",
                "offset": "0x42c976",
                "expected": "d3f8d420",
                "new": "d3f8d820",
                "reason": "A4: 250 ms bo_margin hold timer reads PDCP COUNT (slot+0xd8).",
            },
            {
                "name": "hold_timer_compare",
                "va": "0x8452c982",
                "offset": "0x42c982",
                "expected": "04d9",
                "new": "04d0",
                "reason": "A4: clear hold only when counter unchanged (beq).",
            },
        ]
        spec = {"name": "r4-n4-rust-standalone-a4", "sites": sites}
    else:
        assert args.m1_spec, "--m1-spec is required for --mode stack"
        m1_raw = open(args.m1_spec, "rb").read()
        m1_sha = hashlib.sha256(m1_raw).hexdigest()
        m1 = json.loads(m1_raw)
        assert len(m1["sites"]) == 70, len(m1["sites"])
        assert len(prach) == 1344, len(prach)

        # Verify all 6 fixed ABI labels landed at exact expected VAs
        assert sy["n4_abi_calc_lcg_bo"] == 0x847ED0EE
        assert sy["n4_abi_check_aqm"] == 0x847ED414
        assert sy["n4_abi_n4v3_word"] == 0x847ED458
        assert sy["n4_abi_exit_d"] == 0x847ED51C
        assert sy["n4_abi_exit_b"] == 0x847ED52E
        assert sy["n4_abi_exit_a"] == 0x847ED53C

        hook_retargets = {
            "hook1_mac_tb": (0x842D0914, "hook_mac_tb"),
            # hook2_calc_lcg_bo stays pointing to IMG3 HRB, which tail-calls 0x847ed0ee -> hook_calc_lcg_bo!
            "hook2b_short_bsr": (0x842CD5F4, "hook_short_bsr"),
            "hook3_pdcp_limit": (0x842DCCA2, "hook_pdcp_limit"),
            "hook4_gipc_rx": (0x842DA210, "hook_gipc_rx"),
        }

        sites = []
        replaced_cave = False
        retargeted = set()
        for s in m1["sites"]:
            s = dict(s)
            nm = s["name"]
            if nm in hook_retargets:
                va, sym = hook_retargets[nm]
                assert int(s["va"], 16) == va
                s["new"] = enc_bl(va, sy[sym]).hex()
                s["reason"] = f"R4 Rust N4 retarget -> {sym} ({sy[sym]:#x}). Was: " + s["reason"]
                retargeted.add(nm)
            elif nm == "n4_ul_engine_cave":
                assert int(s["va"], 16) == PRACH_LO and len(s["expected"]) // 2 == 1344
                s["new"] = prach.hex()
                s["reason"] = (
                    "R4 Rust no_std Thumb-2 N4 v2 primary cave (1,344 B, zero literal pools, "
                    "exact fixed-VA ABI veneers for IMG3 HRB, IMG4 n4v3_spare, N5, and M1)."
                )
                replaced_cave = True
            sites.append(s)
        assert replaced_cave and retargeted == set(hook_retargets)

        if cave2:
            for rname, r0, r1 in FORBIDDEN_FOR_CAVE2:
                assert CAVE2_LO + len(cave2) <= r0 or CAVE2_LO >= r1, f"cave2 overlaps {rname}"
            sites.append({
                "name": "n4_rust_cave2_rffe_pam",
                "va": hex(CAVE2_LO),
                "offset": hex(CAVE2_LO - BASE),
                "expected": stock(CAVE2_LO, len(cave2)).hex(),
                "new": cave2.hex(),
                "reason": (
                    f"R4 Rust no_std Thumb-2 N4 v2 overflow code ({len(cave2)} B of 1,032 B, "
                    "zero literal pools, zero VFP/NEON) in proven-dead RFFE_PAM_SKY77643_31_NEC "
                    "(0x84194654..0x84194a5c, cavecheck/rdcheck 0 real refs, disjoint from N6H/C1/N7/U14/IMG4/M1)."
                ),
            })

        spec = {
            "name": "r4 (m1 + rust no_std thumb-2 n4 v2 uplink engine)",
            "m1_spec_sha256": m1_sha,
            "sites": sites,
        }

    # Pairwise non-overlap & stock preimage checks across all sites.
    spans = sorted((int(s["offset"], 16), int(s["offset"], 16) + len(s["expected"]) // 2, s["name"]) for s in sites)
    for (a0, a1, an), (b0, b1, bn) in zip(spans, spans[1:]):
        assert a1 <= b0, f"overlap {an} ({BASE + a0:#x}..{BASE + a1:#x}) vs {bn} ({BASE + b0:#x}..{BASE + b1:#x})"
    for s in sites:
        assert stock(int(s["va"], 16), len(s["expected"]) // 2).hex() == s["expected"], s["name"]

    with open(args.outp, "w") as f:
        json.dump(spec, f, indent=1)

    print(f"mode:             {args.mode}")
    print(f".n4prach:         {len(prach)} / {PRACH_HI - PRACH_LO} B @ {PRACH_LO:#x}")
    print(f".n4cave2:         {len(cave2)} / {CAVE2_HI - CAVE2_LO} B @ {CAVE2_LO:#x}")
    print(f"total sites:      {len(sites)}")
    for nm in ("hook_mac_tb", "hook_calc_lcg_bo", "hook_short_bsr", "hook_pdcp_limit", "hook_gipc_rx"):
        print(f"  {nm:18s} {sy[nm]:#x}")


if __name__ == "__main__":
    main()
