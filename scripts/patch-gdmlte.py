#!/usr/bin/env python3
"""Apply the Witcher-edition IPv6-PD modem patches to a stock Titan gdmlte.ko.

The vendor LTE data driver has TWO source-prefix gates on the IPv6 uplink path
that drop packets whose source is not the bearer's assigned /64 — so a host
behind the customer router using a DHCPv6-PD delegated prefix is dropped twice.
Both are widened from an exact/ /64 match to the customer's /56, so the delegated
prefix (same /56 as the assigned /64) is accepted and transmitted on the correct
bearer, while the management /56 and out-of-/56 sources stay rejected. See
docs/modem-ipv6-pd-patch.md.

Two one-byte changes (verified against R3882-4172-CBRS gdmlte.ko):
  file 0x2f0c: mov r2,#0x10 -> mov r2,#7   (check #1: neighbour-match, selects bearer)
  file 0x32d8: mov r2,#8    -> mov r2,#7   (check #2: source-prefix filter before modem handoff)
The bearer-select branch (file 0x2f18, beq) must remain stock; a prior wrong
attempt forced it unconditional and broke bearer selection — do NOT do that.
"""
import argparse, hashlib, sys
from pathlib import Path

PATCHES = [
    # (file_offset, stock_bytes, patched_bytes, description)
    (0x2f0c, bytes.fromhex('1020a0e3'), bytes.fromhex('0720a0e3'), 'check#1 neighbour-match /64->/56'),
    (0x32d8, bytes.fromhex('0820a0e3'), bytes.fromhex('0720a0e3'), 'check#2 source-prefix filter /64->/56'),
]
BEQ_OFF, BEQ_BYTES = 0x2f18, bytes.fromhex('8d01000a')  # bearer-select branch, must stay stock

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('stock', type=Path)
    ap.add_argument('-o', '--out', type=Path, required=True)
    args = ap.parse_args()
    d = bytearray(args.stock.read_bytes())
    if bytes(d[BEQ_OFF:BEQ_OFF+4]) != BEQ_BYTES:
        sys.exit(f'refusing: bearer-select branch at 0x{BEQ_OFF:x} is not stock; wrong module/version.')
    for off, stock, patch, desc in PATCHES:
        here = bytes(d[off:off+4])
        if here == patch:
            print(f'  already patched @0x{off:x} ({desc})', file=sys.stderr); continue
        if here != stock:
            sys.exit(f'refusing @0x{off:x}: bytes {here.hex()} != stock {stock.hex()} ({desc}).')
        d[off:off+4] = patch
        print(f'  patched @0x{off:x}: {desc}')
    args.out.write_bytes(d)
    print(f'wrote {args.out}  sha256 {hashlib.sha256(bytes(d)).hexdigest()}')

if __name__ == '__main__':
    main()
