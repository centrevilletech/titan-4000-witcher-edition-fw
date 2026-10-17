#!/usr/bin/env python3
"""Modify the Titan CBRS/SAS client's local enforcement paths.

cbrs_fsm (stripped ARM) has two local paths modified below. These changes do
not implement replacement spectrum enforcement or establish compliance.
See docs/cbrs-sas-enforcement.md.

1. On grant-loss/de-register/expire it runs the routine at file 0x4fcc
   ("+++ Block Channel +++") which sets nvram cbrs_mode_grant=0 and SIGUSR1s
   rcinit to tear down the LTE traffic channel — dropping BOTH the customer and
   management bearers. It has exactly two callers (de-register/grant-loss and the
   heartbeat "Radio Offline" path). We make it return immediately:
     0x4fcc  push {r11,lr}   (00 48 2d e9) -> mov r0,#0 (00 00 a0 e3)
     0x4fd0  add  r11,sp,#4  (04 b0 8d e2) -> bx  lr    (1e ff 2f e1)
   Registration, heartbeat, grant-state bookkeeping and the "Open Channel" path
   are untouched, so grant state stays visible upstream.

2. Five iptables/ebtables OUTPUT commands (CRL/SAS firewall pokes) run via
   system(); we replace the 8-byte leading token with "true    " so the shell
   runs `true ...` (no-op). Offsets: 0x1c8b4 0x202a8 0x202e8 0x2037c 0x203b4.
"""
import argparse, hashlib, sys
from pathlib import Path

TRUE = bytes.fromhex('7472756520202020')  # "true    "
FW = [0x1c8b4, 0x202a8, 0x202e8, 0x2037c, 0x203b4]
FW_ORIG = {0x1c8b4: b'iptables', 0x202a8: b'ebtables', 0x202e8: b'iptables',
           0x2037c: b'iptables', 0x203b4: b'ebtables'}
BLOCK = [(0x4fcc, bytes.fromhex('00482de9'), bytes.fromhex('0000a0e3')),
         (0x4fd0, bytes.fromhex('04b08de2'), bytes.fromhex('1eff2fe1'))]

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('stock', type=Path); ap.add_argument('-o','--out',type=Path,required=True)
    a = ap.parse_args()
    d = bytearray(a.stock.read_bytes())
    for off in FW:
        cur = bytes(d[off:off+8])
        if cur == TRUE: continue
        if cur != FW_ORIG[off]:
            sys.exit(f'refusing @0x{off:x}: {cur!r} != {FW_ORIG[off]!r} (wrong binary/version)')
        d[off:off+8] = TRUE
    for off, orig, new in BLOCK:
        cur = bytes(d[off:off+4])
        if cur == new: continue
        if cur != orig:
            sys.exit(f'refusing @0x{off:x}: {cur.hex()} != {orig.hex()} (wrong binary/version)')
        d[off:off+4] = new
    a.out.write_bytes(d)
    print(f'patched cbrs_fsm -> {a.out}  sha256 {hashlib.sha256(bytes(d)).hexdigest()}')
    print('  block routine 0x4fcc: mov r0,#0; bx lr   (no radio block, no rcinit signal)')
    print('  5 firewall commands -> true (no iptables/ebtables changes)')

if __name__ == '__main__': main()
