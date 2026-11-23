#!/usr/bin/env python3
"""Make the gated copy of the stock Titan modem.ko for the boot-time tk loader.

The stock module stays in place, byte for byte. This writes a second copy with
one ARM instruction changed. The boot hook (overlay/etc/init.d/witcher-tk-stage)
loads that copy only on a boot where an operator opted in and a verified modem
firmware image is staged. See docs/tk-boot-loader.md.

The change (R3882-4172-CBRS modem.ko, .text at file offset 0x34):
  .text+0x2054 (file 0x2088), inside read_tk_image:
    stock:  11 00 00 9a   bls 0x20a0   (skip /lib/firmware, read NAND)
    gated:  00 f0 20 e3   nop          (try /lib/firmware first)

What the gated module does, from the stock disassembly (addresses are .text):
  0x2058..0x2060  calls the filesystem loader at 0x1e84.
  0x1e84          calls get_modem_fw_filename (0x1da8). That opens
                  /lib/firmware/tk.gz, then /lib/firmware/tk.xz. If neither
                  opens it returns NULL and 0x1e84 returns -22 (0x1ee4) without
                  calling request_firmware.
  0x2064..0x2068  a negative result falls through to 0x206c..0x2098, which loads
                  the NAND bank exactly as the stock path 0x20a0..0x20c8 does.
  So: no tk.gz and no tk.xz in /lib/firmware means stock NAND firmware.

  If a file opens, 0x1eac calls request_firmware, prints "read from fs" and
  calls the loader callback (firware_downalod, 0x1824). That callback ignores
  the decompressor's result (0x183c then "mov r0, #0" at 0x1844), and 0x1e84
  ignores the callback's result (0x1ecc then "mov r0, #0" at 0x1ed8). A file
  that opens but does not decompress is NOT a fallback: read_tk_image returns
  0 and the modem CPU starts on whatever reached its RAM. The boot hook must
  therefore stage a verified image or nothing at all.

Both digests are pinned. Any other input fails the build.
"""
import argparse
import hashlib
import sys
from pathlib import Path

STOCK_SHA256 = '6993588fda8c3734f4889484e223ec74fabf66c43a3770875734f27f6083d5c8'
GATED_SHA256 = '161ffdd052059a14747041a74b7b7740c705bfd52c9913a9013cbb0a15f55977'
OFFSET = 0x2088
STOCK_BYTES = bytes.fromhex('1100009a')  # bls 0x20a0
GATED_BYTES = bytes.fromhex('00f020e3')  # nop


def gate(data: bytes) -> bytes:
    """Return the gated module, or raise ValueError for any input but the pinned stock one."""
    digest = hashlib.sha256(data).hexdigest()
    if digest != STOCK_SHA256:
        raise ValueError(f'modem.ko is not the pinned stock module: sha256 {digest}')
    if data[OFFSET:OFFSET + 4] != STOCK_BYTES:
        raise ValueError(f'modem.ko bytes at 0x{OFFSET:x} are not the stock bls')
    out = bytearray(data)
    out[OFFSET:OFFSET + 4] = GATED_BYTES
    out = bytes(out)
    digest = hashlib.sha256(out).hexdigest()
    if digest != GATED_SHA256:
        raise ValueError(f'gated modem.ko has an unexpected sha256 {digest}')
    changed = [i for i, (a, b) in enumerate(zip(data, out)) if a != b]
    if len(out) != len(data) or not changed or min(changed) < OFFSET or max(changed) >= OFFSET + 4:
        raise ValueError('gated modem.ko differs outside the 4-byte gate')
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('stock', type=Path)
    ap.add_argument('-o', '--out', type=Path, required=True)
    args = ap.parse_args()
    try:
        out = gate(args.stock.read_bytes())
    except ValueError as err:
        sys.exit(f'refusing: {err}')
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_bytes(out)
    print(f'  gated @0x{OFFSET:x}: {STOCK_BYTES.hex()} -> {GATED_BYTES.hex()}')
    print(f'wrote {args.out}  sha256 {GATED_SHA256}')


if __name__ == '__main__':
    main()
