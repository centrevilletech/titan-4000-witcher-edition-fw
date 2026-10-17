#!/usr/bin/env python3
"""Rebuild a GCT GDM7243 .prg from extracted partitions.

Round-trip requirement: packing the three blobs produced by prg-unpack.py
must be byte-identical to the original file. This was verified for
GTCGR_TITAN4K_V1.6.0P0_R3882-4172-CBRS.prg.

Do not recompress 03_tk.gzip. The vendor gzip (XFL=3) is not reproduced by
Python gzip.GzipFile. Always reuse the original tk blob unless you are
intentionally changing modem firmware, which this project must not do.

Header fields copied from --template (the original 84-byte header) except:
  0x04 payload CRC, 0x08 payload length, 0x24/0x28/0x2C sizes, 0x50 header CRC.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
import sys
import zlib
from pathlib import Path


HEADER_LEN = 0x54
MAGIC = 0x00007243


def crc32(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def pack(parts_dir: Path, template: Path, out: Path) -> None:
    hdr = bytearray((parts_dir / "00_header.bin").read_bytes())
    if template is not None:
        hdr = bytearray(template.read_bytes()[:HEADER_LEN])
    if len(hdr) != HEADER_LEN:
        raise SystemExit(f"header must be {HEADER_LEN} bytes, got {len(hdr)}")
    magic = struct.unpack_from(">I", hdr, 0)[0]
    if magic != MAGIC:
        raise SystemExit(f"bad magic 0x{magic:08X}")

    kernel = (parts_dir / "01_kernel.uImage").read_bytes()
    rootfs = (parts_dir / "02_rootfs.ubi").read_bytes()
    tk = (parts_dir / "03_tk.gzip").read_bytes()
    payload = kernel + rootfs + tk

    struct.pack_into(">I", hdr, 0x08, len(payload))
    struct.pack_into(">I", hdr, 0x24, len(kernel))
    struct.pack_into(">I", hdr, 0x28, len(rootfs))
    struct.pack_into(">I", hdr, 0x2C, len(tk))
    struct.pack_into(">I", hdr, 0x04, crc32(payload))
    struct.pack_into(">I", hdr, 0x50, crc32(bytes(hdr[:0x50])))

    image = bytes(hdr) + payload
    out.write_bytes(image)
    print(f"wrote {out} {len(image)} sha256={hashlib.sha256(image).hexdigest()}")
    print(f"payload CRC 0x{struct.unpack_from('>I', hdr, 0x04)[0]:08X}")
    print(f"header  CRC 0x{struct.unpack_from('>I', hdr, 0x50)[0]:08X}")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("parts", type=Path, help="directory from prg-unpack.py")
    p.add_argument("-o", "--out", type=Path, required=True)
    p.add_argument(
        "--template",
        type=Path,
        default=None,
        help="optional original .prg or 00_header.bin to copy unknown fields from",
    )
    args = p.parse_args()
    template = args.template
    if template is None:
        template = args.parts / "00_header.bin"
    pack(args.parts, template, args.out)


if __name__ == "__main__":
    main()
