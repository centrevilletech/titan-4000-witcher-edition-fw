#!/usr/bin/env python3
"""Unpack a GCT GDM7243 .prg (Titan 4000 / similar) into kernel, UBI, and tk.

Verified against GTCGR_TITAN4K_V1.6.0P0_R3882-4172-CBRS.prg:

  offset 0x00  uint32 BE  magic 0x00007243
  offset 0x04  uint32 BE  CRC32 of payload (bytes 0x54..EOF), zlib/ITU
  offset 0x08  uint32 BE  payload length (file size - 84)
  offset 0x10  uint32 BE  version 0x01060000 = 1.6.0.0
  offset 0x18  uint32 BE  build number (4172)
  offset 0x24  uint32 BE  kernel uImage size
  offset 0x28  uint32 BE  rootfs UBI size
  offset 0x2C  uint32 BE  tk gzip size
  offset 0x50  uint32 BE  CRC32 of header bytes [0x00, 0x50)
  offset 0x54  payload: uImage | UBI | gzip(tk)

No RSA/HMAC field is present in this 84-byte header.
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


def be32(data: bytes, off: int) -> int:
    return struct.unpack_from(">I", data, off)[0]


def crc32(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def unpack(prg_path: Path, out_dir: Path) -> None:
    data = prg_path.read_bytes()
    if len(data) < HEADER_LEN:
        raise SystemExit(f"file too small: {len(data)}")

    magic = be32(data, 0x00)
    if magic != MAGIC:
        raise SystemExit(f"bad magic 0x{magic:08X} (expected 0x{MAGIC:08X})")

    payload_crc = be32(data, 0x04)
    payload_len = be32(data, 0x08)
    version = be32(data, 0x10)
    build = be32(data, 0x18)
    k_size = be32(data, 0x24)
    r_size = be32(data, 0x28)
    t_size = be32(data, 0x2C)
    header_crc = be32(data, 0x50)

    payload = data[HEADER_LEN:]
    if payload_len != len(payload):
        raise SystemExit(
            f"payload length field {payload_len} != actual {len(payload)}"
        )
    if k_size + r_size + t_size != payload_len:
        raise SystemExit(
            f"partition sizes {k_size}+{r_size}+{t_size} != payload {payload_len}"
        )

    calc_payload = crc32(payload)
    calc_header = crc32(data[:0x50])
    if calc_payload != payload_crc:
        raise SystemExit(
            f"payload CRC mismatch stored=0x{payload_crc:08X} calc=0x{calc_payload:08X}"
        )
    if calc_header != header_crc:
        raise SystemExit(
            f"header CRC mismatch stored=0x{header_crc:08X} calc=0x{calc_header:08X}"
        )

    k_off = HEADER_LEN
    r_off = k_off + k_size
    t_off = r_off + r_size

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "00_header.bin").write_bytes(data[:HEADER_LEN])
    (out_dir / "01_kernel.uImage").write_bytes(data[k_off:r_off])
    (out_dir / "02_rootfs.ubi").write_bytes(data[r_off:t_off])
    (out_dir / "03_tk.gzip").write_bytes(data[t_off : t_off + t_size])

    print(f"file        {len(data)} bytes  sha256={hashlib.sha256(data).hexdigest()}")
    print(f"magic       0x{magic:08X}")
    print(f"version     {version >> 24}.{(version >> 16) & 0xFF}.{(version >> 8) & 0xFF}.{version & 0xFF}")
    print(f"build       {build}")
    print(f"payload CRC 0x{payload_crc:08X} OK")
    print(f"header CRC  0x{header_crc:08X} OK")
    print(f"kernel      off=0x{k_off:X} size={k_size}")
    print(f"rootfs UBI  off=0x{r_off:X} size={r_size}")
    print(f"tk gzip     off=0x{t_off:X} size={t_size}")
    print(f"wrote       {out_dir}")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("prg", type=Path)
    p.add_argument("-o", "--out", type=Path, default=Path("firmware-analysis"))
    args = p.parse_args()
    unpack(args.prg, args.out)


if __name__ == "__main__":
    main()
