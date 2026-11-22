#!/usr/bin/env python3
"""Stop the vendor `monitor` from reading a busy eth0 as frozen.

Every pass (120 s plus the pass itself) `monitor` runs two shell commands,
reads the eth0 receive and transmit packet counters with atoi(), and compares
them with the previous pass. If both are unchanged while the link is RUNNING,
it runs `ifconfig eth0 down; sleep 2; ifconfig eth0 up`, and on the third pass
in a row it asks rcinit for a LAN reset (code at 0x9bf0, called from 0xbca4).

The kernel counters are 32-bit and count up to 4,294,967,295. uClibc atoi() is
strtol(), which clamps everything from 2,147,483,647 up to 2,147,483,647. Once
both counters are in that upper half, every pass reads the same two numbers,
so `monitor` bounces eth0 every pass and resets the LAN every third pass while
traffic flows, until a counter wraps or the unit reboots.

The fix changes only the two command strings, so awk prints each counter
modulo 10^9. That value is always below the clamp, it still changes whenever
the counter changes, and for a counter below 10^9 it is the same number as
before. The boot-time check at 0x9f8c uses the same strings and sees the same
values it always did. A real freeze (no frame either way for a whole pass) is
still handled exactly as before.

    0x4234  cat /proc/net/dev | grep eth0 | awk '{print $3}'
         -> grep eth0 /proc/net/dev | awk '{print $3%1e9}'
    0x4268  cat /proc/net/dev | grep eth0 | awk '{print $11}'
         -> grep eth0 /proc/net/dev | awk '{print $11%1e9}'

Each new string is shorter than the old one; the rest of the old string is
filled with NUL bytes, so nothing else in the file moves.
"""
import argparse
import hashlib
import sys
from pathlib import Path

STOCK_SHA256 = '5f7b51ba2a716b1465526053007ccb1259cdf50f69a8553b97df36cfafef1255'
PATCHES = [
    (0x4234, b"cat /proc/net/dev | grep eth0 | awk '{print $3}'",
     b"grep eth0 /proc/net/dev | awk '{print $3%1e9}'"),
    (0x4268, b"cat /proc/net/dev | grep eth0 | awk '{print $11}'",
     b"grep eth0 /proc/net/dev | awk '{print $11%1e9}'"),
]


def patch(data):
    """Return the patched bytes. Refuse anything but the stock or the patched file."""
    out = bytearray(data)
    for offset, old, new in PATCHES:
        assert len(new) < len(old)
        span = len(old) + 1  # the string and its NUL
        current = bytes(out[offset:offset + span])
        wanted = new + b'\0' * (span - len(new))
        if current == wanted:
            continue
        if current != old + b'\0':
            raise ValueError(f'refusing @0x{offset:x}: {current!r} is not the stock string (wrong binary/version)')
        out[offset:offset + span] = wanted
    return bytes(out)


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('stock', type=Path)
    parser.add_argument('-o', '--out', type=Path, required=True)
    args = parser.parse_args()
    data = args.stock.read_bytes()
    try:
        result = patch(data)
    except ValueError as error:
        sys.exit(str(error))
    if hashlib.sha256(data).hexdigest() != STOCK_SHA256 and result != data:
        sys.exit('refusing: monitor is not the stock 4172 binary this patch was proven on')
    args.out.write_bytes(result)
    print(f'patched monitor -> {args.out}  sha256 {hashlib.sha256(result).hexdigest()}')
    print('  eth0 packet counters read modulo 1e9: below the atoi clamp, same values under 1e9')


if __name__ == '__main__':
    main()
