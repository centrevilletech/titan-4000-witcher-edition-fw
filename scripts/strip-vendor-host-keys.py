#!/usr/bin/env python3
"""Remove vendor shared SSH host identities from the pinned rcinit binary.

Null the constant strings in place. The legacy daemon cannot load a shared
identity; Witcher's SSH service creates its own per-unit key independently.
Never substitute a fleet-wide private key supplied through CI.
"""
import sys
from pathlib import Path
from credential_policy import PRIVATE_KEY


def strip_keys(path):
    path = Path(path)
    data = path.read_bytes()
    matches = list(PRIVATE_KEY.finditer(data))
    if not matches:
        return 0
    if [m.group(1) for m in matches] != [b'RSA PRIVATE KEY', b'DSA PRIVATE KEY']:
        raise ValueError('Unexpected vendor SSH host-key layout')
    out = bytearray(data)
    for match in matches:
        out[match.start():match.end()] = b'\0' * len(match.group())
    if PRIVATE_KEY.search(out) or len(out) != len(data):
        raise ValueError('Vendor SSH host-key removal failed')
    path.write_bytes(out)
    return len(matches)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit('usage: strip-vendor-host-keys.py RCINIT')
    try:
        count = strip_keys(sys.argv[1])
    except ValueError as error:
        sys.exit(str(error))
    print(f'vendor shared SSH host keys removed: {count}')
