"""Hash-pinned byte patches for stock vendor ARM executables.

Each patch names a virtual address, the exact stock bytes there and the new
bytes. A patch set runs only on an input whose SHA-256 is pinned, and the
result must match the output SHA-256 pinned for that input. A file that is
already one of the pinned outputs passes through unchanged. Anything else is
refused, so a different vendor build can never be patched by mistake.
"""
import hashlib
import struct
from typing import NamedTuple

# ARM (A32) `mov r0, r0`, the canonical no-op. It changes no register or flag.
NOP = bytes.fromhex('0000a0e1')


class Patch(NamedTuple):
    va: int        # virtual address in the executable
    old: bytes     # stock bytes, checked before writing
    new: bytes     # replacement, same length
    label: str     # what the patch does, for logs and the verifier


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def arm_branch(source, target):
    """Encode an unconditional A32 `b target` placed at `source`."""
    offset = target - (source + 8)
    if offset % 4 or not -(1 << 25) <= offset < (1 << 25):
        raise ValueError(f'branch 0x{source:x} -> 0x{target:x} out of range')
    return struct.pack('<I', 0xea000000 | ((offset >> 2) & 0xffffff))


def arm_branch_target(source, word):
    """Decode an A32 `b`/`bl` word at `source` into its target address."""
    value = struct.unpack('<I', word)[0]
    imm = value & 0xffffff
    if imm & 0x800000:
        imm -= 1 << 24
    return source + 8 + imm * 4


def apply(data, patches, base):
    """Write every patch after checking its stock bytes. `base` maps VA to file offset."""
    out = bytearray(data)
    for patch in patches:
        if len(patch.old) != len(patch.new):
            raise ValueError(f'{patch.label}: replacement changes length')
        offset = patch.va - base
        current = bytes(out[offset:offset + len(patch.old)])
        if current != patch.old:
            raise ValueError(f'refusing @VA 0x{patch.va:x} ({patch.label}): found {current.hex()}, '
                             f'expected stock {patch.old.hex()}')
        out[offset:offset + len(patch.new)] = patch.new
    return bytes(out)


def patch_pinned(data, patches, base, pins, name):
    """Patch a pinned input. `pins` maps input SHA-256 to the expected output SHA-256."""
    digest = sha256(data)
    if digest in pins.values():
        return data
    if digest not in pins:
        raise ValueError(f'refusing: {name} SHA-256 {digest} is not a pinned stock input')
    result = apply(data, patches, base)
    if sha256(result) != pins[digest]:
        raise ValueError(f'refusing: patched {name} SHA-256 {sha256(result)} does not match the pin')
    return result


def run_cli(description, name, patches, base, pins, notes):
    import argparse
    import sys
    from pathlib import Path
    parser = argparse.ArgumentParser(description=description,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('stock', type=Path)
    parser.add_argument('-o', '--out', type=Path, required=True)
    args = parser.parse_args()
    data = args.stock.read_bytes()
    try:
        result = patch_pinned(data, patches, base, pins, name)
    except ValueError as error:
        sys.exit(str(error))
    args.out.write_bytes(result)
    state = 'already patched, copied unchanged' if result == data else f'{len(patches)} patches applied'
    print(f'patched {name} -> {args.out}  sha256 {sha256(result)}  ({state})')
    for line in notes:
        print(f'  {line}')
