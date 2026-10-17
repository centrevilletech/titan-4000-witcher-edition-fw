#!/usr/bin/env python3
"""Restore stock inode modes after extraction AND binary patch replacement.

ubi-reader extraction without perms=True loses modes. Apply the original modes
explicitly without needing root, using only a hash-pinned vendor input. Device
nodes are created by mkfs.ubifs -D. Ownership is assigned in the fakeroot pack.
"""
import os
import stat
import sys
from pathlib import Path
from rootfs_metadata import read_metadata, WITCHER_BOOT_SCRIPTS, WITCHER_BUNDLE_SCRIPTS


def main():
    source, destination = map(Path, sys.argv[1:])
    rows = read_metadata(source.read_bytes())
    for name, row in rows.items():
        target = destination / name.lstrip('/')
        if 'device' in row:
            # A privileged extractor can create nodes that an unprivileged
            # extractor skips. mkfs.ubifs -D must be their sole source: 2.3.1
            # rejects nodes supplied by both the staging tree and the table.
            if os.path.lexists(target):
                actual = target.lstat()
                if stat.S_IFMT(actual.st_mode) != stat.S_IFMT(row['mode']) or \
                        [os.major(actual.st_rdev), os.minor(actual.st_rdev)] != row['device']:
                    raise SystemExit(f'Extracted device identity changed: {name}')
                target.unlink()
            continue
        if not os.path.lexists(target):
            # Only these paths are intentionally removed by the main builder.
            if any(name.startswith(prefix) for prefix in (
                    '/usr/www/', '/home/www/', '/etc/sysconfig/audio/sample/')) \
                    or name == '/etc/sysconfig/audio/sample':
                continue
            raise SystemExit(f'Missing extracted vendor path: {name}')
        actual = target.lstat()
        if stat.S_IFMT(actual.st_mode) != stat.S_IFMT(row['mode']):
            raise SystemExit(f'Extracted file type changed: {name}')
        if stat.S_ISLNK(row['mode']):
            if os.readlink(target) != row['target']:
                raise SystemExit(f'Extracted symlink changed: {name}')
        else:
            target.chmod(stat.S_IMODE(row['mode']))
    # These new paths have no factory mode to restore. Do not infer their
    # executable bit from the checkout: a damaged checkout must be repaired.
    for name in WITCHER_BOOT_SCRIPTS:
        target = destination / name.lstrip('/')
        if not target.is_file() or target.is_symlink():
            raise SystemExit(f'Missing or invalid Witcher startup script: {name}')
        target.chmod(0o755)
    # Overlay files must not inherit the checkout umask (often 077).
    bundle = destination / 'usr/lib/titan-api'
    if bundle.exists():
        for target in [bundle, *bundle.rglob('*')]:
            if target.is_symlink():
                if target == bundle / 'ui/device-mac.txt' and os.readlink(target) == '/tmp/witcher-api/device-mac.txt':
                    continue
                raise SystemExit(f'Unexpected overlay symlink: {target}')
            target.chmod(0o755 if target.is_dir() or target.stat().st_mode & 0o111 else 0o644)
        for name in WITCHER_BUNDLE_SCRIPTS:
            target = destination / name.lstrip('/')
            if not target.is_file() or target.is_symlink():
                raise SystemExit(f'Missing or invalid Witcher bundle script: {name}')
            target.chmod(0o755)
    print('Restored vendor modes and Witcher scripts; device nodes delegated to mkfs table.')


if __name__ == '__main__':
    main()
