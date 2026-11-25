#!/usr/bin/env python3
"""Run `titan-pd-keeper tk-build` end to end against stand-in NAND banks.

The banks are plain files holding the stock tk stream from the vendor .prg
padded with 0xff to 8 MiB, as lane P's dumps of mtd17 and mtd18 show.
TITAN_TK_PROC_MTD, TITAN_TK_MTD_DIR and TITAN_TK_DIR point the keeper at
them and at a temporary tk directory. This proves the keeper's decisions,
writes and refusals, not the vendor kernel's MTD driver or bad block table.

Needs WITCHER_STOCK_PRG (the stock .prg; with WITCHER_REQUIRE_STOCK=1 its
absence fails) and TITAN_PD_KEEPER (default: the debug build).
"""
import hashlib
import os
import re
import stat
import struct
import subprocess
import sys
import tempfile
import zlib
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
BANK = 8 * 1024 * 1024
PROC_MTD = 'dev:    size   erasesize  name\nmtd17: 00800000 00020000 "tk"\nmtd18: 00800000 00020000 "tk2"\n'
failures = []


def check(name, ok, detail=''):
    print(('ok   ' if ok else 'FAIL ') + name + (f' ({detail})' if detail and not ok else ''))
    if not ok:
        failures.append(name)


def release_gzip_sha():
    """The gzip SHA-256 the keeper's built-in manifest (manifests::RELEASE) pins."""
    src = (REPO / 'userspace/tk-patch/src/manifests.rs').read_text()
    name = re.search(r'pub const RELEASE: &str = (\w+);', src)[1].lower()
    text = (REPO / f'userspace/tk-patch/manifests/{name}.manifest').read_text()
    return re.search(r'^gzip \d+ ([0-9a-f]{64})$', text, re.M)[1]


def tree(path):
    """Every file under `path` with its bytes and mode, to see what changed."""
    if not path.exists():
        return None
    return {p.relative_to(path).as_posix(): (p.read_bytes(), stat.S_IMODE(p.lstat().st_mode))
            for p in sorted(path.rglob('*')) if p.is_file()}


class Unit:
    """A temporary root: /proc/mtd, the banks and the tk directory."""

    def __init__(self, root, tk, tk2):
        self.root = root
        (root / 'dev').mkdir()
        (root / 'proc_mtd').write_text(PROC_MTD)
        os.symlink(tk, root / 'dev/mtd17')
        os.symlink(tk2, root / 'dev/mtd18')
        self.tk = root / 'tk'

    def run(self, keeper, *args):
        env = dict(os.environ, TITAN_TK_PROC_MTD=str(self.root / 'proc_mtd'), TITAN_TK_MTD_DIR=str(self.root / 'dev'),
                   TITAN_TK_DIR=str(self.tk), TITAN_PD_RUNTIME=str(self.root / 'run'),
                   TITAN_PD_STATE=str(self.root / 'state'))
        return subprocess.run([keeper, 'tk-build', *args], env=env, capture_output=True, text=True, timeout=600)


def main():
    keeper = os.environ.get('TITAN_PD_KEEPER', str(REPO / 'userspace/target/debug/titan-pd-keeper'))
    prg = os.environ.get('WITCHER_STOCK_PRG')
    if not prg:
        if os.environ.get('WITCHER_REQUIRE_STOCK') == '1':
            sys.exit('WITCHER_STOCK_PRG is not set')
        print('skip: set WITCHER_STOCK_PRG to the stock .prg')
        return
    data = Path(prg).read_bytes()
    kernel, ubi, size = struct.unpack_from('>III', data, 0x24)
    stock_gz = data[0x54 + kernel + ubi:0x54 + kernel + ubi + size]
    want = release_gzip_sha()
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        good = tmp / 'good.bank'
        good.write_bytes(stock_gz + b'\xff' * (BANK - len(stock_gz)))
        broken = tmp / 'broken.bank'
        damaged = bytearray(good.read_bytes())
        damaged[1_000_000] ^= 0x40
        broken.write_bytes(damaged)
        # Another firmware's tk: the stock image with one byte changed.
        raw = bytearray(zlib.decompressobj(31).decompress(stock_gz))
        raw[0x100] ^= 1
        other = gzip_bytes(bytes(raw))
        foreign = tmp / 'foreign.bank'
        foreign.write_bytes(other + b'\xff' * (BANK - len(other)))

        def unit(name, tk, tk2):
            root = tmp / name
            root.mkdir()
            return Unit(root, tk, tk2)

        u = unit('check', good, good)
        r = u.run(keeper, 'check')
        check('check: passes and names the bank', r.returncode == 0 and 'check passed' in r.stdout
              and 'tk (mtd17, 0 bad blocks skipped)' in r.stdout, r.stdout + r.stderr)
        check('check: writes nothing', not u.tk.exists())

        u = unit('stage', good, good)
        u.tk.mkdir(mode=0o700)
        old = '# bench\nenabled=0\nsha256=' + 'a' * 64 + '\ntarget=192.0.2.1\nwm=0x847ed604:0x15\nmanage=off\n'
        (u.tk / 'config').write_text(old)
        (u.tk / 'strikes').write_text('strikes=2\n')
        (u.tk / 'quarantine').write_text('b' * 64 + '\n')
        before = tree(u.tk)
        r = u.run(keeper, 'stage')
        image = u.tk / 'active.gz'
        check('stage: exits 0', r.returncode == 0, r.stdout + r.stderr)
        check('stage: active.gz is the bench file', image.exists() and hashlib.sha256(image.read_bytes()).hexdigest() == want)
        check('stage: active.gz is 0600', image.exists() and stat.S_IMODE(image.stat().st_mode) == 0o600)
        config = (u.tk / 'config').read_text()
        check('stage: config switches on, allows the image and keeps every other line',
              config == f'enabled=1\nsha256={want}\n# bench\ntarget=192.0.2.1\nwm=0x847ed604:0x15\nmanage=off\n', config)
        after = tree(u.tk)
        check('stage: strikes and quarantine untouched',
              all(after[k] == before[k] for k in ('strikes', 'quarantine')))
        check('stage: nothing else in tk/', sorted(after) == ['active.gz', 'config', 'quarantine', 'strikes'], sorted(after))
        check('stage: says the strike count keeps stock firmware', 'note: tk/strikes is 2' in r.stdout, r.stdout)
        log = (u.root / 'run/keeper.log')
        check('stage: one line in the RAM log', log.exists() and 'tk build: staged' in log.read_text())
        check('stage: nothing in the flash state directory', not (u.root / 'state').exists())

        u = unit('fallback', broken, good)
        r = u.run(keeper, 'stage')
        check('a damaged tk bank: builds from tk2', r.returncode == 0 and 'tk2 (mtd18' in r.stdout
              and 'tk (mtd17)' not in r.stdout, r.stdout + r.stderr)
        check('a damaged tk bank: the image is still the bench file',
              hashlib.sha256((u.tk / 'active.gz').read_bytes()).hexdigest() == want)
        check('a fresh tk directory is 0700', stat.S_IMODE(u.tk.stat().st_mode) == 0o700)
        check('a fresh config holds the switch and the hash only',
              (u.tk / 'config').read_text() == f'enabled=1\nsha256={want}\n')

        u = unit('refuse', foreign, broken)
        u.tk.mkdir(mode=0o700)
        (u.tk / 'config').write_text(old)
        before = tree(u.tk)
        r = u.run(keeper, 'stage')
        check('no stock bank: refuses', r.returncode == 1 and 'no tk bank holds the stock image' in r.stderr, r.stderr)
        check('no stock bank: says why for each bank', 'tk (mtd17): ' in r.stderr and 'tk2 (mtd18): ' in r.stderr, r.stderr)
        check('no stock bank: changes nothing', tree(u.tk) == before)

        u = unit('leftover', good, good)
        u.tk.mkdir(mode=0o700)
        (u.tk / '.active.gz.tk-build').write_bytes(b'half')
        before = tree(u.tk)
        r = u.run(keeper, 'stage')
        check('a leftover temporary file: refuses', r.returncode == 1 and '.active.gz.tk-build exists' in r.stderr, r.stderr)
        check('a leftover temporary file: changes nothing', tree(u.tk) == before)

        r = subprocess.run([keeper, 'tk-build'], capture_output=True, text=True)
        check('usage: exit 64', r.returncode == 64, r.stderr)
    print('\nRESULT:', 'ALL PASS' if not failures else f'{len(failures)} FAILURES')
    sys.exit(1 if failures else 0)


def gzip_bytes(raw):
    c = zlib.compressobj(9, zlib.DEFLATED, -15, 8, 0)
    return bytes.fromhex('1f8b0800000000000203') + c.compress(raw) + c.flush() + struct.pack(
        '<II', zlib.crc32(raw) & 0xffffffff, len(raw) & 0xffffffff)


if __name__ == '__main__':
    main()
