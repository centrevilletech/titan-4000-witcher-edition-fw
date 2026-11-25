#!/usr/bin/env python3
"""Cross-check the Rust modem image builder (userspace/tk-patch) against Python's zlib.

Three checks, each independent of the Rust code it tests:

1. Deflate parity. `tk-patch gzip` must write byte for byte what Python's
   gzip.compress(level 9, mtime 0) writes with the OS byte set to 3 (Unix),
   as tkpatch.py does, for many generated inputs. `tk-patch gunzip` must
   undo Python's output.
2. Manifests. This script parses each manifest in userspace/tk-patch/manifests
   itself, applies it to the stock image with Python, and checks the result
   against the manifest's pinned hashes and against the bench images. No
   literal replacement window of 16 bytes with 8 or more distinct values may
   occur anywhere in the stock image: vendor runs must be stock references.
3. The builder. `tk-patch build` on the stock .prg must write the bench
   image's exact gzip file.

Checks 2 and 3 need the stock image: set WITCHER_STOCK_PRG to the stock .prg
(CI downloads it). With WITCHER_REQUIRE_STOCK=1 a missing image fails the run.
Check 1 and 3 need the CLI: set TK_PATCH to the built `tk-patch` binary.
Without it, only check 2 runs.
"""
import gzip
import hashlib
import os
import re
import struct
import subprocess
import sys
import tempfile
import zlib
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
MANIFESTS = REPO / 'userspace/tk-patch/manifests'
STOCK_SHA = '555362d9c050862ac462017df54cbcedc00b0963454b332438d70bbef70f82ea'
STOCK_GZIP_SHA = '6b98f6b428b3f4052f645f307a1d822aec805aa0ebd9527c562b044f8af7ad71'
# The Python-built bench images (tkpatch.py), from the lanes' SHA256SUMS.
BENCH = {
    'n6h': ('a2fc899439b938ec4e16ee2c8519587c4e2fffedee52b8a3bb5cdf33daff8168',
            'a1fc066af1cae2848fee47abb67e501fd76977298ab4b77fd1d81e1174fe5cbe'),
    'm1': ('cd7effdd3c45dced9d434fdb3c4283b14e7c7b7a70fadc457c091a1edab70c6b',
           'e47b04354db5d8280a4fb15e4f9937ca8d94ad18a969ccd11d4c21c72ce1001d'),
    'r1': ('f434277dfd1aa2db6a3ebc458c339ad90c4b311480558f96952753e5817f82b4',
           '186697f32b8831a35e96ca90745c2f7c20bd6d664d4de51da7bdaf61b9abdd1c'),
    'r4': ('60ab8fe7d50f6b44d2ece1d08b50bcc72f2b3e45195f71b0a2378369386ce376',
           '4ced9782d5e0143f5c0426ac24b08dabfc90c2afb9d823d022fe98bcae6c9831'),
    # The release image (lane R1, build-combined): N6H + R4's Rust N4 + R1's PIE.
    'n6h-r4-r1': ('f1aa8add6a4e4e00c17c3cfe90f51e8b31d75c39751c48cf6ffa5c9f159d1f42',
                  '3348aa361c4689c4ff18b647a03bfa55cea36bc6675059cd9995e591592e40bb'),
    # Lane Q1 (build.sh): the release image plus selector 3, M1 block version 0x20261127.
    'n6h-r4-q1': ('832c601a75f3000c9ae62c3dfdf9842bafcbc699136ec826393a6f2c3578bbf6',
                  '98a79d3296fa87e95a4fc12d527181db9c3171e637a724986cb45a333f6a986f'),
}
failures = []


def check(name, ok, detail=''):
    print(('ok   ' if ok else 'FAIL ') + name + (f' ({detail})' if detail and not ok else ''))
    if not ok:
        failures.append(name)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def python_gzip(data):
    out = bytearray(gzip.compress(data, compresslevel=9, mtime=0))
    out[9] = 3
    return bytes(out)


# ---- generated inputs (the Rust tests use the same xorshift32 generators)

def xorshift32(seed):
    x = seed
    while True:
        x ^= (x << 13) & 0xffffffff
        x ^= x >> 17
        x ^= (x << 5) & 0xffffffff
        yield x


def random_bytes(seed, n):
    r = xorshift32(seed)
    return bytes(next(r) & 0xff for _ in range(n))


def mixed(seed, units):
    """Random runs, byte runs, long copies (window slides, far matches) and text."""
    r = xorshift32(seed)
    out = bytearray()
    for _ in range(units):
        kind = next(r) % 4
        n = next(r) % 300 + 1
        if kind == 0:
            out += bytes(next(r) & 0xff for _ in range(n))
        elif kind == 1:
            out += bytes([next(r) & 0xff]) * n
        elif kind == 2 and out:
            d = next(r) % min(len(out), 40000) + 1
            for _ in range(n):
                out.append(out[len(out) - d])
        else:
            out += b'abcabcabd'[:n % 9 + 1] * (n // 9 + 1)
    return bytes(out)


def cases():
    yield 'empty', b''
    yield 'one byte', b'a'
    yield 'short text', b'hello hello hello hello'
    yield 'zeros 70000', bytes(70000)
    yield 'random 40000 (stored blocks)', random_bytes(1, 40000)
    yield 'fox x3000', b'The quick brown fox jumps over the lazy dog. ' * 3000
    yield 'mixed 1500 units', mixed(1, 1500)
    for seed in range(2, 14):
        yield f'mixed seed {seed}', mixed(seed, 100 * seed)
    for n in (16382, 16383, 16384, 32768, 65536, 65537, 98304):
        yield f'random {n}', random_bytes(n, n)


# ---- the manifest format, parsed independently of the Rust parser

def parse_manifest(text):
    lines = [l for l in text.splitlines() if l.strip() and not l.startswith('#')]
    head = [l.split() for l in lines[:6]]
    assert head[0] == ['witcher-tk-manifest', '1'], 'version line'
    assert [h[0] for h in head[1:]] == ['name', 'base', 'stock', 'image', 'gzip'], 'header order'
    m = {'name': head[1][1], 'base': int(head[2][1], 16)}
    for key, row in zip(('stock', 'image', 'gzip'), head[3:]):
        m[key] = (int(row[1]), row[2])
    m['sites'] = []
    for line in lines[6:]:
        f = line.split()
        assert f[0] == 'site', line[:40]
        va, length, name, orig = int(f[1], 16), int(f[2]), f[3], f[4]
        parts = []
        for p in f[5:]:
            ref = re.fullmatch(r'@0x([0-9a-f]{8}):([0-9]+)', p)
            parts.append(('stock', int(ref[1], 16), int(ref[2])) if ref else ('bytes', bytes.fromhex(p)))
        m['sites'].append((va, length, name, orig, parts))
    return m


def apply_manifest(m, stock):
    out = bytearray(stock)
    for va, length, name, orig, parts in m['sites']:
        off = va - m['base']
        if sha(stock[off:off + length]) != orig:
            raise ValueError(f'{name}: original bytes differ')
        new = b''.join(p[1] if p[0] == 'bytes' else stock[p[1] - m['base']:p[1] - m['base'] + p[2]] for p in parts)
        if len(new) != length:
            raise ValueError(f'{name}: replacement length')
        out[off:off + length] = new
    return bytes(out)


def vendor_runs(manifests, stock):
    """Literal replacement windows (16 bytes, at least 8 distinct values) that
    occur anywhere in the stock image: copies of vendor bytes that should
    have been stock references. Returns (manifest, site) pairs."""
    windows = {}
    for name, m in manifests:
        for va, length, site, orig, parts in m['sites']:
            for part in parts:
                if part[0] != 'bytes':
                    continue
                b = part[1]
                for i in range(len(b) - 15):
                    w = b[i:i + 16]
                    if len(set(w)) >= 8:
                        windows.setdefault(w, (name, site))
    found = set()
    for i in range(len(stock) - 15):
        hit = windows.get(stock[i:i + 16])
        if hit:
            found.add(hit)
    return sorted(found)


def stock_gzip(prg):
    data = Path(prg).read_bytes()
    kernel, ubi, tk = struct.unpack_from('>III', data, 0x24)
    start = 0x54 + kernel + ubi
    return data[start:start + tk]


def run(tool, args, data=None):
    done = subprocess.run([tool, *args], input=data, capture_output=True)
    if done.returncode != 0:
        sys.exit(f'{tool} {" ".join(args)}: exit {done.returncode}: {done.stderr.decode(errors="replace").strip()}')
    return done.stdout


def main():
    tool = os.environ.get('TK_PATCH')
    prg = os.environ.get('WITCHER_STOCK_PRG')
    if tool:
        for name, data in cases():
            want = python_gzip(data)
            got = run(tool, ['gzip'], data)
            check(f'gzip parity: {name}', got == want,
                  f'{len(got)} vs {len(want)} bytes, first difference at '
                  f'{next((i for i, (a, b) in enumerate(zip(got, want)) if a != b), min(len(got), len(want)))}')
            check(f'gunzip: {name}', run(tool, ['gunzip'], want) == data)
    if not prg:
        if os.environ.get('WITCHER_REQUIRE_STOCK') == '1':
            check('stock image present (WITCHER_STOCK_PRG)', False)
        else:
            print('skip stock checks: WITCHER_STOCK_PRG is not set')
    else:
        packed = stock_gzip(prg)
        check('stock tk gzip is the pinned 03_tk.gzip', sha(packed) == STOCK_GZIP_SHA)
        stock = zlib.decompressobj(31).decompress(packed)
        check('stock tk image is the pinned one', sha(stock) == STOCK_SHA)
        if tool:
            check('gunzip: stock 03_tk.gzip (GNU gzip -9)', sha(run(tool, ['gunzip'], packed)) == STOCK_SHA)
        carried = [(path.name, parse_manifest(path.read_text())) for path in sorted(MANIFESTS.glob('*.manifest'))]
        runs = vendor_runs(carried, stock)
        check('no manifest carries a run of vendor bytes (16 bytes, 8 distinct values)', not runs, runs)
        for path in sorted(MANIFESTS.glob('*.manifest')):
            m = parse_manifest(path.read_text())
            image = apply_manifest(m, stock)
            check(f'{path.name}: Python applies it to the pinned image', sha(image) == m['image'][1])
            packed_image = python_gzip(image)
            check(f'{path.name}: zlib level 9 gives the pinned gzip',
                  (len(packed_image), sha(packed_image)) == m['gzip'])
            check(f'{path.name}: pins the bench images', (m['image'][1], m['gzip'][1]) == BENCH.get(m['name']),
                  'add its Python-built tk.bin and tk.gz hashes to BENCH')
            if tool:
                with tempfile.TemporaryDirectory() as tmp:
                    out = Path(tmp) / 'image'  # build -o wants a new directory, like tkpatch.py
                    run(tool, ['build', prg, str(path), '-o', str(out)])
                    built = (out / 'tk.gz').read_bytes()
                    check(f'{path.name}: tk-patch build writes the bench tk.bin',
                          sha((out / 'tk.bin').read_bytes()) == m['image'][1])
                check(f'{path.name}: tk-patch build writes the bench gzip byte for byte', built == packed_image)
    print('\nRESULT:', 'ALL PASS' if not failures else f'{len(failures)} FAILURES')
    sys.exit(1 if failures else 0)


if __name__ == '__main__':
    main()
