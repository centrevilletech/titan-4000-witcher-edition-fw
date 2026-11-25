#!/usr/bin/env python3
"""Run the boot-time tk loader hook against recording stubs.

No root and no device. Stubs stand in for ubiattach, ubidetach, mount and
umount: a mount table is a file, a UBI volume is a directory that a mount copies
in and a read-write unmount copies back, and a bind mount is a symlink. This
proves the hook's decisions, its order and what it leaves behind, not the
vendor kernel's mount or UBI behaviour.

Set TK_SHELL (default `sh`) to run the hook under another POSIX shell. A
BusyBox shell that prefers its own applets bypasses the stubs.

The default image (v1.0.17) runs twice: `DefaultImage` against a stand-in
keeper that answers as each test says, and `RealDefaultImage` against the
real keeper (`TITAN_PD_KEEPER`) building from stand-in NAND banks made from
the stock .prg (`WITCHER_STOCK_PRG`; skipped without it unless
`WITCHER_REQUIRE_STOCK=1`).
"""
import gzip
import hashlib
import importlib.util
import json
import os
import re
import shlex
import shutil
import struct
import subprocess
import tempfile
import time
import unittest
import zlib
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
HOOK = REPO / 'overlay/etc/init.d/witcher-tk-stage'
SHELL = shlex.split(os.environ.get('TK_SHELL', 'sh'))


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), REPO / 'scripts' / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MOUNT = r'''#!/usr/bin/env python3
import os, shutil, sys
R = os.environ['TK_ROOT']; M = R + '/proc/mounts'
fail = os.environ.get('TK_FAIL', '').split(',')
args = sys.argv[1:]
open(R + '/actions', 'a').write('mount ' + ' '.join(args) + '\n')
rows = [l.split() for l in open(M).read().splitlines() if l.strip()]
def save():
    open(M, 'w').write(''.join(' '.join(r) + '\n' for r in rows))
def empty(d):
    for name in os.listdir(d):
        p = os.path.join(d, name)
        shutil.rmtree(p) if os.path.isdir(p) and not os.path.islink(p) else os.remove(p)
if args[:2] == ['-o', 'remount,rw']:
    if 'remount' in fail: sys.exit(1)
    for r in rows:
        if r[1] == args[2]: r[3] = 'rw'
    save(); sys.exit(0)
if args[0] == '--bind':
    if 'bind' in fail: sys.exit(1)
    src, dst = args[1], args[2]
    dev = next((r[0] for r in rows if r[1] == src), 'rootfs')
    os.rename(dst, dst + '.under'); os.symlink(src, dst)
    rows.append([dev, dst, 'bind', 'rw']); save(); sys.exit(0)
assert args[0] == '-t' and args[2] == '-o', args
kind, opts, dev, target = args[1], args[3], args[4], args[5]
if kind == 'ubifs':
    if 'mount' in fail or not os.path.isdir(R + '/sys/class/ubi/ubi1'): sys.exit(1)
    empty(target); shutil.copytree(R + '/flash/data', target, dirs_exist_ok=True, symlinks=True)
    rows.append([dev, target, 'ubifs', 'ro' if 'ro' in opts.split(',') else 'rw'])
elif kind == 'tmpfs':
    if 'tmpfs' in fail: sys.exit(1)
    empty(target); rows.append([dev, target, 'tmpfs', 'rw'])
else:
    sys.exit(1)
save()
'''

UMOUNT = r'''#!/usr/bin/env python3
import os, shutil, sys
R = os.environ['TK_ROOT']; M = R + '/proc/mounts'
fail = os.environ.get('TK_FAIL', '').split(',')
args = [a for a in sys.argv[1:] if a != '-l']
open(R + '/actions', 'a').write('umount ' + ' '.join(sys.argv[1:]) + '\n')
target = args[0]
rows = [l.split() for l in open(M).read().splitlines() if l.strip()]
hits = [r for r in rows if r[1] == target]
if not hits or 'umount:' + os.path.basename(target) in fail: sys.exit(1)
row = hits[-1]
def empty(d):
    for name in os.listdir(d):
        p = os.path.join(d, name)
        shutil.rmtree(p) if os.path.isdir(p) and not os.path.islink(p) else os.remove(p)
if row[2] == 'ubifs':
    if row[3] == 'rw':
        shutil.rmtree(R + '/flash/data'); shutil.copytree(target, R + '/flash/data', symlinks=True)
    empty(target)
elif row[2] == 'bind':
    os.remove(target); os.rename(target + '.under', target)
elif row[2] == 'tmpfs':
    empty(target)
rows.remove(row)
open(M, 'w').write(''.join(' '.join(r) + '\n' for r in rows))
'''

ATTACH = r'''#!/usr/bin/env python3
import os, sys
R = os.environ['TK_ROOT']
fail = os.environ.get('TK_FAIL', '').split(',')
open(R + '/actions', 'a').write('ubiattach ' + ' '.join(sys.argv[1:]) + '\n')
if 'attach' in fail: sys.exit(1)
d = R + '/sys/class/ubi/ubi1'
os.makedirs(d); open(d + '/mtd_num', 'w').write('20\n')
for i, name in enumerate(open(R + '/flash/volumes').read().split()):
    os.makedirs(f'{d}_{i}'); open(f'{d}_{i}/name', 'w').write(name + '\n')
'''

DETACH = r'''#!/usr/bin/env python3
import glob, os, shutil, sys
R = os.environ['TK_ROOT']
fail = os.environ.get('TK_FAIL', '').split(',')
open(R + '/actions', 'a').write('ubidetach ' + ' '.join(sys.argv[1:]) + '\n')
busy = any(l.startswith('ubi1:') for l in open(R + '/proc/mounts'))
if 'detach' in fail or busy: sys.exit(1)
for d in glob.glob(R + '/sys/class/ubi/ubi1*'): shutil.rmtree(d)
'''

# A stand-in for `titan-pd-keeper tk-build boot [--write]`. It records each
# call and answers from keeper-plan.json: {"read": step, "write": step}, where
# a step is {"out": line, "rc": code, "files": {name: text or null}, "sleep": s}.
# "files" writes (or with null removes) files in the tk directory it was given.
KEEPER = r'''#!/usr/bin/env python3
import json, os, sys, time
R = os.environ['TK_ROOT']; tk = os.environ.get('TITAN_TK_DIR', '')
write = sys.argv[1:] == ['tk-build', 'boot', '--write']
assert sys.argv[1:] in (['tk-build', 'boot'], ['tk-build', 'boot', '--write']), sys.argv
rows = [l.split() for l in open(R + '/proc/mounts').read().splitlines() if l.strip()]
mode = next((r[3] for r in rows if tk.startswith(r[1] + '/')), 'unmounted')
open(R + '/keeper-calls', 'a').write(('write' if write else 'read') + ' ' + mode + '\n')
step = json.load(open(R + '/keeper-plan.json'))['write' if write else 'read']
time.sleep(step.get('sleep', 0))
for name, text in step.get('files', {}).items():
    os.makedirs(tk, exist_ok=True)
    path = os.path.join(tk, name)
    if text is None:
        os.remove(path)
    else:
        open(path, 'wb').write(bytes.fromhex(text[4:]) if text.startswith('hex:') else text.encode())
print(step['out'])
sys.exit(step['rc'])
'''

HEXDUMP = r'''#!/usr/bin/env python3
import sys
n = int(sys.argv[sys.argv.index('-n') + 1])
sys.stdout.write(open(sys.argv[-1], 'rb').read(n).hex())
'''


class Unit:
    """A fake Titan root at boot: the user partition, the Witcher volume and the rootfs paths."""

    def __init__(self, base: Path, keeper=None, build_limit=120, env=None):
        self.root = base
        for d in ('bin', 'proc', 'sys/class/ubi', 'flash/data', 'lib/firmware/mrvl', 'mnt',
                  'lib/modules/3.10.0-uc0/extra', 'usr/lib/titan-api/tk', 'var/run'):
            (base / d).mkdir(parents=True, exist_ok=True)
        (base / 'proc/mtd').write_text('dev:    size   erasesize  name\nmtd19: 01000000 00020000 "misc"\n'
                                       'mtd20: 04000000 00020000 "user"\n')
        (base / 'proc/mounts').write_text('ubi0:rootfs / ubifs rw\n')
        (base / 'proc/meminfo').write_text('MemTotal: 196000 kB\nMemFree: 120000 kB\n')
        (base / 'proc/uptime').write_text('17.42 12.00\n')
        (base / 'flash/volumes').write_text('cbrs data\n')
        (base / 'lib/firmware/.keep').write_text('')
        self.stock_module = b'stock modem module\n'
        self.module.write_bytes(self.stock_module)
        self.gated.write_bytes(b'gated modem module\n')
        (base / 'dmesg').write_text('[    9.1] read from fs\n')
        for name, body in (('mount', MOUNT), ('umount', UMOUNT), ('ubiattach', ATTACH),
                           ('ubidetach', DETACH), ('hexdump', HEXDUMP), ('titan-pd-keeper', KEEPER),
                           ('timeout', '#!/bin/sh\n[ "$1" = -t ] && shift 2\nexec "$@"\n'),
                           ('dmesg', '#!/bin/sh\ncat "$TK_ROOT/dmesg"\n'),
                           ('sync', '#!/bin/sh\nexit 0\n')):
            path = base / 'bin' / name
            path.write_text(body)
            path.chmod(0o755)
        text = HOOK.read_text()
        values = {
            'export PATH': f'{base}/bin:$PATH',
            'procmtd': f'{base}/proc/mtd', 'mounts': f'{base}/proc/mounts',
            'meminfo': f'{base}/proc/meminfo', 'uptime': f'{base}/proc/uptime',
            'ubi': f'{base}/sys/class/ubi', 'vendor': f'{base}/mnt', 'work': f'{base}/var/witcher-tk',
            'status': f'{base}/var/run/witcher-tk.status', 'firmware': f'{base}/lib/firmware',
            'module': str(self.module), 'gated': str(self.gated),
            'gated_sha': hashlib.sha256(self.gated.read_bytes()).hexdigest(),
            'keeper': str(keeper or base / 'bin/titan-pd-keeper'),
            'witcher_release': f'{base}/etc/witcher-release',
            'build_log': f'{base}/var/run/witcher-tk.build',
            'build_limit': str(build_limit),
        }
        for key, value in values.items():
            text, count = re.subn(rf'^{re.escape(key)}=.*$', f'{key}={value}', text, flags=re.M)
            assert count == 1, key
        self.hook = base / 'hook'
        self.hook.write_text(text)
        self.env = dict(os.environ, TK_ROOT=str(base), **(env or {}))
        # Asked about an empty tk/, the stand-in keeper hands it to the
        # hook's usual checks unless a test says otherwise.
        self.plan({'out': 'operator', 'rc': 0})

    @property
    def module(self):
        return self.root / 'lib/modules/3.10.0-uc0/extra/modem.ko'

    @property
    def gated(self):
        return self.root / 'usr/lib/titan-api/tk/modem-tkfs.ko'

    @property
    def tk(self):
        return self.root / 'flash/data/tk'

    def plan(self, read, write=None):
        (self.root / 'keeper-plan.json').write_text(json.dumps({'read': read, 'write': write or {'out': '', 'rc': 9}}))

    def keeper_calls(self):
        path = self.root / 'keeper-calls'
        return path.read_text().splitlines() if path.exists() else []

    def opt_in(self, image: bytes, allow=True, extra=''):
        self.tk.mkdir(exist_ok=True)
        (self.tk / 'active.gz').write_bytes(image)
        digest = hashlib.sha256(image).hexdigest()
        lines = ['enabled=1  # bench only'] + ([f'sha256={digest.upper()}'] if allow else [])
        (self.tk / 'config').write_text('\n'.join(lines) + '\n' + extra)
        return digest

    def run(self, phase, fail=''):
        env = dict(self.env, TK_FAIL=fail)
        return subprocess.run([*SHELL, str(self.hook), phase], env=env, timeout=60,
                              capture_output=True, text=True)

    def status(self):
        path = self.root / 'var/run/witcher-tk.status'
        rows = path.read_text().splitlines() if path.exists() else []
        return dict(row.split('=', 1) for row in rows)

    def actions(self):
        path = self.root / 'actions'
        return path.read_text().splitlines() if path.exists() else []

    def mounts(self):
        return (self.root / 'proc/mounts').read_text().splitlines()

    def strikes(self):
        path = self.tk / 'strikes'
        return path.read_text() if path.exists() else None

    def boot(self, fail=''):
        """pre, the modem module load, post, then the vendor's own attach."""
        (self.root / 'actions').unlink(missing_ok=True)
        pre = self.run('pre', fail)
        assert pre.returncode == 0, pre.stderr
        firmware = self.root / 'lib/firmware/tk.gz'
        loaded = {
            'module': self.module.read_bytes(),
            'firmware': hashlib.sha256(firmware.read_bytes()).hexdigest() if firmware.exists() else 'nand',
            'pre_mounts': self.mounts(),
        }
        post = self.run('post', fail)
        assert post.returncode == 0, post.stderr
        return loaded

    def assert_stock_after(self, test):
        """What rcinit and a later modem crash see once post has run."""
        test.assertEqual(self.mounts(), ['ubi0:rootfs / ubifs rw'])
        test.assertFalse((self.root / 'sys/class/ubi/ubi1').exists(), 'the partition was left attached')
        test.assertEqual(sorted(p.name for p in (self.root / 'lib/firmware').iterdir()), ['.keep', 'mrvl'])
        test.assertEqual(self.module.read_bytes(), self.stock_module)
        test.assertFalse((self.root / 'var/witcher-tk/fw').exists())


def good_image():
    return gzip.compress(os.urandom(8192), mtime=0)


class Hook(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.unit = Unit(Path(self.tmp.name))

    def tearDown(self):
        self.tmp.cleanup()

    def test_no_config_is_stock_and_never_writes(self):
        unit = self.unit
        loaded = unit.boot()
        self.assertEqual(loaded['firmware'], 'nand')
        self.assertEqual(loaded['module'], unit.stock_module)
        self.assertEqual(unit.status()['state'], 'stock')
        self.assertEqual(unit.status()['reason'], 'off')
        self.assertEqual(unit.status()['firmware'], 'clean')
        # The keeper was asked about the default image on the read-only mount.
        self.assertEqual(unit.keeper_calls(), ['read ro'])
        actions = unit.actions()
        self.assertIn(f'mount -t ubifs -o ro ubi1:data {unit.root}/var/witcher-tk/state', actions)
        self.assertFalse(any('remount' in a or '--bind' in a or 'tmpfs' in a for a in actions), actions)
        self.assertEqual(list((unit.root / 'flash/data').iterdir()), [])
        unit.assert_stock_after(self)

    def test_disabled_config_is_stock(self):
        unit = self.unit
        unit.opt_in(good_image())
        (unit.tk / 'config').write_text((unit.tk / 'config').read_text().replace('enabled=1', 'enabled=0'))
        self.assertEqual(unit.boot()['firmware'], 'nand')
        self.assertEqual(unit.status()['reason'], 'off')
        self.assertIsNone(unit.strikes())
        unit.assert_stock_after(self)

    def test_first_boot_without_the_witcher_volume_is_stock(self):
        unit = self.unit
        (unit.root / 'flash/volumes').write_text('cbrs\n')
        self.assertEqual(unit.boot()['firmware'], 'nand')
        self.assertEqual(unit.status()['reason'], 'no-volume')
        unit.assert_stock_after(self)

    def test_verified_image_loads_once_then_leaves_stock_behind(self):
        unit = self.unit
        image = good_image()
        digest = unit.opt_in(image)
        loaded = unit.boot()
        self.assertEqual(loaded['firmware'], digest)
        self.assertEqual(loaded['module'], unit.gated.read_bytes())
        status = unit.status()
        self.assertEqual((status['state'], status['sha256'], status['strikes']), ('staged', digest, '1'))
        self.assertEqual((status['loaded_at'], status['source'], status['firmware']), ('17', 'fs', 'clean'))
        self.assertEqual(unit.strikes(), 'strikes=1\nfirmware=unknown\n')
        # The partition was released before the modem loaded.
        self.assertFalse(any(row.startswith('ubi1:') for row in loaded['pre_mounts']), loaded['pre_mounts'])
        self.assertIn(f'witcher-tk {unit.root}/lib/firmware bind rw', loaded['pre_mounts'])
        self.assertEqual(unit.keeper_calls(), [], 'an operator config never reaches the keeper')
        actions = unit.actions()
        strike = actions.index(f'mount -o remount,rw {unit.root}/var/witcher-tk/state')
        bind = next(i for i, a in enumerate(actions) if a.startswith('mount --bind') and 'lib/firmware' in a)
        detach = actions.index('ubidetach /dev/ubi_ctrl -m 20')
        self.assertLess(strike, detach)
        self.assertLess(detach, bind)
        unit.assert_stock_after(self)

    def test_strike_limit_stops_a_failing_image_without_the_keeper(self):
        unit = self.unit
        digest = unit.opt_in(good_image())
        self.assertEqual(unit.boot()['firmware'], digest)
        self.assertEqual(unit.boot()['firmware'], digest)
        self.assertEqual(unit.strikes(), 'strikes=2\nfirmware=unknown\n')
        for _ in range(3):
            self.assertEqual(unit.boot()['firmware'], 'nand')
            self.assertEqual(unit.status()['reason'], 'strikes')
            self.assertEqual(unit.strikes(), 'strikes=2\nfirmware=unknown\n')
            unit.assert_stock_after(self)

    def test_keeper_confirm_resets_the_count(self):
        unit = self.unit
        digest = unit.opt_in(good_image())
        for _ in range(4):
            self.assertEqual(unit.boot()['firmware'], digest)
            (unit.tk / 'strikes').write_text('strikes=0\n')  # the keeper's boot confirm

    def test_quarantined_hash_is_stock(self):
        unit = self.unit
        digest = unit.opt_in(good_image())
        (unit.tk / 'quarantine').write_text('# keeper\n' + digest + '\n')
        self.assertEqual(unit.boot()['firmware'], 'nand')
        self.assertEqual(unit.status()['reason'], 'quarantined')
        self.assertIsNone(unit.strikes())
        unit.assert_stock_after(self)

    def test_image_outside_the_allow_list_is_stock(self):
        unit = self.unit
        image = bytearray(good_image())
        unit.opt_in(bytes(image))
        image[100] ^= 1
        (unit.tk / 'active.gz').write_bytes(bytes(image))
        self.assertEqual(unit.boot()['firmware'], 'nand')
        self.assertEqual(unit.status()['reason'], 'not-allowed')
        self.assertIsNone(unit.strikes())
        unit.assert_stock_after(self)

    def test_allowed_image_the_modem_cannot_read_is_stock(self):
        unit = self.unit
        unit.opt_in(b'\x1f\x8b\x08\x20' + os.urandom(4096))  # encrypted flag
        self.assertEqual(unit.boot()['firmware'], 'nand')
        self.assertEqual(unit.status()['reason'], 'header')
        unit.opt_in(os.urandom(4096))
        self.assertEqual(unit.boot()['firmware'], 'nand')
        self.assertEqual(unit.status()['reason'], 'header')
        self.assertIsNone(unit.strikes())
        unit.assert_stock_after(self)

    def test_small_image_and_low_memory_are_stock(self):
        unit = self.unit
        unit.opt_in(gzip.compress(b'x', mtime=0))
        unit.boot()
        self.assertEqual(unit.status()['reason'], 'size')
        unit.opt_in(good_image())
        (unit.root / 'proc/meminfo').write_text('MemFree: 2000 kB\n')
        unit.boot()
        self.assertEqual(unit.status()['reason'], 'memory')
        self.assertIsNone(unit.strikes())
        unit.assert_stock_after(self)

    def test_damaged_gated_module_is_stock(self):
        unit = self.unit
        unit.opt_in(good_image())
        unit.gated.write_bytes(b'flipped bit\n')
        self.assertEqual(unit.boot()['firmware'], 'nand')
        self.assertEqual(unit.status()['reason'], 'module')
        self.assertIsNone(unit.strikes())
        unit.assert_stock_after(self)

    def test_unreadable_strike_count_is_stock(self):
        unit = self.unit
        unit.opt_in(good_image())
        (unit.tk / 'strikes').write_text('strikes=lots\n')
        unit.boot()
        self.assertEqual(unit.status()['reason'], 'strikes-unreadable')
        unit.assert_stock_after(self)

    def test_no_load_without_a_recorded_strike(self):
        unit = self.unit
        unit.opt_in(good_image())
        self.assertEqual(unit.boot(fail='remount')['firmware'], 'nand')
        self.assertEqual(unit.status()['reason'], 'strike-write')
        self.assertIsNone(unit.strikes())
        unit.assert_stock_after(self)

    def test_failed_bind_is_stock(self):
        unit = self.unit
        unit.opt_in(good_image())
        self.assertEqual(unit.boot(fail='bind')['firmware'], 'nand')
        self.assertEqual(unit.status()['reason'], 'bind')
        unit.assert_stock_after(self)

    def test_failed_attach_is_stock(self):
        unit = self.unit
        unit.opt_in(good_image())
        self.assertEqual(unit.boot(fail='attach')['firmware'], 'nand')
        self.assertEqual(unit.status()['reason'], 'attach')
        unit.assert_stock_after(self)

    def test_newer_busybox_timeout_syntax_still_works(self):
        unit = self.unit
        digest = unit.opt_in(good_image())
        (unit.root / 'bin/timeout').write_text('#!/bin/sh\n[ "$1" = -t ] && exit 1\nshift\nexec "$@"\n')
        self.assertEqual(unit.boot()['firmware'], digest)
        unit.assert_stock_after(self)

    def test_no_working_timeout_is_stock(self):
        unit = self.unit
        unit.opt_in(good_image())
        (unit.root / 'bin/timeout').write_text('#!/bin/sh\nexit 1\n')
        self.assertEqual(unit.boot()['firmware'], 'nand')
        self.assertEqual(unit.status()['reason'], 'attach')
        self.assertFalse(any(a.startswith('ubiattach') for a in unit.actions()))
        unit.assert_stock_after(self)

    def test_a_partition_someone_else_attached_is_left_alone(self):
        unit = self.unit
        unit.opt_in(good_image())
        (unit.root / 'sys/class/ubi/ubi1').mkdir()
        (unit.root / 'sys/class/ubi/ubi1/mtd_num').write_text('19\n')
        self.assertEqual(unit.boot()['firmware'], 'nand')
        self.assertEqual(unit.status()['reason'], 'ubi-busy')
        self.assertTrue((unit.root / 'sys/class/ubi/ubi1').exists())
        self.assertFalse(any(a.startswith(('ubiattach', 'ubidetach')) for a in unit.actions()))

    def test_a_run_on_a_live_unit_changes_nothing(self):
        unit = self.unit
        (unit.root / 'proc/mounts').write_text(f'ubi0:rootfs / ubifs rw\nubi1:cbrs {unit.root}/mnt ubifs rw\n')
        (unit.root / 'var/run/witcher-tk.status').write_text('state=staged\n')
        for phase in ('pre', 'post'):
            self.assertEqual(unit.run(phase).returncode, 64)
        self.assertEqual(unit.status(), {'state': 'staged'})
        self.assertEqual(unit.actions(), [])

    def test_post_cleans_up_after_a_killed_pre(self):
        unit = self.unit
        env = dict(unit.env, TK_FAIL='')
        root = unit.root
        work = root / 'var/witcher-tk'
        (work / 'fw').mkdir(parents=True)
        (work / 'state').mkdir()
        run = lambda *args: subprocess.run([str(root / 'bin' / args[0]), *args[1:]], env=env, check=True)
        run('ubiattach', '/dev/ubi_ctrl', '-m', '20', '-d', '1')
        run('mount', '-t', 'ubifs', '-o', 'ro', 'ubi1:data', str(work / 'state'))
        run('mount', '-t', 'tmpfs', '-o', 'size=8m', 'witcher-tk', str(work / 'fw'))
        (work / 'fw/tk.gz').write_bytes(good_image())
        run('mount', '--bind', str(work / 'fw'), str(root / 'lib/firmware'))
        run('mount', '--bind', str(unit.gated), str(unit.module))
        self.assertEqual(unit.run('post').returncode, 0)
        self.assertEqual(unit.status()['firmware'], 'clean')
        unit.assert_stock_after(self)

    def test_post_reports_a_firmware_bind_it_could_not_remove(self):
        unit = self.unit
        digest = unit.opt_in(good_image())
        self.assertEqual(unit.run('pre').returncode, 0)
        self.assertEqual(unit.status()['sha256'], digest)
        post = unit.run('post', fail='umount:firmware,umount:fw')
        self.assertEqual(post.returncode, 0)
        # The bind stayed, but the image under it is gone, so a modem crash
        # reload finds no tk.gz and reads NAND.
        self.assertFalse((unit.root / 'lib/firmware/tk.gz').exists())
        self.assertEqual(unit.status()['firmware'], 'dirty')

    def test_detach_failure_still_records_stock(self):
        unit = self.unit
        unit.boot(fail='detach')
        self.assertEqual(unit.status()['reason'], 'off')
        self.assertFalse(any('--bind' in a for a in unit.actions()))

def default_config(image_sha, edit=lambda body: body):
    """A config with the keeper's default marker; `edit` changes its body."""
    body = edit(f'# Built at boot\nenabled=1\nsha256={image_sha}\nwm=0x847ed604:0x15\n')
    return f'# witcher-default n6h-r4-r1 {hashlib.sha256(body.encode()).hexdigest()}\n{body}'


class DefaultImage(unittest.TestCase):
    """The hook's side of the default image, against a stand-in keeper."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.unit = Unit(Path(self.tmp.name))

    def tearDown(self):
        self.tmp.cleanup()

    def built(self, image):
        """The write step of a build that succeeds: the image and its default config."""
        digest = hashlib.sha256(image).hexdigest()
        return {'out': 'built', 'rc': 0,
                'files': {'active.gz': 'hex:' + image.hex(), 'config': default_config(digest)}}, digest

    def test_first_boot_builds_then_loads_the_image_for_the_same_modprobe(self):
        unit = self.unit
        write, digest = self.built(good_image())
        unit.plan({'out': 'build', 'rc': 2}, write)
        loaded = unit.boot()
        self.assertEqual(loaded['firmware'], digest)
        self.assertEqual(loaded['module'], unit.gated.read_bytes())
        status = unit.status()
        self.assertEqual((status['state'], status['sha256'], status['strikes']), ('staged', digest, '1'))
        self.assertEqual(status['build'], 'built')
        self.assertTrue(status['build_secs'].isdigit())
        # Asked read-only first; only the build ran on a read-write mount.
        self.assertEqual(unit.keeper_calls(), ['read ro', 'write rw'])
        self.assertEqual(unit.strikes(), 'strikes=1\nfirmware=unknown\n')
        self.assertTrue((unit.tk / 'config').read_text().startswith('# witcher-default '))
        unit.assert_stock_after(self)

    def test_a_later_boot_reuses_the_image_without_building(self):
        unit = self.unit
        image = good_image()
        digest = hashlib.sha256(image).hexdigest()
        unit.tk.mkdir()
        (unit.tk / 'active.gz').write_bytes(image)
        (unit.tk / 'config').write_text(default_config(digest))
        unit.plan({'out': 'cached', 'rc': 0})
        self.assertEqual(unit.boot()['firmware'], digest)
        self.assertEqual(unit.status()['build'], 'cached')
        self.assertEqual(unit.keeper_calls(), ['read ro'])
        unit.assert_stock_after(self)

    def test_an_updated_default_config_loads_without_a_build(self):
        unit = self.unit
        image = good_image()
        digest = hashlib.sha256(image).hexdigest()
        unit.tk.mkdir()
        (unit.tk / 'active.gz').write_bytes(image)
        (unit.tk / 'config').write_text(default_config(digest, lambda body: body.replace('0x15', '0x5')))
        unit.plan({'out': 'build', 'rc': 2}, {'out': 'updated', 'rc': 0, 'files': {'config': default_config(digest)}})
        self.assertEqual(unit.boot()['firmware'], digest)
        self.assertEqual(unit.status()['build'], 'updated')
        self.assertEqual(unit.keeper_calls(), ['read ro', 'write rw'])
        self.assertEqual((unit.tk / 'config').read_text(), default_config(digest))
        unit.assert_stock_after(self)

    def test_an_operator_config_never_reaches_the_keeper(self):
        unit = self.unit
        digest = unit.opt_in(good_image())
        unit.plan({'out': 'reason=build', 'rc': 1})
        self.assertEqual(unit.boot()['firmware'], digest)
        self.assertNotIn('build', unit.status())
        (unit.tk / 'config').write_text('enabled=0\n')
        self.assertEqual(unit.boot()['firmware'], 'nand')
        self.assertEqual(unit.status()['reason'], 'off')
        # An edited default config is the operator's too: its marker line is
        # only checked in full by the keeper, but a first line without it is not.
        (unit.tk / 'config').write_text('# bench\n' + default_config(digest))
        self.assertEqual(unit.boot()['firmware'], digest)
        self.assertEqual(unit.keeper_calls(), [])
        unit.assert_stock_after(self)

    def test_a_keeper_reason_keeps_stock_and_writes_nothing(self):
        unit = self.unit
        for reason in ('stock-mismatch', 'quarantined', 'build-limit', 'bank-unknown'):
            unit.plan({'out': 'reason=' + reason, 'rc': 1})
            self.assertEqual(unit.boot()['firmware'], 'nand')
            status = unit.status()
            self.assertEqual((status['state'], status['reason'], status['build']), ('stock', reason, reason))
            self.assertFalse(any('remount' in a for a in unit.actions()), unit.actions())
        self.assertEqual(list((unit.root / 'flash/data').iterdir()), [])
        unit.assert_stock_after(self)

    def test_a_failed_or_strange_build_keeps_stock_with_the_reason_build(self):
        unit = self.unit
        cases = (
            ({'out': 'build', 'rc': 2}, {'out': 'reason=build', 'rc': 1}),  # the keeper's own failure
            ({'out': 'build', 'rc': 2}, {'out': '', 'rc': 101}),  # a crash
            ({'out': 'reason=Not A Word!', 'rc': 1}, None),
            ({'out': 'reason=' + 'x' * 25, 'rc': 1}, None),
            ({'out': 'cached\nbuilt', 'rc': 0}, None),
            ({'out': 'operator', 'rc': 1}, None),
            ({'out': 'build', 'rc': 0}, None),
        )
        for read, write in cases:
            unit.plan(read, write)
            self.assertEqual(unit.boot()['firmware'], 'nand', read)
            self.assertEqual((unit.status()['reason'], unit.status()['build']), ('build', 'build'), read)
            self.assertIsNone(unit.strikes())
            unit.assert_stock_after(self)

    def test_the_build_needs_memory_and_a_writable_volume(self):
        unit = self.unit
        write, _ = self.built(good_image())
        unit.plan({'out': 'build', 'rc': 2}, write)
        (unit.root / 'proc/meminfo').write_text('MemFree: 2000 kB\n')
        self.assertEqual(unit.boot()['firmware'], 'nand')
        self.assertEqual(unit.status()['reason'], 'memory')
        self.assertEqual(unit.keeper_calls(), ['read ro'])
        (unit.root / 'proc/meminfo').write_text('MemFree: 120000 kB\n')
        self.assertEqual(unit.boot(fail='remount')['firmware'], 'nand')
        self.assertEqual(unit.status()['reason'], 'build')
        self.assertEqual(unit.keeper_calls(), ['read ro', 'read ro'])
        unit.assert_stock_after(self)

    def test_the_time_limit_stops_a_build_and_keeps_stock(self):
        unit = self.unit
        real = shutil.which('timeout')
        if real is None:
            self.skipTest('no timeout program')
        # A real time limit, called the way newer BusyBox takes it.
        (unit.root / 'bin/timeout').write_text(f'#!/bin/sh\n[ "$1" = -t ] && exit 1\nexec {real} "$@"\n')
        unit.hook.write_text(re.sub(r'^build_limit=.*$', 'build_limit=1', unit.hook.read_text(), flags=re.M))
        write, _ = self.built(good_image())
        unit.plan({'out': 'build', 'rc': 2}, dict(write, sleep=5))
        began = time.monotonic()
        self.assertEqual(unit.boot()['firmware'], 'nand')
        self.assertLess(time.monotonic() - began, 4.5)
        self.assertEqual((unit.status()['reason'], unit.status()['build']), ('build', 'build'))
        self.assertIsNone(unit.strikes())
        unit.assert_stock_after(self)

    def test_a_symlinked_tk_directory_is_never_built_into(self):
        unit = self.unit
        (unit.root / 'flash/data/elsewhere').mkdir()
        unit.tk.symlink_to('elsewhere')
        self.assertEqual(unit.boot()['firmware'], 'nand')
        self.assertEqual(unit.status()['reason'], 'off')
        self.assertEqual(unit.keeper_calls(), [])


STOCK_PRG = os.environ.get('WITCHER_STOCK_PRG')
REAL_KEEPER = os.environ.get('TITAN_PD_KEEPER')
if os.environ.get('WITCHER_REQUIRE_STOCK') == '1' and not (STOCK_PRG and REAL_KEEPER):
    raise SystemExit('WITCHER_REQUIRE_STOCK=1 needs WITCHER_STOCK_PRG and TITAN_PD_KEEPER')


@unittest.skipUnless(STOCK_PRG and REAL_KEEPER, 'set WITCHER_STOCK_PRG and TITAN_PD_KEEPER')
class RealDefaultImage(unittest.TestCase):
    """The hook and the real keeper build the default image from stand-in banks.

    The banks are the stock tk stream from the vendor .prg padded with 0xff to
    8 MiB, as dumps of mtd17 and mtd18 show. /proc/cmdline names tk2 active.
    """

    @classmethod
    def setUpClass(cls):
        build = load('test-tk-build')
        cls.release = build.release_gzip_sha()
        data = Path(STOCK_PRG).read_bytes()
        kernel, ubi, size = struct.unpack_from('>III', data, 0x24)
        stock = data[0x54 + kernel + ubi:0x54 + kernel + ubi + size]
        raw = bytearray(zlib.decompressobj(31).decompress(stock))
        raw[0x100] ^= 1  # another firmware's tk: the stock image with one byte changed
        cls.banks = tempfile.TemporaryDirectory()
        pad = lambda gz: gz + b'\xff' * (8 * 1024 * 1024 - len(gz))
        cls.good = Path(cls.banks.name) / 'good.bank'
        cls.good.write_bytes(pad(stock))
        cls.foreign = Path(cls.banks.name) / 'foreign.bank'
        cls.foreign.write_bytes(pad(build.gzip_bytes(bytes(raw))))

    @classmethod
    def tearDownClass(cls):
        cls.banks.cleanup()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.unit = self.make(base)

    def make(self, base, build_limit=600):
        (base / 'dev').mkdir(exist_ok=True)
        unit = Unit(base, keeper=str(Path(REAL_KEEPER).resolve()), build_limit=build_limit, env={
            'TITAN_TK_PROC_MTD': str(base / 'proc/mtd'), 'TITAN_TK_MTD_DIR': str(base / 'dev'),
            'TITAN_TK_PROC_CMDLINE': str(base / 'proc/cmdline'),
            'TITAN_WITCHER_RELEASE': str(base / 'etc/witcher-release'),
            'TITAN_PD_RUNTIME': str(base / 'keeper-run'), 'TITAN_PD_STATE': str(base / 'keeper-state')})
        (base / 'proc/mtd').write_text('dev:    size   erasesize  name\nmtd17: 00800000 00020000 "tk"\n'
                                       'mtd18: 00800000 00020000 "tk2"\nmtd19: 01000000 00020000 "misc"\n'
                                       'mtd20: 04000000 00020000 "user"\n')
        (base / 'proc/cmdline').write_text('root=ubi0:rootfs ro rootfstype=ubifs ubi.mtd=16,2048 active=linux2,rootfs2,tk2\n')
        self.bank(base, 'mtd17', self.good)
        self.bank(base, 'mtd18', self.good)
        return unit

    def bank(self, base, name, target):
        path = base / 'dev' / name
        if path.is_symlink() or path.is_file():
            path.unlink()
        elif path.is_dir():
            path.rmdir()
        if target is None:
            path.mkdir()  # reads fail: EISDIR
        else:
            path.symlink_to(target)

    def tearDown(self):
        self.tmp.cleanup()

    def files(self):
        return sorted(p.name for p in self.unit.tk.iterdir()) if self.unit.tk.exists() else []

    def record(self):
        return dict(line.split('=', 1) for line in (self.unit.tk / 'default').read_text().splitlines())

    def test_the_first_boot_builds_and_loads_and_the_next_one_reuses(self):
        unit = self.unit
        loaded = unit.boot()
        self.assertEqual(loaded['firmware'], self.release, unit.status())
        status = unit.status()
        self.assertEqual((status['state'], status['sha256'], status['build']), ('staged', self.release, 'built'))
        self.assertEqual(self.files(), ['active.gz', 'config', 'default', 'strikes'])
        self.assertEqual(hashlib.sha256((unit.tk / 'active.gz').read_bytes()).hexdigest(), self.release)
        config = (unit.tk / 'config').read_text()
        self.assertTrue(config.startswith('# witcher-default n6h-r4-r1 '), config)
        self.assertEqual(self.record(), {'gzip': self.release, 'builds': '1', 'result': 'built'})
        # The words are what stage-latency.sh --profile latency writes for this image.
        staged = subprocess.run(['bash', str(REPO / 'scripts/stage-latency.sh'), '--dry-run', '--no-clamp',
                                 '--profile', 'latency', '192.0.2.1', str(unit.tk / 'active.gz')],
                                capture_output=True, text=True, timeout=120)
        self.assertEqual(staged.returncode, 0, staged.stderr)
        wm = lambda text: [line for line in text.splitlines() if line.startswith('wm=')]
        self.assertEqual(wm(config), wm(staged.stdout))
        self.assertEqual(len(wm(config)), 11)
        unit.assert_stock_after(self)
        # The keeper's boot confirm; the next boot loads the same file.
        (unit.tk / 'strikes').write_text('strikes=0\n')
        before = (unit.tk / 'active.gz').stat().st_mtime_ns
        self.assertEqual(unit.boot()['firmware'], self.release)
        self.assertEqual(unit.status()['build'], 'cached')
        self.assertEqual((unit.tk / 'active.gz').stat().st_mtime_ns, before)
        self.assertEqual(self.record()['builds'], '1')
        unit.assert_stock_after(self)

    def firmware(self, version):
        """Flash firmware `version`: /etc/witcher-release, and its id as the
        hook and the keeper compute it."""
        release = self.unit.root / 'etc/witcher-release'
        release.parent.mkdir(exist_ok=True)
        release.write_text(json.dumps({'name': 'Witcher', 'version': version}) + '\n')
        return hashlib.sha256(release.read_bytes()).hexdigest()[:16]

    def test_a_new_firmware_build_clears_a_quarantine_that_stuck_and_loads_the_image(self):
        unit = self.unit
        old = self.firmware('1.0.17')
        self.assertEqual(unit.boot()['firmware'], self.release)
        self.assertEqual(unit.strikes(), f'strikes=1\nfirmware={old}\n', 'the hook names the build')
        # The keeper quarantined the release image for good under this build
        # (two failures in a row where stock firmware answered). An operator's
        # line for another image stays as it is.
        other = 'ab' * 32
        (unit.tk / 'quarantine').write_text(f'{other}\n{self.release}\n')
        (unit.tk / 'strikes').write_text(f'strikes=2\nfirmware={old}\n')
        verdict = f'gzip={self.release}\nfirmware={old}\ngenuine=2\nnetwork=0\npending=0\noutage=0\n'
        (unit.tk / 'verdict').write_text(verdict)
        self.assertEqual(unit.boot()['firmware'], 'nand')
        self.assertEqual((unit.status()['reason'], unit.status()['build']), ('quarantined', 'quarantined'))
        self.assertEqual((unit.tk / 'verdict').read_text(), verdict, 'the same build keeps it')
        unit.assert_stock_after(self)
        # A firmware update: the image loads again at the first boot.
        new = self.firmware('1.0.18')
        self.assertEqual(unit.boot()['firmware'], self.release)
        status = unit.status()
        self.assertEqual((status['state'], status['build']), ('staged', 'cleared'), status)
        self.assertEqual((unit.tk / 'quarantine').read_text(), f'{other}\n')
        self.assertFalse((unit.tk / 'verdict').exists())
        self.assertEqual(unit.strikes(), f'strikes=1\nfirmware={new}\n')
        self.assertEqual(self.record()['builds'], '1', 'nothing was rebuilt')
        self.assertIn('cleared what another firmware build left', (unit.root / 'var/run/witcher-tk.build').read_text())
        unit.assert_stock_after(self)

    def test_strikes_an_older_firmware_counted_are_cleared_but_this_builds_still_stop_the_image(self):
        unit = self.unit
        build = self.firmware('1.0.17')
        self.assertEqual(unit.boot()['firmware'], self.release)
        # Strikes from before v1.0.17 name no build: a leftover, cleared.
        (unit.tk / 'strikes').write_text('strikes=2\n')
        self.assertEqual(unit.boot()['firmware'], self.release)
        self.assertEqual(unit.status()['build'], 'cleared')
        self.assertEqual(unit.strikes(), f'strikes=1\nfirmware={build}\n')
        # This build's own boots that died before their confirm still stop
        # the image (the keeper's stock boot then judges them).
        self.assertEqual(unit.boot()['firmware'], self.release)
        self.assertEqual(unit.strikes(), f'strikes=2\nfirmware={build}\n')
        self.assertEqual(unit.boot()['firmware'], 'nand')
        self.assertEqual(unit.status()['reason'], 'strikes')
        unit.assert_stock_after(self)

    def test_a_later_firmware_rewrites_an_earlier_default_config_without_a_rebuild(self):
        unit = self.unit
        self.assertEqual(unit.boot()['firmware'], self.release)
        current = (unit.tk / 'config').read_text()
        # What an earlier firmware would have written for the same image:
        # intact (its checksum holds), with other words.
        marker, body = current.split('\n', 1)
        older = body.replace('wm=0x841b5908:0x1\n', '')
        name = marker.split(' ')[2]
        (unit.tk / 'config').write_text(f'# witcher-default {name} {hashlib.sha256(older.encode()).hexdigest()}\n{older}')
        (unit.tk / 'strikes').write_text('strikes=0\n')
        before = (unit.tk / 'active.gz').stat().st_mtime_ns
        self.assertEqual(unit.boot()['firmware'], self.release)
        self.assertEqual(unit.status()['build'], 'updated')
        self.assertEqual((unit.tk / 'config').read_text(), current)
        self.assertEqual((unit.tk / 'active.gz').stat().st_mtime_ns, before)
        self.assertEqual(self.record()['builds'], '1')
        unit.assert_stock_after(self)

    def test_a_stock_mismatch_keeps_stock_and_builds_nothing(self):
        unit = self.unit
        self.bank(unit.root, 'mtd18', self.foreign)
        self.assertEqual(unit.boot()['firmware'], 'nand')
        self.assertEqual((unit.status()['reason'], unit.status()['build']), ('stock-mismatch', 'stock-mismatch'))
        self.assertEqual(self.files(), ['default'])
        self.assertEqual(self.record()['result'], 'stock-mismatch')
        # Later boots decide from the record, on the read-only mount.
        self.assertEqual(unit.boot()['firmware'], 'nand')
        self.assertEqual(unit.status()['reason'], 'stock-mismatch')
        self.assertFalse(any('remount' in a for a in unit.actions()), unit.actions())
        self.assertEqual(self.record()['builds'], '1')
        unit.assert_stock_after(self)

    def test_only_the_active_bank_counts(self):
        unit = self.unit
        # The inactive bank holds the stock image; the active one does not.
        self.bank(unit.root, 'mtd17', self.good)
        self.bank(unit.root, 'mtd18', self.foreign)
        self.assertEqual(unit.boot()['firmware'], 'nand')
        self.assertEqual(unit.status()['reason'], 'stock-mismatch')
        # And with no active= on the command line nothing is built.
        other = Path(self.tmp.name) / 'no-active'
        other.mkdir()
        unit = self.unit = self.make(other)
        (unit.root / 'proc/cmdline').write_text('root=ubi0:rootfs ro\n')
        self.assertEqual(unit.boot()['firmware'], 'nand')
        self.assertEqual(unit.status()['reason'], 'bank-unknown')
        self.assertEqual(self.files(), [])

    def test_an_operator_config_means_no_build(self):
        unit = self.unit
        digest = unit.opt_in(good_image())
        self.assertEqual(unit.boot()['firmware'], digest)
        self.assertNotIn('default', self.files())
        (unit.tk / 'config').write_text('enabled=0\n')
        self.assertEqual(unit.boot()['firmware'], 'nand')
        self.assertEqual(unit.status()['reason'], 'off')
        # An image with no config is an operator's too (or one turned off by
        # deleting the config): nothing is built over it.
        (unit.tk / 'config').unlink()
        self.assertEqual(unit.boot()['firmware'], 'nand')
        self.assertEqual((unit.status()['reason'], unit.status()['build']), ('off', 'operator'))
        self.assertNotIn('default', self.files())
        self.assertEqual(hashlib.sha256((unit.tk / 'active.gz').read_bytes()).hexdigest(), digest)
        unit.assert_stock_after(self)

    def test_a_failed_build_keeps_stock_with_a_reason_and_stops_after_three(self):
        unit = self.unit
        self.bank(unit.root, 'mtd18', None)
        for n in (1, 2, 3):
            self.assertEqual(unit.boot()['firmware'], 'nand')
            self.assertEqual((unit.status()['reason'], unit.status()['build']), ('build', 'build'))
            self.assertEqual(self.record(), {'gzip': self.release, 'builds': str(n), 'result': 'failed'})
            self.assertEqual(self.files(), ['default'])
        self.assertEqual(unit.boot()['firmware'], 'nand')
        self.assertEqual(unit.status()['reason'], 'build-limit')
        self.assertFalse(any('remount' in a for a in unit.actions()), unit.actions())
        log = (unit.root / 'var/run/witcher-tk.build').read_text()
        self.assertIn('reading the bank', log)
        # Deleting the record lets it try again.
        self.bank(unit.root, 'mtd18', self.good)
        (unit.tk / 'default').unlink()
        self.assertEqual(unit.boot()['firmware'], self.release)
        unit.assert_stock_after(self)

    def test_a_build_that_died_is_cleaned_up_and_done_again_next_boot(self):
        # What a build killed by the time limit or a power cut leaves: its
        # record says started, half an image, no config. (A real build here
        # takes about a second, too quick to kill on cue; DefaultImage proves
        # the hook's time limit with a stand-in keeper.)
        unit = self.unit
        unit.tk.mkdir()
        (unit.tk / 'default').write_text(f'gzip={self.release}\nbuilds=1\nresult=started\n')
        (unit.tk / '.active.gz.tk-build').write_bytes(b'\x1f\x8b\x08\x00' + b'half' * 1000)
        (unit.tk / '.default.tk-build').write_text('builds=')
        self.assertEqual(unit.boot()['firmware'], self.release)
        self.assertEqual(unit.status()['build'], 'built')
        self.assertEqual(self.record(), {'gzip': self.release, 'builds': '2', 'result': 'built'})
        self.assertEqual(self.files(), ['active.gz', 'config', 'default', 'strikes'])
        unit.assert_stock_after(self)
        # The same, stopped after the image and before its config: still ours.
        (unit.tk / 'config').unlink()
        (unit.tk / 'default').write_text(f'gzip={self.release}\nbuilds=2\nresult=started\n')
        (unit.tk / 'strikes').write_text('strikes=0\n')
        self.assertEqual(unit.boot()['firmware'], self.release)
        self.assertEqual(self.record(), {'gzip': self.release, 'builds': '3', 'result': 'built'})
        unit.assert_stock_after(self)

class Build(unittest.TestCase):
    def test_hook_and_build_pin_the_same_gated_module(self):
        pinned = re.search(r'^gated_sha=([0-9a-f]{64})$', HOOK.read_text(), re.M).group(1)
        self.assertEqual(pinned, load('patch-modem-ko').GATED_SHA256)

    def test_gate_refuses_any_module_but_the_pinned_stock_one(self):
        gate = load('patch-modem-ko').gate
        for data in (b'', os.urandom(26836), bytes(26836)):
            with self.assertRaises(ValueError):
                gate(data)

    def test_start_lte_hook_wraps_only_the_modprobe(self):
        hook = load('hook-start-lte').hook
        vendor = ('PROBE_MODEM="modprobe modem modem_bootp=\\"x\\""\n\necho "+$PROBE_MODEM"\n'
                  '$PROBE_MODEM\necho "-modprobe modem"\n\ndate 062014002013\n')
        out = hook(vendor)
        self.assertEqual(out.splitlines()[3:6], ['/bin/sh /etc/init.d/witcher-tk-stage pre', '$PROBE_MODEM',
                                                 '/bin/sh /etc/init.d/witcher-tk-stage post'])
        with self.assertRaises(ValueError):
            hook(out)
        with self.assertRaises(ValueError):
            hook(vendor.replace('$PROBE_MODEM\n', 'modprobe modem\n'))


class StageLatencyProfiles(unittest.TestCase):
    """Test scripts/stage-latency.sh --profile latency|stock and overrides with synthetic images."""

    SCRIPT = REPO / 'scripts/stage-latency.sh'
    BASE = 0x84100000

    def make_tk(self, directory: Path, name: str, magics: dict[int, int]) -> Path:
        # Synthetic zero-filled buffer with only our patch magic words placed
        # at their documented virtual addresses (zero vendor bytes).
        size = (0x847ed000 - self.BASE) + 64
        buf = bytearray(size)
        for va, word in magics.items():
            struct.pack_into('<I', buf, va - self.BASE, word)
        path = directory / name
        path.write_bytes(gzip.compress(bytes(buf), mtime=0))
        return path

    def run_dry(self, tk_path: Path, *extra_args: str) -> subprocess.CompletedProcess:
        cmd = ['bash', str(self.SCRIPT), '--dry-run', '--no-clamp', *extra_args, '192.0.2.1', str(tk_path)]
        return subprocess.run(cmd, capture_output=True, text=True, timeout=30)

    def wm_lines(self, stdout: str) -> list[str]:
        return [l for l in stdout.splitlines() if l.startswith('wm=')]

    def test_profile_latency_selects_words_by_image_magic(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            n4 = self.make_tk(d, 'n4.gz', {})
            img4 = self.make_tk(d, 'img4.gz', {0x847ecfe8: 0x494d4734})
            n5 = self.make_tk(d, 'n5.gz', {0x847ecfe8: 0x494d4734, 0x84489a64: 0x4e35464c})
            n6 = self.make_tk(d, 'n6.gz', {
                0x847ecfe8: 0x494d4734,
                0x84489a64: 0x4e35464c,
                0x8418ff00: 0x55324846,
                0x8418ff04: 0x4e360000,
            })
            n6h = self.make_tk(d, 'n6h.gz', {
                0x847ecfe8: 0x494d4734,
                0x84489a64: 0x4e35464c,
                0x8418ff00: 0x55324846,
                0x8418ff04: 0x4e364803,
            })

            r = self.run_dry(n4, '--profile', 'latency')
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn('tk profile:  latency (detected N4)', r.stdout)
            self.assertEqual(self.wm_lines(r.stdout), [
                'wm=0x84f93008:0x140',
                'wm=0x847ed604:0x15',
            ])

            r = self.run_dry(img4, '--profile', 'latency')
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn('tk profile:  latency (detected IMG4)', r.stdout)
            self.assertEqual(self.wm_lines(r.stdout), [
                'wm=0x84f93008:0x140',
                'wm=0x847ed604:0x15',
                'wm=0x847ed548:0x1',
                'wm=0x847ed54c:0x1',
                'wm=0x847ed550:0x1',
                'wm=0x847ecf08:0x1',
            ])

            r = self.run_dry(n5, '--profile', 'latency')
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn('tk profile:  latency (detected N5)', r.stdout)
            self.assertEqual(self.wm_lines(r.stdout), [
                'wm=0x84f93008:0x140',
                'wm=0x847ed604:0x15',
                'wm=0x847ed548:0x1',
                'wm=0x847ed54c:0x1',
                'wm=0x847ed550:0x1',
                'wm=0x847ecf08:0x1',
                'wm=0x84489a84:0x2000',
                'wm=0x84489a88:0x3000',
                'wm=0x84489a6c:0x3',
            ])

            for path, label in ((n6, 'N6'), (n6h, 'N6H')):
                r = self.run_dry(path, '--profile', 'latency')
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertIn(f'tk profile:  latency (detected {label})', r.stdout)
                self.assertEqual(self.wm_lines(r.stdout), [
                    'wm=0x84f93008:0x140',
                    'wm=0x847ed604:0x15',
                    'wm=0x847ed548:0x1',
                    'wm=0x847ed54c:0x1',
                    'wm=0x847ed550:0x1',
                    'wm=0x847ecf08:0x1',
                    'wm=0x84489a84:0x2000',
                    'wm=0x84489a88:0x3000',
                    'wm=0x84489a6c:0x3',
                    'wm=0x8418ff08:0x1',
                ])

    def test_profile_stock_writes_no_wm_lines_and_options_override(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            n6 = self.make_tk(d, 'n6.gz', {
                0x847ecfe8: 0x494d4734,
                0x84489a64: 0x4e35464c,
                0x8418ff00: 0x55324846,
                0x8418ff04: 0x4e360000,
            })
            # --profile stock writes no wm= lines.
            r = self.run_dry(n6, '--profile', 'stock')
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn('tk profile:  stock', r.stdout)
            self.assertEqual(self.wm_lines(r.stdout), [])

            # Existing --flags / --hold options override --profile latency.
            r = self.run_dry(n6, '--profile', 'latency', '--flags', '0x10', '--hold', '0x80')
            self.assertEqual(r.returncode, 0, r.stderr)
            wms = self.wm_lines(r.stdout)
            self.assertIn('wm=0x84f93008:0x80', wms)
            self.assertIn('wm=0x847ed604:0x10', wms)
            # Without N4 bit 0, N5 drops bit 1 (0x1 instead of 0x3) to stay valid.
            self.assertIn('wm=0x84489a6c:0x1', wms)
            self.assertNotIn('wm=0x84489a6c:0x3', wms)

            # Hold > 0x200 refused without --hold-ack prb-tax, accepted up to 0x800 with it.
            r_bad = self.run_dry(n6, '--profile', 'latency', '--hold', '0x400')
            self.assertNotEqual(r_bad.returncode, 0)
            self.assertIn('hold-ack prb-tax', r_bad.stderr)

            r_ack = self.run_dry(n6, '--profile', 'latency', '--hold', '0x400', '--hold-ack', 'prb-tax')
            self.assertEqual(r_ack.returncode, 0, r_ack.stderr)
            self.assertIn('hold_ack=prb-tax', r_ack.stdout)
            self.assertIn('wm=0x84f93008:0x400', self.wm_lines(r_ack.stdout))

            r_over = self.run_dry(n6, '--profile', 'latency', '--hold', '0x801', '--hold-ack', 'prb-tax')
            self.assertNotEqual(r_over.returncode, 0)

            # Default without --profile stays backwards-compatible (N4 two words only).
            r_default = self.run_dry(n6)
            self.assertEqual(r_default.returncode, 0, r_default.stderr)
            self.assertEqual(self.wm_lines(r_default.stdout), [
                'wm=0x84f93008:0x140',
                'wm=0x847ed604:0x15',
            ])

    N6H_MAGICS = {
        0x847ecfe8: 0x494d4734,
        0x84489a64: 0x4e35464c,
        0x8418ff00: 0x55324846,
        0x8418ff04: 0x4e364803,
    }
    M1_MAGIC = 0x4d315049

    def keeper_m1_versions(self) -> list[int]:
        """M1_VERSIONS in the keeper's model, the list the script must match."""
        source = (REPO / 'userspace/pd-model/src/tk_flags.rs').read_text()
        found = re.search(r'pub const M1_VERSIONS: \[u32; \d+\] = \[([^\]]*)\];', source)
        self.assertIsNotNone(found, 'no M1_VERSIONS in tk_flags.rs')
        return [int(v.strip().replace('_', ''), 16) for v in found.group(1).split(',') if v.strip()]

    def test_profile_latency_adds_the_m1_selector_for_an_accepted_build(self):
        versions = self.keeper_m1_versions()
        self.assertTrue(versions)
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            for version in versions:
                m1 = self.make_tk(d, f'm1-{version:08x}.gz', {
                    **self.N6H_MAGICS, 0x841b5900: self.M1_MAGIC, 0x841b5904: version,
                })
                r = self.run_dry(m1, '--profile', 'latency')
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertIn(f'tk profile:  latency (detected N6H + M1 0x{version:08x})', r.stdout)
                wms = self.wm_lines(r.stdout)
                # The N6H set, then the selector last.
                self.assertEqual(wms[:-1], [
                    'wm=0x84f93008:0x140',
                    'wm=0x847ed604:0x15',
                    'wm=0x847ed548:0x1',
                    'wm=0x847ed54c:0x1',
                    'wm=0x847ed550:0x1',
                    'wm=0x847ecf08:0x1',
                    'wm=0x84489a84:0x2000',
                    'wm=0x84489a88:0x3000',
                    'wm=0x84489a6c:0x3',
                    'wm=0x8418ff08:0x1',
                ])
                self.assertEqual(wms[-1], 'wm=0x841b5908:0x1')
                self.assertIn('witcher-tk.m1', REPO.joinpath('scripts/stage-latency.sh').read_text())

                # Without the N4 AQM v2 bits the PIE has nothing to replace: no selector.
                r = self.run_dry(m1, '--profile', 'latency', '--flags', '0x10')
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertNotIn('wm=0x841b5908:0x1', self.wm_lines(r.stdout))
                self.assertIn('no M1 selector line', r.stdout)

                # The stock profile and the default write no selector.
                for extra in (('--profile', 'stock'), ()):
                    r = self.run_dry(m1, *extra)
                    self.assertEqual(r.returncode, 0, r.stderr)
                    self.assertNotIn('wm=0x841b5908:0x1', self.wm_lines(r.stdout))

    def test_profile_latency_leaves_out_the_selector_for_another_m1_build(self):
        newer = max(self.keeper_m1_versions()) + 1
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            m1 = self.make_tk(d, 'm1-newer.gz', {
                **self.N6H_MAGICS, 0x841b5900: self.M1_MAGIC, 0x841b5904: newer,
            })
            r = self.run_dry(m1, '--profile', 'latency')
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn(f'(detected N6H + M1 0x{newer:08x}, not accepted)', r.stdout)
            self.assertIn('which this keeper does not accept', r.stdout)
            wms = self.wm_lines(r.stdout)
            self.assertNotIn('wm=0x841b5908:0x1', wms)
            self.assertEqual(wms[-1], 'wm=0x8418ff08:0x1')
            # A version word with no M1 magic is no M1 block.
            no_magic = self.make_tk(d, 'no-m1.gz', {**self.N6H_MAGICS, 0x841b5904: self.keeper_m1_versions()[0]})
            r = self.run_dry(no_magic, '--profile', 'latency')
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn('tk profile:  latency (detected N6H)', r.stdout)
            self.assertNotIn('wm=0x841b5908:0x1', self.wm_lines(r.stdout))


if __name__ == '__main__':
    unittest.main()
