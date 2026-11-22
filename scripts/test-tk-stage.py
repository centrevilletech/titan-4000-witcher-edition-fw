#!/usr/bin/env python3
"""Run the boot-time tk loader hook against recording stubs.

No root and no device. Stubs stand in for ubiattach, ubidetach, mount and
umount: a mount table is a file, a UBI volume is a directory that a mount copies
in and a read-write unmount copies back, and a bind mount is a symlink. This
proves the hook's decisions, its order and what it leaves behind, not the
vendor kernel's mount or UBI behaviour.

Set TK_SHELL (default `sh`) to run the hook under another POSIX shell. A
BusyBox shell that prefers its own applets bypasses the stubs.
"""
import gzip
import hashlib
import importlib.util
import os
import re
import shlex
import subprocess
import tempfile
import unittest
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

HEXDUMP = r'''#!/usr/bin/env python3
import sys
n = int(sys.argv[sys.argv.index('-n') + 1])
sys.stdout.write(open(sys.argv[-1], 'rb').read(n).hex())
'''


class Unit:
    """A fake Titan root at boot: the user partition, the Witcher volume and the rootfs paths."""

    def __init__(self, base: Path):
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
                           ('ubidetach', DETACH), ('hexdump', HEXDUMP),
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
        }
        for key, value in values.items():
            text, count = re.subn(rf'^{re.escape(key)}=.*$', f'{key}={value}', text, flags=re.M)
            assert count == 1, key
        self.hook = base / 'hook'
        self.hook.write_text(text)
        self.env = dict(os.environ, TK_ROOT=str(base))

    @property
    def module(self):
        return self.root / 'lib/modules/3.10.0-uc0/extra/modem.ko'

    @property
    def gated(self):
        return self.root / 'usr/lib/titan-api/tk/modem-tkfs.ko'

    @property
    def tk(self):
        return self.root / 'flash/data/tk'

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
        self.assertEqual(unit.strikes(), 'strikes=1\n')
        # The partition was released before the modem loaded.
        self.assertFalse(any(row.startswith('ubi1:') for row in loaded['pre_mounts']), loaded['pre_mounts'])
        self.assertIn(f'witcher-tk {unit.root}/lib/firmware bind rw', loaded['pre_mounts'])
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
        self.assertEqual(unit.strikes(), 'strikes=2\n')
        for _ in range(3):
            self.assertEqual(unit.boot()['firmware'], 'nand')
            self.assertEqual(unit.status()['reason'], 'strikes')
            self.assertEqual(unit.strikes(), 'strikes=2\n')
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


if __name__ == '__main__':
    unittest.main()
