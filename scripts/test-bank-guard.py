#!/usr/bin/env python3
"""Boot flow of the bank guard on a fake unit.

Runs the real `/etc/init.d/witcher-bank-guard` and the real keeper binary
(`cargo build -p titan-pd-keeper` first) against files that stand in for the
NAND partitions, the vendor NV helper, the management bearer and the reboot.
The test plays the boot code: before each boot it reads the fake `cmnnv`
flash the way the kernel does, takes the bank the table selects, and boots
it. Time is virtual, so a 300-second window takes a second.
"""
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest
import uuid
import zlib

REPO = Path(__file__).resolve().parent.parent
KEEPER = REPO / 'userspace/target/debug/titan-pd-keeper'
INIT = REPO / 'overlay/etc/init.d/witcher-bank-guard'
ERASE = 0x20000
MAGIC = 0xcafebabe
LIMITS = [4 << 20, 60 << 20, 8 << 20]
NAMES = [['linux', 'linux2'], ['rootfs', 'rootfs2'], ['tk', 'tk2']]
KEEPER_PID = 4242


def adler0(data):
    return zlib.adler32(data, 0)


def ubicrc(data):
    return zlib.crc32(data) ^ 0xffffffff


def record(seq, size, checksum):
    r = bytearray(36)
    struct.pack_into('<5I', r, 4, MAGIC, 36, seq, checksum, size)
    struct.pack_into('<I', r, 0, adler0(bytes(r[4:])))
    return bytes(r)


def seq_of(table, part, bank):
    return struct.unpack_from('<I', table, (part * 2 + bank) * 36 + 12)[0]


def selected(table):
    banks = set()
    for part in range(3):
        a, b = seq_of(table, part, 0), seq_of(table, part, 1)
        if a == b:
            return None
        banks.add(1 if b > a else 0)
    return banks.pop() if len(banks) == 1 else None


def cmn_block(seq, table):
    block = bytearray(b'\x5a' * ERASE)
    block[36:396] = table
    struct.pack_into('<3I', block, 4, MAGIC, 36, seq)
    struct.pack_into('<I', block, 20, ERASE - 36)
    struct.pack_into('<I', block, 16, adler0(bytes(block[36:])))
    struct.pack_into('<I', block, 0, adler0(bytes(block[4:36])))
    return bytes(block)


# The kernel's load_nv: copies in the second and third good blocks, header and
# block checksums, the higher sequence number (the second copy on a tie).
CMN_READ = r'''
def cmn_read(path):
    data = open(path, 'rb').read()
    copies = []
    for index in (1, 2):
        block = data[index * ERASE:(index + 1) * ERASE]
        word = lambda o: struct.unpack_from('<I', block, o)[0]
        ok = word(4) == MAGIC and word(0) == adler0(block[4:36]) and word(16) in (0, adler0(block[36:]))
        copies.append((ok, word(12), block))
    (ok0, seq0, _), (ok1, seq1, _) = copies
    if ok0 and ok1:
        index = 1 if seq0 <= seq1 else 0
    elif ok0 or ok1:
        index = 0 if ok0 else 1
    else:
        raise SystemExit('no valid cmnnv copy')
    return index, copies[index][1], copies[index][2][36:396]
'''
exec(CMN_READ)

HELPER = r'''#!/usr/bin/env python3
# Stand-in for witcher-nv23 and the vendor NV layer: a RAM copy that every
# write updates first, then one program of the older cmnnv copy.
import os, struct, sys, zlib
ERASE = 0x20000
MAGIC = 0xcafebabe
def adler0(data):
    return zlib.adler32(data, 0)
''' + CMN_READ + r'''
root = os.environ['FAKE_UNIT']
ram = os.path.join(root, 'nv-ram.bin')
flash = os.path.join(root, 'dev/mtd8')
mode_file = os.path.join(root, 'nv-mode')
mode = open(mode_file).read().strip() if os.path.exists(mode_file) else ''
if sys.argv[1:] == ['read']:
    sys.stdout.buffer.write(open(ram, 'rb').read())
    sys.exit(0)
if sys.argv[1:] != ['write']:
    sys.exit(64)
data = sys.stdin.buffer.read()
if len(data) != 360:
    sys.exit(65)
with open(os.path.join(root, 'nv-writes'), 'a') as log:
    log.write(data.hex() + '\n')
if mode == 'busy':
    sys.exit(75)
if data == open(ram, 'rb').read():
    sys.exit(0)
open(ram, 'wb').write(data)
if mode in ('fail-once', 'skip-flash-once'):
    os.remove(mode_file)
if mode in ('fail-once', 'fail-always'):
    sys.exit(74)
if mode == 'skip-flash-once':
    sys.exit(0)
index, seq, _ = cmn_read(flash)
target = 1 - index
block = bytearray(b'\x5a' * ERASE)
block[36:396] = data
struct.pack_into('<3I', block, 4, MAGIC, 36, seq + 1)
struct.pack_into('<I', block, 20, ERASE - 36)
struct.pack_into('<I', block, 16, adler0(bytes(block[36:])))
struct.pack_into('<I', block, 0, adler0(bytes(block[4:36])))
with open(flash, 'r+b') as f:
    f.seek((1 + target) * ERASE)
    f.write(block)
sys.exit(0)
'''


def kernel_image(tag):
    payload = bytes([tag]) * (100_000 + tag)
    header = bytearray(64)
    struct.pack_into('>I', header, 0, 0x27051956)
    struct.pack_into('>I', header, 12, len(payload))
    struct.pack_into('>I', header, 4, zlib.crc32(bytes(header)))
    return bytes(header) + payload


def modem_image(tag):
    return b'\x1f\x8b\x08\x00' + bytes([tag, 0x11, 0x22]) * 20_000


def ubi_header(magic, fields):
    h = bytearray(64)
    h[:4] = magic
    h[4] = 1
    for offset, value in fields:
        struct.pack_into('>I', h, offset, value)
    struct.pack_into('>I', h, 60, ubicrc(bytes(h[:60])))
    return bytes(h)


def rootfs_image():
    """Eight eraseblocks: the volume table twice, UBIFS blocks 0 to 2, three
    erased blocks."""
    volume = bytearray(172)
    struct.pack_into('>H', volume, 14, 6)
    volume[16:22] = b'rootfs'
    struct.pack_into('>I', volume, 168, ubicrc(bytes(volume[:168])))
    ec = ubi_header(b'UBI#', [(16, 2048), (20, 4096)])
    blocks = []
    for volume_id, lnum, data in [(0x7fffefff, 0, volume), (0x7fffefff, 1, volume),
                                  (0, 0, b'\x31\x18\x10\x06'), (0, 1, b'node'), (0, 2, b'node')]:
        block = bytearray(b'\xff' * ERASE)
        block[:64] = ec
        block[2048:2112] = ubi_header(b'UBI!', [(8, volume_id), (12, lnum)])
        block[4096:4096 + len(data)] = data
        blocks.append(bytes(block))
    blocks += [b'\xff' * ERASE] * 3
    return b''.join(blocks)


def padded(data):
    return data + b'\xff' * (-len(data) % ERASE)


class Unit:
    """A fake Titan: partitions, NV, bearer and the keeper's files."""

    def __init__(self, root):
        self.root = root
        self.boots = []
        for name in ('bin', 'dev', 'proc', 'tmp', 'bundle', 'sys/class/net/lte0pdn0',
                     'mnt/titan-api/bank-guard', 'mnt/titan-api/pd'):
            (root / name).mkdir(parents=True, exist_ok=True)
        (root / 'bundle/titan-pd-keeper').symlink_to(KEEPER)
        self.write('proc/mtd', ''.join(
            f'mtd{13 + part * 2 + bank}: {LIMITS[part]:08x} 00020000 "{NAMES[part][bank]}"\n'
            for part in range(3) for bank in range(2)) + 'mtd8: 00100000 00020000 "cmnnv"\n'
            + 'mtd20: 04000000 00020000 "user"\n')
        (root / f'proc/{KEEPER_PID}').mkdir()
        (root / f'proc/{KEEPER_PID}/cmdline').write_bytes(b'/tmp/titan-pd-keeper/titan-pd-keeper\0run\0')
        self.exe('bin/witcher-nv23', HELPER)
        self.exe('bin/witcher-state', '#!/bin/sh\nexit 0\n')
        self.exe('bin/ip', '#!/bin/sh\n[ "$(cat "$FAKE_UNIT/net-up")" = up ] || exit 0\n'
                 'echo "    inet 198.51.100.2/30 scope global lte0pdn0"\n')
        self.exe('bin/ping', '#!/bin/sh\n'
                 'n=$(cat "$FAKE_UNIT/ping-count" 2>/dev/null || echo 0); n=$((n + 1)); echo "$n" > "$FAKE_UNIT/ping-count"\n'
                 'if [ -f "$FAKE_UNIT/die-at" ] && [ "$n" -ge "$(cat "$FAKE_UNIT/die-at")" ]; then\n'
                 ' rm -f "$FAKE_UNIT/die-at"; kill -9 0\nfi\n'
                 '[ "$(cat "$FAKE_UNIT/net-up")" = up ]\n')
        # A reboot kills every process of the boot, as the real one does.
        self.exe('bin/reboot', '#!/bin/sh\necho "reboot $*" >> "$FAKE_UNIT/reboots"\nkill -9 0\n')
        self.write('mnt/titan-api/bank-guard/config', 'target=192.0.2.10\nconfirm_secs=300\n')
        self.images = [[kernel_image(1), rootfs_image(), modem_image(1)],
                       [kernel_image(2), rootfs_image(), modem_image(2)]]
        for bank in range(2):
            self.write_bank(bank, self.images[bank])
        table = b''.join(record(seq, len(self.images[bank][part]), adler0(self.images[bank][part]))
                         for part, seqs in enumerate([[27, 26], [54, 52], [55, 53]])
                         for bank, seq in enumerate(seqs))
        table += bytes(360 - len(table))
        self.write_bytes('dev/mtd8', b'\x00' * ERASE + cmn_block(7, table) + cmn_block(6, table)
                         + b'\xff' * (5 * ERASE))
        self.mgmt = {0: True, 1: True}
        self.keeper_up = True
        self.fresh_volume_next_boot = False
        self.ram_override = None
        self.env = dict(
            os.environ,
            FAKE_UNIT=str(root),
            TITAN_BUNDLE=str(root / 'bundle'),
            TITAN_GUARD_RUNTIME=str(root / 'tmp'),
            WITCHER_STATE=str(root / 'bin/witcher-state'),
            TITAN_BANK_GUARD_DIR=str(root / 'mnt/titan-api/bank-guard'),
            TITAN_FIRMWARE_OPERATION=str(root / 'mnt/titan-api/firmware-operation.json'),
            TITAN_PD_STATE=str(root / 'mnt/titan-api/pd'),
            TITAN_PD_RUNTIME=str(root / 'tmp/titan-pd-keeper'),
            TITAN_CMDLINE=str(root / 'proc/cmdline'),
            TITAN_BOOT_ID=str(root / 'proc/boot_id'),
            TITAN_PROC_MTD=str(root / 'proc/mtd'),
            TITAN_MTD_DIR=str(root / 'dev'),
            TITAN_NV23_HELPER=str(root / 'bin/witcher-nv23'),
            TITAN_SYS_NET=str(root / 'sys/class/net'),
            TITAN_IP=str(root / 'bin/ip'),
            TITAN_PING=str(root / 'bin/ping'),
            TITAN_REBOOT=str(root / 'bin/reboot'),
            TITAN_PROC=str(root / 'proc'),
            TITAN_BANK_GUARD_VIRTUAL_CLOCK='20',
        )

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def write_bytes(self, name, data):
        path = self.root / name
        path.write_bytes(data)
        return path

    def exe(self, name, text):
        self.write(name, text).chmod(0o755)

    def write_bank(self, bank, images):
        for part in range(3):
            self.write_bytes(f'dev/mtd{13 + part * 2 + bank}', padded(images[part]))

    def flash_table(self):
        return cmn_read(self.root / 'dev/mtd8')[2]

    def program(self, table):
        """The vendor NV layer: RAM copy, then the older cmnnv copy."""
        index, seq, _ = cmn_read(self.root / 'dev/mtd8')
        with open(self.root / 'dev/mtd8', 'r+b') as f:
            f.seek((2 - index) * ERASE)
            f.write(cmn_block(seq + 1, table))
        self.write_bytes('nv-ram.bin', table)

    def update(self, bank, images, marker='titan-api'):
        """An updater writes `bank` and raises its sequence numbers."""
        self.images[bank] = images
        self.write_bank(bank, images)
        table = bytearray(self.flash_table())
        for part in range(3):
            seq = seq_of(table, part, 1 - bank) + 1
            data = images[part]
            table[(part * 2 + bank) * 36:(part * 2 + bank + 1) * 36] = record(seq, len(data), adler0(data))
        self.program(bytes(table))
        if marker == 'titan-api':
            self.write('mnt/titan-api/firmware-operation.json', json.dumps({
                'state': 'verified-awaiting-reboot', 'target_bank': bank,
                'image': {'build': 4172, 'sha256': 'x' * 64, 'kernel_bytes': len(images[0]),
                          'rootfs_bytes': len(images[1]), 'modem_bytes': len(images[2])}}))
        return bytes(table)

    def prepare_boot(self):
        """Play the boot code, then reset everything that lives in RAM."""
        bank = selected(self.flash_table())
        assert bank is not None, 'the fake boot code found no single bank'
        self.bank = bank
        self.boot_id = str(uuid.uuid4())
        self.write('proc/boot_id', self.boot_id + '\n')
        self.write('proc/cmdline', f'console=ttyS0 ubi.mtd={15 + bank},2048 '
                   f'active={",".join(n[bank] for n in NAMES)} mem=256M\n')
        self.write_bytes('nv-ram.bin', self.ram_override or self.flash_table())
        shutil.rmtree(self.root / 'tmp')
        (self.root / 'tmp/titan-pd-keeper').mkdir(parents=True)
        if self.keeper_up:
            self.write('tmp/titan-pd-keeper/keeper.pid', f'{KEEPER_PID}\n')
            self.write('tmp/titan-pd-keeper/boot-id', self.boot_id)
        up = self.mgmt[bank]
        self.write('sys/class/net/lte0pdn0/carrier', '1\n' if up else '0\n')
        self.write('net-up', 'up' if up else 'down')
        if self.fresh_volume_next_boot:
            self.fresh_volume_next_boot = False
            self.write('mnt/titan-api/bank-guard/volume-created', self.boot_id + '\n')

    def boot(self):
        """One boot. Returns 'reboot', 'died' (killed without a guard reboot,
        like a power cut) or 'stayed'."""
        self.prepare_boot()
        before = self.reboot_count()
        result = subprocess.run(['sh', str(INIT), 'boot'], env=self.env, start_new_session=True,
                                capture_output=True, timeout=120)
        self.boots.append(self.bank)
        if self.reboot_count() > before:
            return 'reboot'
        return 'died' if result.returncode < 0 else 'stayed'

    def run(self, max_boots=8):
        """Boot until a boot stays up."""
        for _ in range(max_boots):
            if self.boot() == 'stayed':
                return self.boots
        raise AssertionError(f'still rebooting after {max_boots} boots: {self.boots}')

    def reboot_count(self):
        path = self.root / 'reboots'
        return len(path.read_text().splitlines()) if path.exists() else 0

    def state(self):
        path = self.root / 'mnt/titan-api/bank-guard/state.json'
        return json.loads(path.read_text()) if path.exists() else {}

    def log(self):
        path = self.root / 'mnt/titan-api/pd/keeper.log'
        return path.read_text() if path.exists() else ''

    def nv_writes(self):
        path = self.root / 'nv-writes'
        return len(path.read_text().splitlines()) if path.exists() else 0

    def keeper(self, *args):
        self.prepare_ram_only()
        return subprocess.run([str(KEEPER), 'bank-guard', *args], env=self.env,
                              capture_output=True, text=True, timeout=60)

    def prepare_ram_only(self):
        if not (self.root / 'nv-ram.bin').exists():
            self.write_bytes('nv-ram.bin', self.flash_table())


class BankGuardBootFlow(unittest.TestCase):
    def setUp(self):
        if not KEEPER.is_file():
            self.skipTest('build the keeper first: cargo build -p titan-pd-keeper')
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.unit = Unit(Path(self.temp.name))

    def confirmed_on_bank_0(self):
        unit = self.unit
        self.assertEqual(unit.boot(), 'stayed')
        self.assertEqual(unit.state()['known_good']['bank'], 0)
        return unit

    def broken_update(self, marker='titan-api'):
        """The bench test: an update to bank 1 that never brings up management."""
        unit = self.confirmed_on_bank_0()
        after = unit.update(1, [kernel_image(3), rootfs_image(), modem_image(3)], marker)
        unit.mgmt[1] = False
        return unit, after

    def test_unit_not_updated_is_never_touched_even_without_management(self):
        unit = self.unit
        unit.mgmt[0] = False
        flash = (unit.root / 'dev/mtd8').read_bytes()
        self.assertEqual(unit.boot(), 'stayed')
        self.assertEqual(unit.boot(), 'stayed')
        self.assertEqual((unit.root / 'dev/mtd8').read_bytes(), flash)
        self.assertEqual(unit.nv_writes(), 0)
        self.assertIsNone(unit.state().get('session'))
        self.assertIsNone(unit.state().get('known_good'))
        unit.mgmt[0] = True
        self.assertEqual(unit.boot(), 'stayed')
        self.assertEqual(unit.state()['known_good']['bank'], 0)
        self.assertEqual(unit.reboot_count(), 0)

    def test_good_update_is_confirmed_and_kept(self):
        unit = self.confirmed_on_bank_0()
        unit.update(1, [kernel_image(3), rootfs_image(), modem_image(3)])
        self.assertEqual(unit.run(), [0, 1])
        state = unit.state()
        self.assertEqual(state['session']['outcome'], 'confirmed')
        self.assertEqual(state['known_good']['bank'], 1)
        self.assertEqual(unit.reboot_count(), 0)
        self.assertIn('the update is kept', unit.log())
        self.assertEqual(unit.boot(), 'stayed')
        self.assertEqual(unit.nv_writes(), 0)

    def test_broken_update_switches_back_once(self):
        unit, after = self.broken_update()
        self.assertEqual(unit.run(), [0, 1, 0])
        self.assertEqual(unit.reboot_count(), 1)
        table = unit.flash_table()
        self.assertEqual(selected(table), 0)
        # The bad bank's records are untouched; the old bank went one above.
        for part in range(3):
            self.assertEqual(table[(part * 2 + 1) * 36:(part * 2 + 2) * 36],
                             after[(part * 2 + 1) * 36:(part * 2 + 2) * 36])
            self.assertEqual(seq_of(table, part, 0), seq_of(after, part, 1) + 1)
        self.assertEqual(table[216:], bytes(144))
        state = unit.state()
        self.assertEqual(state['session']['outcome'], 'rolled-back')
        self.assertEqual(state['session']['switches'], 1)
        self.assertEqual(state['known_good']['bank'], 0)
        self.assertIn('switching back to bank 0', unit.log())
        self.assertIn('the raw cmnnv flash selects bank 0', unit.log())
        self.assertEqual(unit.nv_writes(), 1)
        # Later boots of the old bank never act again, marker or not.
        for _ in range(2):
            self.assertEqual(unit.boot(), 'stayed')
        self.assertEqual(unit.reboot_count(), 1)

    def test_a_dead_keeper_is_not_proof(self):
        unit = self.confirmed_on_bank_0()
        unit.update(1, [kernel_image(3), rootfs_image(), modem_image(3)])
        unit.keeper_up = False
        self.assertEqual(unit.boot(), 'reboot')
        self.assertIn('keeper not running', unit.log())
        unit.keeper_up = True
        self.assertEqual(unit.run(), [0, 1, 0])

    def test_damaged_old_bank_is_never_selected(self):
        for name, offset in (('dev/mtd17', 5000), ('dev/mtd13', 70), ('dev/mtd15', 30)):
            with self.subTest(partition=name):
                self.setUp()
                unit, after = self.broken_update()
                data = bytearray((unit.root / name).read_bytes())
                data[offset] ^= 0x01
                unit.write_bytes(name, bytes(data))
                self.assertEqual(unit.run(), [0, 1])
                self.assertEqual(unit.flash_table(), after)
                self.assertEqual(unit.nv_writes(), 0)
                self.assertEqual(unit.reboot_count(), 0)
                self.assertEqual(unit.state()['session']['outcome'], 'refused')
                self.assertIn('the old bank failed its own check', unit.log())

    def test_failed_nv_write_is_retried_on_the_next_boot(self):
        unit, _ = self.broken_update()
        unit.write('nv-mode', 'fail-once')
        self.assertEqual(unit.run(), [0, 1, 1, 0])
        self.assertEqual(unit.reboot_count(), 2)
        self.assertEqual(unit.state()['session']['switches'], 2)
        self.assertEqual(unit.state()['session']['outcome'], 'rolled-back')

    def test_write_that_missed_the_flash_is_rewritten_with_new_bytes(self):
        unit, after = self.broken_update()
        unit.write('nv-mode', 'skip-flash-once')
        self.assertEqual(unit.run(), [0, 1, 0])
        self.assertEqual(unit.reboot_count(), 1)
        self.assertEqual(unit.nv_writes(), 2)
        self.assertEqual(seq_of(unit.flash_table(), 0, 0), seq_of(after, 0, 1) + 2)
        self.assertIn('on the second write', unit.log())

    def test_reboot_loop_on_the_new_bank_switches_on_the_third_boot(self):
        unit, _ = self.broken_update()
        for _ in range(2):
            (unit.root / 'ping-count').write_text('0')
            unit.write('die-at', '3')
            self.assertEqual(unit.boot(), 'died')
        self.assertEqual(unit.state()['session']['boots'], 2)
        self.assertEqual(unit.boot(), 'reboot')
        self.assertIn('2 boots of this update ended without proof', unit.log())
        self.assertEqual(unit.run(), [0, 1, 1, 1, 0])
        self.assertEqual(unit.reboot_count(), 1)

    def test_guard_reboots_stay_bounded_when_no_write_lands(self):
        unit, _ = self.broken_update()
        unit.write('nv-mode', 'fail-always')
        self.assertEqual(unit.run(), [0, 1, 1, 1])
        self.assertEqual(unit.reboot_count(), 2)
        self.assertEqual(unit.state()['session']['outcome'], 'gave-up')
        for _ in range(3):
            self.assertEqual(unit.boot(), 'stayed')
        self.assertEqual(unit.reboot_count(), 2)

    def test_busy_updater_lock_means_no_switch_now(self):
        unit, after = self.broken_update()
        unit.write('nv-mode', 'busy')
        self.assertEqual(unit.boot(), 'stayed')
        self.assertEqual(unit.flash_table(), after)
        self.assertEqual(unit.reboot_count(), 0)
        self.assertIn('holds the flash lock', unit.log())

    def test_views_that_disagree_never_arm(self):
        unit, after = self.broken_update()
        unit.ram_override = (unit.root / 'nv-ram.bin').read_bytes()[:12] + b'\x99' + after[13:]
        self.assertEqual(unit.boot(), 'stayed')
        self.assertEqual(unit.flash_table(), after)
        self.assertIsNone(unit.state()['session'])
        self.assertIn('different bank tables', unit.log())

    def test_arm_marker_from_another_updater(self):
        unit = self.confirmed_on_bank_0()
        unit.update(1, [kernel_image(4), rootfs_image(), modem_image(4)], marker=None)
        result = unit.keeper('arm')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('next boot of bank 1', result.stdout)
        unit.mgmt[1] = False
        self.assertEqual(unit.run(), [0, 1, 0])
        self.assertEqual(unit.state()['session']['source'], 'arm')
        self.assertEqual(unit.state()['session']['outcome'], 'rolled-back')

    def test_arm_refuses_before_the_update_is_written(self):
        unit = self.confirmed_on_bank_0()
        result = unit.keeper('arm')
        self.assertEqual(result.returncode, 1)
        self.assertIn('write the update first', result.stderr)

    def test_first_witcher_boot_after_a_stock_flash(self):
        unit = self.unit
        unit.update(1, [kernel_image(5), rootfs_image(), modem_image(5)], marker=None)
        unit.mgmt[1] = False
        unit.fresh_volume_next_boot = True
        self.assertEqual(unit.run(), [1, 0])
        session = unit.state()['session']
        self.assertEqual((session['source'], session['fallback_confirmed']), ('first-witcher-boot', False))
        self.assertEqual(session['outcome'], 'rolled-back')

    def test_damaged_state_file_never_arms(self):
        unit, after = self.broken_update()
        unit.write('mnt/titan-api/bank-guard/state.json', '{not json')
        self.assertEqual(unit.boot(), 'stayed')
        self.assertEqual(unit.flash_table(), after)
        self.assertTrue((unit.root / 'mnt/titan-api/bank-guard/state.json.bad').exists())
        self.assertTrue(unit.state()['consumed'][0].startswith('titan-api:'))
        self.assertEqual(unit.boot(), 'stayed', 'the used marker does not arm later')
        self.assertEqual(unit.reboot_count(), 0)

    def test_preflight_and_status(self):
        unit = self.confirmed_on_bank_0()
        result = unit.keeper('preflight')
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn('ok: an update may write bank 1', result.stdout)
        for bank in ('0', '1'):
            result = unit.keeper('check', bank)
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertIn(f'ok: bank {bank} passes', result.stdout)
        data = bytearray((unit.root / 'dev/mtd18').read_bytes())
        data[9] ^= 0x01
        unit.write_bytes('dev/mtd18', bytes(data))
        result = unit.keeper('check', '1')
        self.assertEqual(result.returncode, 1)
        self.assertIn('tk2: the flash does not match its record checksum', result.stdout)
        status = json.loads(unit.keeper('status').stdout)
        self.assertTrue(status['views_agree'])
        self.assertEqual((status['running_bank'], status['selected_bank']), (0, 0))
        self.assertEqual(status['raw']['copy_blocks'], [1, 2])
        self.assertEqual(len(status['records']), 6)
        # The running bank has no proof, the other bank has: refuse.
        state = unit.state()
        state['known_good']['bank'] = 1
        state['known_good']['image']['parts'] = [
            [len(unit.images[1][part]), adler0(unit.images[1][part])] for part in range(3)]
        unit.write('mnt/titan-api/bank-guard/state.json', json.dumps(state))
        result = unit.keeper('preflight')
        self.assertEqual(result.returncode, 3, result.stdout)
        self.assertIn('no confirmed image', result.stdout)


if __name__ == '__main__':
    unittest.main()
