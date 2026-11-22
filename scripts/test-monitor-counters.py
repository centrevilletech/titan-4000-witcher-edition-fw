#!/usr/bin/env python3
"""Run the packed monitor's eth0 counter commands with the image's own BusyBox.

`monitor` hands each command's first output line to uClibc atoi(), which clamps
every value from 2,147,483,647 up. This runs the two command strings stored in
the image's /usr/sbin/monitor through the packed BusyBox grep and awk under
qemu-arm, on files standing in for /proc/net/dev, and checks that:
- every printed value is below the clamp,
- a value below 10^9 prints unchanged (so the boot-time check is unchanged),
- one more packet always prints a different value, across 2^31 and the wrap.

QEMU runs the user-space tools only. Nothing reads the host's network.
Usage: scripts/test-monitor-counters.py ROOTFS
"""
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile

COMMANDS = {
    0x4234: ('rx', b"grep eth0 /proc/net/dev | awk '{print $3%1e9}'"),
    0x4268: ('tx', b"grep eth0 /proc/net/dev | awk '{print $11%1e9}'"),
}
CLAMP = 2**31 - 1
VALUES = [0, 1, 239908, 1153475, 999_999_999, 1_000_000_000, 2_147_483_646,
          2_147_483_647, 2_147_483_648, 3_000_000_000, 4_294_967_294, 4_294_967_295]


def sysroot_from(root, work):
    # Extraction drops modes and vendor loader links are absolute; build a
    # disposable sysroot without altering the audited image tree.
    sysroot = work/'sysroot'
    (sysroot/'bin').mkdir(parents=True)
    (sysroot/'lib').mkdir()
    shutil.copyfile(root/'bin/busybox', sysroot/'bin/busybox')
    (sysroot/'bin/busybox').chmod(0o755)
    for source in (root/'lib').iterdir():
        target = sysroot/'lib'/source.name
        if source.is_symlink():
            link = os.readlink(source)
            target.symlink_to(Path(link).name if link.startswith('/lib/') else link)
        elif source.is_file():
            shutil.copyfile(source, target)
            target.chmod(0o755)
    return sysroot


def net_dev(rx, tx):
    return ('Inter-|   Receive                                                |  Transmit\n'
            ' face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n'
            '    lo:    1234      12    0    0    0     0          0         0     1234      12    0    0    0     0       0          0\n'
            f'  eth0: 3460000000 {rx}    0    0    0     0          0         0 3460000000 {tx}    0    0    0     0       0          0\n'
            '   br0:    5678      34    0    0    0     0          0         0     5678      34    0    0    0     0       0          0\n')


def verify(root):
    root = Path(root).resolve()
    emulator = os.environ.get('QEMU_ARM', 'qemu-arm')
    image = (root/'usr/sbin/monitor').read_bytes()
    with tempfile.TemporaryDirectory(prefix='witcher-monitor-') as temporary:
        work = Path(temporary)
        sysroot = sysroot_from(root, work)
        (work/'bin').mkdir()
        for applet in ('grep', 'awk'):
            wrapper = work/'bin'/applet
            wrapper.write_text('#!/bin/sh\nexec ' + shlex.join([emulator, '-L', str(sysroot), str(sysroot/'bin/busybox'), applet]) + ' "$@"\n')
            wrapper.chmod(0o700)
        environment = dict(os.environ, PATH=f'{work}/bin:' + os.environ['PATH'])

        def run(command, rx, tx):
            fixture = work/'net-dev'
            fixture.write_text(net_dev(rx, tx))
            out = subprocess.run(['sh', '-c', command.replace('/proc/net/dev', str(fixture))],
                                 env=environment, capture_output=True, text=True, timeout=60, check=True).stdout
            return int(out.splitlines()[0])

        for offset, (field, expected) in COMMANDS.items():
            stored = image[offset:image.index(b'\0', offset)]
            assert stored == expected, f'monitor command at 0x{offset:x} is {stored!r}'
            command = stored.decode()
            for value in VALUES:
                rx, tx = (value, 7) if field == 'rx' else (7, value)
                printed = run(command, rx, tx)
                assert printed == value % 10**9, (field, value, printed)
                assert 0 <= printed < CLAMP, (field, value, printed)
                if value < 10**9:
                    assert printed == value, (field, value, printed)
            for value in (2_147_483_646, 2_147_483_647, 4_294_967_294):
                rx, tx = ((value, 7), (value + 1, 7)) if field == 'rx' else ((7, value), (7, value + 1))
                assert run(command, *rx) != run(command, *tx), (field, value)
    print('Packed monitor eth0 commands: below the atoi clamp, unchanged under 1e9, every packet visible PASS')


if __name__ == '__main__':
    verify(sys.argv[1])
