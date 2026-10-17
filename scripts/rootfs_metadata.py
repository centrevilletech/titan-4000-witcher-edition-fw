"""Read on-image UBIFS metadata, never host extraction permissions."""
import os
import stat
import struct
import tempfile
from pathlib import Path, PurePosixPath

WITCHER_BOOT_SCRIPTS = (
    '/etc/init.d/witcher-boot',
    '/etc/init.d/witcher-state',
    '/etc/init.d/witcher-recovery-files',
    '/etc/init.d/witcher-management-access',
    '/etc/init.d/titan-api',
    '/etc/init.d/titan-pd-keeper',
    '/etc/init.d/titan-sshd',
    '/etc/sysconfig/script/passthru-fix.sh',
)
WITCHER_BUNDLE_SCRIPTS = (
    '/usr/lib/titan-api/prepare-tls.sh',
    '/usr/lib/titan-api/start-titan-api.sh',
    '/usr/lib/titan-api/collect.sh',
)


def read_metadata(ubi):
    from ubireader.ubifs import ubifs, walk
    from ubireader.ubi_io import ubi_file

    lebs = {}
    for offset in range(0, len(ubi), 131072):
        block = ubi[offset:offset + 131072]
        if block[:4] != b'UBI#':
            continue
        if block[2048:2052] != b'UBI!':
            raise ValueError('Missing UBI volume header')
        volume, number = struct.unpack_from('>II', block, 2056)
        if volume == 0:
            if number in lebs:
                raise ValueError('Duplicate rootfs logical eraseblock')
            lebs[number] = block[4096:]
    if not lebs or set(lebs) != set(range(max(lebs) + 1)):
        raise ValueError('Missing rootfs logical eraseblocks')
    with tempfile.NamedTemporaryFile() as temporary:
        temporary.write(b''.join(lebs[i] for i in range(len(lebs))))
        temporary.flush()
        source = ubi_file(temporary.name, 2048, 0, None)
        image = ubifs(source)
        inodes, bad = {}, []
        walk.index(image, image.master_node.root_lnum,
                   image.master_node.root_offs, inodes, bad)
        if bad:
            raise ValueError(f'Corrupt UBIFS index blocks: {bad}')
        result = {}

        def visit(number, path, ancestors):
            if number in ancestors or path in result:
                raise ValueError('Cyclic or duplicate directory entry')
            entry = inodes[number]
            node = entry['ino']
            row = dict(mode=node.mode, uid=node.uid, gid=node.gid, size=node.size)
            if stat.S_ISLNK(node.mode):
                row['target'] = node.data.decode()
            if stat.S_ISCHR(node.mode) or stat.S_ISBLK(node.mode):
                device = struct.unpack_from('<I', node.data)[0]
                row['device'] = [os.major(device), os.minor(device)]
            result[path] = row
            if stat.S_ISDIR(node.mode):
                for dent in entry.get('dent', []):
                    if dent.name in ('', '.', '..') or '/' in dent.name:
                        raise ValueError('Invalid directory entry')
                    visit(dent.inum, path.rstrip('/') + '/' + dent.name,
                          ancestors | {number})

        visit(1, '/', set())
        source.close()
        return result


def prg_metadata(path):
    data = Path(path).read_bytes()
    kernel, rootfs, tk = struct.unpack_from('>III', data, 0x24)
    if 84 + kernel + rootfs + tk != len(data):
        raise ValueError('PRG partition lengths do not match file')
    return read_metadata(data[84 + kernel:84 + kernel + rootfs])


def resolve(rows, path):
    """Resolve image symlinks, including /sbin -> bin, without using host /lib."""
    todo = list(PurePosixPath(path).parts[1:])
    done = []
    links = 0
    while todo:
        part = todo.pop(0)
        if part == '..':
            if done:
                done.pop()
            continue
        if part == '.':
            continue
        current = '/' + '/'.join(done + [part])
        row = rows[current]
        if 'target' in row:
            links += 1
            if links > 40:
                raise ValueError('Too many image symlinks')
            target = PurePosixPath(row['target'])
            parts = list(target.parts)
            if target.is_absolute():
                done = []
                parts = parts[1:]
            todo = parts + todo
        else:
            done.append(part)
    return rows['/' + '/'.join(done)]


def boot_errors(stock, built, *, witcher=False):
    errors = []
    required = ('/sbin/init', '/bin/sh', '/bin/busybox', '/bin/bash',
                '/etc/init.d/rcS', '/etc/sysconfig/board.conf', '/usr/sbin/rcinit')
    if witcher:
        required += WITCHER_BOOT_SCRIPTS
        if '/usr/lib/titan-api' in built:
            required += WITCHER_BUNDLE_SCRIPTS
            required += ('/usr/lib/titan-api/witcher-firstboot', '/usr/lib/titan-api/witcher-entropy')
    for path in required:
        try:
            mode = resolve(built, path)['mode']
            if not stat.S_ISREG(mode) or not mode & 0o111:
                errors.append(f'{path}: not executable (mode {stat.S_IMODE(mode):04o})')
        except (KeyError, ValueError):
            errors.append(f'{path}: missing or broken symlink')
    for path, before in stock.items():
        after = built.get(path)
        # Removed vendor web pages/audio are deliberate. Retained executable
        # files, including patched rcinit/cbrs_fsm, must retain execute bits.
        if after and stat.S_ISREG(before['mode']) and before['mode'] & 0o111:
            if (after['mode'] & 0o111) != (before['mode'] & 0o111):
                errors.append(f'{path}: factory execute bits changed')

    def devices(rows):
        return {p: (r['mode'], r['uid'], r['gid'], r['device'])
                for p, r in rows.items() if 'device' in r}

    if devices(stock) != devices(built):
        errors.append('Device paths/types/modes/owners/major/minor differ from stock')
    # UID 65534 serves static assets. Check every ancestor as well as UI files.
    if '/usr/lib/titan-api' in built:
        for path in ('/', '/usr', '/usr/lib', '/usr/lib/titan-api'):
            row = built.get(path, {})
            if not stat.S_ISDIR(row.get('mode', 0)) or not row['mode'] & 0o001:
                errors.append(f'{path}: not traversable by the web worker')
        for path, row in built.items():
            if path == '/usr/lib/titan-api/ui' or path.startswith('/usr/lib/titan-api/ui/'):
                required = 0o005 if stat.S_ISDIR(row['mode']) else 0o004
                if row['mode'] & required != required:
                    errors.append(f'{path}: not readable by the web worker')
        for path in ('/usr/lib/titan-api', '/usr/lib/titan-api/ui'):
            if built.get(path, {}).get('mode') != stat.S_IFDIR | 0o755:
                errors.append(f'{path}: launcher requires directory mode 0755')
    return errors


if __name__ == '__main__':
    import argparse
    import json
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stock')
    parser.add_argument('built')
    args = parser.parse_args()
    errors = boot_errors(prg_metadata(args.stock), prg_metadata(args.built), witcher=True)
    print(json.dumps(dict(errors=errors, passed=not errors), indent=2))
    raise SystemExit(bool(errors))
