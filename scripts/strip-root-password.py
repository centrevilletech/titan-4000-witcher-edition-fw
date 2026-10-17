#!/usr/bin/env python3
"""Lock both stock root-account writers without publishing their credentials.

The caller pins the complete stock PRG SHA-256 before extraction. Discover the
credential from that input, require both writers to agree, and preserve the
binary length. No password is installed in Witcher; SSH uses enrolled keys.
"""
import re
import sys
from pathlib import Path
from credential_policy import ROOT_HASH

BOARD_NEW = b'echo "root:!:0:0:root:/root:/bin/sh" > /var/tmp/passwd\n'
RCINIT_NEW = b'root:!:0:0:root:/:/bin/sh\n'


def lock_root(root):
    board = Path(root) / 'etc/sysconfig/board.conf'
    rcinit = Path(root) / 'usr/sbin/rcinit'
    text, data = board.read_bytes(), rcinit.read_bytes()
    records = list(ROOT_HASH.finditer(data))
    if not records:
        if data.count(RCINIT_NEW) == 1 and text.count(BOARD_NEW) == 1 and b'root:\\$' not in text:
            return
        raise ValueError('Expected stock root account writers are missing')
    if len(records) != 1 or records[0].group(2) != b'/':
        raise ValueError('Unexpected stock root account layout')
    record = records[0]
    credential = record.group(1)
    escaped = credential.replace(b'$', b'\\$')
    old = b'echo "root:' + escaped + b':0:0:root:/root:/bin/sh" > /var/tmp/passwd\n'
    if text.count(old) != 1 or BOARD_NEW in text or RCINIT_NEW in data:
        raise ValueError('Stock root account writers do not agree')
    new_text = text.replace(old, BOARD_NEW, 1)
    replacement = RCINIT_NEW + b'\x00' * (len(record.group()) - len(RCINIT_NEW))
    new_data = data[:record.start()] + replacement + data[record.end():]
    if credential in new_data or credential in new_text or escaped in new_text:
        raise ValueError('Stock root credential remains after replacement')
    # Validate both results before changing either file.
    board.write_bytes(new_text)
    rcinit.write_bytes(new_data)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit('usage: strip-root-password.py ROOTFS')
    try:
        lock_root(sys.argv[1])
    except ValueError as error:
        sys.exit(str(error))
    print('root password locked')
