#!/usr/bin/env python3
"""Run the boot-time tk loader around the one `modprobe modem` in start_lte.sh.

The vendor script builds the modprobe command in $PROBE_MODEM and runs it on a
line of its own. This puts `witcher-tk-stage pre` right before that line and
`witcher-tk-stage post` right after it, so /lib/firmware is only replaced while
the modem module loads. start_lte.sh has no `set -e`, so a failing hook cannot
stop the modem from loading. See docs/tk-boot-loader.md.
"""
import sys
from pathlib import Path

NEEDLE = '\n$PROBE_MODEM\n'
PRE = '/bin/sh /etc/init.d/witcher-tk-stage pre'
POST = '/bin/sh /etc/init.d/witcher-tk-stage post'


def hook(text: str) -> str:
    if PRE in text or POST in text:
        raise ValueError('start_lte.sh is already hooked')
    if text.count(NEEDLE) != 1 or text.count('modprobe modem') != 2:
        raise ValueError('factory modprobe modem line changed')
    return text.replace(NEEDLE, f'\n{PRE}\n$PROBE_MODEM\n{POST}\n')


def main():
    path = Path(sys.argv[1])
    try:
        path.write_text(hook(path.read_text()))
    except ValueError as err:
        sys.exit(f'refusing: {err}')
    print(f'  hooked {path}: witcher-tk-stage pre/post around $PROBE_MODEM')


if __name__ == '__main__':
    main()
