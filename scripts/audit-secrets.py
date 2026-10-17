#!/usr/bin/env python3
"""Scan tracked bytes (including binaries); print locations, never secret values.

Use --history before publication to include deleted files and reachable tags.
Gitleaks is a separate CI layer for provider/API token formats.
"""
import argparse
import re
import subprocess
import sys
from pathlib import Path
from credential_policy import PRIVATE_KEY, legacy_credentials

ROOT = Path(__file__).resolve().parent.parent
HASH = re.compile(rb'\$[156y]\$[A-Za-z0-9./]{1,16}\$[A-Za-z0-9./]{20,}')


def audit(data, name, needles):
    findings = []
    if name.lower().endswith(('.prg', '.ubi', '.ubifs')):
        findings.append('firmware artifact committed to source')
    if PRIVATE_KEY.search(data):
        findings.append('private key')
    if HASH.search(data.replace(b'\\$', b'$')):
        findings.append('password hash')
    if any(value in data for value in needles):
        findings.append('legacy credential')
    return findings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--history', action='store_true')
    args = parser.parse_args()
    try:
        needles = legacy_credentials()
    except ValueError as error:
        sys.exit(str(error))
    findings = set()
    if args.history:
        objects = subprocess.check_output(['git', 'rev-list', '--objects', '--all'], cwd=ROOT).decode().splitlines()
        for row in objects:
            oid, _, name = row.partition(' ')
            if not name:
                continue
            blob = subprocess.run(['git', 'cat-file', 'blob', oid], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            if blob.returncode:
                continue
            for reason in audit(blob.stdout, name, needles):
                findings.add((name, reason))
    else:
        names = subprocess.check_output(['git', 'ls-files', '-z'], cwd=ROOT).decode().split('\0')
        for name in filter(None, names):
            path = ROOT / name
            if not path.is_file() or path.is_symlink():
                continue
            for reason in audit(path.read_bytes(), name, needles):
                findings.add((name, reason))
    for name, reason in sorted(findings):
        print(f'FAIL {name}: {reason}')
    if findings:
        return 1
    print('PASS: credential/artifact audit (' + ('all reachable history' if args.history else 'tracked working tree') + ')')
    return 0


if __name__ == '__main__':
    sys.exit(main())
