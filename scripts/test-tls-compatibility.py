#!/usr/bin/env python3
"""Generate TLS with the actual image's ARM OpenSSL; inspect public outputs only.
QEMU executes the user-space tool, not the vendor kernel or its entropy source.
"""
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile


def verify(root):
    root = Path(root).resolve()
    emulator = os.environ.get('QEMU_ARM', 'qemu-arm')
    with tempfile.TemporaryDirectory(prefix='witcher-tls-compat-') as temporary:
        work = Path(temporary)
        (work/'tls').mkdir(mode=0o700)
        # Extraction drops modes; vendor loader links are absolute. Build a
        # disposable QEMU sysroot without altering the audited image tree.
        sysroot = work/'sysroot'
        (sysroot/'bin').mkdir(parents=True)
        (sysroot/'lib').mkdir()
        shutil.copyfile(root/'bin/openssl', sysroot/'bin/openssl')
        (sysroot/'bin/openssl').chmod(0o755)
        for source in (root/'lib').iterdir():
            target = sysroot/'lib'/source.name
            if source.is_symlink():
                link = os.readlink(source)
                target.symlink_to(Path(link).name if link.startswith('/lib/') else link)
            elif source.is_file():
                shutil.copyfile(source, target)
                target.chmod(0o755)
        (work/'bin').mkdir()
        wrapper = work/'bin/openssl'
        wrapper.write_text('#!/bin/sh\nexec ' + shlex.join([emulator, '-L', str(sysroot), '-E', 'LD_LIBRARY_PATH=/lib', str(sysroot/'bin/openssl')]) + ' "$@"\n')
        wrapper.chmod(0o700)
        script = work/'prepare.sh'
        script.write_text((root/'usr/lib/titan-api/prepare-tls.sh').read_text().replace('tls=/mnt/titan-api/tls', f'tls={work}/tls'))
        environment = dict(os.environ, PATH=f'{work}/bin:' + os.environ['PATH'])
        subprocess.run(['sh', str(script)], env=environment, check=True, capture_output=True, timeout=30)
        pair = work/'tls/current'
        details = subprocess.check_output(['openssl', 'x509', '-in', str(pair/'cert.pem'), '-noout', '-text'], text=True)
        for expected in ('ASN1 OID: prime256v1', 'Jan  1 00:00:00 1970 GMT', 'Dec 31 23:59:59 2099 GMT'):
            assert expected in details, f'Missing certificate property: {expected}'
        cert_key = subprocess.check_output(['openssl', 'x509', '-in', str(pair/'cert.pem'), '-pubkey', '-noout'])
        actual_key = subprocess.check_output(['openssl', 'pkey', '-in', str(pair/'key.pem'), '-pubout'])
        assert cert_key == actual_key, 'Certificate/key mismatch'
        assert (pair/'key.pem').stat().st_mode & 0o777 == 0o600
        first = (pair/'cert.pem').read_bytes()
        subprocess.run(['sh', str(script)], env=environment, check=True, capture_output=True, timeout=30)
        assert (pair/'cert.pem').read_bytes() == first, 'Existing identity replaced'
    print('Packed OpenSSL: named P-256, matching key, fixed validity, identity reuse PASS')

if __name__ == '__main__':
    verify(sys.argv[1])
