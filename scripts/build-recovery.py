#!/usr/bin/env python3
"""Keep the factory desktop UI compressed; unpack it into RAM before rcinit."""
import gzip
import io
import shutil
import sys
import tarfile
from pathlib import Path
from rootfs_metadata import read_metadata

root, ubi = map(Path, sys.argv[1:])
rows = read_metadata(ubi.read_bytes())
web = root / 'usr/www'
buffer = io.BytesIO()
with tarfile.open(fileobj=buffer, mode='w', format=tarfile.USTAR_FORMAT) as archive:
    for path in sorted(web.rglob('*')):
        name = path.relative_to(web).as_posix()
        # Desktop recovery uses /usr/www. The alternate GCT pages under
        # /home/www, mobile pages and a 1.5 MB decorative background are omitted.
        if name.startswith('private/mobile/') or name == 'private/mobile' or name in ('key.pem', 'cert.pem', 'images/bg.png'):
            continue
        info = archive.gettarinfo(str(path), arcname=name)
        info.uid = info.gid = 500
        info.uname = info.gname = ''
        info.mtime = 0
        info.mode = rows['/usr/www/' + name]['mode'] & 0o7777
        if info.isfile():
            with path.open('rb') as source:
                archive.addfile(info, source)
        else:
            archive.addfile(info)
output = root / 'usr/lib/titan-api/vendor-desktop.tar.gz'
output.write_bytes(gzip.compress(buffer.getvalue(), compresslevel=9, mtime=0))
for folder in (web, root / 'home/www'):
    for path in folder.iterdir():
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        else:
            path.unlink()
print(f'Factory desktop recovery archive: {output.stat().st_size} bytes')
