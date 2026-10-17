#!/usr/bin/env bash
# Build a Witcher-edition Titan 4000 .prg from a stock vendor .prg.
#
# Produces: stock kernel + stock tk (byte-identical) + a rebuilt UBIFS rootfs
# carrying (a) the passthrough/SSH overlay and (b) the one-byte gdmlte.ko IPv6-PD
# modem patch. See README.md for prerequisites.
#
# Usage: scripts/build-firmware.sh /path/to/STOCK.prg [-o out.prg]
set -euo pipefail

HERE=$(cd "$(dirname "$0")/.." && pwd)
STOCK=${1:?usage: build-firmware.sh STOCK.prg [-o out.prg]}
OUT=${3:-"$HERE/out/witcher-v$(cat "$HERE/VERSION")-development.prg"}

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing tool: $1" >&2; exit 1; }; }
need mkfs.ubifs; need ubinize; need fakeroot; need python3; need npm
echo "ec18547470302cec65529c501f06971075a06516f7c10f03b8573e18138ea04a  $STOCK" | sha256sum -c -

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
echo ">> unpacking stock image"
python3 "$HERE/scripts/prg-unpack.py" "$STOCK" -o "$WORK/fa"

echo ">> extracting stock rootfs (need a UBIFS reader: ubireader)"
python3 - "$WORK/fa/02_rootfs.ubi" "$WORK/rootfs" <<'PY'
import sys, struct, os, tempfile
from ubireader.ubifs import ubifs
from ubireader.ubi_io import ubi_file
from ubireader.ubifs.output import extract_files
from ubireader import settings; settings.logging_on=False
ubi=sys.argv[1]; out=sys.argv[2]
peb=0x20000; vo=2048; do=4096; leb=126976
d=open(ubi,'rb').read(); lebs={}
for i in range(len(d)//peb):
    p=d[i*peb:(i+1)*peb]
    if p[:4]!=b'UBI#': continue
    v=p[vo:vo+64]
    if v[:4]!=b'UBI!': continue
    vid,ln=struct.unpack_from('>II',v,8)
    if vid==0: lebs[ln]=p[do:do+leb]
carved=os.path.join(os.path.dirname(out),'stock-rootfs.ubifs')
open(carved,'wb').write(b''.join(lebs.get(i,b'\xff'*leb) for i in range(max(lebs)+1)))
os.makedirs(out, exist_ok=True)
extract_files(ubifs(ubi_file(carved,2048,0,None)), out)
PY

echo ">> applying overlay"
cp -a "$HERE/overlay/etc" "$WORK/rootfs/"
if [ -d "$HERE/overlay/usr" ]; then
  mkdir -p "$WORK/rootfs/usr"
  cp -a "$HERE/overlay/usr/." "$WORK/rootfs/usr/"
fi
echo ">> building versioned web UI from source"
"$HERE/scripts/build-ui.sh" "$WORK/rootfs/usr/lib/titan-api/ui"
"$HERE/scripts/build-firstboot.sh" "$WORK/rootfs/usr/lib/titan-api/witcher-firstboot"
"$HERE/scripts/build-keeper.sh" "$WORK/rootfs/usr/lib/titan-api/titan-pd-keeper"
"$HERE/scripts/build-entropy.sh" "$WORK/rootfs/usr/lib/titan-api/witcher-entropy"
install -m 644 "$HERE/userspace/entropy/vendor/jitterentropy/LICENSE.bsd" "$WORK/rootfs/usr/lib/titan-api/jitterentropy-LICENSE"
python3 "$HERE/scripts/stamp-version.py" "$WORK/rootfs"
cat "$HERE/overlay/board.conf.append" >> "$WORK/rootfs/etc/sysconfig/board.conf"
# Keep the desktop recovery UI and updater. No factory shared TLS private key.
echo ">> preserving factory desktop recovery; removing shared TLS and audio tones"
rm -f "$WORK/rootfs/usr/www/key.pem" "$WORK/rootfs/usr/www/cert.pem"
python3 "$HERE/scripts/build-recovery.py" "$WORK/rootfs" "$WORK/fa/02_rootfs.ubi"
python3 - "$WORK/rootfs/etc/sysconfig/board.conf" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1]); text=p.read_text()
needle='\t\t/usr/sbin/rcinit &'
assert text.count(needle)==1, 'factory rcinit hook changed'
text=text.replace(needle, '\t\t/bin/sh /etc/init.d/witcher-recovery-files\n'+needle)
p.write_text(text)
PY
rm -rf "$WORK/rootfs/etc/sysconfig/audio/sample"
echo ">> locking the stock root account"
python3 "$HERE/scripts/strip-root-password.py" "$WORK/rootfs"
python3 "$HERE/scripts/strip-vendor-host-keys.py" "$WORK/rootfs/usr/sbin/rcinit"

echo ">> patching gdmlte.ko (IPv6-PD /56 modem patch)"
KO="$WORK/rootfs/lib/modules/3.10.0-uc0/extra/gdmlte.ko"
python3 "$HERE/scripts/patch-gdmlte.py" "$KO" -o "$KO.patched"
mv "$KO.patched" "$KO"

echo ">> patching cbrs_fsm (disable local SAS enforcement: radio-block + firewall)"
CB="$WORK/rootfs/usr/sbin/cbrs_fsm"
python3 "$HERE/scripts/patch-cbrs_fsm.py" "$CB" -o "$CB.patched"
mv "$CB.patched" "$CB"

echo ">> restoring stock modes after extraction and patching"
python3 "$HERE/scripts/restore-rootfs-modes.py" "$WORK/fa/02_rootfs.ubi" "$WORK/rootfs"

echo ">> mkfs.ubifs (device table restores /dev nodes; ownership 500)"
fakeroot sh -c "
  chown -R 500:500 '$WORK/rootfs'
  mkfs.ubifs -r '$WORK/rootfs' -D '$HERE/device/dev-nodes.mkfs-D.txt' \
    -m 2048 -e 126976 -c 400 -x lzo -o '$WORK/rootfs.ubifs'
"
echo ">> ubinize"
( cd "$WORK" && cp "$HERE/ubinize.ini" ubinize.ini && \
  ubinize -o 02_rootfs.ubi -p 128KiB -m 2048 -s 2048 -O 2048 ubinize.ini )
python3 - "$WORK/02_rootfs.ubi" <<'PY'
from pathlib import Path; import sys
p=Path(sys.argv[1]); d=p.read_bytes(); t=31195136
print(f'UBI bytes {len(d)} limit {t} slack {t-len(d)}')
if len(d)<t: p.write_bytes(d+b'\xff'*(t-len(d)))
assert Path(sys.argv[1]).stat().st_size==t, "UBI size wrong"
PY

echo ">> repacking (stock kernel + stock tk + new rootfs)"
mkdir -p "$WORK/parts"
cp -a "$WORK/fa/00_header.bin" "$WORK/fa/01_kernel.uImage" "$WORK/fa/03_tk.gzip" "$WORK/parts/"
cp -a "$WORK/02_rootfs.ubi" "$WORK/parts/02_rootfs.ubi"
mkdir -p "$(dirname "$OUT")"
python3 "$HERE/scripts/prg-pack.py" "$WORK/parts" -o "$OUT" --template "$STOCK"
python3 "$HERE/scripts/verify-firmware.py" "$STOCK" "$OUT"
echo ">> done: $OUT"
echo ">> verify:  python3 scripts/verify-firmware.py '$STOCK' '$OUT'"
