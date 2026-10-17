#!/usr/bin/env bash
# Rebuild the UI from its pinned source and dependencies; no device access.
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
destination=${1:?usage: build-ui.sh OUTPUT_DIRECTORY}
npm run build:rust-device --prefix "$repo/web"
mkdir -p "$destination"
cp -a "$repo/web/dist-device/." "$destination/"
python3 - "$destination" <<'PY'
import gzip,sys
from pathlib import Path
for path in Path(sys.argv[1]).rglob('*'):
    if path.is_file() and path.suffix in {'.js','.css','.html','.svg'}:
        path.with_name(path.name+'.gz').write_bytes(gzip.compress(path.read_bytes(),compresslevel=9,mtime=0))
PY
# Serve this unit's live Ethernet identity before login; never bake in a MAC.
ln -sfn /tmp/witcher-api/device-mac.txt "$destination/device-mac.txt"
