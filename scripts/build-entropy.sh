#!/usr/bin/env bash
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
destination=${1:?usage: build-entropy.sh OUTPUT_FILE}
# The same pinned Zig/musl toolchain is used locally and in image CI.
if command -v zig >/dev/null; then compiler=(zig); else compiler=(python3 -m ziglang); fi
[ "$("${compiler[@]}" version)" = 0.14.1 ] || { echo 'Zig 0.14.1 is required' >&2; exit 1; }
source=$repo/userspace/entropy/vendor/jitterentropy
mkdir -p "$repo/userspace/target"
"${compiler[@]}" cc -target arm-linux-musleabi -mcpu=cortex_a7 -O0 -fno-lto \
 -fwrapv -fstack-protector-strong -static -Wl,--strip-all -I"$source" -I"$source/src" \
 "$repo/userspace/entropy/main.c" "$source"/src/*.c \
 -o "$repo/userspace/target/witcher-entropy"
install -m 755 "$repo/userspace/target/witcher-entropy" "$destination"
