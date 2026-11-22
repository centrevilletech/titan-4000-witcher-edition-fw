#!/usr/bin/env bash
# Build witcher-nv23 against the vendor libraries of the extracted stock root
# filesystem. It links dynamically to the unit's own uClibc, libnvm and
# libkzload: the same libraries, flags and entry code as the titan-maintenance
# helper that already runs on units. No vendor library is copied into the
# image or the repository.
#
# Usage: scripts/build-nv23.sh STOCK_ROOTFS OUTPUT_FILE
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
rootfs=${1:?usage: build-nv23.sh STOCK_ROOTFS OUTPUT_FILE}
destination=${2:?usage: build-nv23.sh STOCK_ROOTFS OUTPUT_FILE}
for tool in clang ld.lld; do
  command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 1; }
done
# The extracted tree has absolute loader links and mode 600 files. Link against
# a private copy with relative links.
libs=$(mktemp -d)
sysroot=$(mktemp -d)
trap 'rm -rf "$libs" "$sysroot"' EXIT
for name in libuClibc-0.9.33.2.so libpthread-0.9.33.2.so libnvm.so libnvram.so libtarget.so \
  libkzload.so libcurl.so libssl.so.1.0.0 libcrypto.so.1.0.0 libz.so.1.2.12 libgcc_s.so.1; do
  install -m 644 "$rootfs/lib/$name" "$libs/$name"
done
ln -s libuClibc-0.9.33.2.so "$libs/libc.so.0"
ln -s libpthread-0.9.33.2.so "$libs/libpthread.so.0"
ln -s libz.so.1.2.12 "$libs/libz.so.1"
mkdir -p "$repo/userspace/target"
out=$repo/userspace/target/witcher-nv23
# libkzload.so uses libnvm, libnvram, libtarget and libcurl symbols without
# naming them, so every library is linked explicitly and kept (--no-as-needed).
clang --target=arm-linux-gnueabi -march=armv7-a -mfloat-abi=soft -Os \
  -Wall -Wextra -Werror -fno-builtin -fno-stack-protector -fno-pie \
  -nostdlib -no-pie -fuse-ld=lld -Wl,-e,_start -Wl,--hash-style=sysv \
  -Wl,--dynamic-linker=/lib/ld-uClibc.so.0 -Wl,-z,noexecstack -Wl,--build-id=none \
  -Wl,--strip-all -Wl,-rpath-link,"$libs" \
  "$repo/userspace/nv23/start.S" "$repo/userspace/nv23/nv23.c" \
  -L"$libs" -Wl,--no-as-needed -l:libkzload.so -l:libcurl.so -l:libssl.so.1.0.0 \
  -l:libcrypto.so.1.0.0 -l:libz.so.1 -l:libnvm.so -l:libnvram.so -l:libtarget.so \
  -l:libpthread.so.0 -l:libgcc_s.so.1 -l:libc.so.0 -o "$out"
# Under emulation, when available: the loader must find every vendor library
# and bind every symbol. Exit 64 is the usage message, before any vendor call.
if command -v qemu-arm >/dev/null; then
  mkdir -p "$sysroot/lib"
  for entry in "$rootfs"/lib/*; do
    name=${entry##*/}
    if [ -L "$entry" ]; then
      ln -s "$(basename "$(readlink "$entry")")" "$sysroot/lib/$name"
    elif [ -f "$entry" ]; then
      install -m 644 "$entry" "$sysroot/lib/$name"
    fi
  done
  set +e
  qemu-arm -L "$sysroot" "$out" > /dev/null 2>&1
  code=$?
  set -e
  [ "$code" = 64 ] || { echo "witcher-nv23 did not load under emulation (exit $code)" >&2; exit 1; }
  echo "witcher-nv23 loads under emulation with the vendor libraries"
fi
install -m 755 "$out" "$destination"
