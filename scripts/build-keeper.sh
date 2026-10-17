#!/usr/bin/env bash
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
destination=${1:?usage: build-keeper.sh OUTPUT_FILE}
host=$(rustc -vV | sed -n 's/^host: //p')
linker="$(rustc --print sysroot)/lib/rustlib/$host/bin/rust-lld"
test -x "$linker"
RUSTFLAGS="-C linker=$linker" cargo build --locked --release \
  --manifest-path "$repo/userspace/Cargo.toml" \
  --target armv7-unknown-linux-musleabi -p titan-pd-keeper
install -m 755 "$repo/userspace/target/armv7-unknown-linux-musleabi/release/titan-pd-keeper" "$destination"
