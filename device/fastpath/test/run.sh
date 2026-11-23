#!/usr/bin/env bash
# Build and run the k1fp 2.0 host test suite under AddressSanitizer and UBSan.
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

CC=${HOST_CC:-gcc}
"$CC" -std=gnu11 -O1 -g -Wall -Wextra -Werror \
  -fsanitize=address,undefined -fno-sanitize-recover=all \
  "$SCRIPT_DIR/test_k1fp.c" -o "$TMP/test_k1fp"

"$TMP/test_k1fp"
