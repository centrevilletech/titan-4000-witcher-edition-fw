#!/usr/bin/env bash
# Build and run the titan_qctrl host tests under AddressSanitizer and UBSan.
#   run.sh               the tests (CI)
#   run.sh --identity F  also prove that with mode bit 4 clear this titan_qctrl.c forwards the
#                        same bytes as the older source F (a fixed mixed-traffic trace in
#                        modes 0, 2, 3 and 6 must match line for line)
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
CC=${HOST_CC:-gcc}
FLAGS=(-std=gnu11 -O1 -g -Wall -Wextra -Werror -Wno-unused-function
       -fsanitize=address,undefined -fno-sanitize-recover=all)

"$CC" "${FLAGS[@]}" -I "$SCRIPT_DIR" "$SCRIPT_DIR/test_qctrl.c" -o "$TMP/test_qctrl"
"$TMP/test_qctrl"

if [ "${1:-}" = "--identity" ]; then
  old=$(cd "$(dirname "$2")" && pwd)/$(basename "$2")
  cp "$old" "$TMP/old_qctrl.c"
  # the old source includes its headers from its own directory; the mock's include guard
  # makes titan_k310_abi.h empty there
  cp "$SCRIPT_DIR/../source/titan_k310_abi.h" "$TMP/"
  "$CC" "${FLAGS[@]}" -I "$SCRIPT_DIR" -DQCTRL_SRC="\"$TMP/old_qctrl.c\"" -DTRACE_ONLY \
    "$SCRIPT_DIR/test_qctrl.c" -o "$TMP/test_old" 2>"$TMP/old.err" || { cat "$TMP/old.err"; exit 1; }
  "$TMP/test_old" trace > "$TMP/old.txt"
  "$TMP/test_qctrl" trace > "$TMP/new.txt"
  if diff "$TMP/old.txt" "$TMP/new.txt"; then
    echo "PASS: identical forwarding in modes 0, 2, 3, 6 ($(wc -l < "$TMP/new.txt") trace lines)"
  else
    echo "FAIL: forwarding differs from $2" >&2
    exit 1
  fi
fi
