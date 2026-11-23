#!/usr/bin/env bash
# Rebuild titan_ufq.ko from this directory into a new output directory, check
# its ABI/symbols/relocations against the unit's kernel, compare against the
# pinned digest in ../SHA256SUMS, and run the userspace scheduler self-test.
#
# Toolchain: Ubuntu 24.04, apt packages gcc-arm-linux-gnueabihf and
# build-essential (GCC 13.3.0-6ubuntu2~24.04.1).
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
OUT=${1:?supply an output directory}
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
CC=${CC:-arm-linux-gnueabihf-gcc}
HOST_CC=${HOST_CC:-gcc}
WANT_CC='arm-linux-gnueabihf-gcc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0'

have=$("$CC" --version | head -n 1)
if [ "$have" != "$WANT_CC" ]; then
  echo "note: compiler is '$have', the pinned build used '$WANT_CC'; the digest may differ" >&2
fi

"$CC" \
  -march=armv7-a -marm -mabi=aapcs-linux \
  -msoft-float -mfloat-abi=soft \
  -mno-unaligned-access \
  -fno-pic -fno-pie -fno-stack-protector -fno-common -ffreestanding \
  -fno-asynchronous-unwind-tables \
  -fno-strict-aliasing -fno-strict-overflow -fno-delete-null-pointer-checks \
  -O2 -Wall -Wextra -Werror \
  -c "$SCRIPT_DIR/titan_ufq.c" -o "$OUT/titan_ufq.ko"

# Module facts the unit's loader checks.
modinfo=$(readelf -p .modinfo "$OUT/titan_ufq.ko")
grep -qF 'vermagic=3.10.0-uc0 mod_unload ARMv7 ' <<<"$modinfo" || { echo "FAIL: vermagic" >&2; exit 1; }
grep -qF 'license=GPL' <<<"$modinfo" || { echo "FAIL: license" >&2; exit 1; }

# Every imported symbol must be one the unit's kernel exports.
missing=0
while read -r sym; do
  if ! grep -qx -- "$sym" <(grep -v '^#' "$SCRIPT_DIR/kernel-exports.txt"); then
    echo "FAIL: imports $sym, which is not in kernel-exports.txt" >&2
    missing=1
  fi
done < <(readelf -sW "$OUT/titan_ufq.ko" | awk '$7 == "UND" && $5 == "GLOBAL" { print $8 }' | sort -u)
[ "$missing" = 0 ] || exit 1

# The module struct relocations must match the stock modules (init at 0xbc,
# exit at 0x140), or the loader calls the wrong code.
relocs=$(readelf -r "$OUT/titan_ufq.ko" | awk '/this_module/ { in_mod = 1; next } /^Relocation section/ { in_mod = 0 } in_mod')
grep -qE '^000000bc .*init_module' <<<"$relocs" || { echo "FAIL: init_module relocation" >&2; exit 1; }
grep -qE '^00000140 .*cleanup_module' <<<"$relocs" || { echo "FAIL: cleanup_module relocation" >&2; exit 1; }

# Run the userspace scheduler self-test and packet-level LTE simulation.
"$HOST_CC" -O2 -Wall -Wextra -Werror "$SCRIPT_DIR/test_ufq_sim.c" -o "$OUT/test_ufq_sim" -lm
"$OUT/test_ufq_sim"

got=$(sha256sum "$OUT/titan_ufq.ko" | cut -d' ' -f1)
want=$(awk '$2 == "titan_ufq.ko" { print $1 }' "$SCRIPT_DIR/../SHA256SUMS")
echo "built $OUT/titan_ufq.ko $got"
if [ "$got" != "$want" ]; then
  echo "FAIL: digest $got is not the pinned $want" >&2
  exit 1
fi
echo "PASS: titan_ufq.ko matches the pinned digest"
