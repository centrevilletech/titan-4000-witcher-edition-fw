#!/usr/bin/env bash
# Rebuild titan_k1fp.ko from this directory into a new output directory and
# check it against the pinned digest in ../SHA256SUMS.
#
# Toolchain: Ubuntu 24.04, apt package gcc-arm-linux-gnueabihf
# (GCC 13.3.0-6ubuntu2~24.04.1). The object file carries the compiler's
# version string, so another GCC build gives other bytes. The build does not
# depend on the checkout path.
#
# This is a plain object built with `gcc -c`, not Kbuild: titan_k310_abi.h
# holds the kernel structures it needs, with layouts checked against the
# unit's kernel, and the module struct is in titan_k1fp.c.
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
OUT=${1:?supply an output directory}
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
CC=${CC:-arm-linux-gnueabihf-gcc}
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
  -c "$SCRIPT_DIR/titan_k1fp.c" -o "$OUT/titan_k1fp.ko"

# Module facts the unit's loader checks.
modinfo=$(readelf -p .modinfo "$OUT/titan_k1fp.ko")
grep -qF 'vermagic=3.10.0-uc0 mod_unload ARMv7 ' <<<"$modinfo" || { echo "FAIL: vermagic" >&2; exit 1; }
grep -qF 'license=GPL' <<<"$modinfo" || { echo "FAIL: license" >&2; exit 1; }

# Every imported symbol must be one the unit's kernel exports.
missing=0
while read -r sym; do
  if ! grep -qx -- "$sym" <(grep -v '^#' "$SCRIPT_DIR/kernel-exports.txt"); then
    echo "FAIL: imports $sym, which is not in kernel-exports.txt" >&2
    missing=1
  fi
done < <(readelf -sW "$OUT/titan_k1fp.ko" | awk '$7 == "UND" && $5 == "GLOBAL" { print $8 }' | sort -u)
[ "$missing" = 0 ] || exit 1

# Every ARM relocation must be supported by the Linux 3.10 ARM module loader.
bad_reloc=$(readelf -rW "$OUT/titan_k1fp.ko" | awk '/R_ARM_/ { print $3 }' | sort -u | \
  grep -Ev '^(R_ARM_ABS32|R_ARM_CALL|R_ARM_JUMP24|R_ARM_MOVW_ABS_NC|R_ARM_MOVT_ABS|R_ARM_PREL31|R_ARM_NONE|R_ARM_V4BX)$' || true)
if [ -n "$bad_reloc" ]; then
  echo "FAIL: unsupported ARM relocation(s): $bad_reloc" >&2
  exit 1
fi

# The module struct relocations must match the stock modules (init at 0xbc,
# exit at 0x140), or the loader calls the wrong code.
relocs=$(readelf -r "$OUT/titan_k1fp.ko" | awk '/this_module/ { in_mod = 1; next } /^Relocation section/ { in_mod = 0 } in_mod')
grep -qE '^000000bc .*init_module' <<<"$relocs" || { echo "FAIL: init_module relocation" >&2; exit 1; }
grep -qE '^00000140 .*cleanup_module' <<<"$relocs" || { echo "FAIL: cleanup_module relocation" >&2; exit 1; }

got=$(sha256sum "$OUT/titan_k1fp.ko" | cut -d' ' -f1)
want=$(awk '$2 == "titan_k1fp.ko" { print $1 }' "$SCRIPT_DIR/../SHA256SUMS")
echo "built $OUT/titan_k1fp.ko $got"
if [ "$got" != "$want" ]; then
  echo "FAIL: digest $got is not the pinned $want" >&2
  exit 1
fi
echo "PASS: titan_k1fp.ko matches the pinned digest"
