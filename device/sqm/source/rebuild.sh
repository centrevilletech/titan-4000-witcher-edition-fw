#!/usr/bin/env bash
# Rebuild the ARM payload in a fresh output directory on Ubuntu 24.04.
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
mkdir "${1:?supply a new output directory}"
OUTDIR=$(cd "$1" && pwd)
WORK="$OUTDIR/work"
KDIR="$WORK/linux-3.10"
ZIG=${ZIG:-zig}
mkdir -p "$WORK" "$OUTDIR/modules" "$OUTDIR/bin"
cd "$WORK"
curl -fL --retry 3 https://cdn.kernel.org/pub/linux/kernel/v3.x/linux-3.10.tar.xz -o linux.tar.xz
curl -fL --retry 3 https://mirrors.edge.kernel.org/pub/linux/utils/net/iproute2/iproute2-5.19.0.tar.xz -o iproute2.tar.xz
tar -xf linux.tar.xz
tar -xf iproute2.tar.xz
git init -q sch_cake
git -C sch_cake fetch --depth 1 https://github.com/dtaht/sch_cake.git 53ff94d4b58071307084d47a7937afbe71e40070
git -C sch_cake checkout --detach FETCH_HEAD

cd "$KDIR"
sed -i 's/^EXTRAVERSION =.*/EXTRAVERSION = -uc0/' Makefile
GCC_MAJOR=$(arm-linux-gnueabihf-gcc -dumpversion | cut -d. -f1)
cp include/linux/compiler-gcc4.h "include/linux/compiler-gcc${GCC_MAJOR}.h"
if [ -f scripts/dtc/dtc-lexer.lex.c_shipped ]; then
  sed -i 's/^YYLTYPE yylloc;/extern YYLTYPE yylloc;/' scripts/dtc/dtc-lexer.lex.c_shipped
fi

for p in \
  01-gct-skbuff-abi.patch \
  02-gct-netdevice-abi.patch \
  03-hz-1000.patch \
  04-gcc13-armv7.patch
do
  patch -p0 < "$SCRIPT_DIR/$p"
done

cp "$SCRIPT_DIR/titan-3.10.0-uc0.config" .config
make ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- olddefconfig

KCFLAGS="-ffile-prefix-map=$WORK/sch_cake=. -std=gnu89 -fno-pie -fno-pic -Wno-attribute-alias -Wno-packed-not-aligned -Wno-maybe-uninitialized -Wno-array-bounds -Wno-missing-attributes"
make ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- KCFLAGS="$KCFLAGS" modules_prepare >/dev/null

make ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- KCFLAGS="$KCFLAGS" M=net/sched modules
(cd "$WORK/sch_cake" && patch -p1 < "$SCRIPT_DIR/05-sch_cake-kvzalloc-nowarn.patch")
make ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- KCFLAGS="$KCFLAGS" M="$WORK/sch_cake" modules
arm-linux-gnueabi-strip --strip-debug -o "$OUTDIR/modules/sch_cake.ko" "$WORK/sch_cake/sch_cake.ko"
arm-linux-gnueabi-strip --strip-debug -o "$OUTDIR/modules/sch_fq_codel.ko" "$KDIR/net/sched/sch_fq_codel.ko"
cd "$WORK/iproute2-5.19.0"
grep -q "libgen.h" lib/bpf_legacy.c || sed -i '1i #include <libgen.h>' lib/bpf_legacy.c
cat <<MK > config.mk
CC := $ZIG cc -target arm-linux-musleabi -mcpu=cortex_a7 -static
AR := $ZIG ar
HOSTCC := gcc
SHARED_LIBS := n
HAVE_MNL := n
HAVE_ELF := n
HAVE_BPF := n
HAVE_CAP := n
HAVE_SELINUX := n
HAVE_TIRPC := n
HAVE_BERKELEY_DB := n
TC_CONFIG_NO_XT := y
CFLAGS += -Os -D_GNU_SOURCE -DNO_SHARED_LIBS -DHAVE_SETNS -DHAVE_HANDLE_AT
LDFLAGS += -static
LDLIBS += -lm
MK
cat <<'C' > tc/emp_ematch.tab.c
#include <stdio.h>
#include "m_ematch.h"
int ematch_parse(void) {
    fprintf(stderr, "ematch parser not compiled in this minimal static tc\n");
    return 1;
}
C
echo 'void ematch_lex_stub(void) {}' > tc/emp_ematch.lex.c
touch tc/emp_ematch.tab.h
make -j"$(nproc)" SUBDIRS="lib tc" SHARED_LIBS=n TC_CONFIG_NO_XT=y
arm-linux-gnueabi-strip -o "$OUTDIR/bin/tc" tc/tc
chmod 755 "$OUTDIR/bin/tc"
