# titan_k1fp: the passthrough bridge fast path (v2.2)

`payload/titan_k1fp.ko` is a Linux 3.10.0-uc0 kernel module for the Titan
4000, version 2.2. It accelerates steady-state bridged IPv4 and IPv6
TCP/UDP flows between `lte0pdn2` and `eth0` while proving every flow
through the stock bridge and netfilter path first. What it does, how it
coexists with `titan_qctrl` and CBRS SAS gates, and how to test or roll
it back: [docs/fast-path.md](../../docs/fast-path.md).

It is not in the firmware image. An operator stages it per unit and loads
it only after verifying its bytes against `SHA256SUMS`. It starts in
`mode 0` (off) on `insmod`.

## License

`source/titan_k1fp.c`, `source/k1fp_core.h`, `source/k1_fp.h`, and
`source/titan_k310_abi.h` are licensed under the GNU General Public
License, version 2 only (SPDX-License-Identifier: GPL-2.0-only), because
the module runs inside the GPL-2.0 Linux kernel. The full text is in
[`device/sqm/source/COPYING`](../sqm/source/COPYING). The rest of this
repository stays under GPL-3.0-only (see `NOTICE`).

## Rebuild

On Ubuntu 24.04 with the `gcc-arm-linux-gnueabihf` and `binutils` packages:

```sh
device/fastpath/source/build.sh /tmp/fastpath-out
```

The script builds the module with the same flags as the pinned binary,
checks its vermagic, license, imported kernel symbols
(`source/kernel-exports.txt`), ARM relocation types, and module struct
relocations, and compares its SHA-256 with `SHA256SUMS`. CI runs it on
every push. The object carries the compiler's version string, so the
digest matches only with the same GCC build
(`13.3.0-6ubuntu2~24.04.1`). It does not depend on the checkout path.

## Host tests

Run the userspace classifier, lease, CBRS, `titan_qctrl`, watchdog, device re-acquire, TX
ring, SHA-256, and fuzz tests under AddressSanitizer and UndefinedBehaviorSanitizer:

```sh
device/fastpath/test/run.sh
```

## Files

| File | What it is |
| --- | --- |
| `payload/titan_k1fp.ko` | The pinned module binary |
| `SHA256SUMS` | SHA-256 digest for `payload/titan_k1fp.ko` |
| `source/titan_k1fp.c` | Kernel module source |
| `source/k1fp_core.h` | Portable packet classifier, lease table, proof, watchdog, TX ring, and SHA-256 |
| `source/k1_fp.h` | Expected SHA-256 digests of the 8 kernel functions verified at load |
| `source/titan_k310_abi.h` | Linux 3.10.0-uc0 kernel structures with static layout checks |
| `source/kernel-exports.txt` | Kernel symbols the module may import |
| `source/build.sh` | Reproducible build and ELF checks |
| `test/test_k1fp.c` | Userspace unit, integration, and fuzz test suite |
| `test/run.sh` | Builds and runs `test_k1fp.c` under ASan and UBSan |
