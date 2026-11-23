# titan_ufq: uplink flow queue with modem backpressure

`payload/titan_ufq.ko` is a Linux 3.10.0-uc0 kernel module for the Titan 4000
(version v0.1). It isolates sparse uplink flows (ping, DNS, voice, gaming, TLS
handshakes, download TCP ACKs) from bulk uploads without needing DSCP marking or
a static rate limit. See [docs/uplink-flow-queue.md](../../docs/uplink-flow-queue.md)
for the queueing model, controls, and rollback procedure.

The module loads in pass-through mode (`mode=0`) and stays off until an
operator enables it through `/proc/titan_ufq`. It requires no modem firmware
change and loads or unloads live with `insmod` and `rmmod`.

## License

`source/titan_ufq.c`, `source/ufq_core.h`, `source/titan_k310_abi.h`, and
`source/test_ufq_sim.c` are licensed under the GNU General Public License,
version 2 only (`SPDX-License-Identifier: GPL-2.0-only`), because the module
runs inside the GPL-2.0 Linux kernel. The full text is in
[`device/sqm/source/COPYING`](../sqm/source/COPYING). The rest of this
repository stays under GPL-3.0-only (see `NOTICE`).

## Rebuild and test

On Ubuntu 24.04 with `gcc-arm-linux-gnueabihf`, `build-essential`, and
`binutils`:

```sh
device/ufq/source/build.sh /tmp/ufq-out
```

The script compiles `titan_ufq.ko` with the same flags as the pinned binary,
checks vermagic, license, imported kernel symbols (`source/kernel-exports.txt`),
and `this_module` relocations (`init` at `0xbc`, `exit` at `0x140`), runs the
userspace scheduler self-test and packet-level LTE simulation (`test_ufq_sim`),
and checks the built `.ko` against `SHA256SUMS`. CI runs it on every push. The
object embeds the GCC version string, so exact byte equality requires GCC
`13.3.0-6ubuntu2~24.04.1`.

## Files

| File | What it is |
| --- | --- |
| `payload/titan_ufq.ko` | Pinned ARMv7 kernel module binary |
| `SHA256SUMS` | Pinned SHA-256 digest of `titan_ufq.ko` |
| `source/titan_ufq.c` | Linux 3.10.0-uc0 bridge netfilter hook, modem RAM reader, `/proc/titan_ufq` |
| `source/ufq_core.h` | Shared per-flow DRR + sparse fast-pass + CoDel + modem BQL engine |
| `source/titan_k310_abi.h` | Binary-verified Linux 3.10.0-uc0 kernel structures and exports |
| `source/kernel-exports.txt` | Whitelist of kernel symbols `titan_ufq.ko` may import |
| `source/test_ufq_sim.c` | Userspace unit tests and packet-level LTE TDD Config 2 simulator |
| `source/build.sh` | Reproducible build, ABI checks, self-test, and SHA-256 check |
