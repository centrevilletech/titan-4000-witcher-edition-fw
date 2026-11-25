# titan_qctrl: the download clamp module

`payload/titan_qctrl.ko` is a Linux 3.10.0-uc0 kernel module for the Titan
4000, version v0.3-q3. It keeps the tower's download queue short by shrinking
the TCP receive window that customer devices advertise, and adds opt-in adaptive
ACK thinning (`ack_adapt`) and low-burst window control (`ctrl_v3`) that are off
by default so the default path matches v0.2-o1b. What it does, how the
keeper loads it and how to turn it off: [docs/download-clamp.md](../../docs/download-clamp.md).

Since Witcher v1.0.17 it is in the firmware image
(`/usr/lib/titan-api/modules/titan_qctrl.ko`) and on by default. The build
copies this exact file after checking it against `SHA256SUMS`, which is also
built into the keeper: the keeper loads only bytes that match it, whether the
image's copy or one staged in `/mnt/titan-api/qctrl/`.

## License

`source/titan_qctrl.c` and `source/titan_k310_abi.h` are licensed under the
GNU General Public License, version 2 only (SPDX-License-Identifier:
GPL-2.0-only), because the module runs inside the GPL-2.0 Linux kernel. The
full text is in [`device/sqm/source/COPYING`](../sqm/source/COPYING). The
rest of this repository stays under GPL-3.0-only (see `NOTICE`).

## Rebuild

On Ubuntu 24.04 with the `gcc-arm-linux-gnueabihf` and `binutils` packages:

```sh
device/qctrl/source/build.sh /tmp/qctrl-out
```

The script builds the module with the same flags as the pinned binary, checks
its vermagic, license, imported kernel symbols (`source/kernel-exports.txt`)
and module struct relocations, and compares its SHA-256 with `SHA256SUMS`. CI
runs it on every push. The object carries the compiler's version string, so
the digest matches only with the same GCC build
(`13.3.0-6ubuntu2~24.04.1`). It does not depend on the checkout path.

## Files

| File | What it is |
| --- | --- |
| `payload/titan_qctrl.ko` | The module the keeper accepts |
| `SHA256SUMS` | Its digest, built into the keeper |
| `source/titan_qctrl.c` | Module source |
| `source/titan_k310_abi.h` | The kernel structures it uses, with layouts checked against the unit's kernel |
| `source/kernel-exports.txt` | Kernel symbols it may import |
| `source/build.sh` | Reproducible build and checks |
