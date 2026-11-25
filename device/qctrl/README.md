# titan_qctrl: the download clamp module

`payload/titan_qctrl.ko` is a Linux 3.10.0-uc0 kernel module for the Titan
4000, version v0.4. It keeps the tower's download queue short by shrinking
the TCP receive window that customer devices advertise, and adds opt-in adaptive
ACK thinning (`ack_adapt`) and low-burst window control (`ctrl_v3`) that are off
by default so the default path matches v0.2-o1b. What it does, how the
keeper loads it and how to turn it on: [docs/download-clamp.md](../../docs/download-clamp.md).

v0.4 adds the upload clamp (mode bit 16): it lowers the receive window in the
servers' ACKs, so each customer upload keeps only a short queue in the modem.
See [docs/upload-clamp.md](../../docs/upload-clamp.md). With bit 16 clear,
v0.4 forwards exactly what v0.3-q3 did (`test/run.sh --identity`).

It is not in the firmware image. An operator stages it per unit in
`/mnt/titan-api/qctrl/`, and the keeper loads it only when its bytes match
the digest in `SHA256SUMS`, which is built into the keeper.

## License

`source/titan_qctrl.c`, `source/ulclamp_core.h`, `source/titan_k310_abi.h` and
the files in `test/` are licensed under the
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
| `source/ulclamp_core.h` | The upload clamp's law, shared with the host tests |
| `source/titan_k310_abi.h` | The kernel structures it uses, with layouts checked against the unit's kernel |
| `source/kernel-exports.txt` | Kernel symbols it may import |
| `source/build.sh` | Reproducible build and checks |
| `test/test_qctrl.c`, `test/mock_k310.h` | Host tests: the module source itself against a mock kernel |
| `test/run.sh` | Runs them under ASan and UBSan (CI); `--identity OLD.c` proves modes 0, 2, 3 and 6 forward what `OLD.c` did |
