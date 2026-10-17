# Building Witcher

Use the stock `GTCGR_TITAN4K_V1.6.0P0_R3882-4172-CBRS.prg` outside the repository.
Its required SHA-256 is
`ec18547470302cec65529c501f06971075a06516f7c10f03b8573e18138ea04a`.
The build rejects other inputs. The workflow documents the download source.

Install:

- mtd-utils 2.3.1 (`mkfs.ubifs`, `ubinize`) with LZO, and `fakeroot`.
- Python 3, `ubi_reader==0.8.16`, and `python-lzo`.
- Node.js 22 and the locked dependencies (`npm ci --prefix web`).
- Rust 1.99.0 with `armv7-unknown-linux-musleabi`; builds use its bundled linker.
- Zig 0.14.1 (`pip install ziglang==0.14.1`) for the vendored Jitterentropy
  collector, compiled at `-O0` without link-time optimization.

```bash
npm ci --prefix web
scripts/build-firmware.sh /path/to/stock.prg -o out/witcher.prg
scripts/verify-firmware.py /path/to/stock.prg out/witcher.prg
```

Official builds require the `LEGACY_CREDENTIAL_DENYLIST` Actions secret for
additional known-credential absence checks. It is passed as
`WITCHER_CREDENTIAL_DENYLIST_JSON`; it is never installed in the image.
Local builds need no shared password: the stock root hash is discovered from
the hash-pinned vendor input and both account writers are changed to locked.
The generic root-hash/private-key checks always run. To run the additional
private denylist locally, supply that environment variable from your secret
manager, not a tracked file or command-line argument.

`VERSION` supplies the Witcher UI and `/etc/witcher-release` version. The latter
also records the source commit, dirty-tree flag and vendor base version.
Use a new version for a new firmware release and match the tag to it.

The builder compiles `web/`, `userspace/firstboot`, `userspace/pd-keeper` and
`userspace/entropy`. Other native services are pinned binaries under `overlay/`;
their source has not yet been imported from the private ops repository.

| Path | Contents |
| --- | --- |
| `overlay/` | Pinned services, startup scripts and configuration templates |
| `userspace/` | First-boot, keeper, protocol and entropy source |
| `web/` | Device UI, locked dependencies and browser tests |
| `scripts/` | Build, patch, image verification and regression tools |
| `device/` | Factory device-node definitions |
| `docs/` | Implementation notes and synthetic UI screenshots |
| `out/` | Ignored local build output |

CI runs on disposable GitHub-hosted runners. Pull requests get the source and
browser tests; trusted pushes and tags also build and verify the firmware in a
container. Firmware candidates are retained as Actions artifacts; releases are published
manually from the exact verified and tested bytes.

The native web/setup/recovery listeners are IPv4-only. Factory desktop pages
are stored compressed and expanded into RAM for recovery; mobile pages and
large decorative/audio assets are omitted. Factory shared TLS files and the vendor SSH host keys embedded in `rcinit` are removed.
Witcher generates a separate per-unit TLS identity.

Read [component provenance and licensing](../THIRD_PARTY.md) before distributing
an image. The root GPL grant does not supply missing vendor redistribution
rights or corresponding source for bundled binaries.
