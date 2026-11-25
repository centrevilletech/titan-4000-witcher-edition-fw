# Building the modem image on the unit

Status: on by default since v1.0.17. The boot hook runs it on the first boot
that needs it (`tk-build boot`, the [default image](tk-boot-loader.md#the-default-image)),
and an operator can run it by hand (`check`, `stage`). It builds one image,
the release image (below), and hands it to the
[boot-time loader](tk-boot-loader.md).

## Why

Witcher ships no modem firmware bytes. Patched modem images (`tk`) used to be
built on a workstation with `tkpatch.py` from the stock image, then copied to
each unit by hand. Now a unit builds its own image. It reads the stock modem
firmware from its own NAND, applies a manifest that holds only Witcher's bytes
and hashes, and writes the gzip file the loader stages.

## The release image

`n6h-r4-r1`, the only manifest the keeper carries (`manifests::RELEASE`):

| Layer | From | What it adds |
| --- | --- | --- |
| N6H | lane N6H | The latency image: N4's uplink AQM v2 and grant hold, N5's sparse-flow lane, the IMG2 to IMG4 data-path patches, U2's LNK-FIX filter, baked radio stability defaults. |
| R4 | lane R4, PR #39 | N4's uplink engine rewritten in Rust (`no_std`, Thumb-2). |
| R1 | lane R1, PR #42 | M1's Rust PIE uplink AQM, hardened, with the overload latch. M1 block version `0x20261126`. |

Lane R1 built and verified it as `build-combined`: R4's stack spec with its two
`m1_*` sites replaced by R1's. The spec is `becd500c…`, `tk.bin` is
`f1aa8add…`, and `tk.gz` is `3348aa36…`. The unit's build reproduces both
files byte for byte (see [Tests](#tests)). Every feature boots off. The keeper
turns on the ones `tk/config` lists after the boot confirm, and it manages
the PIE selector of M1 block `0x20261126` (see
[Modem feature flags](tk-boot-loader.md#modem-feature-flags)).

## Use

At boot, with no operator files in `tk/`, the hook runs
`titan-pd-keeper tk-build boot` (read-only: decide) and, when a build is due,
`titan-pd-keeper tk-build boot --write` (build). That path builds only from
the bank `/proc/cmdline` names active, writes a default `tk/config` with the
latency profile's words, and records each build in `tk/default`
([the default image](tk-boot-loader.md#the-default-image)).

By hand:

```sh
titan-pd-keeper tk-build check   # build in memory, check every hash, write nothing
titan-pd-keeper tk-build stage   # also write tk/active.gz and tk/config
```

`stage` ends with the next boot's plan. Reboot outside the SAS window (no new
grants 07:00 to 10:00 UTC; avoid 06:45 to 10:15). From there the loader takes
over: the strike count, the boot confirm and the rollback to stock firmware.

```text
manifest n6h-r4-r1: 71 sites; image f1aa8add…; gzip 3348aa36… (4656029 bytes)
tk (mtd17, 0 bad blocks skipped): stock 555362d9…; built image f1aa8add…, gzip 3348aa36… (4656029 bytes)
staged /mnt/titan-api/tk/active.gz: the next boot loads it (reboot outside the SAS window)
```

It runs at nice 19, because the unit has one Linux core and forwarding must not
wait for it.

## What it reads

| Input | How |
| --- | --- |
| The stock image | The NAND banks named `tk` and `tk2` in `/proc/mtd` (`mtd17`, `mtd18`): a gzip stream at offset 0, then `0xff` padding. It reads `/dev/mtdN` read-only, erase block by erase block, and skips blocks the bad block table marks bad, as the vendor kernel does for `modem.ko`. The only ioctl is `MEMGETBADBLOCK`. Either bank serves if it holds the exact stock image. |
| The manifest | Built into the keeper: `userspace/tk-patch/manifests/n6h-r4-r1.manifest` (`manifests::RELEASE`). The other manifests in the tree (N6H, M1, R1, R4) are not in the keeper, because each would cost about 20 KiB of flash. They build on a host with `tk-patch build`, and CI proves them. |

## What it checks

Any mismatch stops the build, and `stage` writes nothing (its temporary file is
removed).

| Check | Against |
| --- | --- |
| The stock image, decompressed | Its size and SHA-256 (`555362d9…`, V1.6.0.P0 R3882-4172), and the gzip trailer's CRC-32 and length |
| Each site's stock bytes | The SHA-256 the manifest pins for that site |
| The patched image | The manifest's SHA-256: the image the bench tested |
| The gzip file | The manifest's size and SHA-256: the file the bench loaded, byte for byte |
| The file on flash | Read back and hashed again before it replaces `active.gz` |

## What it writes (`stage` only)

| File | Content |
| --- | --- |
| `tk/active.gz` | The built image. It is written to `tk/.active.gz.tk-build`, synced and read back, then renamed over `active.gz`. |
| `tk/config` | `enabled=1` and one `sha256=` line for the built image, then every other line of the old config in order (`target=`, `wm=`, `manage=`, `hold_ack=`, comments). It is replaced by a rename after the image. |

The keeper also notes the build in its RAM log. It changes nothing else.
`strikes`, `quarantine` and `confirmed` belong to the loader and the boot
confirm. When either would keep stock firmware at the next boot, `tk-build`
says so and leaves the file alone:

- `strikes` at 2: write `strikes=0` to try again;
- the image's hash in `quarantine`: remove the line to try again.

`stage` makes `tk/config` an operator's config (it drops a default config's
marker line), so later boots leave it alone. The keeper reads `tk/config` every 15 s, so on a
running staged boot that was confirmed, `stage` also turns its `wm=` flags back
on if `enabled` was 0.

A run that dies leaves `tk/.active.gz.tk-build` behind, and the next run refuses
until it is removed. That keeps two runs from writing at once.

## The image is the bench file, byte for byte

The gzip writer is a port of zlib 1.3's level-9 deflate. Its output is what
Python's `gzip.compress(data, 9, mtime=0)` writes, with the OS byte set to 3 as
`tkpatch.py` sets it: the same `tk.gz` the bench ran. This matters because
`modem.ko` decompresses with the old kernel `lib/inflate.c`, which rejects some
valid streams other compressors write (incomplete code trees). A file that
opens but does not decompress is not a fallback (see
[the loader](tk-boot-loader.md#what-the-gated-module-does)).

| Manifest | Image (`tk.bin`) | Gzip (`tk.gz`) |
| --- | --- | --- |
| `n6h` | `a2fc8994…` | `a1fc066a…` (4655428 bytes) |
| `m1` | `cd7effdd…` | `e47b0435…` (4655664 bytes) |
| `r1` | `f434277d…` | `186697f3…` (4655738 bytes) |
| `r4` | `60ab8fe7…` | `4ced9782…` (4655937 bytes) |
| `n6h-r4-r1` (release) | `f1aa8add…` | `3348aa36…` (4656029 bytes) |

## The manifest

```text
witcher-tk-manifest 1
name n6h-r4-r1
base 0x84100000
stock 9553965 <SHA-256 of the stock image>
image 9553965 <SHA-256 of the patched image>
gzip 4656029 <SHA-256 of the gzip file>
site 0x841108f8 4 img4_u3_kvp <SHA-256 of the 4 stock bytes there> ecf2d3f9
site 0x843de954 888 img2_cave_a_print_dbinfo <SHA-256> <hex> @0x842d8bd1:61 <hex>
```

A site replaces `len` stock bytes at its VA. Its replacement is Witcher's
bytes in hex, plus `@VA:LEN` references to stock bytes earlier in the image,
which the unit copies from its own firmware. The header lines come first, in
this order. Sites are sorted, even, apart and inside the image. Every reference
ends before its site, so the build is one pass over the stock image, in about
400 KiB of memory.

## Making a manifest

The host tool reads `tkpatch.py` specs. It applies the same checks:

- sites sorted by offset, at even offsets, with `va = 0x84100000 + offset`;
- sites apart and inside the image;
- `expected` is what the stock image holds;
- every site has a name and a reason.

It then builds the image the way the unit will and compares it with the Python
build:

```sh
cargo run --release --manifest-path userspace/Cargo.toml -p witcher-tk-patch-cli -- \
  manifest STOCK SPEC NAME -o userspace/tk-patch/manifests/NAME.manifest --image tk.bin --gzip tk.gz
```

`STOCK` is the stock `.prg`, its tk gzip stream (`03_tk.gzip` or a NAND bank
dump) or `tk.bin`. The other commands:

- `tk-patch build STOCK MANIFEST [-o DIR]` builds as the unit does;
- `tk-patch show MANIFEST` lists the sites;
- `tk-patch gzip` and `tk-patch gunzip` filter stdin through the same codec.

Thumb decoding stays in `tkpatch.py`'s audit (Capstone or objdump).

To ship another image:

1. Add its manifest under `userspace/tk-patch/manifests/`.
2. Add its bench hashes to the tests.
3. Point `manifests::RELEASE` at it.

A keeper test refuses a release image whose M1 block version the keeper does
not manage (`tk_flags::M1_VERSIONS`).

## Licensing

- **No modem firmware in the source or the image.** A manifest holds:
  - Witcher's replacement bytes, assembled from this project's patch sources;
  - SHA-256 values of the stock bytes each site replaces;
  - references to stock bytes elsewhere in the image.

  The unit combines them with the stock firmware it already holds. Each unit
  builds its own copy, and no patched image is distributed.
- **Copied runs become references.** At each position, when the next 16
  replacement bytes hold at least 8 distinct values and occur in the stock image
  before the site, the longest such match becomes a reference. Today that is
  two runs in IMG2's cave (61 and 22 bytes) that re-create vendor code. What
  stays literal and also occurs in the stock image is fill (zeros, a few
  distinct values) or under 16 bytes. Those short runs are instructions a hook
  displaces and re-executes, written out in Witcher's own patch sources.
- **Hashes are not copies.** A SHA-256 value names the bytes a site expects
  without containing them. For a site of a few bytes the value can be guessed by
  trying every word, much as the VA already says which instruction it is.
- **The deflate port** is a translation of zlib's code under the zlib license
  ([third-party notices](../THIRD_PARTY.md)).
- The image the unit builds is still modified vendor baseband firmware, and
  since v1.0.17 units build and load it by default. The
  [regulatory note](tk-boot-loader.md#regulatory-note) applies. This page
  describes the engineering, not legal advice.

## Tests

- `cargo test` covers:
  - the codec against zlib on generated inputs (stored, static and dynamic
    blocks, window slides, any input split);
  - the manifest rules;
  - the patcher's refusals;
  - the whole pipeline.
- The CI job "Modem image builder against the bench images" downloads the stock
  `.prg` (the vendor's public file, pinned by SHA-256). It then:
  - rebuilds every manifest in the tree (N6H, M1, R1, R4 and the release
    image) and requires the Python builds' `tk.bin` and `tk.gz` hashes;
  - turns each manifest back into a spec and through the Rust converter, which
    must give the same text;
  - checks `tk-patch gzip` against Python's zlib on about 30 more inputs.
  The real images also run zlib's code-length overflow repair, which the
  generated inputs do not reach.
- `scripts/test-tk-patch.py` applies the manifests with an independent Python
  parser. It also fails if any manifest's own bytes hold a 16-byte window with 8
  or more distinct values that occurs anywhere in the stock image: vendor runs
  must be references.
- `scripts/test-tk-build.py` runs the keeper's `tk-build` end to end. Its NAND
  banks are stand-in files: the stock stream padded with `0xff` to 8 MiB. It
  checks that:
  - `check` writes nothing;
  - `stage` writes the bench file and the merged config, and leaves strikes and
    quarantine alone;
  - a damaged `tk` bank falls back to `tk2`;
  - no stock bank, or a leftover temporary file, refuses and changes nothing.

  The stand-ins have no bad block table, so the vendor kernel's MTD driver is
  for the bench to prove.
- `scripts/test-tk-stage.py` runs the boot hook with the real keeper against
  the same stand-in banks (`RealDefaultImage`, in the same CI job). It checks
  that:
  - the first boot builds and loads the image for the same `modprobe`;
  - the next boot reuses it;
  - the default config's words are what `stage-latency.sh --profile latency`
    writes for the image;
  - a bank that is not the stock image, or an inactive bank that is, builds
    nothing;
  - an operator config, or an image without a config, is left alone;
  - a failed build keeps stock firmware and stops after 3 builds;
  - what a killed build leaves is cleaned up and built again.
