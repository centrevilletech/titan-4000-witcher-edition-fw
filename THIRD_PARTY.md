# Component provenance and licenses

The [project notice](NOTICE) and [GPLv3 license](LICENSE) cover Centreville
Tech's original contributions. They do not relicense vendor firmware,
dependencies, artwork or trademarks.

## Source-built components

The UI, first-boot service and network keeper are built from this repository.
Rust dependencies are pinned in `userspace/Cargo.lock`; UI dependencies are
pinned in `web/package-lock.json`. Lockfiles identify versions, but do not
replace the dependencies' copyright and license notices.

| Component | Origin and license | Notices |
| --- | --- | --- |
| Jitterentropy 3.7.0 | Upstream source, BSD option | [Pinned upstream revision](userspace/entropy/vendor/jitterentropy/UPSTREAM), [license](userspace/entropy/vendor/jitterentropy/LICENSE.bsd); installed in the image as `jitterentropy-LICENSE` |
| IBM Plex Sans and Mono, Fontsource 5.3.0 | IBM fonts, SIL Open Font License 1.1 | [Sans](web/public/licenses/ibm-plex-sans-LICENSE.txt), [Mono](web/public/licenses/ibm-plex-mono-LICENSE.txt) |
| Lucide 1.49.0 | Lucide contributors, ISC with included icon notices | [License](web/public/licenses/lucide-LICENSE.txt) |
| Noble hashes 2.4.0 | Paul Miller, MIT | [License](web/public/licenses/noble-hashes-LICENSE.txt) |

The UI serves its bundled notices at `/ui/licenses/index.html`. Keep these
copies synchronized when upgrading dependencies. Build and test dependencies
have their own terms even when they are not installed on the device.

## Pinned services and vendor input

The API, device helper, maintenance, NVRAM and native SSH programs currently
include precompiled inputs under `overlay/usr/lib/titan-api/`. Their matching
source, dependency inventories and reproducible builds are not all provided
here. A SHA-256 pin establishes which bytes were used; it does not establish
license compliance or supply corresponding source.

The build also uses a separately downloaded vendor PRG containing the kernel,
modem payload, utilities, libraries and factory recovery pages. Their respective
licenses and any redistribution restrictions still apply. A public download
URL is not, by itself, a grant to redistribute or relicense those contents.

Before distributing a complete image, resolve the corresponding-source and
notice requirements for all included components, including modified vendor
components. See [GNU GPLv3 section 6](https://www.gnu.org/licenses/gpl-3.0.html#section6)
for distribution of covered object code. This inventory is not a complete
firmware SBOM or a claim that all distribution obligations are satisfied.

## Modem module copy and modem firmware

The build patches vendor binaries from the stock image, as it does for
`gdmlte.ko` and `cbrs_fsm`. For the [boot-time modem firmware loader](docs/tk-boot-loader.md)
it also writes a second copy of the vendor `modem.ko` with one 4-byte
instruction changed. The stock `modem.ko` stays in the image unchanged.

Neither this repository nor the image carries modem firmware (`tk`) bytes,
stock or patched. The image keeps the stock modem payload byte for byte. The
keeper carries a patch manifest (`userspace/tk-patch/manifests/`) of Witcher's
replacement bytes, SHA-256 values of the stock bytes they replace, and
references to stock bytes elsewhere in the image. A unit builds the patched
image from the stock firmware in its own NAND ([how](docs/tk-patch.md)); an
operator can also stage an image by hand. Do not publish built images: they
are modified vendor firmware.

## zlib (deflate port)

`userspace/tk-patch/src/deflate.rs` and `trees.rs` are a Rust translation of
the level-9 path of zlib 1.3's `deflate.c` (Copyright (C) 1995-2023 Jean-loup
Gailly and Mark Adler) and `trees.c` (Copyright (C) 1995-2021 Jean-loup
Gailly), altered for one configuration, so that the unit writes the same modem
image bytes zlib does. The zlib license applies to those files:

> This software is provided 'as-is', without any express or implied
> warranty. In no event will the authors be held liable for any damages
> arising from the use of this software.
>
> Permission is granted to anyone to use this software for any purpose,
> including commercial applications, and to alter it and redistribute it
> freely, subject to the following restrictions:
>
> 1. The origin of this software must not be misrepresented; you must not
>    claim that you wrote the original software. If you use this software
>    in a product, an acknowledgment in the product documentation would be
>    appreciated but is not required.
> 2. Altered source versions must be plainly marked as such, and must not be
>    misrepresented as being the original software.
> 3. This notice may not be removed or altered from any source distribution.

The decoder in `userspace/tk-patch/src/inflate.rs` is written from RFC 1951
and decodes Huffman codes by the method of Mark Adler's `puff.c`; it copies no
zlib code.

## Images and screenshots

The screenshots are generated from the current UI with synthetic fixtures;
see [capture instructions](docs/screenshots/README.md). The login background
`web/public/titan-rooftop.jpg` was imported with the original UI. The project owner confirmed it is an original Centreville Tech photograph.
Copyright 2026 Centreville Tech, LLC; distributed under the project GPLv3 terms.

## Smart queue management

The repository carries, in `device/sqm/payload` (staged on a unit's persistent
volume, not packed in the image), iproute2 5.19.0 `tc` linked statically with
musl from Zig 0.14.1, Linux 3.10 fq_codel, and the out-of-tree CAKE scheduler
at commit `53ff94d4b58071307084d47a7937afbe71e40070`. CAKE uses GPL-2.0 or BSD-3-Clause.
The kernel and iproute2 carry GPL terms. The musl notice, kernel configuration,
ABI patches, exact upstream source locations and ARM build recipe accompany
the payload in [device/sqm/source](device/sqm/source/). Release distributors
should include these inputs and the corresponding upstream sources.

## Download clamp and fast path modules

`device/qctrl/payload/titan_qctrl.ko` and `device/fastpath/payload/titan_k1fp.ko`
are original Centreville Tech, LLC kernel modules. Since v1.0.17 both are packed
in the image at `/usr/lib/titan-api/modules/`. Their sources in
[device/qctrl/source](device/qctrl/source/) and
[device/fastpath/source](device/fastpath/source/) are licensed GPL-2.0-only,
because the modules run inside the GPL-2.0 Linux kernel; the license text is
[device/sqm/source/COPYING](device/sqm/source/COPYING). Each `build.sh` rebuilds
its binary byte for byte with Ubuntu 24.04's `gcc-arm-linux-gnueabihf`
(GCC 13.3.0-6ubuntu2~24.04.1).
