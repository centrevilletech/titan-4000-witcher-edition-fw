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
