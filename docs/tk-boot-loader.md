# Boot-time modem firmware loader

Status: bench only, off by default. Nothing changes on a unit until an
operator stages an image and turns it on. This firmware ships no modem
firmware bytes and writes no modem feature flags.

## Why

The modem firmware (`tk`) runs on the Titan's second CPU. Bench tests load
patched images today by opening a gate in the running `modem.ko`, binding a
RAM copy over `/lib/firmware`, setting `kern em mode 0` and running
`kern modem reset 0`. That reload oopses `kmon_thrd`, so the unit loses modem
crash recovery until the next reboot, and only one reload per boot is safe.
Every reload also gives the SAS grants back.

This loader instead gives the image to the first `modprobe modem` of a boot.
There is no runtime reset, crash recovery stays on, and both NAND `tk` banks
stay stock.

## What ships in the image

| Piece | Where | What it does |
| --- | --- | --- |
| Stock `modem.ko` | `/lib/modules/3.10.0-uc0/extra/modem.ko` | Unchanged, byte for byte. Loads on every boot that does not stage an image. |
| Gated copy | `/usr/lib/titan-api/tk/modem-tkfs.ko` | The stock module with one instruction changed (below). Loads only on a staged boot. |
| Boot hook | `/etc/init.d/witcher-tk-stage` | `pre` runs right before `start_lte.sh`'s one `modprobe modem`, `post` right after it. |
| Boot confirm | `titan-pd-keeper` | Confirms a staged boot, or quarantines the image and reboots once onto stock. |

`scripts/patch-modem-ko.py` makes the gated copy at build time. It refuses any
input but the stock module (SHA-256 `6993588f...d5c8`) and checks the output
(`161ffdd0...5977`). `scripts/verify-firmware.py` checks that the stock module
is untouched, that the copy differs only in those 4 bytes, that the hook runs
only around the modprobe, and that the root filesystem holds no modem firmware
image.

## What the gated module does

The change is at `.text+0x2054` (file offset `0x2088`) in `read_tk_image`:
`bls 0x20a0` (`11 00 00 9a`) becomes `nop` (`00 f0 20 e3`). Stock code skips
the filesystem there and reads NAND. The gated copy tries the filesystem
first. From the stock disassembly (`.text` addresses):

| Address | Code |
| --- | --- |
| `0x2058..0x2060` | Calls the filesystem loader at `0x1e84`. |
| `0x1e84` -> `0x1da8` | `get_modem_fw_filename` opens `/lib/firmware/tk.gz`, then `/lib/firmware/tk.xz`. If neither opens it returns NULL, and `0x1e84` returns -22 at `0x1ee4` without calling `request_firmware`. |
| `0x2064..0x2098` | A negative result falls through and loads the NAND bank, with the same code and bank as the stock path at `0x20a0..0x20c8`. |
| `0x1eac..0x1ed8` | If a file opened: `request_firmware`, log `read from fs`, call the loader callback, then return 0 whatever the callback did. |
| `0x1824..0x1844` | The callback (`firware_downalod`) decompresses and returns 0 whatever the decompressor did. |

So the fallback answer has two parts:

- **No `tk.gz` and no `tk.xz` in `/lib/firmware`: stock NAND firmware.** The
  stock root filesystem has neither (only `.keep` and `mrvl/`).
- **A file that opens but is bad is not a fallback.** `read_tk_image` returns
  0 and the modem CPU starts on whatever reached its RAM. Linux keeps running
  (the probe does not fail), but LTE does not come up.

That is why the hook binds `/lib/firmware` only after the copy it binds has
passed every check, binds nothing on any failure, and removes the image right
after the modprobe. A later modem crash then reloads stock NAND firmware
through the normal crash recovery.

## Turning it on (bench only)

Reboot only outside the SAS window when no new grants are issued (07:00 to
10:00 UTC; avoid 06:45 to 10:15). Keep wired recovery connected.

```sh
# On a workstation: the image and its digest.
sha256sum tk.gz
# Over the enrolled operator SSH login.
ssh <unit> 'mkdir -p /mnt/titan-api/tk && chmod 700 /mnt/titan-api/tk'
scp tk.gz <unit>:/mnt/titan-api/tk/active.gz
ssh <unit> 'cat > /mnt/titan-api/tk/config && sync' <<'EOF'
enabled=1
sha256=<64 hex digits from sha256sum>
target=<address that answers ping through the management bearer>
EOF
ssh <unit> reboot
```

`config` takes one `sha256=` line per allowed image and up to four `target=`
lines. A `#` starts a comment. Without `target=` lines the boot confirm uses
the deaf watchdog's targets (see [the deaf-unit fault](deaf-watchdog.md)).

To try an image again after a rollback, take its hash out of `quarantine` and
write `strikes=0` to `strikes`.

## What `pre` does

Any failed check keeps stock firmware and records a reason. `pre` first undoes
everything it set up itself. It never touches what it did not create.

1. Refuses to run once the vendor has mounted `/mnt`: it runs only at boot.
2. Checks that nothing is already bound over `/lib/firmware` or `modem.ko`,
   that `mtd20` is the `user` partition, and that no UBI device holds it yet.
3. Attaches `mtd20` as `ubi1` and mounts the Witcher volume (`ubi1:data`)
   **read-only** on a private directory. With no opt-in it unmounts,
   detaches and stops here. Nothing is written.
4. Reads `config`, `strikes` and `quarantine`. Checks the image size and
   free memory.
5. Copies the image into a private 8 MiB tmpfs and checks **that copy**: its
   SHA-256 must be on the allow-list and not in quarantine, and its gzip header
   must be one the modem can read. Checks the gated module's SHA-256.
6. Remounts the volume read-write and writes `strikes=N+1` (temporary file,
   sync, rename, sync), then reads it back. No recorded strike means no load.
7. Unmounts the volume and detaches `mtd20`, so the vendor's own attach later
   finds it as it would on any boot.
8. Binds the gated module over `modem.ko` and the tmpfs over `/lib/firmware`.

`start_lte.sh` then runs its usual `modprobe modem`.

Commands that could hang run under a time limit. If the time limit itself does
not work, the command does not run and the check after it keeps stock.

| Reason | Meaning |
| --- | --- |
| `off` | No `config`, or `enabled` is not 1. The default. |
| `no-volume` | No Witcher volume yet (first boot after flashing). |
| `strikes` | Two staged boots without a boot confirm. |
| `strikes-unreadable` | `strikes` exists but holds no count. |
| `quarantined` | The keeper rolled this image back before. |
| `not-allowed` | The image's SHA-256 is not on the allow-list. |
| `header` | Not a gzip file the modem's reader accepts. |
| `size`, `memory`, `no-image` | Image under 1 KiB or over 7.5 MiB, under 32 MiB free, or no `active.gz`. |
| `module` | The gated module does not match its pinned SHA-256. |
| `strike-write` | The strike could not be recorded. |
| `ubi-busy`, `attach`, `mount`, `detach`, `bind`, `tmpfs`, `copy`, `hash`, `leftover`, `no-user-mtd`, `workdir`, `aborted` | A setup step failed or found something unexpected. |

## What `post` does

1. Deletes the image from the tmpfs first. While the bind is still there,
   `/lib/firmware` shows that tmpfs, so the image is gone even if an unmount
   fails.
2. Unmounts both binds and the tmpfs.
3. If `pre` died before it finished, unmounts the volume and detaches `mtd20`.
4. Records when the module loaded, whether the modem logged `read from fs` or
   `read from nand`, and whether `/lib/firmware` is clean again.

## Boot confirm and rollback

The keeper reads the hook's status once at start. It arms only when the hook
staged an image this boot. On any other boot it never reboots for this.

- Every 15 s it pings the `target=` addresses (or the deaf watchdog's).
- An address on `lte0pdn0` plus one answer confirms the boot: `strikes=0` and
  `confirmed` get the hash.
- No confirm within 300 s of the load, after at least two rounds by this
  keeper process: the keeper adds the hash to `quarantine`, writes
  `strikes=2`, reads both back, and reboots once onto stock firmware. If the
  read-back does not show that the hook will refuse the image, it does not
  reboot.
- `/var/run/witcher-tk.result` records the outcome, so a keeper that restarts
  does not judge the boot again.

This covers the case the deaf watchdog cannot: that watchdog arms only after a
first answer, so a modem that never attaches never trips it.

Neither layer can loop:

- With the keeper working, a failing image loads once and the unit reboots
  once. The next boot is stock (`quarantined`).
- If the keeper cannot write, the strike count still stops the hook after two
  staged boots, because the hook records each strike before the load.
- If Linux dies or power fails before the confirm, the same strike count
  applies.

## Files

On the Witcher volume, `/mnt/titan-api/tk/` once mounted:

| File | Written by | Content |
| --- | --- | --- |
| `config` | Operator | `enabled=1`, `sha256=` lines, optional `target=` lines |
| `active.gz` | Operator | The staged image |
| `strikes` | Hook (+1 before each load), keeper (0 on confirm, 2 on rollback) | `strikes=N` |
| `quarantine` | Keeper | One hash per line |
| `confirmed` | Keeper | `sha256=<hash>` of the last confirmed image |

In RAM:

| File | Content |
| --- | --- |
| `/var/run/witcher-tk.status` | `state=staged` or `state=stock`, `reason`, `sha256`, `strikes`, `loaded_at`, `source` (`fs`, `nand`, `unknown`), `firmware` (`clean`, `dirty`) |
| `/var/run/witcher-tk.result` | `confirmed=<hash>` or `rollback=<hash>` |

`keeper.log` lines start with `tk boot`. A default unit logs none.

## Turning it off

| Level | Action | Result |
| --- | --- | --- |
| Off | Write `enabled=0` in `config` (or delete it), then reboot. | Stock firmware and stock `modem.ko` from the next boot. The Witcher root filesystem stays. |
| Automatic | None. | No confirm in 300 s: quarantine and one reboot onto stock. |
| Bank | Firmware rollback (`/api/v1/actions/firmware.rollback` or the recovery page). | The other NAND bank: the previous Witcher or stock firmware. |

## Not in this firmware

- **No signature check.** Phase 1 trusts the allow-list in `config`, which
  only root on the unit can write. The hook has a `verify_signature` stub with
  a fixed interface for Phase 2: an Ed25519 signature in `active.gz.sig` over
  the image's SHA-256, checked against a public key in the image.
- **No feature flags.** The keeper writes no modem memory (`wm`). Images must
  boot with every feature flag at 0. `titan_pd_model::tk_boot::flag_writes_allowed`
  is the gate a later change must use: it allows a write only when
  `vm 0x847ed600 4` reads back the patch magic `4e 34 56 32`.
- **No crash quarantine.** A modem crash after a confirmed boot reloads stock
  NAND firmware without a reboot, but the next boot loads the image again.
- **No on-device patcher** (Phase 2). Each unit needs the image staged by hand.
- **Not yet run on hardware.** The early attach of `mtd20` before the vendor's
  `rcinit` is new. It runs on every boot of every unit with this firmware, opt
  in or not, and the bench must prove it first.

## Regulatory note

The Titan 4000 is a certified CBRS device. The patches in view do not touch RF
calibration, transmit power, MPR tables or band-edge filters, but they change
baseband firmware. Keep patched modem firmware on bench units the operator
owns, keep the loader off by default, and get counsel review before any
customer unit runs it. Loading modified baseband firmware can also void the
manufacturer's warranty.
