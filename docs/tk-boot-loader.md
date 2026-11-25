# Boot-time modem firmware loader

Status: bench only, off by default. Nothing changes on a unit until an
operator stages an image and turns it on. This firmware ships no modem
firmware bytes. Since v1.0.15 the keeper writes modem feature flags, but only
on a confirmed boot of a staged image and only the words `tk/config` lists
(see [Modem feature flags](#modem-feature-flags)).

Since v1.0.16 a unit can build the release image itself from its own stock
firmware: `titan-pd-keeper tk-build stage` writes `tk/active.gz` and
`tk/config` (see [Building the modem image on the unit](tk-patch.md)).

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

`scripts/stage-latency.sh` does all of the steps below from a workstation,
checks every copy by SHA-256 on the unit, and also stages the download clamp
(see [the download clamp](download-clamp.md)):

```sh
scripts/stage-latency.sh --target <ping responder> <unit> tk.gz device/qctrl/payload/titan_qctrl.ko
```

By hand:

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

`config` takes one `sha256=` line per allowed image, up to four `target=`
lines and the `wm=` lines of [Modem feature flags](#modem-feature-flags). A
`#` starts a comment. Without `target=` lines the boot confirm uses the deaf
watchdog's targets (see [the deaf-unit fault](deaf-watchdog.md)).

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

## Modem feature flags

Patched modem images boot with every feature off, as this loader requires. The
keeper manages an allow-listed table of words in modem RAM, keyed by each patch
layer's magic word:

### Managed word table

| Layer & magic (`vm <addr> 4`) | Word | Name | Allowed values | Off / rollback | Meaning |
| --- | --- | --- | --- | --- | --- |
| N4 (`0x847ed600`: `4e 34 56 32`) | `0x84f93008` | `HOLD_MARGIN` | `0..=0x200` (`0..=0x800` with `hold_ack=prb-tax`) | `0` | Grant-hold size in bytes (`0x140` fits a 228-byte ping) |
| N4 | `0x847ed608` | `N4_PDCP_MIN` | `4096..=24576` (`min <= max`) | `0x4000` (16384) | N4 PDCP staging min for images without N5 |
| N4 | `0x847ed60c` | `N4_PDCP_MAX` | `4096..=24576` (`min <= max`) | `0x6000` (24576) | N4 PDCP staging max for images without N5 |
| N4 | `0x847ed604` | `N4_FLAGS` | bits `0x15` (`0x1`, `0x4`, `0x10`) | `0` | AQM v2 (`0x5`), grant-hold rescue (`0x10`), both (`0x15`). Bit `0x2` (lead) and bit `0x8` (stock sparse promotion) are refused everywhere. |
| IMG4 (`0x847ecfe8`: `49 4d 47 34`) | `0x847ed548` | `G1A` | `0` or `1` | `0` | UL GIPC idle-clear |
| IMG4 | `0x847ed54c` | `G1B` | `0` or `1` | `0` | Bounded LLCE1 poll |
| IMG4 | `0x847ed550` | `G1C` | `0` or `1` | `0` | Early LLCE0 harvest |
| IMG4 | `0x847ecf08` | `TK1` | `0` or `1` | `0` | Batched DL GIPC send |
| IMG4 | `0x847ed554` | `LNK` | `0` or `2` (`1` only with N6 magic and `U2_FLAGS` bit `0x1` in the same config) | `0` | UL local NACK (`2` observe only; `1` active local NACK gated by N6 LNK-FIX) |
| N5 (`0x84489a64`: `4e 35 46 4c`) | `0x84489a70` | `N5_RATE_BPMS` | `8..=200` | `0` | Sparse-flow rate threshold (bytes/ms) |
| N5 | `0x84489a74` | `N5_BURST_B` | `512..=16384` | `0` | Sparse-flow burst allowance (bytes) |
| N5 | `0x84489a78` | `N5_HOLD_MS` | `100..=5000` | `0` | Bulk-flow hold duration (ms) |
| N5 | `0x84489a7c` | `N5_BUDGET_PCT` | `1..=50` | `0` | Global Ring 0 promoted-byte cap (% of `20 * G_ema`) |
| N5 | `0x84489a84` | `N5_PDCP_MIN` | `4096..=24576` (`min <= max`) | `0` | N5 PDCP staging min (writing `0` restores 16384) |
| N5 | `0x84489a88` | `N5_PDCP_MAX` | `4096..=24576` (`min <= max`) | `0` | N5 PDCP staging max (writing `0` restores 24576) |
| N5 | `0x84489a8c` | `N5_PDCP_K_Q4` | `0..=64` | `0` | Adaptive PDCP multiplier in Q4 |
| N5 | `0x84489a6c` | `N5_FLAGS` | `0..=3` (bit `0x4` refused) | `0` | `0x1` sparse flow lane, `0x2` N5 PDCP staging override (requires `N4_FLAGS` bit `0x1`), `0x3` both |
| N6 (`0x8418ff00`: `55 32 48 46`) | `0x8418ff08` | `U2_FLAGS` | `0` or `1` | `0` | LNK-FIX post-ACK filter + per-carrier counters (same magic on N6 and N6H; `0x8418ff04` distinguishes N6 `4e 36 00 00` from N6H `4e 36 48 03`) |
| M1 (`0x841b5900`: `4d 31 50 49`, then an accepted build version at `0x841b5904`: `20 26 11 25`) | `0x841b5908` | `M1_SELECT` | `0..=2` | `0` | Uplink AQM: `0` N4 AQM v2 (the boot value), `1` Rust PIE, `2` no AQM. `1` and `2` act only while `N4_FLAGS` has bits `0x5`; without them the modem enqueues as with the N4 AQM off. |

**Never on the allow-list (always refused and logged):** IMG4 words `TRCP`
(`0x847ecf1c/20/24`), `W5` (`0x847ece88..94`), `UHQ` (`0x847ecff0`), `U3T`
(`0x847ecff4`), `R17` (`0x847ecff8/fc`), `X4`/`HRB` (`0x847ecf14`), `DSR`
(`0x847ecf18`), `U14` (`0x847ecf28/2c`), `PHR` (`0x847ecf10`), the rest of the
M1 block (magic, version, the PIE tunables at `+0x0c..+0x37`, its live state
and its counters: the keeper only reads them, see [Status](#status)), any RF,
transmit power, MPR or calibration address, and any address not in the table
above.

**Cross-word rules:**
- `N4_PDCP_MIN <= N4_PDCP_MAX` and `N5_PDCP_MIN <= N5_PDCP_MAX` (an omitted
  side is checked against its boot default `16384` / `24576`).
- `N5_FLAGS` bit 1 (`0x2`) requires `N4_FLAGS` bit 0 (`0x1`).
- `LNK=1` (`0x847ed554`) is refused unless the N6 magic (`0x8418ff00`: `55 32 48 46`)
  is present in the same session and `U2_FLAGS` bit 0 (`0x1`) is requested in
  the same config (`U2_FLAGS` is written before `LNK` and disabled after `LNK`).
- `M1_SELECT` has no rule of its own: the modem itself runs the PIE (or no
  AQM) only while `N4_FLAGS` has bits `0x5`. Turning the selector on comes
  after every other word, and turning it off comes before every other word
  (it is last in the table).
- `HOLD_MARGIN` above `0x200` (up to `0x800`) requires an explicit
  `hold_ack=prb-tax` line in `tk/config`. **Tower cost:** while the unit is
  active, a larger hold margin makes the modem ask for bigger standing padding
  grants on the uplink carrier (increasing PRB consumption on the sector; on
  the bench `0x400` cut idle RTT by ~2.5 ms and `0x800` by ~3.2 ms). Do not
  enable `hold_ack=prb-tax` on a loaded cell without checking sector uplink
  utilization.

The rules are tables in `titan_pd_model::tk_flags` (`REQUIRES`, `MIN_MAX`), so
a new rule, like a new word, is one table entry.

**Profiles in `scripts/stage-latency.sh`:**
- `--profile latency`: inspects the local `tk.gz` magic bytes (N4, IMG4, N5,
  N6/N6H, M1) and writes the proven `wm=` set for that image (for N6/N6H: N4 AQM v2
  + hold `0x140`, G1A/G1B/G1C/TK1, N5 sparse lane + 8/12 KB PDCP staging, and
  `U2_FLAGS=1`). `--flags`, `--hold`, and `--hold-ack prb-tax` override profile
  values.
  - An image with the M1 block of an accepted build also gets
    `wm=0x841b5908:0x1` (Rust PIE), as the last line. It does not when
    `--flags` lacks the N4 AQM v2 bits `0x5`, or when the block's build is not
    one the keeper accepts: with an unaccepted M1 build in `tk/config` the
    keeper would write nothing at all. The script says why in a `note:` line.
- `--profile stock`: writes no `wm=` lines.

Example `tk/config` for an N6/N6H image:

```
enabled=1
sha256=<64 hex digits>
wm=0x84f93008:0x140
wm=0x847ed604:0x15
wm=0x847ed548:0x1
wm=0x847ed54c:0x1
wm=0x847ed550:0x1
wm=0x847ecf08:0x1
wm=0x84489a84:0x2000
wm=0x84489a88:0x3000
wm=0x84489a6c:0x3
wm=0x8418ff08:0x1
```

An M1 image (N6H plus the Rust PIE) adds one line at the end:

```
wm=0x841b5908:0x1
```

A value is hex with `0x` or decimal. Any disallowed `wm=` line is ignored and
logged with the reason.

### When the keeper writes them

1. Only after the boot confirm succeeds for a staged image: status
   `state=staged`, a `confirmed=<hash>` result for that same hash, and a modem
   that did not report `read from nand`. On a stock boot nothing is ever
   written. A keeper that restarts after the confirm takes over.
2. Each write session opens the modem console (`/usr/lte/lted_cli`) and sends
   one line about every 3 s: `arm1log 2`, `quit 0`, `dbg revert`, then `vm` for
   every patch layer magic required by the words in that session. For M1 one
   line reads the magic and the version together: `vm 0x841b5900 8`.
3. It writes only if every required magic reads back in the same session (N4
   through `tk_boot::flag_writes_allowed`), and for M1 only if the version is
   one this keeper accepts (`tk_flags::M1_VERSIONS`, today `0x20261125` and `0x20261126`). The
   N4 magic appears only after the first uplink transport block. Until then
   the keeper writes nothing and asks again after 15 s, then 30 s, doubling up
   to 10 minutes. An unaccepted M1 build waits the same way: nothing is
   written for any layer, the status names the build it saw, and `keeper.log`
   says so once per reason.
4. It reads each word first and writes only what differs, in safe order:
   - First: flags that disable or reduce behaviour (reverse dependency order:
     `N5_FLAGS` before `N4_FLAGS`, all disabling flags before any parameter
     change).
   - Second: parameters and limits (`HOLD_MARGIN`, PDCP limits, N5 tunables).
   - Third: flags that enable (`N4_FLAGS` before `N5_FLAGS`).
5. Sessions keep the 90 s limit and 3 s line spacing. When a config has more
   words than fit within a 75 s worst-case budget (for example the 10-word N6
   latency profile), the keeper splits the apply into consecutive sessions in
   write order (parameters first, then flags), so a failed session never leaves
   an enabled flag without its dependent parameter.
6. It reads every write back in the same session. When every word reads as
   wanted and the session holds `M1_SELECT`, one more line reads the M1 block
   (`vm 0x841b5900 160`, the bench's own read) into `/var/run/witcher-tk.m1`
   (see [Status](#status)). Then it sends `arm1log 1`. The session budget
   counts that line.

The console prints a dump's bytes most significant first, under a header that
names each column's byte offset:

```
           | 03 02 01 00  07 06 05 04  0B 0A 09 08  0F 0E 0D 0C
0x847ED604 | 00 00 00 15  .. .. .. ..  .. .. .. ..  .. .. .. ..
0x84F93008 | 00 00 01 40  .. .. .. ..  .. .. .. ..  .. .. .. ..
```

The keeper strips colours, maps the columns back with the header, and reads
the word little-endian. A dump without that header line counts as unread.

**A missing read-back means the write did not happen.** A console left in
logging mode by `quit 1` ignores every line with no error. That is why each
write session starts with `quit 0` and `dbg revert`.

### Bench/maintenance hold (`hands-off`)

To work on `/usr/lte/lted_cli` by hand without colliding with the keeper's
writes or 10-minute checks, put the keeper in hands-off mode in either way:

- **Temporary (RAM, cleared on reboot):** `touch /var/run/witcher-tk.hands-off`
  (remove with `rm -f /var/run/witcher-tk.hands-off` when done). Takes effect
  within 1 s.
- **Persistent (`tk/config`):** add `manage=off` to `/mnt/titan-api/tk/config`
  (remove it or set `manage=on` when done). Takes effect within 15 s.

While hands-off is active, the keeper opens no console sessions, runs no
periodic checks, writes no modem words, and reports `state=hands-off` in
`/var/run/witcher-tk.flags`. Removing the hold resumes management immediately
with a fresh read of every configured word.

### Retries and failure

| Case | What the keeper does |
| --- | --- |
| No patch magic | Writes nothing, waits (15 s doubling to 10 min). Not a failure. |
| M1 magic with a build version this keeper does not accept | The same: writes nothing for any layer and waits. `detail` names the version it saw and the ones it accepts. |
| No reply to the magic read, or a read-back missing or wrong | Tries again after 20 s. After 3 failed sessions it stops. If any write went out since the last modem restart, it rolls every managed word back to its documented off value (`0x4000`/`0x6000` for N4 PDCP limits, `0` for N5 tunables, flags and hold; magic still required, disabling flags first) and reads them back. The status says `failed` and whether the rollback read back. |
| Applied | A read-only check every 10 minutes. A word that reads back wrong is written again. Three checks with no reply start a write session, which resets the console. |
| Modem restart | The kernel log shows `read from nand` or `read from fs` after the keeper started. It starts over 30 s later. A crash reload runs stock NAND firmware, which never shows the magic, so nothing is written then. |
| Another console session | The radio profile's marker file is present: the keeper waits 20 s and counts no failure. |
| Hands-off (`manage=off` or `/var/run/witcher-tk.hands-off`) | Stops all console sessions and checks; status says `state=hands-off`. Removing it resumes with a fresh read. |
| `tk/config` changed | Read every 15 s. New values are written at once (or queued while hands-off). `enabled=0`, a deleted file, or dropped `wm=` lines roll those managed words back to their documented off values. |

Unless hands-off is active, writes typed by hand in `lted_cli` get overwritten
at the next check. Either set hands-off for manual bench work or edit
`tk/config`.

### Turning the flags off

- **Now, no reboot:** remove the `wm=` lines (or set `enabled=0`) in
  `/mnt/titan-api/tk/config`. Within about 15 s the keeper rolls every managed
  word back to its documented off value (flags first) and reads them back.
  Watch `/var/run/witcher-tk.flags`.
- **Stock modem firmware:** `enabled=0` rolls back at once, and the next boot
  loads stock firmware.
- **By hand**, with hands-off set (`touch /var/run/witcher-tk.hands-off`):
  write the kill switch in a `lted_cli` session (after `arm1log 2`), then read
  back.

**The Rust PIE (M1) alone:** write `wm=0x841b5908:0` in `tk/config`, or delete
the line. Within about 15 s the keeper writes `0` (the N4 AQM v2 again) as the
first word of the session and reads it back; the other words stay. A reboot or
a modem restart also brings back `0`, the selector's boot value, until the
keeper writes it again from `tk/config`. By hand (hands-off set):
`wm 0x841b5908 0`, then `vm 0x841b5908 4`.

### Status

`/var/run/witcher-tk.flags`:

| Line | Values |
| --- | --- |
| `state` | `off`, `pending`, `waiting-magic`, `applied`, `zeroing`, `failed`, `hands-off` |
| `detail` | Why, in words. On `failed`: what went wrong and whether the rollback read back. |
| `want` | The words and values the keeper keeps, or `none` |
| `attempts` | Failed sessions in a row |

`keeper.log` lines start with `tk flags`.

`/var/run/witcher-tk.m1`, written at the end of each verified session that
holds `M1_SELECT` (the apply, then the 10-minute check), from the same console
session as the read-back:

| Line | Values |
| --- | --- |
| `version` | The M1 build, `0x20261125` (lane M1) or `0x20261126` (lane R1: overload latch, time-based ceiling) |
| `selector` | `0` N4 AQM v2, `1` Rust PIE, `2` no AQM |
| `seen` | Packets the PIE evaluated (`+0x60`) |
| `pie_drops` | Probabilistic PIE drops (`+0x68`) |
| `ce_marks` | ECN CE marks (`+0x6c`) |
| `hard_drops` | Drops at the overload ceiling (`+0x70`) |
| `peak_qdelay_us` | Peak estimated queue delay, in microseconds (`+0x80`) |
| `updated` | The keeper's clock (seconds since boot), as in `witcher-tk.flags` |

Counters are decimal, count from the modem's start and wrap at 2^32; the
keeper never writes them. It writes the file only from a dump that shows the
M1 magic and an accepted version, so a stale file keeps its old `updated`.

## Files

On the Witcher volume, `/mnt/titan-api/tk/` once mounted:

| File | Written by | Content |
| --- | --- | --- |
| `config` | Operator | `enabled=1`, `sha256=` lines, optional `target=` and `wm=` lines |
| `active.gz` | Operator | The staged image |
| `strikes` | Hook (+1 before each load), keeper (0 on confirm, 2 on rollback) | `strikes=N` |
| `quarantine` | Keeper | One hash per line |
| `confirmed` | Keeper | `sha256=<hash>` of the last confirmed image |

In RAM:

| File | Content |
| --- | --- |
| `/var/run/witcher-tk.status` | `state=staged` or `state=stock`, `reason`, `sha256`, `strikes`, `loaded_at`, `source` (`fs`, `nand`, `unknown`), `firmware` (`clean`, `dirty`) |
| `/var/run/witcher-tk.result` | `confirmed=<hash>` or `rollback=<hash>` |
| `/var/run/witcher-tk.flags` | The flag writes (see [Status](#status)) |
| `/var/run/witcher-tk.m1` | The M1 selector and PIE counters (see [Status](#status)) |
| `/var/run/witcher-tk.hands-off` | Optional operator marker file to pause all modem console sessions (`state=hands-off`) |

`keeper.log` lines start with `tk boot` or `tk flags`. A default unit logs none.

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
- **Flags only from `tk/config`, allow-listed table only.** Images must still boot with
  every feature flag at 0. The keeper writes only the allow-listed words of
  [Modem feature flags](#modem-feature-flags), and only after verifying each
  layer's patch magic in the same session (N4 through
  `titan_pd_model::tk_boot::flag_writes_allowed`). A new word needs a code
  change and its own bench test.
- **No crash quarantine.** A modem crash after a confirmed boot reloads stock
  NAND firmware without a reboot, but the next boot loads the image again.
- **One image built on the unit.** `tk-build` builds the release image the
  keeper carries ([tk-patch.md](tk-patch.md)). Any other image is staged by hand.
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
