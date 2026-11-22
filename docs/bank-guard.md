# Bank guard: boot confirm after a firmware update

A Titan on a roof has one link: LTE. If a new firmware image boots but never
brings up management, nobody can reach the unit, and someone has to climb to
it. The Titan keeps the old image in its second bank, but the boot code never
goes back to it by itself.

The bank guard closes that gap. On the first boot after an update, the new
image must prove itself within 10 minutes. If it cannot, the guard selects the
old bank and reboots once.

The guard is part of `titan-pd-keeper` (`titan-pd-keeper bank-guard`). It
runs as its own process, started by `/etc/init.d/witcher-bank-guard`, because
one of the things it checks is whether the keeper itself stays up.

## How the Titan picks a bank

### Two banks

| Part | Bank 0 | Bank 1 | Partition size |
| --- | --- | --- | --- |
| Kernel | `mtd13` (`linux`) | `mtd14` (`linux2`) | 4 MiB |
| Root filesystem | `mtd15` (`rootfs`) | `mtd16` (`rootfs2`) | 60 MiB |
| Modem firmware | `mtd17` (`tk`) | `mtd18` (`tk2`) | 8 MiB |

### The bank table (NV item 23)

NV item 23 in the `cmnnv` partition (`mtd8`) is the bank table. It is 360
bytes: ten 36-byte records. Records 0 and 1 are the kernel in bank 0 and bank
1, records 2 and 3 the root filesystem, records 4 and 5 the modem firmware.
Records 6 to 9 are unused and stay zero. Each record is little-endian:

| Offset | Field |
| --- | --- |
| `0x00` | Adler-32 of bytes `0x04` to `0x23` |
| `0x04` | Magic `0xcafebabe` |
| `0x08` | Record length, 36 |
| `0x0c` | Sequence number |
| `0x10` | Adler-32 of the image as written |
| `0x14` | Image size in bytes |

The Adler-32 here starts both sums at 0, not at 1 as zlib does. The vendor
code passes a seed of 0 (`adler_chksum32(0, ...)` in `libnvm.so` and
`libkzload.so`, and the kernel's own copy at `0x80034928`).

For each part, the bank whose record has the higher sequence number boots.

Evidence:

- `libkzload.so` `Upgrade_toggleFormatProgram` (`0x220a8`) reads NV 23 with
  `nv_read(23, buf, 0, 360)`, picks the pair at `type * 72`, takes the record
  with the higher sequence number as the active one, sets the other one's
  sequence number to the active one's plus 1, recomputes its record checksum
  over bytes `0x04` to `0x23`, and writes the table back with one
  `nv_write(23, buf, 0, 360)`.
- `modem.ko` takes the modem firmware bank by the same rule (lane P, function
  `0x1b50`).
- A table read from a unit with `nv_read` on 2026-10-15 selects bank 0 (kernel
  27 over 26, root filesystem 54 over 52, modem 55 over 53). The kernel and
  modem record checksums match the raw partition dumps taken the same day, for
  both banks. The unit tests use this table.
- The boot code (U-Boot) is not in hand, so its code was not read. Its
  behavior is: after every update and every bank switch, the unit boots the
  bank with the higher sequence numbers. The guard also checks this at every
  boot: if the running bank is not the one the table selects, it never acts on
  that unit.

The root filesystem record checksum names the image as written. It does not
match the flash after the bank has run once, because UBI writes its erase
counter headers when it attaches. The kernel and modem firmware never change
after the write, so their checksums match the flash exactly.

### How `cmnnv` stores the table

NV item 23 shares one 128 KiB block with the other common NV items. The block
starts with a 36-byte wrapper in the same record format (magic, checksum,
sequence number, a checksum of the rest of the block, and the length 131,036).
NV 23 sits right after the wrapper, at byte 36.

The partition holds two copies of that block, in its second and third good
erase blocks. Evidence:

- Kernel `load_cmn_nv` (`0x804bc878`) opens MTD 8 and calls `load_nv`
  (`0x80034a04`). `load_nv` skips bad blocks, takes the second and third good
  blocks as the two copies, and checks each: magic, wrapper checksum, then the
  block checksum (a stored 0 is accepted). If both are valid it takes the first
  copy only when its sequence number is higher, else the second.
- `libnvm.so` `cmn_nv_write` (`0xea60`) copies the new bytes into its RAM image
  of the block, then calls `0xcff4`, which moves the target to the other copy
  and adds 1 to the sequence number, then `nv_data_write` (`0xe460`), which
  computes both checksums and programs the whole block into that copy.
  `select_header` (`0xc054`) picks the copy at startup by the same rule as the
  kernel.

What follows from this:

1. **One `nv_write` cannot leave a broken table.** It programs only the older
   copy. A power cut during the program leaves a copy whose block checksum
   fails, and the reader takes the other copy, which still holds the old
   table.
2. **The vendor bank switch can leave the banks split.**
   `Upgrade_toggleAllFormatProgram` (`0x223c8`) calls the toggle three times,
   once per part, so it makes three NV writes. A power cut between them leaves
   the kernel on one bank and the root filesystem on the other. It also
   ignores the result of each write, and running it again after a split flips
   the parts that had already moved back the other way.
3. **The vendor read can say yes when the flash says no.** `cmn_nv_write`
   updates the RAM image before it programs flash, and `cmn_nv_read` returns
   the RAM image. After a failed program, `nv_read(23, ...)` still shows the
   new table until the next boot. `cmn_nv_write` also skips the program when
   the new bytes match the RAM image.

So the guard does three things differently from the vendor switch:

- It computes "every part on bank N" from the table it reads, in one write. A
  part already on bank N keeps its record. Running it twice writes nothing the
  second time.
- It reads the `cmnnv` blocks itself, the way the kernel does, before and
  after the write. It acts only when that raw view and the vendor's view agree.
- If the flash missed the write, it writes once more with different bytes
  (one more on each sequence number), because the NV layer would skip a
  repeat of the same bytes.

The write goes through a small helper, `/usr/lib/titan-api/witcher-nv23`,
which calls the vendor's own `nv_write(23, ...)` while holding the vendor
updater's lock (`Upgrade_AllocTokenLock`, a lock on `/tmp/flashwr.lcok`). It
has no policy of its own. The build links it against the stock libraries with
the same flags as `titan-maintenance`, and CI loads it under emulation.

## When the guard arms

The guard arms only on the first boot of a bank that an updater just wrote. A
unit that was not just updated is never touched. Three markers count:

| Marker | Written by | When |
| --- | --- | --- |
| `firmware-operation.json`, state `verified-awaiting-reboot` | titan-api's updater (System → Firmware) | after a checked install, before the reboot |
| `firmware-operation.json`, state `selected-awaiting-reboot` | titan-api's bank switch | before the reboot |
| `bank-guard/arm.json` | `titan-pd-keeper bank-guard arm` | by any other updater, after its write, before its reboot |
| `bank-guard/volume-created` | `witcher-state` | on the first Witcher boot after a stock flash, when it creates the data volume |

A marker arms the guard only when all of these hold:

- The marker names the bank that is running now.
- titan-api's install marker names the same part sizes as the running bank's
  records. An `arm.json` names the exact records and was written in an earlier
  boot. `volume-created` holds this boot's id.
- The vendor view and the raw flash view of the table agree, and the table
  selects the running bank.
- The guard has not used this marker before. It keeps the last eight.

The old bank becomes the fallback. If the guard confirmed the old bank on an
earlier boot, the log says so. If not, the fallback has only proved that it
could run the updater, and the log says that.

## What counts as proof

All of these, before 600 seconds of uptime (`confirm_secs`):

1. The management bearer `lte0pdn0` has carrier and an IPv4 or global IPv6
   address.
2. A ping target answers. The targets are the guard's own `target=` lines,
   else the deaf watchdog's targets, else the DNS servers the core gave the
   unit.
3. The keeper process that the supervisor started in this boot is running,
   and the same process is still there 30 seconds later.
4. Optional (`require_customer=1`): a customer bearer (`lte0pdn1` and up) has
   carrier, and if `customer_target=` lines are set, one answers through that
   bearer.

The guard checks every 15 seconds. It needs at least two checks of its own
before it gives up, so a guard that starts late still looks first.

Management works without a SAS grant, so the SAS grant window (07:00 to 10:00
UTC) does not stop proof. A customer ping can fail in that window, because the
vendor drops customer IPv4 without a grant. Leave `customer_target=` unset for
updates in that window.

When proof comes, the guard closes the update as `confirmed` and records the
running bank as the confirmed bank. On a boot that was not armed, it only
records the running bank. It writes its state file only when something
changed.

## What the guard does without proof

1. It reads the table both ways again. If the table changed during this boot
   (someone else is working on the unit), it stops.
2. It checks the old bank:
   - kernel and modem firmware: reads the whole image, skipping bad blocks as
     the vendor writer does, and compares the Adler-32 with the record. It also
     checks the uImage header CRC and the gzip header `modem.ko` accepts.
   - root filesystem: every UBI erase counter header and volume header must
     pass its CRC, both copies of the volume table must name `rootfs`, UBIFS
     blocks 0 to 2 must be present, and block 0 must start with the UBIFS
     superblock magic.

   If any check fails, it refuses, records `refused`, and does not switch.
3. It counts the switch attempt in its state file and reads that back. No
   recorded count, no switch.
4. It builds the new table: each part of the old bank gets the other bank's
   sequence number plus 1. The other bank's records do not change. It checks
   that the new table is valid, selects the old bank, and differs only where
   it should.
5. It writes the table through `witcher-nv23`, then reads both views back.
6. It reboots once. If `reboot` does not take effect in 45 seconds, it runs
   `reboot -f`.

It does not reboot when nothing was written (the updater lock was held, or the
helper refused), or when the flash shows a table the boot code might refuse.

## Limits on reboots

The guard writes a boot count and a switch count for each update to flash
before it acts on them.

| Situation | What happens |
| --- | --- |
| Boot 1 or 2 of the update, window expires | switch back, reboot |
| The last switch did not take effect (same bank booted again) | switch at once, reboot |
| Boot 3 of the update with no proof (the first two died early, as in a reboot loop) | switch at once, reboot |
| Two switches did not take effect | give up, record `gave-up`, never act on this update again |

So one update causes at most three guard reboots. A power cut or a crash at
any point lands in one of these rows. The unit tests and the boot flow test
check every row.

## The second-flash trap

The updater always writes the bank that is not running. Flash two images in a
row, and the second one overwrites the bank that held the last good image.

The guard records which bank it last saw prove itself, with that bank's part
sizes and checksums. Before an update, an updater can ask:

```
titan-pd-keeper bank-guard preflight
```

Exit 0 means the update may go ahead. Exit 3 means refuse, with the reason:

- the update would overwrite the last confirmed bank while the running bank
  has no confirmed boot, or
- the running bank is still inside its own boot confirm, or
- the table already selects the other bank for the next boot.

It also notes when the bank about to be overwritten holds the only stock 4172
image. After that, a return to stock needs a stock `.prg` upload.

titan-api's updater ships as a pinned binary and does not ask yet. Until it
does, run `preflight` before each update, and wait for the boot confirm after
an update before the next one. If an update replaces the last confirmed bank
anyway, the guard logs a warning when it arms.

## Settings

Optional file `/mnt/titan-api/bank-guard/config`:

```
enabled=1
confirm_secs=600
target=192.0.2.1
require_customer=0
customer_target=192.0.2.2
```

`confirm_secs` runs from 300 to 1800. Up to four targets of each kind. Name
targets on the core itself, so an outage beyond the core does not count as a
failed update.

## Commands

| Command | What it does |
| --- | --- |
| `titan-pd-keeper bank-guard status` | prints both views of the table, which copy the kernel would take, every record, the guard state and the `preflight` verdict, as JSON |
| `titan-pd-keeper bank-guard preflight` | exit 0 to allow an update, 3 to refuse |
| `titan-pd-keeper bank-guard arm` | after an update's write and before its reboot: arm the guard for the next boot |
| `titan-pd-keeper bank-guard boot` | the boot run, from the init script |

Files under `/mnt/titan-api/bank-guard/`: `state.json` (counters, the
confirmed bank, the last 12 outcomes), `config`, `arm.json`,
`volume-created`. A damaged `state.json` is kept as `state.json.bad`, and the
guard starts over with every marker on disk already used, so it never arms
from a guess.

## Log lines

In `/mnt/titan-api/pd/keeper.log`, with the boot output in
`/tmp/witcher-bank-guard.log`:

- `bank guard: armed by titan-api: first boot of bank 1; without proof the guard switches back to bank 0`
- `bank guard: confirmed: bank 1 answered through the core and the keeper stayed up; the update is kept`
- `bank guard: switching back to bank 0: no proof within 600 s of boot (...)`
- `bank guard: switched: the raw cmnnv flash selects bank 0 (vendor copy agrees: yes); rebooting once`
- `bank guard: not switching: the old bank failed its own check: ...`
- `bank guard: running the old bank 0 again; the guard switched back`
- `bank guard: 2 bank switches did not take effect; giving up on this update`

## What it cannot do

- **A kernel that panics before init.** Linux never runs, so the guard never
  runs. The Titan's hardware watchdog is off in the vendor startup
  (`#kern wd hw en`). Qualify every image on the bench first.
- **A persistent volume that does not mount.** The markers and counters live
  there. The guard does nothing that boot.
- **A stock flash onto a unit that already has a data volume.** It leaves no
  marker, because `witcher-state` does not create a new volume.
- **titan-api's own bank switch** still calls the vendor toggle (three NV
  writes). It is safe while the power stays on. A later titan-api could call
  the guard's single write instead.
- **U-Boot's code** was not read. The guard trusts the behavior seen on every
  update, and refuses to act on any unit where the running bank and the table
  disagree.

## Tests

- `pd-model` `bank_guard` unit tests: the captured table, the single-write
  switch and its read-back rules, a split table repaired in one write, damaged
  records, the kernel's copy choice (torn writes, erased blocks, a stored 0),
  bad block positions, the kernel command line, the uImage, gzip and UBI
  checks, markers, every boot decision, the counters (including a simulation
  where no write ever lands), proof and its window, and `preflight`.
- `scripts/test-bank-guard.py`: the real init script and keeper binary on a
  fake unit, with a stand-in for the vendor NV layer that keeps a RAM copy and
  programs the older `cmnnv` copy. The test plays the boot code between boots.
  It covers a unit that was not updated, a good update, the broken update that
  switches back once, a dead keeper, a damaged old bank (kernel, modem, root
  filesystem), a failed NV write, a write that missed the flash, a reboot loop,
  a write that never lands, a held updater lock, views that disagree, the
  `arm` marker, the first Witcher boot, a damaged state file, and `preflight`
  and `status`.
- `scripts/test-firstboot.py`: `witcher-state` records the boot that created
  the data volume, once, and `witcher-boot` starts the guard.
- The image build links `witcher-nv23` against the stock libraries and loads
  it under emulation. `verify-firmware.py` checks it matches that build.

Not yet run on hardware. The bench plan is in the pull request.
