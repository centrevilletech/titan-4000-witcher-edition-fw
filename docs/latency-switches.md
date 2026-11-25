# Latency features: on by default

Since v1.0.17 a unit that is only flashed gets every latency and upload
improvement Witcher has. Nothing needs SSH, staging or flags. Each feature
can be turned off on its own, live.

| Feature | What it does | Bench result | Details |
| --- | --- | --- | --- |
| Upload latency and AQM (the modem words) | A patched modem image the unit builds from its own stock firmware. Its words turn on the uplink queue control, the grant hold, the sparse-flow lane and the Rust PIE uplink AQM. | Ping during an upload about 100 ms to 38 ms; 4-stream CUBIC upload on two carriers 7.4 to 14.9 Mbps | [Boot-time loader](tk-boot-loader.md), [building the image](tk-patch.md) |
| Download clamp (`titan_qctrl`) | Keeps the tower's download queue short, mode 3 (window clamp plus ACK thinning). It acts in IP passthrough. | Ping during a full download about 310 ms to 50 ms in mode 2, for about 8 % less peak speed; mode 3 took about 6 ms more off with no speed cost | [Download clamp](download-clamp.md) |
| Fast path (`titan_k1fp`) | Forwards steady IP passthrough flows past the full bridge path, mode 2 (downlink). | About 20 points of CPU back at 170 to 200 Mbps, +7 to 10 % download | [Fast path](fast-path.md) |

## The first boot of v1.0.17

1. **Modem image.** Right before the boot's one `modprobe modem`, the boot
   hook asks the keeper whether `tk/` holds anything an operator made. When
   it does not, the keeper builds the release image from the active modem
   bank and writes it with a default `tk/config`. The image loads for that
   same `modprobe`. This makes that one boot about 20 s slower (17.5 s on the
   bench), and later boots reuse the file. After the boot confirm (an answer
   through the core within 300 s) the keeper writes the modem words.
2. **Clamp and fast path.** The keeper loads both from the image about 30 s
   after the customer port and LTE are up: the clamp first, then the fast
   path, which needs IP passthrough.

A unit flashed from stock firmware has no Witcher volume on its first boot,
so it builds the modem image on its next boot. The clamp and the fast path
start on the first boot.

Nothing is built, and stock modem firmware loads, when any of these hold:

- an operator's own `tk/config` exists, or `enabled=0`;
- the active modem bank is not the exact stock image the release image is
  built from;
- an image was rolled back (anything in `tk/quarantine`, or `tk/strikes` at 2).

`/var/run/witcher-tk.status` says why (`reason=`), and `build=` says what the
default image did this boot.

A rollback of the default image is provisional: a tower outage or a power
cut does not keep it off. The next section shows how.

## A tower outage at the moment of upgrade

This is what a unit does when its tower is down as it boots v1.0.17 for the
first time. Any later boot with the default image goes the same way from
step 2. Times are from the modem load; `3348aa36` is the release image.

1. **Boot 1, boot hook.** Before the boot's one `modprobe modem`, the keeper
   builds the release image from the active modem bank (about 20 s). It
   writes `tk/active.gz`, the default `tk/config` and `tk/default`
   (`result=built`). The hook records strike 1 of 2 in `tk/strikes` and
   loads the image. Status: `state=staged`, `build=built`.
2. **Boot 1, boot confirm.** The keeper pings its targets every 15 s. With
   the tower down the modem never attaches and nothing answers. The modem
   words stay off. The clamp and the fast path wait for LTE as always.
3. **Boot 1, at 300 s: a provisional rollback.** The keeper adds the image's
   hash to `tk/quarantine` and writes `strikes=2`. Because this is the
   default image, it also writes `pending=1` in `tk/verdict`. It reads the
   record back and reboots onto stock modem firmware. `keeper.log`:
   `tk boot confirm: no management answer within 300 s of loading modem
   firmware 3348aa36; quarantined it for now (the next stock boot tells
   whether the image or the network failed), rebooting onto stock modem
   firmware`.
   - Between 06:45 and 10:15 UTC (the SAS CPAS window) with the clock set,
     the reboot waits for the window to end; the record is written at once.
   - A unit that never reached the network has no set clock, so it reboots
     at once.
4. **Boot 2, boot hook.** `strikes=2`, so there is no build and no load: stock
   modem firmware. Status: `state=stock`, `reason=strikes`.
5. **Boot 2, the verdict.** The keeper finds `pending=1` and watches the stock
   boot the same way, for 300 s. `keeper.log`: `tk boot verdict armed: stock
   modem firmware after a rollback of modem firmware 3348aa36; ...`.
6. **Boot 2, at 300 s, tower still down: the network failed.** The keeper
   removes the hash from `tk/quarantine`, writes `strikes=0` and records
   `network=1`, `pending=0`. Nothing reboots. `keeper.log`: `tk boot
   verdict: stock modem firmware got no answer through the core either, so
   the rollback of modem firmware 3348aa36 was the network's (1 so far); it
   is out of quarantine and a later boot loads it again`.
   - When the tower comes back, stock modem firmware attaches as it always
     has, and the clamp and the fast path load about 30 s later.
   - The unit runs stock modem firmware, without the modem words, until its
     next boot.
   - **Network → Latency** shows **Modem image**: "Not held back; it loads
     at boot." with the counts.

   **If the tower is back before those 300 s are up**, stock firmware
   answers where the image did not: failure 1 of 2. The keeper takes the
   image out of quarantine and writes `strikes=0`. The tower is known to be
   up now, so it reboots at once to try the image again (step 7). That
   reboot waits until the clock is set and the CPAS window is over.
7. **Boot 3**: after the reboot to try again, or whenever the unit next
   boots (a power cut, an upgrade, **System → Restart**). The hook finds the
   image and the default config intact (`build=cached`), records strike 1
   and loads the image. Nothing is rebuilt.
8. **Boot 3, tower up.** The modem attaches, and the first answer through the
   core confirms the boot, usually within a minute. The keeper writes
   `strikes=0`, sets the failure count back to 0 and writes the modem words.
   Every feature is on.
   - If the tower is down again at this boot, the unit goes back to step 3.
     Each outage at boot costs one extra reboot. A network failure never
     forces one, so a long outage cannot make the unit cycle.

Power that comes and goes while the unit boots can end two image boots
before their confirm decides anything. That leaves `strikes=2` and no
rollback. The stock boot after them records the two as one rollback and
judges it as in step 5.

The image stays off only after two failures in a row (with no confirmed boot
between) where stock firmware answered each time. The second of those comes
from the retry, with the tower known to be up. **Network → Latency** then
shows **Modem image**: "Quarantined after 2 failures in a row where stock
modem firmware answered. Retry tries it again at the next boot."

**Retry the modem image** clears the quarantine, the failure counts and the
strikes. It does not reboot: restart the unit to load the image now. If the
image fails its boot confirm again, the unit goes back to stock modem
firmware by itself.

[Boot-time loader](tk-boot-loader.md#the-default-image-a-rollback-is-provisional)
has the rules.

## Turning a feature off

Use the web interface, **Network → Latency**, or edit one file:
`/mnt/titan-api/latency/config`. Each line turns one feature off; a missing
file or line means on.

```text
modem=off      # the modem words go back to their stock values
clamp=off      # the download clamp passes everything (mode 0)
fastpath=off   # the fast path forwards everything the stock way (mode 0)
```

The keeper reads the file every 5 s and acts at once: no reboot, and nothing
is unloaded. `on`, `1`, `yes` and `true` mean on; `off`, `0`, `no` and
`false` mean off. Any other value also means off, and `keeper.log` says so.
The web screen and the keeper read and write the same file.

| To... | Do this | Result |
| --- | --- | --- |
| Turn the modem words off now | `modem=off` | Within seconds the keeper writes every word back to its documented off value and reads each one back. The patched image then behaves as stock firmware. |
| Run stock modem firmware | `printf 'enabled=0\n' > /mnt/titan-api/tk/config` | The words go off at once, and the next boot loads stock firmware. Keep the file: with no `tk/config` the default applies again. |
| Turn the download clamp off | `clamp=off`, or `mode=0` in `qctrl/config` | Mode 0 within seconds. The module stays loaded and passes everything. |
| Turn the fast path off | `fastpath=off`, or `mode=0` in `fastpath/config` | Mode 0 within seconds; the SAS grant lease is revoked. |
| Go back to the default | Delete the lines (or the file); for the modem image delete `tk/config` and `tk/active.gz` | The default applies again: live for the switches, at the next boot for the image. |

## Your own settings still win

The switch is the master off. While it is on, an operator's own file
replaces the default for that feature:

| Feature | Operator file | Instead of the default |
| --- | --- | --- |
| Modem | `tk/config` without the `# witcher-default` first line (or with any line edited) | Your image, your `sha256=` allow-list and your `wm=` words. The firmware never rewrites it. |
| Clamp | `qctrl/config` | Your `mode=` and knobs. |
| Fast path | `fastpath/config` | Your `mode=`. |

`scripts/stage-latency.sh` still writes these files from a workstation.

The default clamp stands aside (mode 0) while `sch_cake` is loaded. Only a
radio profile's `sqm` action loads it, and CAKE download shaping and the clamp
have not been tested together. An operator's `qctrl/config` overrides that.

## Status

| File | Shows |
| --- | --- |
| `/var/run/witcher-tk.status` | The modem image this boot: `state`, `reason`, `build`, `build_secs` |
| `/mnt/titan-api/tk/verdict` | The default image's rollbacks: `genuine` (failures where stock answered, since its last confirmed boot), `network`, `pending` |
| `/var/run/witcher-tk.flags` | The modem words |
| `/var/run/witcher-qctrl.status` | The clamp; `detail` says where its mode came from |
| `/var/run/witcher-fastpath.status` | The fast path; `detail` says where its mode came from |

`keeper.log` lines start with `latency switches`, `tk boot` (`tk boot verdict`
for rollbacks of the default image), `tk flags`, `download clamp` or
`fast path`. **Network → Latency** shows the same: a row for each feature and
a **Modem image** row with the rollback state.
