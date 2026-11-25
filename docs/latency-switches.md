# Latency features: on by default

Since v1.0.17 a unit that is only flashed gets every latency and upload
improvement Witcher has. Nothing needs SSH, staging or flags. Each feature
can be turned off on its own, live.

| Feature | What it does | Bench result | Details |
| --- | --- | --- | --- |
| Upload latency and AQM (the modem words) | A patched modem image the unit builds from its own stock firmware. Its words turn on the uplink queue control, the grant hold, the sparse-flow lane and the Rust PIE uplink AQM, whose v1.0.17 defaults are bench step S3 (drop budget 5%, ceiling 35 ms). | Ping during an upload about 100 ms to 38 ms; 4-stream CUBIC upload on two carriers 7.4 to 14.9 Mbps; S3 at or below v1.0.16's queue delay in every A/B (about 5-7 ms lower with four CUBIC flows) at the same throughput | [Boot-time loader](tk-boot-loader.md), [building the image](tk-patch.md) |
| Download clamp (`titan_qctrl`) | Keeps the tower's download queue short, mode 3 (window clamp plus ACK thinning). It acts in IP passthrough. | Ping during a full download about 310 ms to 50 ms in mode 2, for about 8 % less peak speed; mode 3 took about 6 ms more off with no speed cost | [Download clamp](download-clamp.md) |
| Fast path (`titan_k1fp`) | Forwards steady IP passthrough flows past the full bridge path, mode 2 (downlink). | About 20 points of CPU back at 170 to 200 Mbps, +7 to 10 % download | [Fast path](fast-path.md) |

## The first boot of v1.0.17

1. **Modem image.** Right before the boot's one `modprobe modem`, the boot
   hook asks the keeper whether `tk/` holds anything an operator made. When
   it does not, the keeper builds the release image from the active modem
   bank and writes it with a default `tk/config`. The image loads for that
   same `modprobe`. This makes that one boot about 20 s slower (17.5 s on the
   bench), and later boots reuse the file. After the boot confirm (an answer
   through the core) the keeper writes the modem words.
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
- the release image's rollback waits for its stock verdict, or its
  quarantine stuck (two failures in a row where stock firmware answered),
  or this firmware build counted two of its boots without a confirm.

`/var/run/witcher-tk.status` says why (`reason=`), and `build=` says what the
default image did this boot.

No network condition keeps a unit off the image: not a tower, core or
backhaul outage, a missing SAS grant, the CPAS window or targets that ignore
ping. A new firmware build clears a quarantine by itself (`build=cleared`).
The next section shows what a unit does.

## A tower outage at the moment of upgrade

This is what a unit does when its tower is down as it boots v1.0.17 for the
first time and stays down for hours. Any later boot with the default image
goes the same way from step 2. `564d918b` is the release image.

1. **Boot 1, boot hook.** Before the boot's one `modprobe modem`, the keeper
   builds the release image from the active modem bank (about 20 s). It
   writes `tk/active.gz`, the default `tk/config` and `tk/default`. The hook
   records strike 1 of 2 (`strikes=1` with `firmware=`, this build) and loads
   the image. Status: `state=staged`, `build=built`.
2. **Boot 1, waiting.** The keeper probes every 15 s, with ping and DNS. The
   modem searches and sees no cell, so the boot confirm's 300 s clock does
   not run: no cell is waiting, not failure. The modem words stay off until
   the confirm. The clamp and the fast path wait for LTE as always.
   `keeper.log`: `tk boot confirm armed: ... time with no cell is waiting,
   not failure`.
3. **Boot 1, after 30 minutes with no cell: one comparison.** The reboot gate
   lets it go: nothing has answered since boot, so the unit holds no SAS
   grant to lose. The keeper adds the image's hash to `tk/quarantine`, writes
   `strikes=2` and `pending=1` in `tk/verdict`, reads them back and reboots
   onto stock modem firmware. `keeper.log`: `tk boot confirm: no cell in view
   for 1800 s in a row with modem firmware 564d918b...; quarantined it for
   now (the next stock boot tells whether the image or the network failed),
   rebooting onto stock modem firmware`.
4. **Boot 2, stock modem firmware.** The hook keeps stock firmware
   (`reason=quarantined`). The keeper watches stock firmware the same way,
   for 300 s from the modem load. `keeper.log`: `tk boot verdict armed: ...`.
5. **Boot 2, at 300 s, the tower still down: the network failed.** The
   keeper takes the hash out of `tk/quarantine`, writes `strikes=0`, records
   `network=1` and `outage=1`, and reboots straight back onto the image.
   `keeper.log`: `tk boot verdict: stock modem firmware got no answer through
   the core either, so the rollback of modem firmware 564d918b... was the
   network's (1 so far); it is out of quarantine, and the unit goes back onto
   it, where it waits for the network`, then `tk boot verdict: rebooting back
   onto modem firmware 564d918b...`.
6. **Boot 3, the image again** (`build=cached`, nothing rebuilt). It waits
   for the tower as stock firmware would.
   - With `outage=1` it is not compared again until it answers. The one
     exception is a recheck after 24 hours without an answer.
   - No more reboots for the rest of the outage, however long it lasts.
   - **Network → Latency** shows **Modem image**: "Waiting for the network:
     ...".
7. **Service returns.** The modem sees the cell and attaches. The first
   answer through the core (ping or DNS) confirms the boot, usually within a
   minute: `strikes=0`, `outage=0`, the failure count back at 0. The keeper
   writes the modem words, and every feature is on. Nothing reboots when
   service returns.

So the whole outage costs one image → stock → image cycle, and the unit is
on the image when service returns.

- **The tower comes back before the 30 minutes run out** (step 2): the image
  attaches and confirms, with no comparison at all.
- **The tower comes back while the unit is on stock firmware** (step 4):
  stock answers, which counts as failure 1, and the unit reboots straight
  back onto the image anyway. With the tower up the image confirms, and the
  count goes back to 0.
- **The core or backhaul is down but the cell is up:** the same, except that
  the comparison comes after 300 s with the cell in view instead of 30
  minutes of searching.
- **Power comes and goes while the unit boots.** Two image boots can end
  before their confirm decides anything (`strikes=2`, no rollback). The stock
  boot after them records the two as one rollback and judges it as in steps
  4 and 5.
- **A reboot falls due inside the SAS CPAS window** (06:45 to 10:15 UTC) on a
  unit with a set clock: it waits for the window to end, and a rollback
  records nothing until then.
- **Every keeper reboot counts toward a cap of 4 in 24 hours**, with the last
  slot kept for the way back onto the image.
- **The modem crashes** while the image runs: the keeper judges the crash on
  that boot by watching stock firmware, and the unit goes straight back onto
  the image. Only two crashes in a row where stock then answers keep it
  quarantined.

The image stays off only after two failures in a row where stock firmware
answered each time, the second straight after a retry with the tower known
to be up. **Network → Latency** then shows **Modem image**: "Quarantined
after 2 failures in a row where stock modem firmware answered. Retry, or a
new firmware, tries it again at the next boot." A new firmware build clears
that quarantine by itself.

**Retry the modem image** clears the quarantine, the failure counts and the
strikes. It does not reboot: restart the unit to load the image now. If the
image fails again, the same rules apply.

[Boot-time loader](tk-boot-loader.md#the-default-image-no-network-condition-keeps-it-off)
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
| `/mnt/titan-api/tk/verdict` | The default image's rollbacks: `genuine` (failures in a row where stock answered, since its last confirmed boot), `network`, `pending`, `outage` (waiting for the network), `firmware` (the build that wrote it) |
| `/mnt/titan-api/pd/keeper-reboots` | The keeper's own reboots, for its cap of 4 a day |
| `/var/run/witcher-tk.flags` | The modem words |
| `/var/run/witcher-qctrl.status` | The clamp; `detail` says where its mode came from |
| `/var/run/witcher-fastpath.status` | The fast path; `detail` says where its mode came from |

`keeper.log` lines start with `latency switches`, `tk boot` (`tk boot verdict`
for rollbacks of the default image), `tk flags`, `download clamp` or
`fast path`. **Network → Latency** shows the same: a row for each feature and
a **Modem image** row with the rollback state.
