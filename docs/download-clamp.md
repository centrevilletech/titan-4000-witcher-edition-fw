# Download clamp (titan_qctrl)

Status: off by default. Since v1.0.15 the keeper loads the clamp only on a
unit where an operator staged it and turned it on.

## Why

A full download fills the tower's queue for this unit. Everything else waits
behind it, so ping and every interactive flow slow down. On the bench
(2026-11-22) ping during a full download of about 130 Mbps sat near 310 ms.

## What it does

`titan_qctrl.ko` (v0.2-o1b) is a small kernel module. It sits on the bridge
between the customer bearer (`lte0pdn2`) and the customer port (`eth0`). It
lowers the TCP receive window that the customer's devices advertise, so each
sender keeps only a short queue at the tower.

- It measures the tower queue from the server's own TCP timestamp clock. A
  server without a usable timestamp clock falls back to round-trip time.
- One shared window covers all bulk downloads. A feedback loop keeps a few
  milliseconds of queue, so the link never runs dry.
- It never raises a window and never moves a window's right edge back.
- It lets go when it has no queue signal, and it releases the clamp if the
  download starves.

Bench result (2026-11-22, mode 2): ping during a full download went from
about 310 ms to 50 ms, for about 8 % less peak speed.

It works on TCP only. QUIC and other UDP pass untouched. It does its work in
IP passthrough, where customer traffic crosses that bridge. In NAT mode it
loads but sees no customer downloads.

## Where it comes from

The module is not in the firmware image (the root filesystem has little
room). Its source, a reproducible build and the binary are in
[`device/qctrl`](../device/qctrl/README.md) under GPL-2.0-only. The keeper
carries the binary's SHA-256 and loads nothing else.

## Turning it on

`scripts/stage-latency.sh` stages it together with the modem firmware
image (see [the boot-time loader](tk-boot-loader.md)). To stage only the
clamp, over the enrolled operator SSH login:

```sh
ssh -p 2222 root@<unit> 'mkdir -p /mnt/titan-api/qctrl && chmod 700 /mnt/titan-api/qctrl'
scp -P 2222 device/qctrl/payload/titan_qctrl.ko root@<unit>:/mnt/titan-api/qctrl/
ssh -p 2222 root@<unit> 'printf "mode=2\n" > /mnt/titan-api/qctrl/config && sync'
```

No reboot is needed. The keeper loads it within about 45 s once the customer
port and LTE are up.

`/mnt/titan-api/qctrl/config`:

| Line | Values | Meaning |
| --- | --- | --- |
| `mode=` | `0`, `2`, `3`, `6` | 0 off (pass-through). 2 receive-window clamp (the bench setting). 3 adds ACK thinning, 6 adds downlink ECN marks. |
| `trough_ms=` | 0 to 40 | Standing queue the loop keeps. Module default 4. A bursty uplink may need 8 or 12 for full speed. |
| `target_ms=` | 4 to 80 | Cap on the mean queue. Module default 40. |

A `#` starts a comment. The last line for a key wins. A bad `mode=` line
leaves the clamp off, and a bad knob line leaves the module default. Either
one is logged. Mode 8 (drop UDP) is never set.

## What the keeper does

Every 15 s, in every mode:

1. Reads `qctrl/config`. With no file or `mode=0` and no module loaded, it
   does nothing.
2. Waits until the customer port has carrier and the management bearer
   (`lte0pdn0`) has an address, both for 30 s.
3. Refuses to load if any other module with `qctrl` in its name is loaded,
   or a `titan_qctrl` whose `/proc/titan_qctrl` shows another version.
4. Copies `titan_qctrl.ko` into its RAM directory and checks the copy's
   SHA-256 against the digest built into the keeper, then runs `insmod` on
   that copy. The module starts in mode 0 (observe only).
5. Writes `trough_ms` and `target_ms` if the config sets them, then `mode`,
   to `/proc/titan_qctrl`, one line per write. Then it reads them back.
6. On later rounds it reads `/proc/titan_qctrl` again and writes the config
   again if they differ, so a config change applies within 15 s.

A failed load is not retried until the config changes or the unit reboots.

Status: `/var/run/witcher-qctrl.status`, with `state` (`off`, `waiting`,
`applied`, `failed`), `detail`, `mode`, `trough_ms`, `target_ms`.
`keeper.log` lines start with `download clamp`. A unit that never staged it
logs none.

`cat /proc/titan_qctrl` shows the live controller: `w_kb` (the shared
window), `rate100_kbps`, `q_owd_ms` (tower queue), `owd_ok` and `owd_bad`
(servers with and without a usable clock), `failsafe` (starvation releases).

## Turning it off

| Level | Action | Result |
| --- | --- | --- |
| Off now | `mode=0` in `qctrl/config` | The keeper writes mode 0 within 15 s. The module stays loaded and passes everything. |
| Off at boot | Delete `qctrl/config` (or keep `mode=0`) and reboot | Nothing is loaded. |
| Unload now | `mode=0` first, then `rmmod titan_qctrl` | Gone until the config asks again. With `mode=2` still set, the keeper loads it again. |

## Not tested yet

- Together with the radio profile's CAKE download shaping. Use one of them
  for downloads.
- Hours of customer traffic. The bench runs were 20-second downloads.
