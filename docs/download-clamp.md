# Download clamp (titan_qctrl)

Status: on by default since v1.0.17, in mode 3 (receive-window clamp plus
ACK thinning). The module is in the firmware image. `clamp=off` in
`/mnt/titan-api/latency/config`, or the **Download clamp** switch under
**Network → Latency**, turns it off live (see [latency features](latency-switches.md)).

## Why

A full download fills the tower's queue for this unit. Everything else waits
behind it, so ping and every interactive flow slow down. On the bench
(2026-11-22) ping during a full download of about 130 Mbps sat near 310 ms.

## What it does

`titan_qctrl.ko` (v0.3-q3) is a small kernel module. It sits on the bridge
between the customer bearer (`lte0pdn2`) and the customer port (`eth0`). It
lowers the TCP receive window that the customer's devices advertise, so each
sender keeps only a short queue at the tower. With no new knobs set, v0.3-q3
executes the exact v0.2-o1b control and ACK-thinning paths so operators can
A-B-B-A old against new in a single loaded module.

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

Since v1.0.17 the module is in the firmware image, at
`/usr/lib/titan-api/modules/titan_qctrl.ko`. Its source, a reproducible build
and the binary are in [`device/qctrl`](../device/qctrl/README.md) under
GPL-2.0-only. The keeper carries the binary's SHA-256 and loads nothing else.
A copy staged in `/mnt/titan-api/qctrl/` still takes precedence, but only
when it has that same SHA-256; any other bytes are refused, and the image's
copy loads instead.

## Settings

With no `qctrl/config` the keeper runs `qctrl::DEFAULT_MODE`, which is 3, and
the module's own knobs. That one constant in `userspace/pd-model/src/qctrl.rs`
sets the default: 2 is the clamp alone, 0 leaves it off until an operator
turns it on.

The default stands aside, at mode 0, while a CAKE qdisc is installed. Only a
radio profile's `sqm` action installs one, and the two have not been tested
together (below). The keeper reads it from `sch_cake`'s use count in
`/proc/modules`: every qdisc holds a reference to its module, so the count is
the number of CAKE qdiscs. When the profile is reverted or removed the count
drops to 0, with the module still loaded, and the default clamp comes back
within 15 s. (v1.0.17's first draft stood aside while the module was merely
loaded, so after a revert the unit had neither CAKE nor the clamp until it
rebooted.) An operator's `qctrl/config` overrides both the default and this
rule. To set your own mode or knobs, stage a config. `scripts/stage-latency.sh`
writes one together with the modem firmware image (see
[the boot-time loader](tk-boot-loader.md)). For only the clamp, over the
enrolled operator SSH login:

```sh
ssh -p 2222 root@<unit> 'mkdir -p /mnt/titan-api/qctrl && chmod 700 /mnt/titan-api/qctrl'
ssh -p 2222 root@<unit> 'printf "mode=2\ntrough_ms=8\n" > /mnt/titan-api/qctrl/config && sync'
```

No reboot is needed: the keeper applies a change within 15 s.

`/mnt/titan-api/qctrl/config`:

| Line | Values | Meaning |
| --- | --- | --- |
| `mode=` | `0`, `2`, `3`, `6` | 0 off (pass-through). 2 receive-window clamp (the bench setting). 3 adds ACK thinning, 6 adds downlink ECN marks. |
| `trough_ms=` | 0 to 40 | Standing queue the loop keeps. Module default 4. A bursty uplink may need 8 or 12 for full speed. |
| `target_ms=` | 4 to 80 | Cap on the mean queue. Module default 40. |
| `ack_adapt=` | `0`, `1` | 0 off (v0.2-o1b thinning path, default). 1 adaptive safe ACK thinning when mode bit 0 is set (per-flow time/segment budget, SACK/dupACK recovery cooldown, slow-start and rate-floor bypass, automatic rate-drop backoff, evenly staggered flush grid). |
| `ctrl_v3=` | `0`, `1` | 0 off (v0.2-o1b controller, default). 1 low-burst controller (gentler ramped 12 s drain, faster dead-flow eviction on join/leave, fast recovery after capacity steps, zero-collapse guard at `trough_ms=0`). |
| `ack_ms=` | 1 to 10 | Per-flow ACK time budget in ms when `ack_adapt=1`. Module default 6. |
| `ack_segs=` | 2 to 32 | Per-flow ACK segment budget when `ack_adapt=1`. Module default 18. |
| `ack_min_kbps=` | 0 to 100000 | Per-flow DL rate floor in kbps below which `ack_adapt=1` never thins. Module default 2000. |

A `#` starts a comment. The last line for a key wins. A bad `mode=` line
leaves the clamp off, and a bad knob line leaves the module default. Either
one is logged. Mode 8 (drop UDP) is never set.

## What the keeper does

Every 15 s, in every mode, and at once when the latency switches change:

1. Works out the mode: 0 while `clamp=off` is in the latency switches; the
   operator's `qctrl/config` when there is one; else the default (mode 3,
   or 0 beside CAKE). With mode 0 and no module loaded, it does nothing.
   Without the Witcher volume there is no operator file, so the default
   loads from the image; the file counts again as soon as the volume is
   mounted.
2. Waits until the customer port (`eth0`) and the customer bearer (the LTE
   port in the bridge in passthrough, else the vendor's data bearer) have
   carrier, both for 30 s. The clamp sits between those two; it does not
   wait for the management bearer.
3. Refuses to load if any other module with `qctrl` in its name is loaded,
   or a `titan_qctrl` whose `/proc/titan_qctrl` shows another version.
4. Copies `titan_qctrl.ko` (the staged copy, if it is the pinned one, else
   the image's) into its RAM directory and checks the copy's SHA-256 against
   the digest built into the keeper, then runs `insmod` on that copy. The
   module starts in mode 0 (observe only).
5. Writes any configured knobs (`trough_ms`, `target_ms`, `ack_adapt`,
   `ctrl_v3`, `ack_ms`, `ack_segs`, `ack_min_kbps`), then `mode`, to
   `/proc/titan_qctrl`, one line per write. Then it reads them back.
6. On later rounds it reads `/proc/titan_qctrl` again and writes the config
   again if they differ, so a config change applies within 15 s.

A failed load (the module refused, ENOMEM, a bad read of the image copy) is
tried again after 1 min, then 2, 4 ... up to an hour between tries, for as
long as it fails; the status says when. Another config, or the switch turned
off and on, tries at once.

Status: `/var/run/witcher-qctrl.status`, with `state` (`off`, `waiting`,
`applied`, `failed`), `detail` (which says where the mode came from: the
firmware default, `qctrl/config`, the switch, or standing aside for CAKE),
`mode`, `trough_ms`, `target_ms`, `ack_adapt`, `ctrl_v3`.
`keeper.log` lines start with `download clamp`. A clamp that is off from the
start logs none.

`cat /proc/titan_qctrl` shows the live controller: `w_kb` (the shared
window), `rate100_kbps`, `q_owd_ms` (tower queue), `owd_ok` and `owd_bad`
(servers with and without a usable clock), `failsafe` (starvation releases).

## Turning it off

| Level | Action | Result |
| --- | --- | --- |
| Off now | `clamp=off` in `/mnt/titan-api/latency/config`, or the web switch | The keeper writes mode 0 within seconds. The module stays loaded and passes everything. |
| Off now, operator config | `mode=0` in `qctrl/config` | The same, within 15 s. |
| Off at boot | Keep `clamp=off` (or `mode=0`) and reboot | Nothing is loaded. |
| Unload now | Turn it off first, then `rmmod titan_qctrl` | Gone until a non-zero mode asks for it again. |

## Not tested yet

- Together with the radio profile's CAKE download shaping. The default clamp
  stands aside while a CAKE qdisc is installed; an operator who sets both up
  in `qctrl/config` runs both.
- Hours of customer traffic. The bench runs were 20-second downloads.
