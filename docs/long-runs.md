# Long runs: flash writes, logs and clocks

A unit can run for weeks between reboots. Since v1.0.12 Witcher avoids four
slow problems that only show up over days. Since v1.0.13 it also fixes a
vendor counter bug that bounces the customer's Ethernet after billions of
packets.

## Flash writes

The keeper keeps its state in `/mnt/titan-api/pd`, on the unit's UBIFS data
volume. Before v1.0.12 each periodic router advertisement (every 45 s) added a
line to `keeper.log` there and made the keeper rewrite `status.json`. That is
about 5,700 flash writes a day. A 25.6-hour bench log held 2,860 lines, and
2,213 of them were that one line.

Now:

| File | Where | When it is written |
| --- | --- | --- |
| `keeper.log` | flash | Real events only: actions, state changes, warnings. Same repeat filter as before (an identical line waits 60 s unless it is an action). |
| `keeper.log` | RAM, `/tmp/titan-pd-keeper` | Every line, including each periodic or solicited advertisement. Moves to `keeper.log.1` at 64 KB. |
| `status.json` | RAM, `/tmp/titan-pd-keeper` | Every change. `titan-pd-keeper status` reads this copy. |
| `status.json` | flash | When its content changes, at most once a minute. A change inside that minute is written when the minute is up. The web service reads this copy, so it can lag by up to a minute. |

A routine line is no longer the keeper's "last action" in the web interface.
That field now shows the last real action.

Nothing that must survive a reboot moved. The setting, the pending change, its
confirmation, the router's delegation, the action budget, the watchdog strikes
and the management interface ID all stay on flash. So do real log lines, such
as a watchdog reboot. The keeper writes `status.json` again on its first pass
after a start, so the old copy never carried over anyway.

## Logs in `/tmp`

`/tmp` is RAM (ramfs) with no size limit. Once a minute `witcher-boot` checks
these logs. A log over 64 KB keeps its last 16 KB in `NAME.1` and starts again
empty:

- `/tmp/witcher-management.log`, `/tmp/witcher-recovery.log`
- `/tmp/titan-sshd-boot.log`, `/tmp/titan-pd-keeper-boot.log`, `/tmp/titan-api-boot.log`
- `/tmp/witcher-api/api.log`, `broker.log`, `collector.log`, `routes.log`

Every writer opens these files for append, so emptying one in place is safe
while its process runs.

## A setting change and a reboot

Saving the prefix delegation setting re-attaches LTE. A guard process puts the
previous IP family back after 180 s unless management came back. If the unit
reboots first, the guard is gone, and the keeper finishes the job when it
starts.

The Titan has no battery clock. It boots at 2013-06-20, and NTP fixes the clock
about a minute later, after the keeper has started. Before v1.0.12 the keeper
compared that 2013 clock with a 2026 time in `pending.json`, decided it was
too early, and never reverted. Now:

- On the keeper's first start in a boot (a marker in its RAM directory, with
  the kernel's boot ID), no guard can be running. The keeper reverts the
  change, whatever the clock says.
- If management had come back before the reboot (`confirm-<token>` holds the
  token), the keeper keeps the new setting, as the guard would have.
- On a later start in the same boot, the short gap before the guard starts
  still counts, but never more than 60 s, so a clock step cannot stretch it.
- The confirm step times its 150 s window and its 20 s stability check with
  the monotonic clock. An NTP step can no longer end the window early and
  revert a working setting.

## The vendor ping watchdog

While the keeper's own watchdog is on, the keeper turns off the stock ping
watchdog in RAM. See [the deaf-unit fault](deaf-watchdog.md#the-vendor-ping-watchdog).

## The vendor eth0 watchdog and the 2^31 packet clamp

The stock `monitor` daemon has an Ethernet watchdog. Each pass (a 120 s sleep
plus the pass itself) it reads the `eth0` receive and transmit packet counts:

```
cat /proc/net/dev | grep eth0 | awk '{print $3}'    -> atoi()
cat /proc/net/dev | grep eth0 | awk '{print $11}'   -> atoi()
```

If both numbers match the last pass while the link is `RUNNING`, it runs
`ifconfig eth0 down; sleep 2; ifconfig eth0 up`. On the third such pass in a
row it also asks `rcinit` for a LAN reset. That is meant for a frozen port.

The bug: the kernel's counters are 32-bit and go up to 4,294,967,295, but
uClibc `atoi()` is `strtol()`, which turns every value from 2,147,483,647 up
into 2,147,483,647. Once both counters are in that upper half, every pass
reads the same two numbers. `monitor` then bounces the customer's Ethernet
every pass and resets the LAN every third pass, while traffic flows, until a
counter wraps or the unit reboots. Taking `eth0` down does not clear the
counters: the driver keeps them in its own `net_device_stats`, and its open
and stop routines do not zero them.

How it was proven (`scripts/emulate-monitor-eth0.py`):

- The real ARM code of `monitor` (0x9bf0) and of uClibc `atoi` ran in an
  emulator. Each command ran through the image's own BusyBox `grep` and `awk`
  under `qemu-arm`, on a file standing in for `/proc/net/dev`.
  `system()` and `kill()` were only recorded.
- `atoi("2147483648")`, `atoi("3000000000")` and `atoi("4294967295")` all
  return 2147483647.
- Both counters past 2^31 and still moving: the stock binary bounced `eth0` on
  4 of 7 passes and asked for a LAN reset on the 3rd bounce. The patched one did
  nothing.
- A real freeze (no frame either way), with small or large counters: both
  binaries bounce on the 2nd, 3rd and 4th pass and ask for the LAN reset on
  the 4th. The fix keeps that.

When it happens: both counters must be past 2^31 at once. The driver counts a
large TCP download as one packet per GRO burst (about 14 KB in a bench
capture), so the transmit count often grows slowly. A busy household can get
there in a few months, sooner with a lot of UDP traffic such as QUIC video,
which is not merged. A unit with 62 days of uptime does not rule it out,
because this fault does not reboot the unit.

The fix (`scripts/patch-monitor.py`) changes only the two command strings:

```
grep eth0 /proc/net/dev | awk '{print $3%1e9}'
grep eth0 /proc/net/dev | awk '{print $11%1e9}'
```

`awk` prints each counter modulo 10^9. That is always below the clamp, and it
still changes when the counter changes. Below 10^9 it is the same number as
before, so the boot-time check that uses the same strings sees the same
values. A false match would need a counter to move by an exact multiple of
10^9 within one pass. No code, timing or action in `monitor` changes, and
Witcher adds no process that can take `eth0` down. The build checks the stock
bytes before it patches, and `verify-firmware.py` runs both commands with the
packed BusyBox under QEMU at 0, 999,999,999, 2^31 - 1, 2^31 and 2^32 - 1.

To check on a unit: run the two commands above. Each should print a number,
and `/tmp/monitor.log` should not show `eth tx & rx packets are not changed`
while traffic flows. If a unit ever misbehaves with this patch, the fallback
is to skip the check altogether: the call at 0xbca4 (`bl 0x9bf0`).

## Clock steps and the SAS 300 s guard: no change

`sqn-date` sets the clock from NTP with `stime()`, then sleeps
`ntp_refresh_interval` minutes (720 on the bench), and retries every 30 s
after a failure. `cbrs_fsm` treats any jump of more than 300 s between two of
its own samples as "Date Jumped" and deregisters. A step over 300 s would cost
the grant.

The worry was a clock that runs 0.154 % slow (133 s a day). That number is the
kernel log's timestamp clock, not the system clock. In two units' keeper logs
the wall clock minus uptime stayed within about 1 s over a 25.6 h boot and a
28.4 h boot, and the 12 h NTP step was about 1 s (it was -0.9 s on the bench;
`sqn-date` drops the fraction of a second). At that rate a step over 300 s
needs months with no NTP answer at all. A shorter refresh interval would add
more of these small backward steps and fix nothing, so this release leaves
`sqn-date` and `cbrs_fsm` alone.

## Not changed

- The vendor `radvd` log (`/tmp/radvd.log`). Witcher does not start `radvd`.
- Core dumps. The vendor's `board.conf` sets them up (`ulimit -c`, a
  `core_pattern` in `/var/tmp` named after the program), so each program can
  leave at most one file there.
- The vendor's own logs. Its log helper, `syslogd` and `lted` cap their files.
