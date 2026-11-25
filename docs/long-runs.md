# Long runs: flash writes, logs and clocks

A unit can run for weeks between reboots. Since v1.0.12 Witcher avoids four
slow problems that only show up over days.

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

The IPv6 health check times prefix delegations with the monotonic clock too,
since v1.0.13. See [IPv6 router health](ipv6-health.md#a-busy-link-is-never-cut).

## The vendor ping watchdog

The keeper keeps the stock ping watchdog off in RAM, whether its own watchdog
is on or off (v1.0.17). See [the deaf-unit fault](deaf-watchdog.md#the-vendor-ping-watchdog).

## Not changed

- The vendor `radvd` log (`/tmp/radvd.log`). Witcher does not start `radvd`.
- Core dumps. The vendor's `board.conf` sets them up (`ulimit -c`, a
  `core_pattern` in `/var/tmp` named after the program), so each program can
  leave at most one file there.
- The vendor's own logs. Its log helper, `syslogd` and `lted` cap their files.
