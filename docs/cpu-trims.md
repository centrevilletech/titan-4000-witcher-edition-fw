# CPU trims on the Linux core

The Titan 4000 has one Linux core (CPU0). It forwards every customer packet
and also runs the vendor's daemons, the keeper and the API. Work the vendor
does in the background is CPU the forwarding path cannot use.

The keeper can trim two pieces of that background work. Both are **off by
default**, both are undone live, and neither needs a server or a reflash.

## Status: not qualified

The first bench run (2026-11-25, one unit, one A-B-C-A pass) did not show a
gain. `softirq` changed nothing measurable. `led` cut the vendor loop's own
CPU by 65 to 70 %, but `ucid` and `lted` did more work while the loop was
paced, so the net was about zero at rest and about 3 points of CPU0 worse
under load. The idle windows were noisy. Leave both trims off until a
cleaner A/B shows otherwise.

## The setting

One file on the persistent volume:

```text
/mnt/titan-api/cpu-trims/config
```

```text
# which trims are on: none, led, softirq, or both
trims=led,softirq
# seconds in one LED pacing period (2 to 8, default 4)
led_period=4
```

- No file, an empty file, or `trims=none`: every trim is off.
- One unknown name in `trims=` refuses the whole line, and every trim stays
  off. The keeper logs the refused line once.
- The keeper reads the file every 5 s. Remove the file (or write
  `trims=none`) and the keeper undoes both trims within 5 s. No reboot.

Status is in `/var/run/witcher-cpu-trims.status`:

```text
trims=led,softirq
led=pacing
led_period=4
softirq=nice -5
pauses=1234
lock_backoffs=2
updated=5678
```

## `led`: pace the vendor LED loop

### What the loop is

`/tmp/child_gp` is the vendor's `rcinit` binary under another name, started
and restarted by `/tmp/gpio`. It runs one loop every 500 ms. Read from the
stock `rcinit` (`Gpio_main`), each pass does this:

1. **Reset button.** Only while `/tmp/gpio4_interrupt_mask` exists. `bmon`
   creates that file when the button interrupt fires. The loop then reads
   the button each pass. After more than 10 passes held down (about 5.5 s)
   it restores factory defaults and reboots. When the button is up it
   removes the file.
2. **Radio refresh for the LEDs.** Every eighth pass (every 4 s) it forks a
   shell to `touch /tmp/sqns_admin_refreshForLed`. `ucid` sees the file,
   forks another shell to remove it, and runs a set of modem queries that
   write the radio fields into the vendor configuration cache
   (`/tmp/nvram.cfg`).
3. **Signal LEDs.** It reads the SIM state, the connection state and the
   RSRP from the cache (three reads, each one a lock, a whole-file read and
   a parse) and repaints the LEDs when the level changed.
4. **Reconnect.** While the unit is attached and the RSRP it reads is `-`,
   `-,-`, below -140.00 dBm or above -20.00 dBm, it counts passes. After
   more than 40 passes in a row (about 20 s) it sets `sqns_admin_apply=1`,
   which makes the vendor stack reconnect.

It does not touch the hardware watchdog. `monitor` sets that up, and the
trims never touch `monitor`.

So the loop cannot simply be stopped: that would take away the reset button
and the vendor's reconnect.

### What the trim does

The keeper pauses the loop with `SIGSTOP` and lets it run for about one
second in every `led_period` seconds. At the default of 4 the loop runs
about a quarter of its stock passes.

The keeper paces the loop **only** while both of these hold. It checks them
every second:

- `/tmp/gpio4_interrupt_mask` does not exist, so no button press is pending;
- the cache shows `sqns_connection_mediaState` as `CONNECTED` or `ATTACHED`,
  `sqns_simcard_state` as `Ready`, and every value in `sqns_radio_RSRP`
  inside -140.00 to -20.00 dBm, so the loop's reconnect counter is at rest.

In every other state the keeper resumes the loop at once and leaves it at
the vendor's full rate. The reset button and the reconnect therefore keep
their stock timing, with up to one extra second for the keeper to notice.

A paused process keeps any lock it holds. The loop takes a lock on the
vendor configuration cache when it reads it, and a lock held across a pause
would block `ucid`, `cbrs_fsm` and every other reader. So after every
`SIGSTOP` the keeper reads `/proc/locks`. If the loop holds any lock, the
keeper resumes it at once and tries again a second later
(`lock_backoffs` in the status file). If `/proc/locks` cannot be read, the
keeper never pauses the loop.

The keeper finds the loop by `argv[0]` (`/tmp/child_gp`) and checks
`/proc/<pid>/cmdline` again before every signal. If it finds more than one
such process it touches none.

### What changes for the user

- The signal LEDs follow the radio up to `led_period` seconds late.
- The radio fields in the vendor cache that the LED refresh drives
  (RSRP, RSRQ, RSSI and the carrier list) refresh less often: about every
  16 s at the default period instead of every 4 s. `ucid` also refreshes
  them on its own 2 s loop when asked to.
- The vendor's reconnect takes up to `led_period` + 1 seconds longer to
  start counting, because the keeper must first see the bad signal in the
  cache.

### A keeper that dies

A keeper that dies while the loop is paused would leave the unit with no
reset button. Three things bound that:

- the supervisor in `/etc/init.d/titan-pd-keeper` checks the keeper every
  10 s and sends `SIGCONT` as soon as it finds it gone, before it waits to
  start it again. A keeper that starts always sends one `SIGCONT` before
  anything else;
- `/etc/init.d/titan-pd-keeper stop` sends `SIGCONT` itself;
- a reboot starts a fresh loop.

## `softirq`: priority for `ksoftirqd/0`

Packet work that does not fit in the interrupt path runs in the kernel
thread `ksoftirqd/0`. At nice 0 it takes turns with every daemon on the
unit. The trim sets it to nice -5 with `setpriority`, and back to 0 when
the trim is off.

This does not make any work cheaper. Under load it gives forwarding a
larger share of the core than the vendor daemons get. Userspace still runs:
the scheduler gives a nice 0 task about a quarter of the core against one
nice -5 task.

The keeper owns only the step between 0 and -5. A value someone else set
stays as it is.

## What the trims leave alone, and why

| Candidate | Finding | Decision |
| --- | --- | --- |
| Stop `/tmp/child_gp` for good | It runs the reset button and the vendor reconnect (above). | Pace it, never stop it. |
| Idle `webs -x` | The vendor's WiFi script daemon. It sleeps until a signal asks it to run `init.sh`. `top` on the unit shows 0.0 % CPU. | Nothing to save. Left running. |
| Idle `udhcpd -f /tmp/udhcpd_wifi.conf` | The DHCP server for the unit's own WiFi. It sleeps in `select` with no clients. 0.0 % CPU. | Nothing to save. Left running. |
| `gps` | It writes `gps_latitude`, `gps_longitude`, `gps_height` and `gps_date` into the vendor cache, and `cbrs_fsm` has a GPS path for its SAS registration when the unit is not CPI-registered. | Not safe to stop on every unit. Left running. |
| `monitor` | It sets up the hardware watchdog and restarts `ucid`, `tr069`, `rcinit` and four more daemons. | Never touched. |
| `net.core.netdev_tstamp_prequeue=0` | On Linux 3.10 this only moves the receive timestamp from before the backlog queue to after it. The timestamp is taken once either way, and only when a socket asks for timestamps. | No CPU to save on one core. Not shipped. |
| `eth0` qdisc bypass | The keeper's IPv6 leak guard is a `prio` qdisc with a blackhole band, and `prio` cannot be bypassed. The only other place to drop the core's router advertisements is the bridge, and the unit's kernel has no `ebt_ip6` match (and `iproute2` has no `gact`). | Needs a kernel-side guard first. Not shipped. See the lane report. |
| `kern netif q 0` | It switches off the vendor's receive hook, which is where the vendor rewrites the host MAC in net_mode 2. The router-swap fix depends on that rewrite. | Never touched. |
| `ucid` polling | Needs a binary patch. | Patch spec only, in the lane report. Not shipped. |

## Bench qualification

Measure CPU0 idle from `/proc/stat` over 60 s, at rest and under a fixed-rate
UDP download, with the trims off, on, and off again. Keep the radio state,
the fast path mode and the download clamp mode the same in all three.

To check the reset-button gate, press the real button for a second or two
(the vendor loop acts only after about 5.5 s held down). The status file
must show `led=full-rate (reset button pending)` within a second, and
`led=pacing` again after the release. Creating `/tmp/gpio4_interrupt_mask`
by hand also triggers the gate, and the loop removes the file on its next
pass while the button is up. Do that only on a bench unit, and remove the
file yourself within 3 s: if the button input ever read as "down", the loop
would count towards a factory restore.
