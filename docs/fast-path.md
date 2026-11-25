# Passthrough bridge fast path (titan_k1fp 2.2.1)

Status: on by default since v1.0.17, in mode 2 (downlink fast path), which
the bench has run for days. `titan_k1fp.ko` is in the firmware image
(`/usr/lib/titan-api/modules/`). The keeper verifies its SHA-256 against
[`device/fastpath/SHA256SUMS`](../device/fastpath/SHA256SUMS), loads it in IP
passthrough once the links settle, and drives its SAS grant lease directly
from the keeper's CBRS gate. On load the module starts in `mode 0` (off).
`fastpath=off` in `/mnt/titan-api/latency/config`, or the **Fast path**
switch under **Network → Latency**, turns it off live (see
[latency features](latency-switches.md)).

## Why

At 133 to 146 Mbps in IP passthrough, the Titan 4000 CPU sits at 0 to 5 %
idle with 66 to 72 % softirq, backlog drops, and time squeezes in
`/proc/net/softnet_stat`. Every bridged IPv4 packet walks the bridge,
ebtables, `br_netfilter`, iptables, and conntrack before reaching
`dev_queue_xmit`. Saturated softirq also adds queueing delay under load.

`titan_k1fp` (v2.2.1) short-circuits steady-state unicast IPv4 and IPv6
TCP/UDP flows between `lte0pdn2` and `eth0` straight from the bridge port
RX handler to `dev_queue_xmit`, after proving each flow through the full
stock path first.

## Operating modes

Control and telemetry live in `/proc/k1fp`. Write one command per write:

| Command | Meaning |
| --- | --- |
| `mode 0` | Off (default at load). Immediate pass-through to `br_handle_frame_hook`. |
| `mode 1` | Observe. Classifies packets, proves flows on the stock path, and counts `would_fast` without changing forwarding. |
| `mode 2` | Downlink fast path (`lte0pdn2 -> eth0`). Uplink stays on the stock path. |
| `mode 3` | Both directions. When `titan_qctrl` is loaded on `NF_BR_FORWARD`, uplink TCP stays on stock so receive-window clamping and ACK thinning never get bypassed. |
| `grant <0..60>` | Renew or revoke (`0`) the userspace SAS grant lease in seconds. |
| `require_grant <0\|1>` | Default `1`. Fast path stays closed until a live grant lease is present. |
| `v4 <0\|1>`, `v6 <0\|1>` | Enable or disable IPv4 or IPv6 fast-path eligibility (both default `1`). |
| `lease_ms <10..1000>` | Per-flow lease lifetime (default `60` ms). |
| `sample_ms <2..50>` | Periodic stock-path re-proof interval (default `20` ms, capped at `50` ms). |
| `wd_mod <0..10000>` | Watchdog `modified + wrongport` burst limit per window (default `20`, `0` disables). |
| `wd_mod_win_ms <1000..60000>` | Sliding burst window (two half-windows) for `wd_mod` (default `10000` ms). |
| `wd_mismatch <0..10000>` | Watchdog lease mismatch limit per second (default `64`, `0` disables). |
| `wd_stall_ms <100..5000>` | Watchdog TX stall: how long the `eth0` TX tail may stay frozen with the ring full or the queue stopped (default `2000` ms). |
| `wd_ringfull_ms <0, 100..5000>` | Watchdog: how long the ring may stay full while it drains (default `0`, off; for `txirq` tests). |
| `flush` | Clear all flow leases and bump the epoch. |
| `zero` | Zero counters, clear the diagnostic mismatch ring, and re-baseline the watchdog. |

## What stays on the stock path

Every control, management, and non-steady-state frame stays on the normal
bridge and netfilter path:

- Non-IP frames: ARP, 802.1Q VLAN, 802.1ad QinQ, PPPoE.
- Multicast, broadcast, invalid source MAC, IPv4 special ranges (`0/8`,
  `127/8`, `224/4`, `240/4`), IPv6 multicast (`ff00::/8`), unspecified
  (`::`), loopback (`::1`), and link-local (`fe80::/10`).
- ICMP, IGMP, ICMPv6 (RS, RA, NS, NA, MLD, Packet Too Big), IPv6
  extension headers, IPv4 options, IPv4 fragments, TTL/hop-limit 0, and
  bad IPv4 header checksums.
- TCP `SYN`, `FIN`, and `RST` packets (so conntrack, TCP MSS clamping,
  and `titan_qctrl` window-scale tracking see every handshake and close).
- DHCPv4 (UDP 67/68) and DHCPv6 (UDP 546/547).
- Shared, loopback, VLAN-tagged, non-linear, or GSO/GRO skbs, packets
  larger than the egress MTU, and frames addressed to `br0`, `eth0`, or
  `lte0pdn2` MACs (local management traffic).
- Any packet during a vendor bridge hold (`external_dev_stop` or queued
  `brhook` frames), non-forwarding port state, or when `br0` does not have
  exactly two ports.

## Safety design

- **Vendor router-MAC rewrite preserved**: `dlbypass` (the v1.2 `gdmlte`
  live patch) is removed in 2.0. Downlink frames stay on the vendor
  `netif_enqueue` path (`netifq_enabled=1`) so the driver always applies
  its learned router MAC before bridge RX.
- **CBRS and SAS enforcement (IPv4 and IPv6)**: IPv4 leases are granted
  only at `NF_INET_POST_ROUTING` (`NF_IP_PRI_LAST`), after iptables
  `FORWARD` and `SNAT`. IPv6 leases are granted only at
  `NF_BR_POST_ROUTING` (`NF_BR_PRI_LAST`), after ebtables `FORWARD` and
  `br_nf_post_routing`. When a grant drops, vendor IPv4 `iptables FORWARD
  DROP` and Witcher IPv6 `ebtables FORWARD DROP` drop the next re-proof
  sample within `sample_ms` (20 ms) and revoke the lease. In addition,
  `require_grant=1` closes both families immediately when the grant feeder
  writes `grant 0` or stops renewing. While the gate is closed, candidates
  stay on the stock path without sampling or renewing leases, and every
  gate open/close transition bumps `epoch` so every flow must prove fresh
  against the open-gate rules before any packet is fast-pathed.
- **Local-delivery and SLUB-alias proof isolation**: Bridge hooks at
  `NF_BR_LOCAL_IN` and `NF_BR_LOCAL_OUT` (`NF_BR_PRI_FIRST`) cancel an
  active pending proof whenever a sampled skb enters `br_pass_frame_up`
  (such as a reverse-SNATed SAS reply delivered to `br0`) or a locally
  originated frame on `__br_deliver` aliases its pointer. Any pre-existing
  lease on a cancelled flow is still revoked fail-closed, while the
  unit's own synchronous TCP replies cannot trigger false `modified` or
  `wrongport` counts.
- **`titan_qctrl` coexistence**: `titan_k1fp` discovers a loaded
  `titan_qctrl` hook live on `NF_BR_FORWARD` under softirq RCU without
  holding stale pointers. On downlink fast path (modes 2 and 3), it calls
  `titan_qctrl`'s hook directly so the clamp sees 100 % of downlink bytes,
  timestamps, OWD, RTT, ECN marking, and UDP drop. On uplink TCP (modes 1
  and 3), it yields to stock while `titan_qctrl` is loaded so RWND
  clamping and ACK thinning run untouched.
- **In-kernel watchdog and mismatch ring (no kernel-log dependence)**:
  While `mode >= 2`, a 100 ms timer and inline proof checks drop `mode` to
  `0` on `modified + wrongport` bursts (`wd_mod`, default 20 within a
  sliding `wd_mod_win_ms` window, default 10 s), lease mismatch storms
  (`wd_mismatch`, default 64/s), an `eth0` TX stall (a TX tail that stays
  frozen with the ring full or the queue stopped, `wd_stall_ms`, default
  2 s), or invalid TX ring state. Up to v2.2 it also tripped on a ring that
  stayed full for 500 ms while it drained (`wd_ringfull_ms`), and on a
  500 ms stall. A router port linked at 100 Mb/s under a faster download
  keeps the ring full at line rate, and two 802.3x PAUSE frames from the
  router at 100 Mb/s (up to 336 ms each; the driver obeys them) freeze the
  tail for longer than 500 ms. Neither is the fast path's doing, so since
  v2.2.1 `wd_ringfull_ms` is off by default and `wd_stall_ms` is 2 s
  (`k1_wd_defaults` in `k1fp_core.h`). A frozen tail still trips. The
  last 16 mismatches are recorded in a bounded header-only ring (`diag:`
  in `/proc/k1fp`, at most `min(hdrlen, 64)` bytes before and after plus a
  field diff summary, with zero payload bytes beyond transport headers),
  readable after a trip and cleared by `zero`. All health counters live in
  `/proc/k1fp`.
- **Device loss and re-acquire (v2.2)**: A modem re-attach makes the vendor
  scripts delete and recreate `br0` and `lte0pdn2`. When `eth0`,
  `lte0pdn2`, or the bridge is unregistered, the module drops its pointer
  and reference, sets `mode 0`, and counts `dev_gone` (line `devices:` in
  `/proc/k1fp`). This is not a watchdog trip. Its 1 s housekeeping work
  then looks the missing devices up again by name under RTNL. It adopts
  them only once `eth0` and `lte0pdn2` are both stock ports of one bridge
  again, the same test the module applies at load, and only if that agrees
  with every device it still holds. It then counts `reacq`, bumps the
  epoch so every flow proves itself again, and stays at `mode 0` until
  userspace writes the mode. Up to v2.1 the module never looked again:
  after a re-attach `/proc/k1fp` showed `br=- br_ports=-1 ports_ok=0`
  until someone reloaded it.
- **Kernel fingerprint verification**: On `insmod`, `titan_k1fp` hashes
  the 8 kernel functions it relies on with freestanding SHA-256 and
  refuses to load on any byte mismatch.

## Stopping `[IPC ST]` kernel log spam

Running `kern ipc st` on the unit starts a 1 Hz kernel timer
(`start_ipc_timer`, default period 1 s) that calls `print_ipc_info` once
per second forever (~18 lines/s, wrapping the 256 KB dmesg buffer every
~3.5 minutes). Neither vendor daemons nor Witcher invoke it.

- Stop an active timer live: `kern ipc -st`
- Take a one-shot IPC snapshot without starting a timer: `kern ipc i`

## Keeper-managed lifecycle

With no `/mnt/titan-api/fastpath/config` the keeper runs mode 2
(`fastpath::DEFAULT_MODE`). An operator's config sets another mode:

```ini
mode=3
```

Allowed values are `mode=0`, `1`, `2`, or `3` (comments start with `#`; the
last `mode=` line wins; an invalid `mode=` line resets to `mode=0` and is
logged). `scripts/stage-latency.sh --fastpath ... --fastpath-mode N <unit>`
writes it from a workstation. A copy of `titan_k1fp.ko` staged in
`/mnt/titan-api/fastpath/` still takes precedence over the image's, but only
when it has the pinned SHA-256; any other bytes are refused, and the image's
copy loads instead. With mode 0 and no module loaded, the keeper loads
nothing and logs nothing.

Every 15 s, and at once when the latency switches change, the keeper:

1. Works out the mode: 0 while `fastpath=off` is in the latency switches;
   the operator's `fastpath/config` when there is one; else mode 2. Without
   the Witcher volume there is no operator file, so mode 2 loads from the
   image; the file counts again as soon as the volume is mounted.
2. Refuses to load if any other module with `k1fp` in its name is loaded, or if
   `/proc/k1fp` reports a version string other than `titan_k1fp v2.2.1`. If
   `titan_k1fp` is already loaded by hand and `/proc/k1fp` starts with the
   exact pinned version line `titan_k1fp v2.2.1`, the keeper adopts it, logs
   `fast path: adopted a loaded module`, and takes over its mode and grant
   lease without running `insmod`.
3. Waits until the unit is in IP passthrough, `br0` holds exactly `eth0` and
   `lte0pdn2`, both have carrier for 30 s, and any configured download clamp
   (`titan_qctrl`) has finished loading first. A load that fails (the bridge
   rebuilt under `insmod`, ENOMEM, a bad read of the image copy) is tried
   again after 1 min, then 2, 4 ... up to an hour between tries, for as long
   as it fails. Another config, or the switch turned off and on, tries at
   once.
4. Copies `titan_k1fp.ko` (the staged copy, if it is the pinned one, else the
   image's) into its private RAM directory (`/tmp/titan-pd-keeper/fastpath/`),
   verifies the RAM copy's SHA-256 against the digest pinned at build time
   (`device/fastpath/SHA256SUMS`), and runs `insmod` on that RAM copy.
5. Reads `/proc/k1fp` and checks `ports_ok=1`, `lan_hooked=1`, and
   `wan_hooked=1`. Anything else stays at `mode 0` and records why in the
   status file.
6. Writes `mode N` to `/proc/k1fp` and reads it back.
7. Tracks `qctrl_present` in `/proc/k1fp` and logs if `titan_qctrl` is loaded
   or unloaded later.

### Grant lease from the CBRS gate

The keeper drives `/proc/k1fp`'s SAS grant lease directly from its own CBRS
gate state (`cbrs_mode_grant=1` and `cbrs_grant_state=2`, fail closed):

- Once per second, while the gate is open and fast path is active, the keeper
  does one small `write()` of `grant 5` directly to `/proc/k1fp` with no
  process spawns (closing the fd immediately so `rmmod` is never blocked).
- The moment the gate closes (clear loss, or after the confirm window when
  CBRS keys are absent), the keeper writes `grant 0` first, before logging or
  running `ebtables`/`ip6tables`.
- The keeper never writes a lease while `cbrs_mode_grant` is not `1` (including
  on a torn read or on a unit with no CBRS mode).
- If the keeper stops or crashes, the module's 5-second lease counts down and
  closes the gate on its own.

### Watchdog awareness

When the module's watchdog drops `mode` to `0` on an anomaly (or if the live
mode in `/proc/k1fp` drifts from the applied config):

- The keeper leaves the module at `mode 0`, revokes the grant lease, logs the
  reason (`wd_reason` and `wd_trips`) once and sets `state=tripped` in
  `/var/run/witcher-fastpath.status`, with the wait in `detail`.
- After the wait it writes the configured mode again (`fast path:
  re-arming mode 2`). The wait is 1 min after the first drop and doubles
  with each drop in a row, up to an hour, and the keeper never stops
  re-arming. An hour at the mode without a drop forgets the earlier ones.
- `fastpath/config` changing, or the **Fast path** switch turned off and on,
  re-arms at once and starts the count over. Nothing of this is kept across
  a keeper restart or a reboot. (Earlier releases held `mode 0` after the
  second drop in a boot until the config changed or the unit rebooted.)

A lost bridge device is not a drop in this sense. When `dev_gone` in
`/proc/k1fp` has moved since the keeper's last look and `wd_trips` has
not, the keeper logs it once and writes the configured mode again as soon
as `ports_ok=1 lan_hooked=1 wan_hooked=1` read back. This is not a drop,
so any number of re-attaches in one boot leave the fast path on. The keeper checks every 15 s, so the fast path is back at most
about 16 s after the vendor scripts finish rebuilding the bridge.

### Status and logs

Status lives in `/var/run/witcher-fastpath.status` (`state` is `off`,
`waiting`, `applied`, `tripped`, or `failed`, along with `detail`, `mode`,
`active_mode`, `gate`, `qctrl_present`, `wd_trips`, `wd_reason`, and
`updated`; `detail` says where the mode came from). Keeper log lines start
with `fast path`. A fast path that is off from the start logs none. `scripts/stage-latency.sh --status <unit>` prints
the status file, the first lines of `/proc/k1fp`, and recent `fast path` log
lines.

## Build and host tests

```sh
device/fastpath/source/build.sh /tmp/fastpath-out
device/fastpath/test/run.sh
```

## Rollback

| Level | Action | Result |
| --- | --- | --- |
| Off now | `fastpath=off` in `/mnt/titan-api/latency/config`, or the web switch | The keeper writes `mode 0` and `grant 0` within seconds and sets `state=off`. |
| Off now, operator config | Write `mode=0` to `/mnt/titan-api/fastpath/config` | The same, within 15 s. |
| Off immediately (manual) | `echo "mode 0" > /proc/k1fp` | Immediate pass-through; turn it off as above too, or the keeper takes it as a drop and re-arms after the wait. |
| Unload now | Turn it off, wait for `state=off`, then `rmmod titan_k1fp` | Module unloaded cleanly (`modref=0`). |
| Off at boot | Keep `fastpath=off` (or `mode=0`) and reboot | Nothing is loaded and nothing is logged. |
