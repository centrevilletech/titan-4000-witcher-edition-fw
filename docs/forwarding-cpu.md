# Forwarding CPU and keeper packet capture

The customer port (`eth0`) and the customer bearer (`lte0pdn1` or `lte0pdn2`)
are bridged under `br0`. Up to v1.0.15 the keeper bound a single `ETH_P_ALL`
(`0x0003`) packet socket to `eth0`. On stock Linux 3.10, any entry in
`ptype_all` causes `dev_queue_xmit_nit()` to `skb_clone()` every transmitted
frame on the interface before the socket filter runs, and `PACKET_IGNORE_OUTGOING`
is absent on 3.10. That clone-and-filter cost showed up directly in `ksoftirqd/0`
during downloads.

The keeper no longer opens an `ETH_P_ALL` socket at all, neither in steady state
nor during the three-second RA sniff. Instead it opens protocol-specific
`AF_PACKET` `SOCK_DGRAM` (`ptype_base`) sockets bound to **`br0`** (the bridge
master), each with a tight classic BPF filter attached before `bind()` and a
64 KiB `SO_RCVBUF`:

- **`ETH_P_ARP` (`0x0806`) on `br0`**: accepts ARP replies (`oper == 2`,
  length >= 28) for the IPv4 local reachability watch.
- **`ETH_P_IP` (`0x0800`) on `br0`**: accepts non-fragmented UDP packets to
  DHCP server port 67 (including IPv4 options) for new-router DHCP detection.
  Because DHCP discovers and unicast renews to `udhcpd` are addressed to the
  bridge's MAC or broadcast, the bridge delivers them up to `br0` (`br_pass_frame_up`).
- **`ETH_P_IPV6` (`0x86dd`) on `br0`**: opened **only when IPv6 prefix
  delegation is enabled**. Accepts ICMPv6 control frames (excluding core RAs,
  type 134, in steady state) and DHCPv6 server requests (UDP port 547). An
  auxiliary `AF_INET6` socket joins `ff02::2` and `ff02::1:2` on `br0` so bridge
  MLD snooping always delivers RS and DHCPv6 frames to `br0`. During the
  three-second startup RA sniff the filter temporarily admits type 134 on the
  same `br0` socket (core RAs are multicast to `ff02::1`, so the bridge delivers
  them to `br0`).
- **Marked sender**: an unbound protocol-0 `AF_PACKET` socket (`SO_MARK = filter::MARK`)
  injects RAs and DHCPv6 replies out `eth0` and registers no receive tap.

Because `ptype_all` stays empty, `dev_queue_xmit_nit()` does zero work on
transmit. Because bridge-forwarded customer frames (`eth0` <-> `lte0pdn*`) are
consumed inside `br_handle_frame()` before `ptype_base` runs, bulk IPv4 and IPv6
customer traffic never hits `packet_rcv()` or any BPF filter. Leaving
passthrough closes all control sockets.

## Background work

| Component | Cadence and behavior |
| --- | --- |
| Keeper | Event-driven `poll()` on the control sockets and `/tmp/titan-kmsg` with a 1 s steady-state timeout (200 ms only while a ping probe is running or draining boot `kmsg`). Main routes, IPv6 addresses, and `/proc/<pid>/cmdline` customer-`udhcpd` liveness are read in-process without forking `ip` or `ps`. NVRAM lookups read `/tmp/nvram.cfg` once per second in-process (falling back to `nvram_get` only if a key is absent). `config.json` is stat-cached; `br0` probe IPv4 is cached for 10 s; DHCP flood rules are checked via `ebtables -L FORWARD` every 300 s (and immediately on bearer change or firewall restart) and only written if missing. |
| Management IPv6 | Checks `/proc/net/if_inet6` and `accept_ra` every 10 s without forking `ip` or reading `klogctl` (live IID lines come from `/tmp/titan-kmsg`). Once settled (`accept_ra=0` and global up), `ip -6 route show` is verified every 300 s or immediately on `lte0pdn0` link/PDN events. |
| Shell collector | One second as before. Exclusive shell redirection creates a readable snapshot under the root-owned directory. It needs a helper and rename, without a separate chmod and creation subshell per sample. |
| Management access | Ten seconds as before. Each bridge chain gets one listing. The eight accepts are rebuilt only for chains whose leading four rules no longer cover the management ports. Vendor changes ahead of an accept still trigger repair. |
| Web health supervisor | Checks service PIDs every ten seconds. Full identity and HTTP checks move from ten to sixty seconds while all PIDs live. Missing processes trigger the full check at the next ten-second tick. Startup checks stay immediate. A wedged process that still has a PID can take a minute to detect. |

The API broker (`titan-api --device-broker`) and its web sampler ship as the
pinned binary in `docs/native-api-build.json`. Their polling cuts need a change
in that binary's source and a new pin. They are not part of this firmware.

Two more opt-in trims of vendor background work (pacing the vendor LED loop
and `ksoftirqd/0` priority) are in [CPU trims](cpu-trims.md).

## Bench qualification

Use a cabled test router, an independent management connection and a known-good
image. Keep radio conditions, number of carriers, bearer MTU, packet sizes and
TCP stream count matched. Use the same external traffic endpoints for both
images. A capture running on the Titan itself can reintroduce an all-packet
tap, so take throughput measurements with captures stopped.

1. Save an idle 60-second interval, then three steady 60-second four-stream
   downloads at the same offered rate near the earlier CPU limit. Repeat with
   reverse traffic, the representative packet-size mix and a simultaneous
   latency probe. Record delivered Mbps, packet rate, latency distribution,
   retransmissions and the negotiated radio conditions.
2. Take the following snapshots immediately before and after each interval.
   Subtract counters within a boot. In the aggregate CPU row, busy fraction
   is one minus the delta of idle plus iowait divided by the total delta of
   user through steal. Record user, system and softirq separately. Divide the
   processes delta by elapsed time for forks/s. In softnet_stat the first
   three columns are hex processed, dropped and time_squeeze. Compare their
   deltas per second and per million packets across runs.

   ```sh
   cat /proc/uptime /proc/stat /proc/net/softnet_stat /proc/net/dev
   cat /proc/net/packet /proc/softirqs /proc/interrupts
   cat /proc/sys/net/core/netdev_budget /proc/sys/net/core/dev_weight
   cat /proc/sys/net/core/netdev_max_backlog
   ```

3. Compare the stock baseline, keeper-only changes, polling changes and then
   the new softnet settings. Verify boot readback of budget 300, weight 128
   and backlog 4000. Record memory headroom and latency under bursts. The
   larger backlog can consume more RAM and delay packets. Restore the three
   saved values for an A/B repeat. Kernel-thread priorities use their platform
   defaults.
4. Test IPv4 with PD both off and on. Observe DHCP discovery, request, a router
   swap, lease replacement and validated unicast ARP replies. Exercise a LAN
   link flap and a bearer reattach. Verify DHCP-first escalation only on a real
   series of misses. Test startup core RA withdrawal, solicited RA, DHCPv6 PD,
   renewal, NS for the bridge and the core, and steady forwarded IPv6 from the
   delegated block with no control traffic for longer than the silence window.
   Require no false renegotiation. Check management IPv6, the external-device
   and driver-MAC guards, and SAS heartbeat across reattach.
5. Exercise dashboard, Align, background history, collector failure and
   recovery. Confirm stale samples age out and API sequences advance on new
   snapshots. Displace a management rule and verify repair within the original
   sweep interval. Test both a stopped API and one that accepts no HTTP requests.

## Optional bridged IPv4 trial

The firmware has no boot hook for this trial. The default setting is off.
Use an isolated RF bench with a verified grant and an independent rollback
path. First record the following with ordinary bridge filtering enabled.

- Identify the actual IPv4 SAS TLS peer, its direct bridge host route, the
  outgoing SNAT, the returning bearer, destination IP and **on-wire destination
  port or reserved port range**. Capture registration, grant, heartbeat,
  reconnect and endpoint rotation. Verify this port selection covers the
  client's connections and excludes the downstream router's connections to
  the same peer. If the ports overlap, the redirect can steal customer TLS.
- Verify working no-grant filtering, LAN and WAN management, blocked inbound
  services, customer TCP MSS/PMTUD and IPv4 and IPv6 traffic. Inventory the
  filter, mangle and nat tables and all bridges. Any required bridged IPv4
  policy that depends on iptables makes bypass unsuitable.
- The helper requires fresh registered/authorized/error-free SAS telemetry, a
  matching SNAT rule, one customer bearer bridged with Ethernet, the verified
  SAS peer as the only other bridge host route, and an empty ACCEPT filter
  FORWARD chain. Other bridges must retain per-bridge IPv4 filtering. A
  command failure, stale telemetry or ambiguous routes prevents the trial.

For one supervised bench interval, pass the peer and reply ports measured
above. The setting applies only to this invocation.

```sh
WITCHER_BENCH_BRIDGE_IPV4=1 /bin/sh /usr/lib/titan-api/bench-bridge-ipv4.sh "$sas_peer" "$reply_ports"
```

The trial installs a bearer-, peer-, destination- and TCP-port-scoped bridge
redirect before clearing the global switch. Check on both sides that the CPE's
replies enter local conntrack reverse NAT and that unrelated flows reach the
router. Observe actual successful heartbeats and grant renewal. Repeat with a
firewall restart, reconnect and grant loss on the isolated bench. The monitor
polls once a second and restores iptables first on a change. An independent
120-second deadline restores the switch. Polling leaves a transition window
before a newly inserted FORWARD drop takes effect. **Customer use requires
synchronous preservation of that policy at grant loss.** A successful download
or an Authorized display alone does not qualify the bypass.

Interrupt the trial to restore the prior path. For recovery, first write
`1` to `/proc/sys/net/bridge/bridge-nf-call-iptables`, verify the value, then
remove the exact PREROUTING jump and its WITCHER_SAS_TEST chain. Verify the
original SNAT, SAS heartbeat and no-grant behavior again. Rebooting into the
known-good image restores the boot settings and the previous userspace.
