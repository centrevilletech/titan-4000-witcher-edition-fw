# IPv6 router health and the customer port

With prefix delegation on, the keeper answers the customer router's router
solicitations and DHCPv6 from the pinned block. It also watches for signs that
the router is still there. When the router goes quiet, it steps up:

1. After 45 s of silence it sends a fresh router advertisement.
2. 20 s later it restarts its own responders and the port filter.
3. 30 s later it renegotiates the Ethernet link once (`mii-tool -r eth0`), and
   again after 90 s if the router is still quiet.

IPv4 and IPv6 share one limit of three renegotiations an hour. The keeper never
re-attaches LTE and never reboots the unit for this.

## What counts as the router being there

- A router solicitation, a neighbour solicitation for the unit, or DHCPv6.
- A neighbour probe for `fe80::1` from the router the keeper delegated to,
  while that delegation is inside its two-hour lifetime.
- ICMPv6 from the delegated prefix, such as a host behind the router that
  answers a ping.
- Since v1.0.13, a busy port: the router sent 5 or more frames a second over
  the last 5 to 60 s, read from `eth0`'s `rx_packets` counter every 5 s.

## A busy link is never cut

Since v1.0.13 a link drop needs two things. The port must be quiet by the same
counter, and the router must have sent IPv6 (a solicitation, a neighbour probe
or DHCPv6) since it was last plugged in. An unreadable counter counts as busy.
When either is missing, the step that was due waits and spends nothing from the
shared limit. A router that never speaks IPv6 also gets no responder restart:
it would gain nothing from one.

Before v1.0.13 three faults could cut a working link:

- **A router with IPv6 off.** It never sends IPv6, so it always looked quiet.
  A unit with delegation on renegotiated its link three times an hour, all day.
- **The clock step at boot.** The Titan boots at 2013 and NTP moves the clock
  to 2026 about a minute later. The keeper timed the delegation with the wall
  clock, so that step ended a fresh delegation at once, and a link carrying
  traffic was renegotiated 95 s later. The keeper now times the delegation with
  the monotonic clock. After a restart it does not trust the saved time at all:
  the router's next DHCPv6 starts a new delegation.
- **A router swap.** A delegation to router A kept the health check quiet for
  two hours, even after router B, with no prefix, took A's place. Now a
  neighbour probe for `fe80::1` from another router ends that hold, and so does
  `eth0` staying down for 10 s or more. The keeper's own renegotiation is
  shorter than that.

## The escalation starts over after an outage

An LTE or cable outage is not the router's fault. Since v1.0.13 the steps start
over when both are back, so the first action is again a re-announce after 45 s
of silence. Before, a restart that was due before the outage became a link drop
30 s after LTE came back. An IPv4 renegotiation spends the shared limit but no
longer moves the IPv6 steps.

## After 18 hours

About 18 hours into a session the vendor SDK removes the bridged bearer's own
global IPv6 address, and it does not come back until the next attach. The
bearer still carries the delegated prefix. Up to v1.0.12 the keeper took the
missing address for LTE being down: the health check stopped for the rest of
the session, and the status page said the LTE bearer was down. Since v1.0.13 a
bearer that is a port of the LAN bridge and has carrier counts as up.

## The port filter

The keeper reads the customer port through a packet socket with a socket
filter. Up to v1.0.12 the filter cut every other IPv6 frame to 40 bytes and
handed it to the keeper, only to check its source address. That cost a clone,
a wakeup and a copy for every upload packet and download ACK, several percent
of the CPU at 100 Mbps. Since v1.0.13 the filter keeps that traffic in the
kernel. The keeper still reads ARP, DHCP to a server, all ICMPv6 and DHCPv6 to
a server, in full. The DHCP checks read the port, not the destination address,
so a unicast renew is read too. The port's receive counter stands in for the
bulk traffic.
