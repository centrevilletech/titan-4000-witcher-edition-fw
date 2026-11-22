# IPv4 passthrough recovery

The network keeper starts independently of the web service and runs IPv4
maintenance even when IPv6 delegation is off. It repairs the DHCP offer,
restarts a missing customer DHCP server, and discards the old lease when the
bearer address changes. DHCP changes have a 15-second cooldown.

In passthrough it also restores the vendor SNAT rule for the unit's own SAS
traffic when a vendor firewall restart removes it. See
[SAS reachability in passthrough](cbrs-sas-enforcement.md#sas-reachability-in-passthrough).

The local reachability monitor is enabled automatically in passthrough:

1. It requires Ethernet and the customer LTE interface to have carrier, the
   current bearer host route, a matching DHCP offer, and exactly one live
   downstream lease. NAT, missing/expired leases, or ambiguous clients are
   ineligible.
2. It sends a unicast ARP request every ten seconds to that leased router's
   MAC/address, using the Titan's own bridge address and Ethernet MAC. It
   validates the reply's Ethernet source, ARP sender and target addresses.
   Recovery arms only after a successful response within three seconds.
3. Three missed replies trigger a DHCP refresh. Three more missed replies
   trigger one `mii-tool -r eth0` PHY renegotiation, which briefly interrupts
   Ethernet. Ordinary traffic silence and failed internet pings are not
   failure signals.
4. A new successful ARP baseline is required before another IPv4
   renegotiation. IPv4 and IPv6 share a limit of three renegotiations in a
   one-hour monotonic-clock window. The action count is saved atomically and
   synced before acting. Failure to save it suppresses the action. The
   existing reboot handling starts a new window when the monotonic clock
   restarts.
5. Carrier loss, missing bearer routes, or a changed peer disarms the monitor.
   Returning LTE does not immediately trigger a port reset. A router that
   never answers this probe is left alone.

This targets loss of local IPv4 reachability. It cannot detect every case in
which a router still answers ARP but its internet forwarding is broken. It
neither resets LTE nor reboots the Titan, and does not establish a fix for the
modem's historical MAC latch.

## Public data PDN offers

Up to v1.0.7 the keeper found the customer address only by the private
customer pool's prefix. A passthrough unit whose data PDN carries a public
IPv4 address got no customer DHCP restart, and its IPv4 peer was never armed
for the IPv6 driver-MAC repair. A router behind it kept its lease until the
lease ran out, then lost its WAN address.

Since v1.0.8, an offer outside the private pool and the LAN ranges qualifies
only when all of this agrees:

- The vendor snapshot `/tmp/nvram.cfg` has exactly one `pdn_data_ifname`,
  `pdn_data_ipaddr`, `pdn_manage_ifname` and `pdn_manage_ipaddr`. The data and
  management PDNs use different LTE interfaces and different addresses.
- The data interface is the keeper's customer bearer, `eth0` is in `br0`, and
  `br0` has exactly one LTE port.
- The offer on disk is one address equal to the data address, on `br0` or
  `br0:9`, with `remaining yes`, a nonzero lease, and a different usable
  gateway in a contiguous subnet.
- `ip route` has a direct host route for that address on `br0`, not via a
  next hop and not `linkdown`. A SAS host route on `br0` cannot qualify.

The keeper reads the snapshot at most once a second. A qualified offer is
never rewritten. If the customer `udhcpd` is gone, the keeper reads the offer,
the snapshot, the routes and the process list again, then starts `udhcpd` on
the unchanged file. That line goes to `keeper.log`. Any disagreement means no
action. A qualified lease also arms the existing driver-MAC repair. The PHY
renegotiation in step 3 above stays off for public addresses, because it has
not been qualified on them. Without the snapshot evidence, an offer outside
the private pool gets only the v1.0.7 behavior: a DHCP request from a new
router still releases the old lease.

A renegotiation is a real PHY operation, but is not guaranteed to have the
same effect as physically unplugging every router model. Reproducing the
reported IPv4-only WAN-cable recovery on the affected router remains a
hardware qualification task.

`test-ipv4-recovery-network.py` runs the actual host keeper in private mount,
PID and network namespaces against a Linux ARP peer. It tests DHCP daemon
loss, an LTE outage, suppressed peer ARP replies, DHCP-first escalation, and
one recorded PHY action with a persisted budget. The PHY program is a stub;
this test is not a Titan port test. Model tests additionally cover never-
responsive peers, stale/mismatched replies, send errors, peer changes,
expired/ambiguous leases, and the shared action limit.

ARP packet fields follow [RFC 826](https://www.rfc-editor.org/rfc/rfc826.html).
The budget uses file and directory fsync; mainline Linux 3.10 UBIFS provides
its directory fsync operation in
[`fs/ubifs/dir.c`](https://github.com/torvalds/linux/blob/v3.10/fs/ubifs/dir.c).
