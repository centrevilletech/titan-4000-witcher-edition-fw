# IPv4 passthrough recovery

The network keeper starts independently of the web service and runs IPv4
maintenance even when IPv6 delegation is off. It repairs the DHCP offer,
restarts a missing customer DHCP server, and discards the old lease when the
bearer address changes. DHCP changes have a 15-second cooldown.

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
modem's historical MAC latch. The current bearer selector retains the
previously qualified 172.20.x.x customer-network assumption.

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
