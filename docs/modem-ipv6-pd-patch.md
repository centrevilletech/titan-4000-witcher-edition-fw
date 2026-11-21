# IPv6 prefix delegation in the LTE data driver

The vendor `gdmlte.ko` driver checks IPv6 source addresses at two places on
the uplink path. In passthrough mode, a downstream router can receive a WAN
address and a delegated prefix while traffic from its LAN still fails these
checks. Receiving a delegated prefix alone does not establish end-to-end
IPv6 connectivity.

Witcher changes two comparison lengths in the hash-pinned 4172 module:

| File offset | Factory comparison | Witcher comparison | Purpose |
| --- | --- | --- | --- |
| `0x2f0c` | 16 bytes, exact address | 7 bytes, `/56` | Match a learned neighbor and select its bearer |
| `0x32d8` | 8 bytes, `/64` | 7 bytes, `/56` | Permit the source prefix before modem handoff |

The conditional bearer-selection branch at `0x2f18` stays unchanged. Forcing
it to accept the first neighbor would select the wrong bearer. Both comparison
changes are needed. [`patch-gdmlte.py`](../scripts/patch-gdmlte.py) checks the
expected instructions and branch before writing; image verification checks
the resulting module.

## Address-plan requirements

The router's WAN `/64` and delegated prefix must be inside the same assigned
`/56`. For example, `2001:db8:1234:100::/64` and delegated
`2001:db8:1234:180::/57` are within `2001:db8:1234:100::/56`.
These are documentation addresses, not deployable allocations.

Management and customer allocations must use distinct `/56` blocks. The
patch broadens the accepted source range and does not authenticate a subscriber
or replace core-network source validation. Operators must configure and verify
that validation in their own core; Witcher cannot establish it automatically.
Other prefix layouts or overlapping bearer allocations are not covered by
this design.

## Management bearer advertisements

The keeper lets Linux process one router advertisement on the management
bearer and then closes it (`accept_ra=0`, learned default route kept without
its expiry). A prefix processed there later makes the vendor kernel treat the
management bearer as its external device, which stops customer IPv4 and then
makes the unit deaf. The keeper's guard undoes that. The simplest safe layout
is a management APN on IPv4 and a dual-stack customer APN. See
[the deaf-unit fault](deaf-watchdog.md).

## Downlink MAC after a handover

The LTE driver writes a destination MAC on each downlink IPv6 frame of the
customer bearer, and it learns that MAC from the ARP requests it answers on the
bearer. About a minute after a handover the vendor restarts its firewall, and
the unit itself then ARPs for the SAS host from its own MAC. The driver starts
sending the customer's IPv6 to the unit, which forwards it nowhere, until the
router's next ARP. IPv4 keeps working. On a bench unit this cost 3 to 30 s of
IPv6 each time, and up to 2 minutes in the field.

In passthrough the unit forwards no IPv6 of its own, so a rise in the kernel's
`Ip6OutForwDatagrams` is the symptom. The keeper then sends the router's own
ARP request (router MAC, router address, DHCP gateway) out the customer bearer,
at most once every 2 s. If forwarding goes on after 8 corrections, something
else routes through the unit, and the keeper pauses for 2 minutes. See
`userspace/pd-model/src/driver_mac.rs`.

## Validation

Check the downstream router's WAN address, delegated prefix, LAN router
advertisements and a LAN client's global IPv6 address separately. Then test
traffic from the client through the core. A WAN address or a successful probe
from the router itself does not prove that delegated-source traffic works.
The keeper and model tests cover protocol and recovery behavior; they do not
replace testing the actual core, CPE and downstream router together.
