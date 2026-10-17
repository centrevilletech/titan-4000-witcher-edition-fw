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

## Validation

Check the downstream router's WAN address, delegated prefix, LAN router
advertisements and a LAN client's global IPv6 address separately. Then test
traffic from the client through the core. A WAN address or a successful probe
from the router itself does not prove that delegated-source traffic works.
The keeper and model tests cover protocol and recovery behavior; they do not
replace testing the actual core, CPE and downstream router together.
