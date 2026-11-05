# Local CBRS/SAS enforcement changes

Witcher changes vendor enforcement behavior. These patches are not a regulatory
compliance mechanism. Successful SAS registration or visible grant state does
not establish that a radio is operating with valid authorization. Blocking
IP traffic upstream is not evidence that RF transmissions have stopped.

For U.S. deployments, review [47 CFR Part 96](https://www.ecfr.gov/current/title-47/chapter-I/subchapter-D/part-96),
including the requirements applicable to the equipment's role as an End User
Device or CBSD. This repository does not establish equipment authorization or
compliance of a modified device. An educational purpose does not exempt radio
operation from those requirements.

## Default build

[`build-firmware.sh`](../scripts/build-firmware.sh) applies
[`patch-cbrs_fsm.py`](../scripts/patch-cbrs_fsm.py) to the pinned vendor binary:

- At file offsets `0x4fcc` and `0x4fd0`, the Block Channel routine is replaced
  with `mov r0,#0; bx lr`. It returns before its grant-state update and signal
  to `rcinit`, bypassing that local channel-teardown path.
- Five `iptables`/`ebtables` command prefixes are replaced with same-length
  `true` commands, making those command strings no-ops.
- Registration and heartbeat code are not changed by this patch. That is a
  statement about patched bytes, not proof that registration always succeeds.

The normal builder does not apply the separate grant-state patch to `rcinit`.
Do not describe all of its remaining behavior as unconditionally grant-free.

The same-length patches and byte guards check compatibility with the known
input. They do not demonstrate regulatory or operational safety, and this
project supplies no tested replacement for spectrum enforcement.

## SAS reachability in passthrough

In IP passthrough the customer router holds the data bearer address. The vendor
`rcinit` routes the SAS host out `br0` from the LAN management address
(`lan_management_ipaddr`, normally `10.1.1.1`). It selects GCT bridge mode with
`kern natq act 0` and adds `iptables -t nat -I POSTROUTING -s
<lan_management_ipaddr> -j SNAT --to <pdn_data_ipaddr>` so replies come back.
About a minute after an LTE handover the connection manager signals `rcinit`,
which restarts the firewall. That restart removes the rule and selects the
NAT-router `natq` mode.

Stock firmware puts both back through the cbrs service restart that Block
Channel requests (`action_service=cbrs`, then `SIGUSR1` to `rcinit`). The
relinquish routine calls Block Channel before it releases a grant, so a
handover to a new channel restores the rule. With the Block Channel patch that
request never happens. After a handover to a new channel the SAS client cannot
open a connection to the SAS until a reboot or a SAS configuration save. A
handover that keeps the same channel still recovers, because the grant start
path requests the same restart.

Since v1.0.1 the network keeper checks the nat table every 10 seconds in
passthrough. The rule it expects comes from the same nvram keys `rcinit` reads,
and only while the data bearer's host route is on `br0`. When that rule is
missing on two checks in a row, it runs `kern natq act 0` and inserts the rule,
at most once a minute. It does not change forwarding, grants or the SAS client.
NAT mode needs no SNAT for this traffic, and the check does not run there.

Do not repair this by forcing the vendor cbrs restart while
`cbrs_mode_grant=0`: the same `rcinit` path inserts `iptables -I FORWARD -j
DROP` on Band 48 until a grant arrives.
