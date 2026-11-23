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

That pace was too slow right after a re-attach. The vendor SAS client sends
its relinquishments about 6 and 12 s after the radio connects. With the rule
missing for up to 20 s, both failed, the old grants stayed at the SAS, and the
next grant request got 401: 7 of 28 bench channel changes took 46 to 65 s
instead of about 12 s. Since v1.0.11, for 30 s after the kernel logs a PDN
coming up (`LTE: set apn type lte0pdnN`) or the customer bearer joins `br0`,
the keeper checks every second. The other guards stay: misses must run in a
row across 2 s (three checks), longer than a vendor rebuild; an unreadable
table is not a miss; no rule is expected unless the bearer is bridged. In that
window a restore that later showed up in the table may be followed by another
after 5 s, because the vendor can flush the table again during bearer setup. A
restore that never showed up still waits a minute. Outside the window the
10-second, two-miss, once-a-minute rule is unchanged.

That still missed three cases, fixed in v1.0.13:

- **A carrier change inside one connection.** Neither PDN goes down and the
  bridge keeps its port, so nothing started the one-second checks. `ucid` logs
  `HandOver CBRS(...)` and `rcinit` logs `CBRS LTE Freq changed !` to
  `/tmp/rcinit.log`, then restarts the firewall. The rule could be missing for
  10 to 20 s, past both relinquishments. The keeper now reads new lines in
  `/tmp/rcinit.log` once a second. `CBRS LTE Freq changed`, `HandOver CBRS`
  and `Restart service=[cbrs]` each start 30 s of one-second checks. `rcinit`
  caps that log at 64 KB and starts it again empty; the keeper then reads it
  from the start.
- **A flush the keeper did not see coming.** Any first missing check now
  starts one-second checks too, and they last as long as the miss run. A
  burst that ended in the middle of a miss run used to wait 10 s for the next
  check.
- **A second flush right after a restore.** The keeper reads the table back
  right after its own commands. A rule it sees there counts as seen, so a
  second vendor flush a moment later is restored after 5 s instead of a
  minute.

A restore whose rule never shows up still waits a minute, and the checks stay
at 10 s during that minute, so a failing command cannot become a one-second
loop.

Do not repair this by forcing the vendor cbrs restart while
`cbrs_mode_grant=0`: the same `rcinit` path inserts `iptables -I FORWARD -j
DROP` on Band 48 until a grant arrives.

## Customer IPv6 without a SAS grant

The vendor blocks customer traffic without a grant with one IPv4 rule. On
Band 48, when `cbrs_mode_grant` is `0`, each `rcinit` firewall rebuild adds
`iptables -I FORWARD -j DROP` and an accept for DHCP. The radio stays attached
and keeps sending. `ucid` keeps the modem power limit at 26 dBm, and nothing
suspends the bearer. Only a SAS answer that makes the client block the cell
(Channel Invalid) takes the radio off that cell.

The vendor has no matching rule for IPv6:

- `rcinit` writes `0` to `/proc/sys/net/bridge/bridge-nf-call-ip6tables`, so
  IPv6 that crosses `br0` in passthrough never reaches ip6tables.
- The vendor IPv6 firewall (`ip6tables-restore /tmp/.ip6t`) holds no grant
  rule.

So a passthrough unit without a grant keeps forwarding the customer router's
IPv6 in both directions. A bench unit did that on 2026-11-22 while the vendor
IPv4 drop was in place. With prefix delegation, that is the whole customer
LAN, on every Witcher release from v1.0.0 to v1.0.13.

Since v1.0.14 the keeper holds four DROP rules whenever the unit has no grant:

| Table | Rule | Stops |
| --- | --- | --- |
| ebtables FORWARD | `-p IPv6 -o lte0pdn+ -j DROP` | Bridged IPv6 toward LTE (passthrough uplink) |
| ebtables FORWARD | `-p IPv6 -i lte0pdn+ -j DROP` | Bridged IPv6 from LTE (passthrough downlink) |
| ip6tables FORWARD | `-o lte0pdn+ -j DROP` | IPv6 the unit routes toward LTE (NAT mode) |
| ip6tables FORWARD | `-i lte0pdn+ -j DROP` | IPv6 the unit routes from LTE (NAT mode) |

`-p IPv6` matches the Ethernet type, so it needs no `ebt_ip6` module. The unit
has none. The rules match only forwarded traffic. The unit's own traffic never
reaches FORWARD: the SAS client, management on `lte0pdn0`, NTP, and the
keeper's own router advertisements and DHCPv6 replies use INPUT and OUTPUT or
skip the bridge.

"Grant held" means `cbrs_mode_grant=1` and `cbrs_grant_state=2`, the same test
the radio profile uses. The vendor IPv4 rule follows `cbrs_mode_grant`. The
Block Channel patch stops the SAS client from clearing that key at transmit
expiry and before a relinquish. The client still sets `cbrs_grant_state` to
`1` or `0` at those times, so the IPv6 gate closes then too. The gate does not
check the band, because this is a Band 48 unit and a torn read of the band
must never open the gate.

The keeper reads both keys from the vendor RAM cache (`/tmp/nvram.cfg`) every
second, in every mode. It fails closed: a cache it cannot read, a missing key,
or a value it does not know counts as no grant. The vendor rewrites that file
in place, so one read can be torn. A clear "no grant" closes the gate at once.
A read with a missing key or an odd value closes it when a read at least a
second later agrees.

Each vendor firewall restart flushes both tables (`ebtables -F`,
`ip6tables -F`). While the gate is closed, the keeper reads both FORWARD chains
every second and puts back any rule that is missing. If a chain cannot be
read, it adds the rules anyway, one delete first so copies cannot pile up.
When the grant returns, it removes every copy of its own rules and leaves all
other rules alone. Each change goes to the keeper log as `CBRS gate closed`,
`CBRS gate open` or `CBRS gate rules put back`.

What this does not change:

- IPv4 still follows the vendor rule only. That rule is missing after an
  in-connection carrier change and, with the Block Channel patch, after
  transmit expiry. In those cases customer IPv6 stops and IPv4 does not.
- Customer IPv6 now pauses for each re-grant after a carrier change, for as
  long as the new grant takes (on the bench, a median of 14 s and up to about
  a minute). A re-attach that keeps its channel pauses it for about a second.
- These rules do not stop RF transmission. Without a grant the radio still
  sends control traffic, the unit's own SAS and management traffic, and
  customer DHCP, as in the vendor design. The rules reduce what the unit
  forwards without a grant. They do not by themselves establish compliance.
- After a vendor firewall restart, forwarded IPv6 can pass for up to about a
  second before the keeper puts the rules back. The vendor IPv4 rule has a
  similar short gap during its own rebuild.
- If the keeper is not running, nothing adds the rules. Rules it already added
  stay until a vendor firewall restart flushes them. The service supervisor
  restarts the keeper within about 5 s.
