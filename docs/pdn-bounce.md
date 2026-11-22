# PDN bounces and carrier changes: vendor stalls

When the LTE data connection drops and comes back (a PDN bounce), two vendor
daemons decide how long the customer waits. `ucid` watches the modem and tells
`rcinit` that the PDNs changed. `rcinit` then rebuilds the network. Both add
fixed waits that do no work. `rcinit` also takes the customer's Ethernet port
down and up on every PDN change, and it restarts the wrong firewall when the
serving carrier changes while the unit stays attached.

Since v1.0.x the build patches both binaries. Each patch replaces one call
with a no-op, except one branch in `ucid` and one log line in `rcinit`. The
patch scripts refuse any file that is not the pinned vendor build.

## What the stock daemons do

All addresses are virtual addresses in the stock 4172 binaries. The file
offset is the address minus `0x8000`.

On a PDN change (down or up) in passthrough, `rcinit`'s signal handler
(`0xd1d8`) runs `stop_wan`, `stop_lan`, `start_bridge_lan` and `start_wan`,
then `cbrs_lte_change`, and then always runs:

```
ifconfig eth0 down        0xd508
sleep(2)                  0xd510
ifconfig eth0 up          0xd548
```

NAT mode reaches the same three calls. The port then needs a few more seconds
to negotiate its link again, and the customer router may start DHCP over.
Inside those steps:

- `stop_wan` calls `stop_l2tp` with no check for an L2TP setup (`0x218a4`).
  `stop_l2tp` sleeps 2 s between stopping `pppd` and `xl2tpd` (`0x3ab38`).
  Its kill helper (`0x3b3f4`) already waits up to 2 s for each process and
  then sends SIGKILL, so the extra sleep adds nothing even with L2TP.
- `stop_udhcpd` sends `killall -10 udhcpd`, sleeps 1 s and sends
  `killall -q udhcpd` (`0xf218`, sleep at `0xf268`). A PDN down calls it
  twice and a PDN up calls it three times.
- The IPv6 router advertisement handler sleeps 1 s before it starts
  (`0xd578`). `ucid` already slept 1 s after writing the IPv6 keys (`ucid`
  `0xd174`), and `rcinit` handles one signal at a time behind its
  `rc_signal_done` handshake.

On a bench unit's stock log, `rcinit` took 8 s on a PDN down and 9 s on a PDN
up, most of it in these sleeps.

Before that, `ucid` holds the PDN-up signal. Its handler (`0x240b0`) writes
`-` to `sqns_radio_freqDl` and `sqns_radio_bandwidthDl` and resets its radio
cache. It asks the modem for a fresh report and checks once a second until
band, frequency, bandwidth, EARFCN and PCI are all valid. The first valid
read then wipes both keys again, because the saved value starts at 0
(`0x24498`..`0x24640`). After that it needs two more matching reads
(`0x24648`) and sleeps 1 s more before it signals (`0x2472c`). That is three
modem refresh rounds where one would do.

When the serving carrier changes while the unit stays attached, `ucid` waits
about a minute after the last cell change, writes `sqns_network_cbrs=1`,
sleeps 1 s (`0xe078`) and signals `rcinit`. `rcinit` logs `CBRS LTE Freq
changed !` and calls the NAT-router firewall restart (`0x30cbc`) at `0xdc48`
with no `router_disable` check. Every other caller checks it first: NAT mode
gets that restart and passthrough gets the bridge firewall (`0xe218`..`0xe25c`,
`0xe284`..`0xe2e8`). In passthrough that restart:

- flushes the nat, filter and mangle tables, which removes the SNAT rule the
  unit's own SAS client needs (see
  [SAS reachability in passthrough](cbrs-sas-enforcement.md#sas-reachability-in-passthrough)),
- runs `conntrack -D`,
- flushes ebtables and ip6tables,
- turns on `kern natq act 1`, the NAT-router fast path, because
  `cbrs_mode_grant` is still `1` at that moment. A stock bench log shows
  `GCT7243 set NATQ mode 1` right after `CBRS LTE Freq changed !` on a
  passthrough unit.

Then `cbrs_lte_change` (`0xdc70`) sets `cbrs_mode_grant=0` and sends the new
channel mask to the SAS client.

## The patches

| | Binary | Address | Stock | Now |
| --- | --- | --- | --- | --- |
| R1 | rcinit | `0xd508`, `0xd510`, `0xd548` | `ifconfig eth0 down`, `sleep(2)`, `ifconfig eth0 up` on every PDN change | No-ops. The port stays up |
| R1 | rcinit | `0x3f854` | Log line `down eth0 and sleep 2 sec , then up eth0!!` | `sqns_network_changed: Witcher keeps eth0 up` |
| R2 | rcinit | `0xdc48` | NAT-router firewall restart on a carrier change | No-op. `cbrs_lte_change` still runs |
| R3 | rcinit | `0x3ab38` | `sleep(2)` in `stop_l2tp` | No-op |
| R4 | rcinit | `0xf268` | `sleep(1)` in `stop_udhcpd` | No-op. Both `killall` commands still run |
| R5 | rcinit | `0xd578` | `sleep(1)` before the IPv6 RA handler | No-op |
| U1 | ucid | `0x24458` | Second wipe and two more matching reads | `b 0x24650`: take the first valid report after the wipe |
| U2 | ucid | `0x2472c` | `sleep(1)` before the PDN signal | No-op |
| U3 | ucid | `0xe078` | `sleep(1)` before the carrier-change signal | No-op |

What stays as it was:

- The PHY reset when the bearer address really changes. `start_pdn` compares
  the old and new address (`check_reset_eth`, `0x1f30c`) and runs
  `mii-tool eth0 -R` when they differ (`0x1968c`).
- `cbrs_lte_change` on every PDN change and carrier change, so the SAS client
  always gets the new channel mask and `cbrs_mode_grant` drops to `0`.
- The bridge firewall rebuild on PDN up. It puts back the SAS SNAT rule and,
  without a grant, the vendor `iptables -I FORWARD -j DROP`.
- The first frequency wipe in `ucid`. The modem report that answers the next
  refresh rewrites every field it carries, because the reset cache no longer
  matches. A frequency written before this PDN change cannot reach `rcinit`.

`patch-rcinit.py` pins two inputs: the stock 4172 `rcinit` and the Witcher
v1.0.0 to v1.0.12 `rcinit` (stock after `strip-root-password.py` and
`strip-vendor-host-keys.py`, which change only text strings elsewhere). The
build patches the stock file before the strip steps. Both routes give the
same file. `patch-ucid.py` pins the stock `ucid`. Each script also pins its
output.

| File | SHA-256 |
| --- | --- |
| rcinit, stock 4172 | `6eeab2c4c0d64f817ed4aec3c66f87d601740dd9975b1fdf3403789d85bab065` |
| rcinit, Witcher v1.0.0 to v1.0.12 | `b4b7461dba2bd21c6124b9a4ab9f47ca604a64a7e68d3d4a845aeab1d6faf6bf` |
| rcinit, in this image | `87be2be2c93f28e03c49aa460eb779a593ebaa3d6586a204d5a0024526aa6344` |
| ucid, stock 4172 | `a2bbc4cf8a8ba26f7f589932c4190ed87b9a0e7152bd9cf11d1111a90f25633e` |
| ucid, in this image | `ddd66ce6bfc75821f5380620b456411aee946ac18144f39ecb7e31f31cb013aa` |

## What changes for the SAS client

- A carrier change no longer removes the SAS SNAT rule, no longer switches
  `natq` to router mode in passthrough, and no longer deletes all connection
  tracking state. In NAT mode the customer's NAT state survives it too.
- A second carrier change while the unit waits for a grant no longer removes
  the vendor IPv4 drop. The NAT-router restart flushed the filter table and
  never adds that rule back.
- After a re-attach, the SAS SNAT rule is missing until `rcinit`'s PDN-up
  handler adds it back. Before v1.0.11 that gap was up to about 20 s and made
  7 of 28 bench channel changes take 46 to 65 s. Since v1.0.11 the keeper puts
  the rule back within a few seconds, and since v1.0.13 it also watches for
  `CBRS LTE Freq changed !`. The patches make `rcinit`'s handler run sooner as
  well, and the keeper's repair stays as the safety net. `rcinit` still logs
  every line the keeper watches for.

## Limits

- IPv4 still has no grant rule after a carrier change while attached: the
  vendor clears `cbrs_mode_grant` after its firewall work, and nothing
  rebuilds the firewall until the next grant. This was true before the patch
  too. The keeper's IPv6 grant gate covers IPv6 only.
- The carrier-change path for a move to another band (`0xdcc4`) still calls
  the NAT-router restart. This unit runs on Band 48 only.
- `ucid` still waits about a minute after the last cell change before it
  reports a carrier change, and still sleeps 1 s before the IPv6 RA signal.
- A customer router whose DHCP lease ran out while LTE was down no longer
  gets a link bounce when LTE returns. It asks for an address again on its
  own timer. The keeper's IPv4 monitor needs a live lease, so it does not
  help there. Short bounces inside the lease are not affected.
- U1 drops the vendor's check that two later reports agree. If the modem's
  first report after an attach were ever out of date, `rcinit` would send the
  SAS client one wrong channel mask, and the next carrier-change signal would
  correct it.
- None of this stops RF transmission or establishes compliance. See
  [Local CBRS/SAS enforcement changes](cbrs-sas-enforcement.md).

## How it was checked

[`emulate-pdn-paths.py`](../scripts/emulate-pdn-paths.py) runs the real ARM
code of `rcinit`'s signal handler, `stop_l2tp` and `stop_udhcpd`, and of
`ucid`'s PDN and handover handlers, in Unicorn (the QEMU CPU emulator as a
library). Library calls are answered in Python and recorded. `ucid` talks to a
simulated modem that answers each refresh after a set delay.

| Scenario | Stock | Patched |
| --- | --- | --- |
| PDN change, passthrough, NAT mode, first event after a start | eth0 down, `sleep(2)`, eth0 up | No bounce, no sleep. Same bring-up calls and `cbrs_lte_change(1)` |
| Carrier change, passthrough and NAT mode | NAT-router restart, then `cbrs_lte_change(1)` | `cbrs_lte_change(1)` only |
| IPv6 RA | `sleep(1)` first | No sleep. Same handler |
| `stop_l2tp`, with and without `pppd` | `sleep(2)` | No sleep. The kill helper still waits for `pppd` |
| `stop_udhcpd` | `killall -10`, `sleep(1)`, `killall -q` | Both `killall` commands, no sleep |
| `ucid` PDN up, modem answers in 1 s | 2 wipes, signal at 4 s | 1 wipe, signal at 1 s |
| `ucid` PDN up, old carrier in nvram, modem answers in 3 s | Signal at 8 s with the new carrier | Signal at 3 s with the new carrier. The old one never shows |
| `ucid` PDN up, modem never answers | 30 rounds, vendor exception line, signal | Same, 1 s sooner |
| `ucid` carrier change | `sleep(1)`, then signal | Signal |

`verify-firmware.py` checks both files against their pins and each patched
site. With `WITCHER_VERIFY_TLS=1`, as in CI, it also runs the emulator on the
packed image and requires the patched results above.

## On a unit

- `/tmp/rcinit.log` shows `sqns_network_changed: Witcher keeps eth0 up`
  instead of `down eth0 and sleep 2 sec` after each `LTE pdn changed !`.
- `/sys/class/net/eth0/carrier_changes` does not move on a PDN bounce that
  keeps the same address.
- `CBRS LTE Freq changed !` is followed by `cbrs_lte_change 1` with no
  `stop firewall done` or `GCT7243 set NATQ mode 1` line.
