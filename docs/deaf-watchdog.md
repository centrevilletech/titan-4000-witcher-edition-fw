# The deaf-unit fault: cause, guard, freeze and watchdog

The freeze and the watchdog are in v1.0.2. The external-device guard and the
customer bearer discovery are in v1.0.3. All live in the network keeper
(`titan-pd-keeper`).

## The fault

A Titan in IP passthrough with IPv6 on its bearers could stop hearing the
network while it stayed attached. It still transmitted, and the core still
showed it attached, but no downlink packet reached Linux on any bearer:
management and customer, IPv4 and IPv6. Nothing could reach the unit to
restart it. A re-attach did not clear it. Only a power cycle did.

In the field it came one router lifetime after bearer setup (18 hours on a
core that advertises a 64,800 second lifetime), and again after each power
cycle. Asking the core for a fresh advertisement on the management bearer
reproduced it at once.

## The cause

Reproduced on a bench unit on 2026-11-20, with a shell on its LAN side.

The vendor kernel keeps one "external device" for its hardware forwarding
path. In IP passthrough `rcinit` ends bearer setup with
`kern netif extdev lte0pdn0 down`, and the kernel log shows
`external_dev=NULL`.

Whenever Linux processes a router advertisement prefix on the management
bearer, the kernel sets the external device again
(`set external_dev: lte0pdn0 ipv6 mask=50`). At bearer setup `rcinit` clears it
afterwards. Later nothing does. Then:

1. **Customer IPv4 through the bridge stops at once.** Customer IPv6 keeps
   working.
2. **At the next DHCP or ARP from the customer router, the unit goes deaf.**
   The LTE driver stores that router's MAC as the destination address of the
   management bearer (`kern lte nic` shows it). Downlink frames on `lte0pdn0`
   then carry a MAC that is not the interface's own, and Linux drops them
   before the IP layer. The frames are visible in `tcpdump -e`. A re-attach
   re-runs the vendor setup, which fixes the first part and not the second.
   That is why a core Kick brought the customer back and left the Titan deaf.

Stock firmware never processes an advertisement on `lte0pdn0`. Witcher sets
`accept_ra` to 2 there so the management address can form. The vendor SDK also
runs its own timer at router lifetime minus 30 seconds that flushes the
bearer's IPv6 addresses. On Witcher 1.0.0 the keeper then solicited again,
Linux processed the answer, and the unit wedged one router lifetime after
bearer setup.

`rcinit` is not involved in the fault. It logs nothing when it happens.

## The repair

Both commands leave a healthy unit unchanged. Neither needs a reboot.

```
kern netif extdev lte0pdn0 down                          # customer IPv4 back
ip link set dev lte0pdn0 address <the interface's own MAC>   # unit hears again
```

## What the keeper does

**External-device guard (since v1.0.3).** The keeper follows the kernel log
(the vendor image has no `/dev/kmsg`, so it makes the node in RAM). In
passthrough, when the external device stays set on a bearer other than the
customer one for 2 seconds, it runs the repair and logs
`external device guard: ...`. It runs the same repair on the first silent round
of the watchdog.

**Advertisement freeze (since v1.0.2).** Once the management global is up, the
keeper sets `accept_ra` to 0 on `lte0pdn0` and replaces the learned default
route with one that does not expire. While the bearer is closed the fault
cannot start. When the global is lost (a re-attach, or the SDK timer), the
keeper opens the bearer again and solicits, so the vendor stack forms the
address as it does at boot, and the guard clears the side effect. Putting the
old address back by hand does not work: the modem and driver only pass a
prefix the vendor stack has formed.

**Customer bearer (since v1.0.3).** The keeper finds the customer bearer from
the bridge (`/sys/class/net/br0/brif`), then from the vendor's
`pdn_data_ifname`. Earlier versions assumed `lte0pdn1`.

A unit whose management APN is IPv4-only has IPv6 off on `lte0pdn0`
(`disable_ipv6` is 1), and none of the management code runs. That is the
simplest safe layout: management on IPv4, the customer bearer dual-stack.

To check the freeze on a unit, run `titan-pd-keeper solicit-mgmt` over SSH.
It sends one router solicitation on `lte0pdn0`. The core answers, the kernel
log shows the advertisement with `accept_ra=0`, and nothing else changes.

## The watchdog

The guard and the freeze deal with the cause that is known. The watchdog is
for anything else that leaves a unit attached and deaf.

Every 30 seconds the keeper pings its targets once each. The targets are the
DNS servers the core gave the unit (`wan_get_dns`), unless the operator lists
others. One answer from any target means the downlink works.

It reboots the unit when all of these hold:

- A target has answered at least once since boot. A target that never
  answers, or a core that is down when the unit boots, cannot cause a reboot.
- No target has answered for `deaf_secs` (300 by default, 120 at the least).
- The modem reported `ATTACHED` through all of that time. Time detached does
  not count, because a radio drop is a different fault. Neither do the first
  90 seconds after an attach, while the bearer settles.

Each watchdog reboot that is followed by silence again doubles the wait
before the next one, up to six hours. An hour of answers clears the count
(`watchdog-strikes.txt` in the keeper state directory).

An outage upstream of every target, with the radio still attached, looks the
same from the unit. Each unit then reboots once, and does not arm again until
a target answers. To avoid that, name targets on the core itself.

### Settings

Optional file `/mnt/titan-api/pd/watchdog.conf`, read every round:

```
enabled=1
deaf_secs=300
target=192.0.2.1
target=2001:db8::1
```

Up to four targets. Without the file the watchdog is on with the defaults.

### Log lines

In `/mnt/titan-api/pd/keeper.log`:

- `deaf watchdog armed: a target answered through the core; ...`
- `deaf watchdog: attached, but no target answered this round`
- `deaf watchdog: answers are back after N s of silence`
- `deaf watchdog: attached but nothing heard through the core for N s; rebooting (reboot K in a row)`

## Limits

- The guard and the repair were proven on one bench unit, by forcing the
  fault. An 18-hour run across the SDK timer is still to be done.
- A watchdog reboot was tested with its targets silenced, not against a real
  wedge. A vendor ping watchdog (`detection_enable` in nvram) does clear a
  wedged unit with `kern reboot`. It also reboots a unit after about 110
  seconds without its ping target, with no backoff. Run one or the other.
- The passthrough driver serves one LAN device. It learns one host MAC.
- The unit tests cover the decisions. The packet integration test covers the
  freeze on a dummy bearer, the guard against a file standing in for the
  kernel log, and a watchdog reboot through recording stubs.
