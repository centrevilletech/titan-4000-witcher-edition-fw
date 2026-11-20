# The deaf-unit watchdog and the management advertisement freeze

Since v1.0.2. Both live in the network keeper (`titan-pd-keeper`).

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

## The cause, as far as it is known

The vendor stack is told about every router advertisement that Linux
processes on an LTE bearer: the kernel sends `RTM_NEWPREFIX` to the LTE
daemon, which signals `rcinit`. `rcinit` logs `IPV6 RA signal received !`,
rebuilds the IPv6 firewall and resets the hardware bridge
(`GCT7243 bridge set NATQ mode 0`). At bearer setup that is how IPv6 comes
up. A later run in passthrough leaves the unit deaf.

Stock firmware leaves `accept_ra` at 1 on the management bearer
(`lte0pdn0`), and with forwarding on Linux then ignores advertisements there.
Witcher sets it to 2 so the management address can form. That is what lets a
second advertisement through, and the learned default route then carries the
core's router lifetime.

What is not proven: what asks for the second advertisement when the lifetime
runs out, and whether the same reset is harmless in NAT mode.

## The freeze

Once the management global is up, the keeper:

1. Sets `/proc/sys/net/ipv6/conf/lte0pdn0/accept_ra` to 0, so Linux processes
   no further advertisement on that bearer and sends no solicitation of its
   own.
2. Takes the expiry off the learned default route on `lte0pdn0`.
3. Remembers the global for this boot in `/tmp/titan-pd-mgmt-global`.

It checks these every 10 seconds and puts them back if anything undoes them.

If the global is lost later (a re-attach flushes it):

- **In passthrough** the keeper adds the remembered address back itself. It
  still sends a router solicitation, because the modem has to see an
  advertisement on the bearer, but `accept_ra` stays 0, so the kernel does
  not act on the answer. A core that hands out a different management prefix
  on each attach will leave the old address in place until the next reboot.
  Management over IPv4 is not affected.
- **In NAT mode** the keeper opens `accept_ra` again and solicits through the
  kernel, as before v1.0.2.

A keeper on an IPv4-only bearer (`disable_ipv6` is 1 on `lte0pdn0`) now does
nothing here. Before v1.0.2 it retried and logged an error every 10 seconds.

To check the freeze on a unit, run `titan-pd-keeper solicit-mgmt` over SSH.
It sends one router solicitation on `lte0pdn0`. The core answers, and
`/tmp/rcinit.log` must not gain an `IPV6 RA signal received !` line.

## The watchdog

The freeze closes the one trigger that is proven. The watchdog is for
anything else that leaves a unit attached and deaf.

Every 30 seconds the keeper pings its targets once each. The targets are the
DNS servers the core gave the unit (`wan_get_dns`), unless the operator lists
others. One answer from any target means the downlink works.

It reboots the unit when all of these hold:

- A target has answered at least once since boot. A target that never
  answers, or a core that is down when the unit boots, cannot cause a reboot.
- No target has answered for `deaf_secs` (300 by default, 120 at the least).
- The modem reported `ATTACHED` through all of that time. Time detached does
  not count, because a radio drop is a different fault.

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

- The watchdog restarts the unit. It was not possible to test that a restart
  from software clears a real wedge in the same way a power cycle does.
- The unit tests cover the decisions. The packet integration test covers the
  freeze on a dummy bearer and a watchdog reboot through recording stubs. The
  vendor reaction itself can only be seen on a Titan.
