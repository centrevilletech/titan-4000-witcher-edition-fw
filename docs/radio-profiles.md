# Radio profiles and smart queue management

A new installation and an upgraded unit use stock modem settings and queues.
Nothing changes until an operator saves a nonempty profile. Applying or
removing a profile never cycles the radio. The current firmware does not
establish a universal throughput gain for any profile.

## Operator interface

Use the enrolled operator SSH login. On the unit, the JSON client is
`/tmp/titan-pd-keeper/titan-pd-keeper radio-profile`. Its three operations are
`get`, `set` (one JSON document on stdin), and `status`. A successful set
acknowledges storage. Poll status for the asynchronous outcome.

The following example caps the unit at two carriers and shapes both
directions. Replace the placeholder with an IPv4 ping responder reachable
through the management bearer. Choose rates below the sustained speeds
measured in each direction.

```json
{
  "version": 1,
  "management_probe": "<management ping responder>",
  "actions": [
    {"kind": "carrier_aggregation", "carriers": 2},
    {"kind": "sqm", "upload_kbit": 8000, "download_kbit": 80000}
  ]
}
```

```sh
keeper=/tmp/titan-pd-keeper/titan-pd-keeper
"$keeper" radio-profile set < profile.json
"$keeper" radio-profile status
printf '%s\n' '{"version":1,"actions":[]}' | "$keeper" radio-profile set
```

Saving the empty action list restores stock. Saving a profile, even the same
one again, clears its strikes and its wait, so it is tried at once: that is
how to clear a locked profile. A replacement nonempty list reconciles changed
and removed actions together. A missing setting means off. A persistent volume
that mounts late delays activation until it mounts.

| Action kind | Fields | Setting |
| --- | --- | --- |
| carrier_aggregation | `carriers` 1 to 4 | One uses `AT%GCACTRL=0`. Two to four use `AT%GCACTRL=3,<n>`. Takes effect at the next attach. |
| | `cycle_hours` 6 to 168, optional | Opt-in enforcement re-attach. See below. Absent: the radio is never cycled for the cap. |
| | `nudge` `{earfcn, pci}`, optional | Band 48 primary cell held only during an enforcement re-attach. Needs `cycle_hours`. |
| sqm | `upload_kbit` 64 to 50000, `download_kbit` 64 to 250000 | Bidirectional CAKE on the passthrough path. |
| carrier_pick | `arms` (2 to 6 of `{earfcn, pci, carriers}`) | Surveys the arms and holds the best. Needs no server. Replaces `carrier_aggregation`. See [the carrier picker](#carrier-picker). |
| | `survey_hours` 24 to 336 (72), `window_utc` `HH:MM-HH:MM` (`10:45-12:30`), `ul_weight` 0 to 20 (4), `ul_sink` IPv4 (`management_probe`) | Optional. |

The keeper accepts each kind once. Version 1 permits 4096 bytes and rejects
unknown fields and unknown kinds. The socket API uses one JSON document per
Unix stream connection at `/tmp/titan-pd-keeper/radio.sock` in the root-owned
mode 0700 directory. Send `{"op":"get"}`, `{"op":"status"}`,
`{"op":"set","profile":...}` or `{"op":"survey"}`, then shut down the write
half and read the JSON `result` or `error`. The native web listener has no radio-profile route.

### Settings this firmware will not apply

These came out of the 2026-11-22 bench study and are rejected or never sent:

- A permanent PCell lock. If the locked cell disappears, the unit stays
  offline. `AT%GLOCKPCELL=0` also returns ERROR and changes nothing; only
  `AT%GLOCKPCELL=1,0,0` clears a lock.
- `AT%GLOCKSCELL`: the tower adds carriers blind, and the lock check rejects
  the whole reconfiguration, so every add becomes a reconnect.
- `rrc dm pref cell`: cost about a third of download.
- `dp bo_margin 1` and `rrc capw pdcp r11 2`.
- The receiver and capability tweaks the bench measured with no gain
  (`l1r cfg mmse act_dse`, `rrc capw rf layer ca`).

## Carrier cap and enforcement

A cap is RAM only and applies at the next attach. The tower can still add a
carrier during a connection: on the bench it held three carriers under a cap
of two. So the guard does not trust the cap. Every 30 s, and 20 s after each
attach, it reads `AT%GCACTRL?` and the serving carriers in
`sqns_connection_sccInfo`. A lost cap is written again for the next attach.
When the tower holds more carriers than the cap, `keeper.log` gets one line
(at most one an hour).

A re-attach that changes the carrier set makes the vendor SAS client give
back every grant. Customer IPv4 then stops until new grants arrive, which took
3 hours on the bench. A re-attach on the same carriers keeps them. So the
only radio cycle a profile can cause is the enforcement re-attach, and only
when all of this holds:

- `cycle_hours` is set.
- The unit is attached and has held more carriers than the cap for 5 minutes.
- At least `cycle_hours` (minimum 6) have passed since the last enforcement
  re-attach, or since boot.
- `cbrs_mode_grant` is 1 and `cbrs_grant_state` is 2, read right before the
  cycle. No re-attach while a grant request is pending or the grant is gone.
- The clock is set and the time is outside 06:30 to 10:30 UTC: the SAS CPAS
  window every keeper reboot waits out (06:45 to 10:15) with 15 minutes on
  each side, so the grants a carrier change gives back can come again before
  it opens. Up to v1.0.16 enforcement had no time-of-day check at all.
- Fewer than 8 radio cycles (enforcement and picker together) ran in the last
  24 hours, counted in `/mnt/titan-api/radio/cycles` and kept across reboots.

Each cycle is counted before it starts and logged in `keeper.log` before and
after. With a `nudge`, the PCell lock is set while the radio is off and
cleared with `AT%GLOCKPCELL=1,0,0` as soon as the unit attaches, or after 90 s,
attached or not. A lock that does not read back cleared fails the check and
reverts the profile. Status shows the carrier count, the cap, how long the
unit has been over it, and why enforcement is or is not due.

## Carrier picker

The `carrier_pick` action measures which combination of carriers serves this
unit best and holds it. Each arm is a primary cell and a carrier cap:

```json
{
  "version": 1,
  "management_probe": "<management ping responder>",
  "actions": [
    {"kind": "carrier_pick",
     "arms": [{"earfcn": 55440, "pci": 199, "carriers": 2},
              {"earfcn": 56440, "pci": 208, "carriers": 3},
              {"earfcn": 56638, "pci": 217, "carriers": 2}]}
  ]
}
```

A survey visits every arm once. A visit is one radio cycle through the same
nudge as the enforcement re-attach. The radio goes off, the arm's cap and
PCell lock are written, the radio comes on, and the lock is cleared as soon as
the unit attaches, or after 90 s if it does not. The tower still chooses the
secondary carriers. The arm the unit is already on is measured without a
cycle. After each attach the picker waits up to 10 minutes for SAS grants that
cover the new primary and uplink secondary carrier, then 15 s more, and
scores the arm. It needs no server:

- Download, estimated. The Titan cannot measure its own download without a
  sender: its CPU caps a TCP download on the unit near 53 Mbps. Instead the
  picker reads the SINR the modem reports for every serving carrier once a
  second for 20 s, using each carrier's weaker receive branch because rank 2
  runs at its pace. It takes each carrier's median and the median rank, and sums a
  per-carrier capacity: Shannon with a 4.6 dB implementation gap, 256QAM at
  most, over the downlink share of TDD configuration 2. There is no rate cap
  beyond that. On the bench the estimate read 128 Mbps for c5 at 11 dB with c9
  at 15 dB, where a UDP burst from the core measured 130.7, and 180 Mbps for
  c6 at 10 dB with c9 and c5 at 15 and 12 dB, where the burst measured 176.8,
  and 150 Mbps for c6 at 9 dB with c9 and c12 at 11 and 12 dB on their weaker
  branches, where floods from the core measured 148 to 150.
  At 17 dB on three carriers it gives about 270 Mbps. The estimate sees radio
  quality, not how busy each carrier is, so it ranks arms rather than
  promising rates.
- Upload, measured. Over the same 20 s the unit sends a UDP burst offering
  45 Mbps through the management bearer to the discard port (UDP 9) of
  `management_probe`, or of `ul_sink` when the action sets one. Any host
  works: nothing needs to listen, and a firewall that drops the packets is
  fine. Set `ul_sink` when the management probe is a router, so the burst
  stays off its control plane. The rate is the modem's own upload report
  (`sqns_radio_ulThroughput`), which refreshes about every 6.5 s. On the bench
  it read 13.8 Mbps where the far end counted 11.2 to 12.2 Mbps of payload.
  Every arm carries the same bias, so the ranking holds. The burst only starts
  while the customer is idle, and it stops at once when the customer bearer
  carries 2 Mbps either way in a second. That arm is measured again once the
  customer has been idle for 2 minutes.
- Round trip: five pings to `management_probe`, before the burst.

A visit sends about 35 to 75 MB to the sink. With three arms and
the default 72-hour survey interval, that is at most about 75 MB a day per
unit.

Each arm scores `download + ul_weight x upload`. Only a visit that attached on
its arm's primary cell, within its cap, counts. The arm the unit is on keeps
its place unless another scores 5% higher. Within 2%, the lower round trip
wins. The result goes to `/mnt/titan-api/radio/pick.json`. The keeper logs one
line per visit and one per survey.

A radio cycle starts only when all of these hold, read fresh each time:

- The clock is set and the time is outside 06:30 to 10:30 UTC: the SAS CPAS
  window every keeper reboot waits out (06:45 to 10:15, `tk_boot::CPAS_QUIET`)
  with 15 minutes on each side. No new SAS grants are issued in that window,
  and a carrier change gives back every grant.
- The time is inside `window_utc`. An operator request through `survey` lifts
  this one rule.
- The unit is attached and holds its SAS grant (`cbrs_mode_grant` 1,
  `cbrs_grant_state` 2).
- The customer bearer has carried under 2 Mbps each way for 2 minutes.
- No keeper recovery is pending: an IP family change in its first 10 minutes,
  or a deaf-watchdog restart in the first hour after boot.
- Fewer than 8 radio cycles ran in the last 24 hours, with one kept free for
  a way back (below).

A survey runs at most once per `survey_hours`. One that is still unfinished
after 6 hours is dropped. When no covering grant arrives within 10 minutes of
a visit, the survey stops and the picker goes straight back to where the unit
was before the visit, which held its grants then: that arm, or that primary
cell with the stock cap. That way back has no grant to protect, so it waits
for no grant and not for the customer, and only for the keeper's own reboot
window (06:45 to 10:15 UTC, without the 15-minute margin), the clock and the
daily cap. A visit starts before 06:30 and its grant wait ends before 06:45,
so the way back is not held for hours. It is skipped when grants cover the
unit where it is by then. Up to v1.0.16 the unit stayed on the ungranted arm,
and the grant check kept it from ever coming back. If the unit leaves the held
arm (a reboot, the tower), the picker returns to the arm with one cycle, at
most every 6 hours, outside the survey window too. A cycle that does not attach within 90 s is
not a failure: the nudge is cleared and the radio is on, so the unit attaches
where the tower lets it, and the grant wait and the way back take it from
there. A cycle whose nudge does not clear reverts the profile like a failed
enforcement. Removing the action restores the stock cap and clears any lock,
without a radio cycle.

Every visit costs the customer one re-attach, 30 to 60 s, plus the wait for
grants, which took 15 s on the bench at 19:00 UTC. That is why visits wait for
an idle customer.

### Status and requests

Status shows the survey state and every visit under `pick`: the SINR of each
carrier, the download estimate, the measured upload, the round trip, the
score, and the modem's own download and upload high-water marks for the
record. To survey now, outside the window:

```sh
/tmp/titan-pd-keeper/titan-pd-keeper radio-profile survey
/tmp/titan-pd-keeper/titan-pd-keeper radio-profile status
```

## Application and recovery

After the Witcher volume mounts, a separate keeper guard waits for lted,
lteatcm, ucid, the HCI socket, and the band's board identity and media state.
It checks the baseline before taking ownership. The worker uses interactive
lted_cli stdin and restores `arm1log 1` after each console session.

**One console owner.** Every modem console session holds
`/tmp/titan-pd-keeper/console.lock` (`flock`) for its whole length: each radio
worker from start to end, so nothing slips between a cycle's steps, and each
session of the modem flag writer. The flag writer never waits: a held console
makes its session `Busy`, which costs it nothing. A radio check waits up to
15 s and a radio change up to 100 s, longer than a whole flag session; past
that the guard skips the step and judges nothing. The kernel drops the lock
when its holder exits or dies. Up to v1.0.16 only the flag writer looked (for
a marker file), and on the bench the two cut each other's replies short:
once a flag session reverted a profile, once the radio checks made the flag
writer give up.

These rules (v1.0.17, `titan_pd_model::radio_guard`) make sure that no
transient condition keeps a profile off once it clears:

- **A trial needs a working stock baseline.** A trial starts only once the
  unit is attached, its management probe answers, the LTE stack is up and no
  keeper recovery is pending. A tower or core outage, a boot inside the CPAS
  window, a slow SAS grant or a busy console is "not tried": nothing is
  written or counted, and the guard looks again 30 s later. Up to v1.0.16 a
  tower outage at boot cost a strike.
- **Confirmation** requires setting read-backs, attached media, a management
  bearer address and successful bound pings over a 30-second settle period
  within 90 s. A SAS grant loss neither blocks confirmation nor reverts a
  profile, because the profile does not cycle the radio; the enforcement gate
  handles grants.
- **A running profile** is checked every 30 s, and 20 s after each attach. It
  is rolled back for management only after 5 minutes of failed checks while
  attached, as the deaf watchdog waits. A lost ping, a core blip, a probe that
  drops ICMP for a while, a detach or a busy console changes nothing. Up to
  v1.0.16 two pings 3 s apart, about 7 s of loss, reverted it for the rest of
  the boot. RRC reconfiguration failures still roll it back at once: two in
  one sample, or single increases within a minute. A counter that goes down
  (the modem restarted) or a lost baseline gets a fresh baseline, and a check
  the console returns no counter for is skipped. Neither is a failure.
- **Only a comparison with stock counts against a profile.** After a
  management failure the guard puts stock settings back and runs the same
  30-in-90 s test on them. Management answering on stock is a strike. When
  stock does not answer either, the network failed and nothing is counted.
  Other failures (a setting that does not read back, RRC trouble, the SQM
  tools) are rolled back but never counted.
- **Nothing gives up.** After any rollback the profile is tried again after 5
  minutes, doubling to an hour, forever. Three strikes with no confirmed
  trial between them lock the profile (status `locked`). The lock clears
  itself on a new firmware or a changed profile, and saving the profile again
  clears it too. Strikes live in `/mnt/titan-api/radio/strikes`, stamped with
  the profile and the firmware they were counted under. A record written
  before v1.0.17, or a damaged one, reads as none.
- **Power cuts only delay.** A trial is counted on flash before its first
  write and cleared once it is judged. A trial that a power cut, a crash or a
  restarted guard cut short stays counted, and the next boot waits 5 minutes
  of uptime for each such trial, doubling to an hour, before it tries again.
  Flapping power never locks a profile. A profile that crashed the unit would
  run at most once an hour.
- **A restarted guard** keeps a profile it had confirmed and checks it as
  usual. Anything cut short in the middle (an apply, a radio cycle, a restore)
  goes back to stock and is tried again after a backoff.

Rollback writes the stock values (`AT%GCACTRL=3,4`, which applies at the next
attach), removes SQM, and never cycles the radio. After an interrupted
enforcement re-attach it turns the radio back on and clears the nudge. A
restore that does not confirm is tried again after 30 s, doubling to 10
minutes. After 10 minutes of failed restores the guard asks the keeper for a
restart, which clears modem RAM and the qdiscs. The restart goes through the
keeper's reboot gate: never inside 06:45 to 10:15 UTC, never with the clock
unset, at most within the daily reboot cap, and cancelled if a restore works
first. The saved profile is never touched. Up to v1.0.16 one failed restore
overwrote it with an empty profile and rebooted at once, at any hour.

Status (`radio-profile status`) shows the phase and its reason, the strikes
and the unjudged trials counted for the saved profile, and the counters.
Status, counters and the retry schedule live in RAM. The keeper's ordinary
packet loop runs independently of modem I/O.

## Smart queue management

The SQM tools are not in the image (the rootfs has no room). Stage them once
per unit on the persistent volume before saving a profile with `sqm`:

```sh
# From a checkout, over the enrolled operator SSH login.
ssh <unit> 'mkdir -p /mnt/titan-api/sqm && chmod 700 /mnt/titan-api/sqm'
scp device/sqm/payload/tc device/sqm/payload/sch_cake.ko <unit>:/mnt/titan-api/sqm/
```

The keeper copies them into its private runtime directory only when their
bytes match the digests in `device/sqm/SHA256SUMS`, built into the keeper.
A missing or different file fails the `sqm` action, and the profile reverts to
stock. Removal works without them.

Upload uses the root on lte0pdn2. Download requires the existing prio root
and blackhole on eth0 and grafts only onto band 1:2. Checks restore a lost
CAKE leaf within 30 s after the keeper rebuilds the filter. Cleanup restores a
FIFO there because deleting a child in Linux 3.10 prio installs a discarding
leaf. The CAKE handles are ca01: and ca02:. The restored FIFO uses ca03:. The
fq_codel module is in the payload for qualification. The v1 applier uses CAKE.

On the bench (fixed rates, 2026-11-22), CAKE held ping under load near idle:
during download p50 292 to 43 ms, during upload 103 to 32 ms. A fixed rate
costs speed when the radio rate moves: download 113 to 97 Mbps, upload 14 to
8 Mbps.

The download clamp, on by default since v1.0.17, stands aside (mode 0) while
`sch_cake` is loaded: the two have not been tested together. An operator's
`qctrl/config` overrides that (see [the download clamp](download-clamp.md)).

## Qualification plan

1. Run the locked Rust workspace tests and the firmware build and verifier.
   Stage the SQM tools, check the module vermagic and run the staged tc on
   the target.
2. Cold-boot an empty profile and record normal attach, modem log routing,
   Ethernet filters and module list. Verify operator get/set/status and
   denial from the panel UID. Reject unknown fields, unknown or removed kinds,
   duplicate actions, bad rates and malformed, oversize and unsupported-version
   profiles.
3. With wired recovery connected, apply a cap with no `cycle_hours`. Confirm
   no radio cycle, the cap read-back, the over-cap log line when the tower adds
   a carrier, and stock read-back on removal. Monitor vendor HCI client slots
   across repeated samples.
4. Exercise SQM alone under upload, download and bidirectional load. Compare
   bytes, drops, latency, CPU headroom and throughput. Reinstall the keeper
   filter, replace the profile, then disable it. Verify continued packet flow
   in 1:2 and the existing RA/DHCPv6 blackhole rules at every step. Test a
   foreign qdisc and a missing keeper parent.
5. Enforcement, on a bench only: set `cycle_hours` 6 with and without a
   nudge. Confirm no cycle while the grant is missing or a grant request is
   pending, one cycle at most per window, both log lines, the nudge cleared
   after attach and after a failed attach, and the SAS grant outcome after a
   carrier-set change.
6. Interrupt an apply and an enforcement re-attach after radio-off and before
   the nudge clear. Test a stuck CLI, failed attach, unreachable probe and a
   counter reset. Verify the radio comes back on, the lock is cleared, stock
   values return, processes are cleaned up and the failure detail is recorded.
7. Power-cycle three times during unconfirmed trials. On boot four verify
   that the trial waits 20 minutes of uptime (`unjudged_trials` 3 in status),
   then runs and confirms, and that no lock is set. Boot with the tower down:
   status says `not tried`, nothing is counted, and the profile applies within
   30 s of the attach. Exercise a rollback failure (a console that refuses
   `AT%GCACTRL`): the restore is retried, `keeper.log` shows the restart
   request and, inside 06:45 to 10:15 UTC, that the restart waits, and the
   saved profile is unchanged after the restart.
