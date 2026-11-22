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

Saving the empty action list restores stock. Wait for `off` before rearming
a locked profile. A replacement nonempty list reconciles changed and removed
actions together. A missing setting means off. A missing persistent mount
prevents activation.

| Action kind | Fields | Setting |
| --- | --- | --- |
| carrier_aggregation | `carriers` 1 to 4 | One uses `AT%GCACTRL=0`. Two to four use `AT%GCACTRL=3,<n>`. Takes effect at the next attach. |
| | `cycle_hours` 6 to 168, optional | Opt-in enforcement re-attach. See below. Absent: the radio is never cycled for the cap. |
| | `nudge` `{earfcn, pci}`, optional | Band 48 primary cell held only during an enforcement re-attach. Needs `cycle_hours`. |
| sqm | `upload_kbit` 64 to 50000, `download_kbit` 64 to 250000 | Bidirectional CAKE on the passthrough path. |
| | `classify` `true` or `false`, optional | Stage 1 traffic classes on both CAKE qdiscs. Absent means on. See below. |

The keeper accepts each kind once. Version 1 permits 4096 bytes and rejects
unknown fields and unknown kinds. The socket API uses one JSON document per
Unix stream connection at `/tmp/titan-pd-keeper/radio.sock` in the root-owned
mode 0700 directory. Send `{"op":"get"}`, `{"op":"status"}` or
`{"op":"set","profile":...}`, then shut down the write half and read the JSON
`result` or `error`. The native web listener has no radio-profile route.

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

Each cycle is counted before it starts and logged in `keeper.log` before and
after. With a `nudge`, the PCell lock is set while the radio is off and
cleared with `AT%GLOCKPCELL=1,0,0` as soon as the unit attaches, or after 90 s,
attached or not. A lock that does not read back cleared fails the check and
reverts the profile. Status shows the carrier count, the cap, how long the
unit has been over it, and why enforcement is or is not due.

## Application and recovery

After the Witcher volume mounts, a separate keeper guard waits for lted,
lteatcm, ucid, the HCI socket, and the band's board identity and media state.
It checks the baseline before taking ownership. The worker uses interactive
lted_cli stdin and restores `arm1log 1` after each console session. Bench
operators sharing a console should expect that every 30 s.

The guard records a strike on the persistent volume before the trial and a
rollback journal in RAM before writes. Its 180-second deadline covers the
worker and its children. Confirmation requires setting read-backs, attached
media, a management bearer address and successful bound pings over a
30-second settle period. A SAS grant loss neither blocks confirmation nor
reverts a profile, because the profile does not cycle the radio; the
enforcement gate handles grants. While attached, a confirmed profile keeps
checking management reachability and RRC reconfiguration-failure deltas. A
detached unit is not judged until it attaches again. Two failures
in one sample or single increases observed within a minute trigger rollback.
A decreasing or unreadable counter also fails the check.

Rollback writes the stock values (`AT%GCACTRL=3,4`, which applies at the next
attach), removes SQM, and never cycles the radio. After an interrupted
enforcement re-attach it turns the radio back on and clears the nudge. A
failed trial stays blocked for the rest of the boot. A cold boot clears the
RAM changes and retries the saved profile up to three consecutive
unsuccessful trials. Confirmation clears strikes. If in-place rollback fails,
the guard persists Off before requesting a restart. Status and counters live
in RAM. The keeper's ordinary packet loop runs independently of modem I/O.

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
Up to v1.0.11 download ran `besteffort` and upload `diffserv4` with the
default host isolation. A CAKE of ours with other modes is changed in place
at the next check.

### Traffic classes (Stage 1, since v1.0.12)

Both directions run CAKE `diffserv4`, which has four tins: Bulk, Best Effort,
Video and Voice. Voice may use up to a quarter of the rate and Video half
before they lose their priority. Hosts are grouped by the far end:
`dual-dsthost nonat` on upload and `dual-srchost nonat` on download. In IP
passthrough every IPv4 device in the home shares the router's one WAN
address. Under the default `triple-isolate`, all of the home's bulk flows
counted against that one host, and a new game or call flow started with a
quantum so small (300 bytes at 9 Mbit/s, divided by the number of bulk flows)
that it dropped out of CAKE's sparse queue after one packet.

Most customer devices send DSCP 0, so filters on each CAKE qdisc pick a tin.
They use the kernel's built-in `cls_u32` and `act_skbedit` and only set
`skb->priority` to `<qdisc>:<tin>`, which CAKE reads before DSCP. They change
no packet, and CAKE keeps its own flow and host hashing. In order:

| Order | Match | Tin |
| --- | --- | --- |
| 1 | TCP | DSCP decides (leaves the filter list at once) |
| 2 | ICMP, ICMPv6 | Voice |
| 3 | UDP 443 (QUIC), 80, 1194 and 51820 (VPNs) | DSCP decides |
| 4 | DNS (53), NTP (123) | Voice |
| 5 | 3074, 27015 to 27050, 50000 to 50019 | Voice |
| 6 | 3478 to 3481, 8801 to 8810, 19302 to 19309, 50020 to 50059 | Video |
| 7 | Other UDP of 255 bytes or less (IPv6: payload) | Voice |

Ports match as source or destination, for IPv4 and IPv6: 126 filters per
direction. QUIC and VPNs stay out of the size rule so one flow is never split
across two tins. u32 reads ports at fixed offsets, so a packet with IPv4
options or IPv6 extension headers falls back to its DSCP. On download, the
DSCP a packet arrives with still counts. CAKE `wash` clears it afterwards.

The keeper installs the filters with one `tc -batch`. After every apply and
every 30 s check it counts them on each qdisc (`tc filter show`, one
`skbedit` action per filter). A failed install or a wrong count removes them,
and the `sqm` action fails, so the profile reverts to stock. `"classify":
false` keeps `diffserv4` CAKE with DSCP only, for an A/B test or a kernel where
the filters do not install. The status counters list each tin's packets,
drops and delay (Bulk, Best Effort, Video, Voice).

Stage 1 has not run on hardware yet. Check before relying on it:

- `tc -s filter show dev lte0pdn2 parent ca01:` and `dev eth0 parent ca02:`
  list 126 filters each, and the Voice and Video tins count packets under a
  game-like UDP probe (60 packets a second, about 200 bytes) and a call-like
  one on 8801.
- Ping and the probes under 4-stream upload, download and both, against
  `"classify": false`, with CPU idle and `/proc/net/softnet_stat` drops.
- The LTE driver receives `skb->priority` values like `ca01:4` on upload.
  Nothing is known to read them; confirm upload rate and loss are unchanged.

On the bench (fixed rates, 2026-11-22), CAKE held ping under load near idle:
during download p50 292 to 43 ms, during upload 103 to 32 ms. A fixed rate
costs speed when the radio rate moves: download 113 to 97 Mbps, upload 14 to
8 Mbps.

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
7. Power-cycle three times during unconfirmed trials. On boot four verify zero
   profile writes, stock attach and a locked status. Save Off, wait for off,
   then confirm a fresh trial. Exercise rollback failure and check that the
   subsequent boot leaves the profile disabled.
