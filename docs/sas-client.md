# A Witcher SAS client for the Titan 4000

Status on 2026-11-22: design and first code. **The code has not run on a radio, is not in the firmware
image, and nothing starts it.** `userspace/sas-model` holds the logic and a pretend SAS for tests.
`userspace/sasd` is the program for the unit. Read [the enforcement notes](cbrs-sas-enforcement.md) first:
nothing here establishes that a modified unit complies with 47 CFR Part 96. Replacing the SAS client changes
how an authorized device is controlled. The operator carries that responsibility.

Tags: `[proven]` means read in the vendor binaries, a unit's log, or a rule text. `[inferred]` means reasoned
from proven facts. `[guess]` means not checked.

## 1. What it does and why

The stock client (`cbrs_fsm`) treats many SAS events as a reason to start over: it gives grants back and
registers again. Each restart costs customers seconds to minutes of service. This client keeps whatever
still works and repairs only what changed. Its design properties:

1. **Keep grants that still work.** A change of carriers asks only for the ranges no held grant covers.
   A grant stays for 24 hours after its range was last in use.
2. **Handle errors per carrier.** A 500, 501 or 502 on one carrier closes traffic only while that carrier
   is in use, and never touches another carrier's grant.
3. **Wait for real answers.** Real Grant answers take 3 to 6 s. This client waits 30 s, then longer after a
   timeout.
4. **Retry slowly and with limits.** A silent SAS gets about one Grant call every two minutes.
5. **Register only when the SAS asks.** No deregistration at start, on a 401, or when the clock moves.
6. **Gate customer traffic in every forwarding path.** Routed IPv4, routed IPv6 and the passthrough bridge,
   set from grant state, not from firewall rebuilds.
7. **Count transmit expiry on a monotonic clock** from the SAS's own `Date` header, so a wrong or stepped
   unit clock changes nothing.
8. **Keep grants across a reboot,** and use each one only after a fresh heartbeat succeeds.
9. **Batch heartbeats.** One HTTPS call carries the heartbeat for every grant that is due.

### Differences from the stock client

| Behavior | Stock client | This client |
|---|---|---|
| Carrier change | Relinquishes all grants, then asks for the new set `[proven]` | Keeps held grants and asks only for what is missing |
| Start, a 401, a clock step over 300 s | Deregisters, then registers again `[proven]` | Keeps the registration and grants. A 401 relinquishes only the grant it names |
| Answer timeout | 6 s `[proven]` | 30 s. A Grant call that timed out waits 60, then 120 s |
| Heartbeat 501 | Relinquishes all grants and leaves the main cell `[proven]` | Keeps and heartbeats the suspended grant. Other carriers keep theirs. Leaves a carrier only when it stays refused (section 3.8) |
| Retries against a silent SAS | Every 15 s `[proven]` | Grant: about every 2 minutes. Heartbeat: 30, 60, 120, then every 300 s |
| Customer-traffic gate | `cbrs_mode_grant` and one routed-IPv4 `FORWARD` rule that `rcinit` adds when it rebuilds its firewall `[proven]` | `cbrs_mode_grant` plus a chain of its own in `iptables`, `ip6tables` and `ebtables`, set and checked from grant state |
| Timers | Wall clock `[proven]` | Monotonic clock. Transmit expiry from the SAS `Date` header |
| Reboot | A new registration and new grants `[proven]` | Saved grants come back as Granted. One heartbeat each before use |
| Heartbeat messages | One message per grant `[inferred]` | One request array for all grants due |

The transmit limit before any grant is 26 dBm at the antenna port `[proven]`. This design does not raise any
limit. Section 9 lists a way to lower that one.

## 2. How the vendor stack is wired

```
 modem --> ucid --nvram--> rcinit --datagram--> cbrs_fsm --HTTPS--> SAS
              ^               ^                    |
              |               +-- SIGUSR1 ---------+   cbrs_mode_grant, sqns_radio_maxTxPower,
              +-- nvram ---------------------------+   cbrs_block_list, sqns_admin_apply
```

- **Who owns SAS.** `cbrs_fsm`, one process, one thread. `rcinit` starts it with `cbrs_fsm &` when no process
  of that name runs `[proven: rcinit 0x15a08]`.
- **How it learns the carriers.** `rcinit` reads the main carrier (`sqns_radio_freqDl`,
  `sqns_radio_bandwidthDl`) and the uplink secondary carrier (`cbrs_radio_freqUl`, `cbrs_radio_bandwidthUl`)
  from nvram. It builds a 32-bit mask (bit 31 is 3550 MHz, 5 MHz per bit) and sends a 16-byte datagram to
  `/tmp/.socket_fsm`: source 3, destination 0, type 4, length 16, connection state, mask `[proven]`.
  Downlink-only secondary carriers are not in the mask. The unit does not transmit on them.
- **How customer traffic is gated.** `cbrs_fsm` sets `cbrs_mode_grant` to 1 or 0 and signals `rcinit`. When
  `rcinit` rebuilds its firewall with the value 0 on band 48, it inserts `iptables -I FORWARD -j DROP`
  `[proven]`.
- **How transmit power is set.** `ucid` sends the modem `AT%TXPOWLMT=1,<sqns_radio_maxTxPower>` while
  `cbrs_mode_grant` is 1, and `AT%TXPOWLMT=1,26` while it is not `[proven]`. The granted value is
  `min(26, maxEirp - 4 + 3)` with cyclic delay diversity on `[proven]`.
- **What stops RF.** One mechanism only. "Channel Invalid" appends the main cell (`earfcn,pci`) to
  `cbrs_block_list` and sets `sqns_admin_apply=1`. `ucid` then re-applies the LTE connection with that cell
  blocked: the modem detaches and may attach elsewhere. `ucid` clears the list after 900 s with no attach
  `[proven]`. The vendor uses it for 500 and 501 and for an unusable carrier set.
- **What `ucid` and the modem expect from the SAS client.** Only those nvram keys. Nothing else speaks to
  `cbrs_fsm` except status readers on the same socket (the web service asks as "source 4").

## 3. The replacement

### 3.1 Process model

`witcher-sasd run` is one process with one thread. It sleeps in a socket read until its next deadline: the
next heartbeat, an expiry, or a retry. A radio event wakes it early. It makes one HTTPS call at a time by
starting the unit's own `curl`, and it polls that child once a second only while a call is out.

| It reads | It writes |
|---|---|
| `rcinit` datagrams on `/tmp/.socket_fsm` | `cbrs_mode_grant`, `cbrs_grant_state`, `cbrs_grant_erip`, `sqns_radio_maxTxPower` |
| Carriers from the same nvram keys `rcinit` uses | Its own drop chain in `iptables`, `ip6tables` and `ebtables` |
| Saved grants in `state.json` on the Witcher volume | `cbrs_block_list` and `sqns_admin_apply`, only to take the radio off a carrier |
| The CBSD ID the SAS already issued (`cbrs_cbsdId`) | `status.json` and a log in RAM |

The decisions live in `witcher-sas-model::engine`. It does no I/O, so every rule below runs in tests against
a pretend SAS on a virtual clock.

### 3.2 Certificate and key

TS-0016 section 8.2 requires TLS 1.2 with both sides authenticated and one of five cipher suites `[proven:
V1.2.7]`. The unit's CBSD certificate, key and SAS trust chain sit in flash as files encrypted by the
vendor. The vendor ships a tool that decrypts them (`cbrs_encrypt 2 <out.pem> <in.bin>`) `[proven: its usage
text]`. At start the daemon runs that tool into a directory in RAM that only root can enter, points `curl`
at the three files with `--cert`, `--key` and `--cacert`, forces TLS 1.2 and the same five suites, and
deletes the directory when it exits. The daemon never opens the files, never logs them, and no key or
passphrase is in this repository. The unit talks only to the SAS address already configured in
`cbrs_sasurl`. The argument order of the vendor tool is `[inferred]` and is the first thing to check on the
bench.

### 3.3 State

- **CBSD:** unregistered or registered.
- **Each grant:** Granted, Authorized or Suspended, with its range, power, heartbeat interval, and a
  monotonic deadline for transmit authority.
- **Gate:** open only while every carrier in use lies inside grants that are Authorized with the deadline
  still ahead.

```
             (start: restore saved grants as Granted, never as Authorized)
 Unregistered --registration 0--> Registered --grant 0--> Granted --heartbeat 0--> Authorized
       ^                              |                      ^  ^                      |
       | 105, 101, 103 "cbsdId"       | 401: give back the   |  | heartbeat 0          | 501
       +------------------------------+ named grant, retry   |  +----- Suspended <-----+
                                                             |          (kept, heartbeated)
              expiry passes: Authorized -> Granted ----------+
              500: grant gone, ask again (with the SAS's suggestion, else after an inquiry)
              502: gate closed, give that grant back, ask again
```

### 3.4 Message flows (WINNF-TS-0016 V1.2.7)

| Procedure | When | Notes |
|---|---|---|
| Registration | Only when the unit has no CBSD ID, or the SAS answers 103 naming `cbsdId` or 105 | Never at boot, never for a grant error. Waits 60, 300, 900 then 3600 s between failed tries. Version 1 has no registration request of its own: see section 8 |
| Spectrum inquiry | Only after a 400, or a 500 with no suggestion | TS-0016 makes it optional before a grant. Skipping it saves the slowest call (up to 16 s) |
| Grant | For each part of a carrier in use that no held grant covers | Pieces of at most 20 MHz. All pieces go in one request array |
| Heartbeat | At 80% of `heartbeatInterval`. First one right after a grant, with `operationState` GRANTED | All grants due in the next fifth of an interval share one request. `grantRenew` goes out when `grantExpireTime` is under 2 days away |
| Relinquishment | For a grant the SAS names in a 401, a grant that drew a 502, and a grant no carrier has used for 24 h | The radio is never on that range when it is sent |
| Deregistration | Only on a hand back to the vendor client | Gate closed first, then relinquish, then deregister |

One request array per call is allowed for a single CBSD: "individual heartbeat requests are sent for each
Grant, possibly aggregated in a single transmission" (section 7) `[proven]`.

### 3.5 Which grants to hold

- **In use:** the main carrier and the uplink secondary carrier. Always.
- **Kept:** a grant stays for 24 hours after its range was last in use. A unit that moves between two
  carriers of its sector asks for each once, then never again. The gate does not close on the move back,
  because the old grant is still Authorized.
- **Standby (off by default):** the operator may list other carriers of the serving sector
  (`WITCHER_SAS_STANDBY=3620-3640,3660-3680`). The unit then holds grants for them before it is ever moved
  there, so a first move costs nothing either.

Is holding a grant for a carrier not in use allowed? TS-0016 lets a CBSD hold several grants `[proven:
section 7]`. Google's documentation says CBSDs "are encouraged to retain their grants for a long time"
`[proven]`. Overlapping grants are refused with 401, so this client never asks for a range it already holds.
The open point is WINNF-TS-0112 R1-DEV-04(f): a CPE-CBSD "shall request a grant with the same
frequency-range parameters as, or a subset of, the frequency range parameters used by the BTS-CBSD to which
the CPE-CBSD connects" `[proven: V1.9.2]`. A carrier of the same base station fits that sentence only if the
base station counts as one BTS-CBSD across its carriers `[inferred]`. Ask the SAS administrator before
turning standby on. The 24-hour keep rests on the same reading for carriers the unit did use.

Grants cost the unit no power: the modem still transmits on at most two uplink carriers, at the limit of the
grants that cover them.

### 3.6 Heartbeats and transmit expiry

- The deadline is `transmitExpireTime` minus the SAS's own clock, taken from the HTTP `Date` header of the
  answer, counted on the monotonic clock from the moment the request left. That can only be early. A wrong
  or stepped unit clock changes nothing.
- When the deadline passes, the grant drops to Granted and the gate closes in the same second. Heartbeats go
  on.
- A failed heartbeat is retried after 30, 60, 120, then every 300 s. With the 6 hour transmit expiry units
  in the field get from their SAS `[proven: unit logs]`, a healthy grant rides out a long SAS outage with no
  customer effect, and nothing is thrown away meanwhile.

### 3.7 Timeouts and retries

| Call | Connect | Answer | After a failure |
|---|---|---|---|
| Heartbeat | 10 s | 30 s | 30, 60, 120, 300 s |
| Grant | 10 s | 30 s, then 60, then 120 after timeouts | No connection: 5, 10, 20, 40, 60 s. Timeout: ask again at once with the longer wait |
| Spectrum inquiry | 10 s | 45 s | 30 s |
| Registration | 10 s | 30 s | 60, 300, 900, 3600 s |

A Grant call that timed out may have been granted. The retry then draws a 401 that names the grant. The
client gives back exactly that grant and asks again. It never deregisters for this. A silent SAS gets about
one Grant call every two minutes.

### 3.8 500, 501 and 502, per carrier

- **501 (suspended):** keep the grant. Close the gate if the grant covers a carrier in use. Heartbeat it again
  after 5, 10, 20 s and then every 60 s when the reason is "Interference Calculations Pending", every 300 s
  for any other reason. Google asks for exactly this: keep the grant, heartbeat for updates, do not
  re-register `[proven]`. No other carrier's grant is touched.
- **500 (terminated):** the grant is gone. With an `operationParam` suggestion, ask again at that power. With
  none, wait 30 s, send a spectrum inquiry, then ask.
- **502 (out of sync):** close the gate, give that grant back, ask again, as TS-0016 requires.
- **Leaving the carrier.** TS-0016 says to turn off transmission on a grant within 60 s after its
  `transmitExpireTime` for 500, 501 and expiry, and within 60 s of receipt for 502 `[proven]`. If a carrier
  in use is still not authorized 45 s after that time, the daemon takes the radio off it:
  - Main carrier: the vendor's own block-list mechanism from section 2 `[proven mechanism]`.
  - Uplink secondary carrier only: an operator command (`WITCHER_SAS_DROP_UPLINK`) that makes the modem drop
    that carrier. None is proven yet. Without one the daemon leaves the main cell, as the vendor does.
  - It tries again after 900, 1800, then every 3600 s: clear the block list, let the unit attach, heartbeat
    the kept grant at once, and leave again after 20 s if it is still refused. Each try is one heartbeat, not
    a new registration and grant. The waits are long on purpose: before authorization a CPE-CBSD may transmit
    above 23 dBm/10 MHz for 20 s in any hour (TS-0112 R1-DEV-04(e)) `[proven]`.

### 3.9 Reboots, restarts and clock jumps

Every change to the grant list is saved with an atomic rename. At start the grants come back as Granted. The
gate stays closed until one heartbeat for each succeeds, which is the same rule as for a new grant (TS-0016
8.5: a successful heartbeat "prior to activating its transmitter") `[proven]`. No deregistration, no new
grants. The supervisor closes the gate whenever the daemon exits.

### 3.10 The customer-traffic gate

Closed means one chain of our own, first in `FORWARD`, in three tables: `iptables` (routed IPv4),
`ip6tables` (routed IPv6) and `ebtables` (the passthrough bridge, IPv4 and IPv6 frames). The unit's own SAS
and management traffic is not forwarded, so it stays open. Open means the chains are removed, so an open
gate costs nothing per packet and needs no watching.

The vendor firewall rebuild would drop our rules. While the gate is closed and the radio is up, the daemon
checks every 5 s that all three tables still start with the chain and puts it back if not. On every radio
event it re-evaluates at once. The gate does not depend on `rcinit` having rebuilt anything.

To open, the daemon writes the same nvram keys as the vendor's Start Channel. If the vendor's own
`-A FORWARD -j DROP` is present, it asks `rcinit` for the same service restart the vendor client asks for
after every grant `[proven path]`.

### 3.11 CPU budget

The unit's single Linux core is the download ceiling, so the client must stay out of the way.

| Moment | Vendor client | This client |
|---|---|---|
| Idle, two grants | Two heartbeat calls per 24 min `[proven: log]`, each its own TLS session `[inferred]`; main loop wake-ups not measured | One `curl` run per 24 min carrying both grants. No wake-ups between |
| Carrier change, grant kept | 2 relinquish, 1 inquiry, 2 grants, 2 heartbeats: 7 calls `[proven: log]` | 0 calls |
| Carrier change, new carrier | 7 calls | 2 calls (grant, heartbeat) |
| Boot or clock jump | Deregister, register, inquiry, 2 grants, 2 heartbeats: 7 calls `[proven: log]` | 1 call |
| Gate closed, radio up | Nothing | Three short listing commands every 5 s, only in that state |

One TLS handshake on this core is a fraction of a second of CPU `[guess]`. Measure both clients in shadow
mode from `/proc/<pid>/stat` before quoting a number.

## 4. Rules the design is written against

This table records what the design does for each rule. It is design intent, not a compliance claim: read
[the enforcement notes](cbrs-sas-enforcement.md), and section 9.

| Rule | What it asks | What this client does |
|---|---|---|
| 47 CFR 96.39(a) | Report location, and changes to it | Registration data is not changed. See section 8 on registration |
| 96.39(c) | Register and be authorized before service; update the SAS within 60 s of a change | Service (the gate) opens only after a successful heartbeat on every carrier in use. Registration data is never altered by this client |
| 96.39(c)(1) | Operate at or below the authorized power, on authorized channels | The modem limit is the vendor's formula over the lowest `maxEirp` of the grants in use, never above 26 dBm. The gate closes the moment a carrier in use lacks an Authorized grant |
| 96.39(c)(2) | Cease, move or change power within 60 s as the SAS instructs | Gate closed in the same second as a 500, 501, 502 or expiry. Radio off the carrier 45 s after transmit expiry if still refused |
| 96.39(d), (e) | Report signal levels and the channel in use when the SAS directs | Not built in version 1. A `measReportConfig` request is ignored: section 8 |
| 96.39(f) | Talk only to approved SASs, over secured links | TLS 1.2, both sides authenticated, the WInnForum cipher list, the SAS trust chain already on the unit, the configured SAS address only |
| 96.39(g) | Protect software from unauthorized change | Outside this client. Replacing the SAS client is a software change the operator must review: section 9 |
| 96.41(b) | EIRP limits per device class | No limit is raised. Requests use the same `maxEirp` as the vendor client (dBm/MHz, as TS-0016 defines it) |
| 96.41(c) | Use the minimum power needed; limit EIRP on instruction | Uplink power control stays with the modem and the base station. A lower suggested `maxEirp` from the SAS is used for the next grant and lowers the modem limit |
| 96.43, 96.45 | Category A and B conditions: height, outdoor use, professional install, antenna data at registration | Registration data comes from the vendor provisioning and is not changed |
| 96.47 | End User Devices operate only under a CBSD's authorization, and act within 10 s | The unit registers as a CBSD because it transmits above the End User Device limit (96.47(b)). The gate acts within 1 s of an answer |
| TS-0016 8.2 | TLS 1.2, mutual authentication, listed suites | Section 3.2 |
| TS-0016 8.5 | No transmission on a grant before a successful heartbeat | A new or restored grant is Granted and the gate stays closed until its heartbeat succeeds |
| TS-0016 8.6 | Heartbeat within `heartbeatInterval`; stop within 60 s after `transmitExpireTime` | Heartbeats at 80% of the interval; a monotonic deadline; section 3.8 |
| TS-0016 8.6, 501 | Keep heartbeating a suspended grant or relinquish it; no transmission until a success | Kept and heartbeated. Gate closed until a success |
| TS-0016 8.6, 502 | Stop within 60 s and relinquish | Gate closed at once; relinquishment is the next call |
| TS-0016 8.7 | Stop radio operation on a grant before relinquishing it | Only grants off the air are relinquished. On hand back the gate closes first |
| TS-0016 8.8 | Cease transmission before deregistering | Hand back only, after the gate closes |
| TS-0016 table 39, 401 | Fix a conflict by syncing with the SAS and relinquishing out-of-sync grants | Relinquish exactly the grants named in `responseData` |
| TS-0016 table 39, 105 | Cease all transmission, drop all grants, consider itself unregistered | All grants dropped, gate closed, radio off the carrier within 60 s, registration after a wait |
| TS-0112 R1-DEV-02 | Cease within 60 s when a grant expires | `grantRenew` before expiry; a refused heartbeat follows the 500 or 103 path |
| TS-0112 R2-DEV-03 | No authorization from two SASs at once | One configured SAS |
| TS-0112 R1-DEV-04(e) | Before authorization, above 23 dBm/10 MHz: at most 1 s in 10, 10 s in 300, 20 s in 3600 | Spaces its tries after a refusal (section 3.8) and offers a limit on a first attach (`WITCHER_SAS_HANDSHAKE_LIMIT`, off by default). Section 9 |
| TS-0112 R1-DEV-04(f) | Ask only for the base station's frequency range or a subset | In-use grants follow the carriers the modem is on. Standby is off until the operator confirms the reading in section 3.5 |
| TS-0112 R1-DEV-04(g) | Limit failed registration tries, then wait | 60, 300, 900, then 3600 s |

## 5. Tests for each property

| Property (section 1) | Test in `sas-model/tests/scenarios.rs` |
|---|---|
| 1. Keep grants that still work | `a_carrier_change_adds_one_grant_and_drops_none`, `twenty_carrier_flaps_cost_seconds_not_minutes`, `a_reattach_on_the_same_carriers_reopens_at_once_and_idle_time_sends_nothing`, `a_grant_nothing_has_used_for_the_retention_time_goes_back` |
| 2. Handle errors per carrier | `a_short_suspension_closes_the_gate_and_keeps_the_grant`, `a_long_suspension_takes_the_radio_off_the_carrier_within_a_minute`, `a_suspended_uplink_carrier_does_not_take_the_main_carrier_down`, the two `a_terminated_grant_*` tests, `an_out_of_step_grant_is_given_back_and_replaced` |
| 3. Wait for real answers | `a_slow_grant_answer_is_waited_for`, `a_call_the_daemon_never_answers_is_treated_as_lost` |
| 4. Retry slowly and with limits | `a_sas_that_acts_but_never_answers_does_not_cause_a_deregistration`, `an_unreachable_sas_changes_nothing_until_it_answers` |
| 5. Register only when the SAS asks | `grants_left_by_another_client_are_given_back_one_by_one`, `a_deregistration_by_the_sas_stops_everything_then_registers_again`, `a_unit_that_cannot_register_says_so_and_stays_closed` |
| 6. Gate every forwarding path | Every scenario checks each second that the gate is never open while the pretend SAS says no. `gate.rs` unit tests cover the commands; packets need the bench |
| 7. Monotonic transmit expiry | `transmit_expiry_is_enforced_when_the_sas_goes_dark`, `a_clock_jump_changes_nothing` |
| 8. Keep grants across a reboot | `grants_survive_a_reboot_but_wait_for_a_heartbeat`, `a_saved_state_that_is_damaged_is_refused` |
| 9. Batch heartbeats | `a_day_of_normal_service_is_one_grant_call_and_batched_heartbeats`, `the_engine_says_when_it_next_needs_a_tick` |
| Hand back | `a_hand_back_closes_the_gate_before_anything_is_given_up` |
| Standby and first-attach limit (both off by default) | `standby_grants_make_a_move_to_a_new_carrier_free`, `the_handshake_limit_is_off_unless_the_operator_sets_it` |

The pretend SAS (`sas-model/src/mock.rs`) can refuse connections, act on a request and lose the answer,
answer late, answer any code, suspend, terminate, fall out of sync, and forget the unit. It never touches a
network. **Never point a radio at a pretend SAS or a replaced trust store.** That would be transmitting
with no real grant.

## 6. Build and test

```bash
cargo test --locked --workspace --manifest-path userspace/Cargo.toml
scripts/build-sasd.sh /tmp/witcher-sasd
```

## 7. Bench plan

**Shadow first.** `witcher-sasd shadow` changes nothing: no SAS call, no nvram write, no firewall rule, no
modem command. It reads the vendor log and the carrier keys, runs the engine against a pretend SAS that is
given the trouble the vendor met, and writes `/tmp/witcher-sasd/shadow.json` and `sas.log`. Run it for 72
hours. Compare calls and closed seconds per event. Check the vendor tool's decrypt command by hand once, to
a RAM directory, and delete the output.

**Then a supervised takeover on one bench unit, with a person watching.**

1. Record the state: vendor log tail, `iptables -S FORWARD`, the nvram grant keys, customer-side pings.
2. Put the daemon binary in RAM under the name `cbrs_fsm` (the name `rcinit` looks for, so it does not start
   a second client). Stop the vendor client with a plain kill. The grants it held stay alive at the SAS.
3. Start the daemon. Expect: gate closed, grant requests answered 401, the named grants relinquished, new
   grants, heartbeat, gate open. Under a minute.
4. Watch `status.json`, the log, all three firewall tables, and pings for IPv4 and IPv6.
5. Steer carrier changes. Pass: no deregistration, one grant per new carrier, no gate closure on a return.
6. Only once a supervisor starts the daemon at boot: reboot. Pass: one heartbeat call, then open. Without a
   supervisor, `rcinit` starts the vendor client at boot, which is the safe default.

**Roll back.** Kill the daemon and run `witcher-sasd hand-back`. It sets `cbrs_mode_grant` to 0, asks
`rcinit` for its cbrs service restart (which puts the vendor's own no-grant rule in and starts the vendor
client, since none is running), waits 5 s, and removes our rules. Or reboot: nothing on flash is changed
except `state.json` on the Witcher volume. The vendor client deregisters at its start, which clears every
grant this client held, then registers again.

**Fail safe.** The supervisor runs `gate-close` whenever the daemon exits and starts it again. On exit
status 78 it runs `hand-back` and stops.

## 8. What is not built yet

- A registration request of our own. Version 1 adopts the CBSD ID the vendor client obtained and exits with
  status 78 if the SAS no longer knows it.
- An answer to status queries on the vendor socket. The web service must read `status.json`.
- Measurement reports.
- A proven modem command to drop only the uplink secondary carrier.
- Firmware image wiring: start script, supervisor, image verification.

## 9. Risks, unknowns and operator decisions

1. **Equipment authorization.** A CPE-CBSD's equipment grant refers to its "configuration and control
   protocols as specified in the filing" (FCC KDB 940660 D02, grant note 40) `[proven: FCC TCB workshop
   slides, 2019]`. Replacing the SAS client changes how the unit is controlled. Get counsel's view before
   any use on the air, and consider running the WInnForum CBSD test cases (WINNF-TS-0122) against the
   WInnForum test harness with the radio off the air.
2. **Standby and kept grants** (section 3.5). Ask the SAS administrator whether a CPE-CBSD may hold grants
   for carriers of its base station that it is not using now.
3. **Waiting for a first grant.** By default this client stays attached while a first grant is pending.
   Leaving the carrier after a set time is stricter but takes the unit off management too.
   `WITCHER_SAS_HANDSHAKE_LIMIT` turns that on. Another option is to cap the modem at the End User Device
   level (23 dBm/10 MHz EIRP) whenever no grant is Authorized. That takes a `ucid` patch, may stop weak units
   from attaching, and is not built.
4. **The 20 seconds per hour rule** also bounds how often a refused unit may come back to try. The defaults
   (15, 30, then 60 minutes) are a judgment, not a measurement of time on air.
5. **Authority after a reboot.** A restored grant may still be inside its old transmit expiry. This client
   ignores that and waits for a heartbeat. That is the cautious reading and costs a few seconds per boot.
6. **A grant made by a lost answer.** The client relinquishes it and asks again. Adopting it would save two
   calls, but its range would be an assumption.
7. **Killed hard.** If the daemon and its supervisor both die with the gate open, nothing closes it. The
   keeper should watch `status.json` for age.
8. **Vendor internals taken on inference:** the decrypt tool's argument order, the `nvram_get` reply format
   for long values, whether `pdn_data_ipaddr` is a sound "attached" test at start, whether clearing
   `cbrs_block_list` and re-applying brings the unit back before the vendor's 900 s, and whether `ucid`
   picks up nvram writes made through the Witcher helper.
9. **Tested only on a host.** CI compiles the workspace and runs the tests against the pretend SAS. The
   daemon's I/O paths (`curl`, nvram, the firewall, the vendor socket) have not run on a unit.

## Sources

- [47 CFR Part 96](https://www.ecfr.gov/current/title-47/chapter-I/subchapter-D/part-96), sections 96.39,
  96.41, 96.43, 96.45, 96.47 (text read 2026-11-22 from the Cornell LII copy)
- [WINNF-TS-0016 V1.2.7, SAS to CBSD interface](https://winnf.memberclicks.net/assets/CBRS/WINNF-TS-0016.pdf)
- [WINNF-TS-0112 V1.9.2, CBRS operational and functional requirements](https://winnf.memberclicks.net/assets/CBRS/WINNF-TS-0112.pdf)
- [Google SAS: grant suspension and response codes](https://docs.cloud.google.com/spectrum-access-system/docs/cbsd/errors-grant-suspension)
- [FCC TCB workshop, CBRS devices, November 2019](https://transition.fcc.gov/oet/ea/presentations/files/nov19/25-CPECBSDs-CC.pdf)
- [WINNF-19-IN-00033, CPE-CBSD as UUT test guidelines](https://winnf.memberclicks.net/assets/work_products/WINNF-19-IN-00033-CPE_CBSD_as_UUT_Test_Guidelines_v1_1.pdf)
