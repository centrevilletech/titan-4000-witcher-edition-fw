# Carrier watch (SAS grant coverage)

Status: runs in `log` mode by default when no config file is present. Forced
re-grants (`mode=regrant`) are off by default and must be turned on per unit.

## Why

The vendor SAS client (`cbrs_fsm`) asks Google's SAS for grants that cover the
main carrier (PCell) and the uplink SCell. `rcinit` builds that channel mask
and sends it to `cbrs_fsm` only after a re-attach that `rcinit` sees, or more
than 60 s after a PCell change (`ucid`'s handover hook).

When the tower adds or swaps an uplink SCell inside an existing connection,
nothing notifies `rcinit` or `cbrs_fsm`. The unit keeps `cbrs_mode_grant=1` and
can transmit on an ungranted 20 MHz Band 48 channel for hours.

## What the keeper does

At most once per second, in every network mode:

1. Reads `/tmp/nvram.cfg` in-process and computes the active Band 48 transmit
   spans using the vendor's 5 MHz rounding:
   - PCell from `sqns_radio_earfcnDl` (or `sqns_radio_freqDl` and
     `sqns_radio_bandwidthDl`).
   - Uplink SCell from `sqns_connection_uplinkScc` (or `cbrs_radio_freqUl` and
     `cbrs_radio_bandwidthUl`).
2. Reads `/mnt/cbrslog0.txt` incrementally (handling log rotation and partial
   trailing lines) for the latest authorized grants: lines with three `()`
   groups (`=<idx>(<n>):(<lowHz>-<highHz>:<eirp>)(<hb>:<grantExpiry>)(<txExpiry>)`)
   whose transmit expiry is in the future when the wall clock is sane.
3. Checks whether every active transmit carrier lies inside a held authorized
   grant while `cbrs_mode_grant=1`.
4. Requires 3 consecutive uncovered seconds (configurable via `debounce_secs`)
   before entering `uncovered`, so a normal re-grant in flight or a torn nvram
   read never triggers it.
5. Acts by policy from `/mnt/titan-api/carrier-watch/config`:
   - `mode=log` (default with no file): writes `carrier watch` lines to the
     keeper log and updates `/var/run/witcher-carrier.status`. Takes no radio
     or firewall action.
   - `mode=off`: stays inactive and logs nothing.
   - `mode=regrant`: waits until `rc_signal_done` reads `1` and no re-grant is
     in flight, then runs the same sequence `ucid` uses on a PCell handover:
     sets `sqns_network_cbrs=1` in RAM nvram and sends `SIGUSR1` to `rcinit`.
     `rcinit` restarts its firewall (resetting open TCP sessions through the
     unit's own stack) and sends the updated channel mask to `cbrs_fsm`. The
     keeper then waits up to 180 s for coverage and logs the result and elapsed
     time.

A unit with no SAS/CBRS mode at all logs nothing. The existing IPv6 SAS gate
(`cbrs_gate`) is unchanged.

## Guards and rate limits

In `mode=regrant`, the keeper never forces a re-grant when any of these hold:

- **CPAS quiet window:** Google's SAS issues no new grants during daily CPAS
  (07:00-10:00 UTC). Dropping grants then can leave the PCell ungranted for
  hours. Default `quiet_utc=06:45-10:15` (since v1.0.17 the same window as
  every keeper reboot; it ended at 10:00 before) blocks forced re-grants
  during the window, logs `carrier watch: uncovered, quiet window, waiting`
  once every 10 minutes, and re-checks at 10:15 UTC.
- **Vendor re-grant already in flight:** `cbrs_mode_grant=0` suppresses
  detection and forced re-grants.
- **Unsane clock:** before NTP corrects the Titan's 2013 boot clock, forced
  re-grants are blocked because neither transmit expiry nor the UTC quiet
  window can be trusted.
- **Rate limits and backoff:** at most one forced re-grant per 5 minutes and
  at most 6 in any 24-hour window. Each failed or timed-out re-grant doubles
  the wait before the next attempt (10 min, 20 min, 40 min, capped at 60 min).
- **Dry-run guard:** when `hide_grant=<idx>` is set, forced re-grants are
  always suppressed, even if `mode=regrant` is also present.

## Config file

`/mnt/titan-api/carrier-watch/config` is re-read every 5 seconds. No reboot or
keeper restart is needed.

| Key | Values | Default | Meaning |
| --- | --- | --- | --- |
| `mode` | `off`, `log`, `regrant` | `log` | Policy when a transmit carrier leaves the held grants. |
| `quiet_utc` | `HH:MM-HH:MM` or empty | `06:45-10:15` | Daily UTC window that blocks forced re-grants (supports crossing midnight). Empty disables. |
| `debounce_secs` | `1` to `60` | `3` | Consecutive uncovered seconds before entering `uncovered`. |
| `hide_grant` | `0` to `7` or `none` | `none` | Test-only dry-run option. Hides one grant slot from the comparator and suppresses forced re-grants. |

`#` starts a comment. The last line for a key wins. An invalid `mode` resets to
`log` and logs the ignored line.

## Status and logs

- Status file: `/var/run/witcher-carrier.status` (state, mode, quiet window,
  `cbrs_mode_grant`, PCell and UL SCell spans, held grants, `hide_grant`,
  `last_action`, and counters).
- Log lines: `/mnt/titan-api/pd/keeper.log` (and `/tmp/titan-pd-keeper/keeper.log`),
  all starting with `carrier watch`.

## Dry run on a live unit

To verify the live comparator without transmitting on a new channel or dropping
any grant:

```sh
ssh -p 2222 root@<unit> 'mkdir -p /mnt/titan-api/carrier-watch && printf "mode=log\nhide_grant=1\n" > /mnt/titan-api/carrier-watch/config'
```

Within 10 seconds, `/var/run/witcher-carrier.status` shows `state=uncovered`
for the carrier that slot 1 covered, and `keeper.log` records
`carrier watch: uncovered (...)`. Remove the config to return to normal `log`
mode:

```sh
ssh -p 2222 root@<unit> 'rm -f /mnt/titan-api/carrier-watch/config'
```

## Enabling automatic re-grant and rollback

To enable forced re-grants on one unit:

```sh
ssh -p 2222 root@<unit> 'mkdir -p /mnt/titan-api/carrier-watch && printf "mode=regrant\nquiet_utc=06:45-10:15\n" > /mnt/titan-api/carrier-watch/config && sync'
```

Rollback (live, takes effect within 5 seconds, no reboot):

```sh
ssh -p 2222 root@<unit> 'rm -f /mnt/titan-api/carrier-watch/config && sync'
```

Deleting the file returns the keeper to `mode=log`.
