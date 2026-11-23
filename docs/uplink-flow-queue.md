# Uplink flow queue (`titan_ufq`)

Status: off by default (`mode=0` pass-through at `insmod`). Requires no modem
firmware change and can be loaded, toggled, and unloaded live.

## Why

Under a full 4-stream TCP upload (14 to 15 Mbps on Band 48 2CC TDD Config 2),
modem patch N4 ("uplink AQM v2" plus grant hold) keeps uplink latency near
37 ms p50 and 53 ms p95, compared to 18 ms p50 idle. The remaining 19 ms comes
from a FIFO queue inside the modem: N4 holds roughly 34.5 KB across Ring 1 and
PDCP/RLC so four CUBIC streams stay busy, and stock `gipc_rx_loop` only routes
packets of 127 bytes or less into the fast Ring 0 lane. A 228-byte ping, DNS
query, VoIP or game packet, or TLS handshake waits behind the full bulk queue.

Standard `tc` CAKE cannot solve this on the LTE uplink without guessing a static
rate, because LTE uplink capacity moves with scheduling, MCS, and CA state.

## How it works

`titan_ufq.ko` implements "BQL for the modem" on the bridge forwarding path
(`NFPROTO_BRIDGE`, `NF_BR_FORWARD`, priority `+150`, right after `titan_qctrl`
at `+100`) for customer uplink traffic (`eth0 -> lte0pdn*`):

1. **Per-flow isolation without DSCP marking.** Each IPv4 or IPv6 packet hashes
   by 5-tuple into a 64-bucket deficit round-robin scheduler (RFC 8290) with a
   256-packet static pool and zero dynamic allocation. Newly active sparse
   flows enter `new_flows` and strictly preempt bulk flows in `old_flows`.
   Non-IP frames (such as ARP) pass straight through untouched.
2. **Bulk-only CoDel (RFC 8289).** CoDel runs only on `old_flows` (target 5 ms,
   interval 100 ms). Sparse flows in `new_flows`, ICMP, ICMPv6 (including
   Neighbor Discovery), DHCP, packets under 128 bytes, and the last packet of
   any flow are never dropped. In `mode=3`, ECT(0)/ECT(1) bulk packets receive
   ECN-CE marks instead of drops.
3. **Modem-backlog BQL with TTI-phase pacing.** The module maps four modem RAM
   pages read-only via `__arm_ioremap` (`MT_DEVICE`):
   - `0x84dd59d8` (8 `rbc` slots, stride `0x248`): sums Ring 0/1/cipher
     (`+0x130`) and RLC TX BO (`+0x10c`) across all active AM DRBs
     (`+0x11 == 1 && +0x15 == 3`), avoiding the single-slot bearer pitfall.
   - `0x84d62c70`: MAC UL buffer occupancy cross-check.
   - `0x84a1f860`: modem 1 ms TTI clock (`knl_ms`) for cache-freshness checks.
   - `0x847ed600`: N4 state block (`ST_MAGIC`, `ST_G_EMA` at `+0x2c`,
     `ST_LAST_Q_TRUE` at `+0x54`) when N4/N3R is loaded; falls back to
     self-measured delivery rate on stock `tk.bin`.

   It never writes modem RAM, never reads the 1 Hz stats block (`0x84af11e0`),
   and never maps or touches the AFC register (`0x14110000`).
4. **Anti-staleness defense for non-coherent CPU1 cache.** CPU1 maps modem RAM
   (`0x84xxxxxx`) as Non-Shareable WB-WA, so reads can freeze when CPU1's L1
   D-cache does not evict a line. `titan_ufq` fuses modem RAM with the
   SCU-coherent Linux `gipc` channel-1 outstanding IRB counter (`&gipc + 0x8c`):
   - When `gipc_ch1_out == 0`, the modem is proven empty and `q_est` snaps to 0.
   - Modem RAM anchors `q_est` only when a fresh change is observed; if RAM
     stays unchanged for more than 10 ms, `q_est` decays continuously using the
     measured uplink rate so forwarding never stalls.
5. **Honest BSR and short sparse wait.** Bulk release caps modem occupancy near
   `1.75 * G_ema` (about 15.9 KB at 14.5 Mbps, with a 12 KB floor), keeping
   post-TB BSR around 6.8 to 7.5 KB so the eNB keeps granting full transport
   blocks. After each detected UL TTI drain, a short 1.2 ms bulk holdoff plus
   smooth refill keeps modem backlog below one transport block early in each
   5 ms TTI so sparse packets bypass bulk and catch the next UL subframe.
6. **Hard fail-safe.** If queued packets make no forward progress for
   `failsafe_ms` (default 250 ms) or an internal pool invariant fails, the
   module flushes all queued packets forward and switches to `mode=0`
   pass-through. A netdevice notifier drops held skbs safely if `lte0pdn*` or
   `br*` goes down.

## Controls (`/proc/titan_ufq`)

Read state and counters with `cat /proc/titan_ufq`. Write one `key value` line
at a time:

| Key | Default | Range | Meaning |
| --- | --- | --- | --- |
| `mode` | `0` | `0..7` | Bit 0 (`1`): enable FQ + BQL + bulk CoDel. Bit 1 (`2`): ECN-CE mark ECT bulk flows (`mode 3`). Bit 2 (`4`): ignore modem RAM (GIPC + local rate only). `mode 0` flushes queued packets and passes everything through. |
| `bql_mult_q4` | `28` | `12..64` | Bulk modem queue limit in sixteenths of `G_ema` (`28` = `1.75x`). Lower cuts ping further; higher protects BSR on stricter schedulers. |
| `bql_min_kb` | `12` | `4..64` | Floor on `bql_limit` (KB) to prevent BSR collapse on brief rate dips. |
| `bql_max_kb` | `36` | `8..128` | Cap on `bql_limit` (KB). |
| `tti_hold_us` | `1200` | `0..4000` | Post-TTI bulk holdoff (us) keeping modem backlog under one TB early in the TTI. |
| `pace` | `1` | `0..1` | Enable smooth bulk refill pacing across the UL TTI. |
| `pace_gain_q4` | `24` | `16..32` | Pacer refill rate in sixteenths of estimated link rate (`24` = `1.5x`). |
| `codel_target_ms` | `5` | `2..50` | Per-flow bulk CoDel sojourn target (ms). |
| `codel_interval_ms` | `100` | `20..500` | Per-flow bulk CoDel interval (ms). |
| `quantum` | `1500` | `512..4096` | DRR quantum (bytes). |
| `failsafe_ms` | `250` | `50..2000` | Stall timeout before automatic flush and revert to `mode 0`. |
| `reset` | - | - | Zero counters and clear `failsafe_tripped`. |

## Loading and rollback

```sh
# Load in safe pass-through mode (mode=0)
insmod /tmp/titan_ufq.ko
cat /proc/titan_ufq

# Enable uplink flow isolation (mode 1 = drop CoDel, mode 3 = ECN + drop CoDel)
echo "mode 1" > /proc/titan_ufq

# Instant rollback to pass-through, then unload
echo "mode 0" > /proc/titan_ufq
rmmod titan_ufq
```

## Scope and limits

- Operates on IP passthrough bridge traffic (`eth0 -> lte0pdn*`). In NAT mode
  it loads cleanly and passes traffic untouched.
- Compatible with `titan_qctrl` mode 2 (runs after `titan_qctrl` on
  `NF_BR_FORWARD`).
- Bench verification is pending (see PR bench test plan). Packet-level LTE TDD
  Config 2 simulation (`device/ufq/source/test_ufq_sim.c`) measures 22.8 ms
  p50 / 31.1 ms p95 ping, 0.15 % upload throughput loss, 0 % sparse loss, and
  Jain fairness 1.000 across 4 bulk TCP flows.
