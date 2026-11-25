# Upload clamp (titan_qctrl mode bit 16)

Status: off by default. It is part of `titan_qctrl.ko` v0.4, the staged module
the keeper already loads for the [download clamp](download-clamp.md). Turn it
on by adding 16 to the clamp mode.

## Why

An upload's queue sits in the modem: the GIPC ring (Ring 1) and the PDCP/RLC
staging in front of the radio. Linux on the Titan cannot see it, and the
modem's AQM (the Rust PIE in v1.0.16) controls it only by dropping packets.
On the bench, PIE keeps four CUBIC uploads at about 24 ms of bulk queue on two
uplink carriers. A BBR upload ignores most of its drops, and PIE's overload
latch brings it down to about 19 ms by dropping 17 % of its packets.

## What it does

Every upload flow's ACKs (server to customer) cross the Titan. The clamp lowers
the receive window in those ACKs, so each sender keeps only a short queue in the
modem, whatever its congestion control, and nothing is dropped. The law is in
[`device/qctrl/source/ulclamp_core.h`](../device/qctrl/source/ulclamp_core.h):

    W_f = bw / n x (rtt_f + ul_target_ms)

- `bw` is the upload delivery rate. The ACKs give it: the bytes all uploads had
  acknowledged over one round trip, the maximum of the last 2 s.
- `rtt_f` is the flow's shortest round trip from the Titan over the last
  5-10 s. The first sample is the handshake.
- `n` is the number of bulk uploads. They share the rate equally, and each
  window covers its own round trip plus `ul_target_ms`.
- While a download runs, its tower queue (measured from the servers' clocks)
  adds to the target, because the uploads' ACKs wait in it.

Startup runs free: a new upload gets twice its bytes in flight, at least
64 KB, until it has delivered 64 KB and the link is full. The link is full at
the first round trip that shows a queue, or once the rate stops growing.

The window never rises above what the server advertised. A zero window passes
untouched, and a window rewrite fixes the TCP checksum incrementally.

Once the clamp has sent a right edge (ACK plus window), it never sends one
behind it by a whole window-scale unit or more. The server's real window is
always larger, so no byte is ever refused.

It handles IPv4 and IPv6 alike. It clamps only flows whose handshake it saw, so
it knows the server's window scale. A connection the customer accepts (its SYN
comes from the internet) is left alone.

`ul_pulse_kb` (off by default) grows every window by that much for one round
trip every `ul_pulse_ms`. The Nokia eNB schedules a second uplink carrier only
while the UE's buffer report is high enough. A pulse raises the report, and it
lets `bw` see the link's full rate when the target sits below what the tower
needs.

The modem's PIE stays on as the backstop. With the clamp holding the queue
under PIE's target, PIE drops nothing.

### The fast path

In IP passthrough with `titan_k1fp` in mode 2 or 3, downlink packets skip
netfilter. The fast path calls `titan_qctrl`'s hook for every downlink packet
it forwards, so the clamp also rewrites those ACKs.

The fast path also re-proves each flow on the stock path every 20 ms. Up to
v2.2 it counted the clamp's rewrite there as a modified packet and tripped its
watchdog within a second. `titan_k1fp` v2.3 accepts exactly that change, and
only on downlink, while `titan_qctrl` is loaded:

- a lower TCP window;
- a checksum whose one's complement sum with the window is unchanged;
- every other header byte the same.

The keeper pins v2.3.

### NAT mode

The hook sits on the bridge between `lte0pdn2` and `eth0`, so in NAT mode it
sees no customer traffic and does nothing, like the download clamp. Covering
NAT needs a second hook at `NF_INET_FORWARD` for IPv4 and IPv6. It must match
`br0` to `lte0pdn*` traffic only, so it doesn't run twice on bridged packets
that `br_netfilter` also passes through it (they show `br0` both ways). That is
not built.

## Turning it on

Stage the module as for the download clamp (it is the same `titan_qctrl.ko`).
Then put the upload bit in `qctrl/config`:

```sh
ssh -p 2222 root@<unit> 'printf "mode=18\nul_target_ms=8\n" > /mnt/titan-api/qctrl/config && sync'
```

`scripts/stage-latency.sh --mode 18 --ul-target-ms 8 ...` writes the same file.

| Line | Values | Meaning |
| --- | --- | --- |
| `mode=` | `16`, `18`, `19`, `22` | 16 upload clamp alone; 18, 19 and 22 add it to download modes 2, 3 and 6. |
| `ul_target_ms=` | 0 to 40 | Queue each upload keeps above its round trip. Module default 8. |
| `ul_pulse_kb=` | 0 to 64 | Extra window per pulse, for one round trip. Module default 0 (no pulses). |
| `ul_pulse_ms=` | 50 to 2000 | Time between pulses. Module default 200. |

The keeper writes the knobs, then the mode, to `/proc/titan_qctrl` within 15 s
and reads them back. An unknown line is ignored and logged. The status file
`/var/run/witcher-qctrl.status` shows `upload=1` and the knobs.

`cat /proc/titan_qctrl` shows the live clamp on its `upload:` lines:

- `ul_bw_kbps`: the rate estimate.
- `ul_rtt_ms`: the shortest round trip.
- `ul_flows`: bulk uploads sharing the window.
- `ul_w_kb`: the total window.
- `ul_acks`, `ul_clamped`, `ul_samples`, `ul_pulses`: counters.

The estimates run in every mode, so they are filled in before you turn the
clamp on.

## Turning it off

| Level | Action | Result |
| --- | --- | --- |
| Upload only | Drop 16 from `mode=` | The keeper writes it within 15 s. Windows pass unchanged from the next ACK. |
| Everything | `mode=0` | As for the download clamp. |

## Evidence

Lane Q2 (2026-11-25). The host tests (`device/qctrl/test/run.sh`, CI) compile
the module source itself against a mock kernel. They show:

- four IPv4 or IPv6 uploads on a 16 Mbps link: a 10.4 ms queue at full rate,
  against 3.9 s with the server's window alone;
- one upload at targets 0, 8 and 16 ms: queues of 1.5, 9.4 and 17.3 ms;
- valid checksums, and no right edge moved back by a scale unit;
- with bit 16 clear, the same bytes as v0.3-q3 in modes 0, 2, 3 and 6.

Closed-loop models of the bench link (lanes R1 and Q3), and what they predict,
are in the lane report. The bench decides the default target.

## Not tested yet

- On the bench. Next: the A/B runs in the lane Q2 report.
- Uploads from Windows hosts, which turn TCP timestamps off. The clamp does not
  need them, but no bench run covered it.
- Uploads and downloads together. A download's tower queue delays every upload
  ACK. The module measures that queue from the servers' clocks (the download
  clamp's one-way signal, computed in every mode) and adds it to the upload
  target, so an upload should keep its rate. Only the host tests cover this.
