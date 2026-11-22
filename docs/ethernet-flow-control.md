# Ethernet flow control on the customer port

Since v1.0.11 the network keeper stops the Titan from sending 802.3x PAUSE
frames to the customer router.

## What the vendor driver does

Autonegotiation on `eth0` settles on no PAUSE, because the Titan advertises
none (`ethtool eth0`: `Advertised pause frame use: No`). The vendor `gdm_eth`
driver turns flow control on anyway:

- When the interface opens, it sets hardware flow control (EFC) in the DMA
  operation mode register, with RX FIFO thresholds of 2 KB on and 1 KB off.
  The MAC then sends a PAUSE frame with the longest pause time (0xffff quanta,
  about 33.5 ms at 1 Gb/s) whenever its receive FIFO fills, for example while
  the CPU is busy with the LTE interrupt. A router that obeys it stops all
  upload for that long.
- At every link-up it sets the MAC flow control register to send PAUSE frames
  and to obey them (TFE and RFE).

A bench unit's `kern eth fc` showed `mac fc(ffff0006): rx=1 tx=1
pause-time=ffff` and `dma ctrl(00203306): efc=1`.

## What Witcher changes

The vendor kernel has its own command for this: `kern eth -fc` clears EFC and
nothing else. Without EFC the MAC never starts a PAUSE frame by itself. It does
not reset the PHY, the MAC or the DMA rings, and the link stays up. A frame
that arrives with the receive FIFO full is dropped instead, the way any other
congested port behaves.

The driver sets EFC again whenever the interface opens, and the vendor
`rcinit` takes `eth0` down and up after every PDN change. So the keeper runs
`kern eth -fc` when it starts and each time `eth0` gets its carrier back, in
every mode. It reads the kernel's report (`efc=0`) and writes one line to
`keeper.log` per keeper start.

Obeying PAUSE frames that a router sends (RFE) is left on. No `kern`
subcommand reaches it: only a raw register write, which the driver repeats at
every link-up. Witcher does not write raw registers.

## Checking it and turning it back on

- `kern eth fc` prints the current state to the kernel log (`dmesg`). It
  changes nothing.
- `kern eth fc 1 2` turns EFC back on with the stock thresholds, until the
  keeper's next run after `eth0` comes back up.
- To keep the vendor setting, write `flow_control=stock` to
  `/mnt/titan-api/pd/ethernet.conf`. The keeper reads it each time it would
  run the command. A reboot then restores the vendor setting.
- `kern eth mac vm 0x170` and `kern eth mac vm 0x1d0` read the MAC's sent and
  received PAUSE frame counters.

This has not been measured on hardware yet. A bench check compares ping under
a full-rate two-way load with `efc=1` and `efc=0`, and reads the PAUSE frame
counters before and after.
