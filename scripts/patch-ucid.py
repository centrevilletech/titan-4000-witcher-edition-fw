#!/usr/bin/env python3
"""Cut the vendor ucid's wait before it tells rcinit that the PDNs changed.

All addresses are virtual addresses in the stock 4172 ucid (file offset =
VA - 0x8000). See docs/pdn-bounce.md for the disassembly behind each patch.

On every PDN change the handler at 0x240b0 first writes `-` to
sqns_radio_freqDl and sqns_radio_bandwidthDl and resets its radio cache
(0x24230..0x24380). The modem report that answers the next refresh request
rewrites every field it carries, because the cache no longer matches. Stock
then wipes both keys a second time on the first valid read (prev starts at 0,
0x24498..0x24640) and waits for two more matching reads (0x24648), sleeping
1 s per round. That costs three modem refresh rounds instead of one.

  U1  0x24458  On the first round where band, freqDl, bandwidthDl, earfcnDl
      and pci are all valid, branch to the loop's success exit (0x24650).
      The first wipe stays, so no frequency written before this PDN change
      can pass. What goes is the check that two later reports agree.
  U2  0x2472c  `sleep(1)` after the loop, before the `rc_signal_done` wait and
      the signal to rcinit. The writes before it are synchronous.
  U3  0x0e078  `sleep(1)` in the handover path after writing
      sqns_network_cbrs=1 and before signalling rcinit.

Only the stock 4172 ucid is pinned. No other Witcher step changes ucid.
"""
from vendor_patch import NOP, Patch, arm_branch, run_cli

BASE = 0x8000
STOCK_SHA256 = 'a2bbc4cf8a8ba26f7f589932c4190ed87b9a0e7152bd9cf11d1111a90f25633e'
STOCK_PATCHED_SHA256 = 'ddd66ce6bfc75821f5380620b456411aee946ac18144f39ecb7e31f31cb013aa'
PINS = {STOCK_SHA256: STOCK_PATCHED_SHA256}

POLL_ACCEPT = 0x24458   # first instruction after all five field checks pass
POLL_SUCCESS = 0x24650  # `mov r3, #0; str r3, [fp, #-0x1c]; b 0x24690`
PATCHES = [
    Patch(POLL_ACCEPT, bytes.fromhex('2c0207e3'), arm_branch(POLL_ACCEPT, POLL_SUCCESS),
          'U1 accept the first valid radio report after the wipe'),
    Patch(0x2472c, bytes.fromhex('4a97ffeb'), NOP, 'U2 no sleep(1) before signalling a PDN change'),
    Patch(0x0e078, bytes.fromhex('f7f0ffeb'), NOP, 'U3 no sleep(1) before signalling a carrier change'),
]

if __name__ == '__main__':
    run_cli(__doc__, 'ucid', PATCHES, BASE, PINS, [
        'PDN change: one modem refresh round after the frequency wipe, then signal rcinit',
        'carrier change: signal rcinit right after sqns_network_cbrs=1',
    ])
