#!/usr/bin/env python3
"""Cut the vendor rcinit's fixed stalls on a PDN bounce and stop its NAT-mode
firewall restart on a carrier change.

All addresses are virtual addresses in the stock 4172 rcinit (file offset =
VA - 0x8000). Every patch replaces one `bl` with `mov r0, r0`; one also
corrects a log line. See docs/pdn-bounce.md for the disassembly behind each.

  R1  0xd508 0xd510 0xd548  `ifconfig eth0 down`, `sleep(2)`, `ifconfig eth0 up`
      on every `sqns_network_changed` (PDN down and PDN up, both modes). The
      PHY reset on a real address change (check_reset_eth -> mii-tool eth0 -R,
      0x1f30c..0x1f318) stays. The log line at 0x3f854 that claims the bounce
      now says the port stays up.
  R2  0xdc48  `CBRS LTE Freq changed !` calls the NAT-router firewall restart
      (0x30cbc) with no router_disable check. In passthrough that flushes the
      SAS SNAT rule, runs `conntrack -D`, flushes ebtables and ip6tables and
      sets `kern natq act 1`. Every other caller checks router_disable first
      (0xe218..0xe25c, 0xe284..0xe2e8). cbrs_lte_change (0xdc70) still runs.
  R3  0x3ab38  stop_l2tp `sleep(2)` between killing pppd and xl2tpd. stop_wan
      calls it on every PDN change (0x218a4). The kill helper (0x3b3f4)
      already waits up to 2 s for each process and then sends SIGKILL.
  R4  0xf268  `sleep(1)` between `killall -10 udhcpd` and `killall -q udhcpd`
      (0xf218, only caller stop_udhcpd 0x12894): 2 calls on PDN down, 3 on up.
  R5  0xd578  `sleep(1)` before handling `sqns_network_ra`. ucid already sleeps
      1 s after writing the keys (ucid 0xd174), and rcinit handles one signal
      at a time behind the rc_signal_done handshake.

Two inputs are pinned: the stock 4172 binary (the firmware build patches it
before strip-root-password.py and strip-vendor-host-keys.py, which change only
.rodata strings elsewhere) and the Witcher v1.0.0 to v1.0.12 binary (stock plus
those two strips), so a copy taken from a unit can be patched for a RAM-only
bench test. Both give the same code.
"""
from vendor_patch import NOP, Patch, run_cli

BASE = 0x8000
STOCK_SHA256 = '6eeab2c4c0d64f817ed4aec3c66f87d601740dd9975b1fdf3403789d85bab065'
WITCHER_SHA256 = 'b4b7461dba2bd21c6124b9a4ab9f47ca604a64a7e68d3d4a845aeab1d6faf6bf'
STOCK_PATCHED_SHA256 = '61f9421f9951375015d8ab3b51230c692e8556ce29f19fadc6065358d4240d1f'
WITCHER_PATCHED_SHA256 = '87be2be2c93f28e03c49aa460eb779a593ebaa3d6586a204d5a0024526aa6344'
PINS = {STOCK_SHA256: STOCK_PATCHED_SHA256, WITCHER_SHA256: WITCHER_PATCHED_SHA256}

OLD_LOG = b'sqns_network_changed down eth0 and sleep 2 sec , then up eth0!!\n\0'
NEW_LOG = b'sqns_network_changed: Witcher keeps eth0 up\n'
PATCHES = [
    Patch(0x0d508, bytes.fromhex('66f3ffeb'), NOP, 'R1 no `ifconfig eth0 down` on a PDN change'),
    Patch(0x0d510, bytes.fromhex('ebf3ffeb'), NOP, 'R1 no sleep(2) with eth0 down'),
    Patch(0x0d548, bytes.fromhex('56f3ffeb'), NOP, 'R1 no `ifconfig eth0 up` (eth0 never went down)'),
    Patch(0x3f854, OLD_LOG, NEW_LOG.ljust(len(OLD_LOG), b'\0'), 'R1 log line tells the truth'),
    Patch(0x0dc48, bytes.fromhex('1b8c00eb'), NOP, 'R2 no NAT-router firewall restart on a carrier change'),
    Patch(0x3ab38, bytes.fromhex('613effeb'), NOP, 'R3 no sleep(2) in stop_l2tp'),
    Patch(0x0f268, bytes.fromhex('95ecffeb'), NOP, 'R4 no sleep(1) in stop_udhcpd'),
    Patch(0x0d578, bytes.fromhex('d1f3ffeb'), NOP, 'R5 no sleep(1) before the IPv6 RA handler'),
]

if __name__ == '__main__':
    run_cli(__doc__, 'rcinit', PATCHES, BASE, PINS, [
        'PDN change: eth0 stays up; stop_l2tp, stop_udhcpd and RA handler sleeps removed',
        'carrier change: SAS SNAT, natq mode and conntrack left alone; cbrs_lte_change still runs',
    ])
