#!/usr/bin/env python3
"""Run the real keeper against a veth ARP peer. No host or Titan networking.

Requires root namespace capabilities. PHY action is a recording stub: this
proves packet detection/escalation, not a physical Titan cable disconnect.
The SAS NAT repair runs against recording iptables and kern stubs: this proves
the keeper's decision and commands, not the vendor NAT path itself.
The management advertisement freeze runs against a dummy lte0pdn0 and the real
kernel. The external-device guard reads a file standing in for the kernel log
and runs a recording `kern` stub. The deaf watchdog runs against ping,
modem-state and reboot stubs. The LTE driver MAC correction reads a file
standing in for /proc/net/snmp6 and is checked on the wire of a dummy bearer.
The router swap reads the vendor kernel's `set host mac` line from that kernel
log file and runs a recording `kern netif hmac` stub that logs the line back:
this proves when the keeper points the IPv4 host MAC, not the vendor rewrite.
The 802.3x flow control change runs a recording `kern eth` stub that prints
the kernel's report: this proves when the keeper runs it, not the register.
The vendor ping watchdog runs against a file standing in for the vendor's RAM
configuration cache and a recording `titan-nvram` stub. The keeper's RAM log
and RAM status copy are checked against the flash files in the state directory.
A file stands in for rcinit's log, and an empty lease file for the vendor Wi-Fi
DHCP server's write over the shared lease file.
The CBRS gate reads the SAS grant keys from that same cache file and edits two
files standing in for the ebtables and ip6tables FORWARD chains, through stubs
that print them the way the unit's tools do: this proves the keeper's
decisions and commands, not the kernel tables. One ip6tables call is made to
hang for an hour: the keeper stops it after 10 s, keeps its loop and its
heartbeat file going, and the gate still closes.
The boot confirm for a staged modem firmware image reads a status file standing
in for the boot hook's and runs against the ping and reboot stubs, the
vendor cache (attached with an RSRP, or searching) and a DNS stand-in for the
bearer's DNS server. The main run has no staged image and must never reboot
for it. Only time with a cell in view counts against an image (20 s here),
and every keeper reboot passes the reboot gate (the CPAS window, the clock,
four a day). For the default image no network condition may keep the unit
off it: a tower down at the upgrade costs one comparison and one way back,
and the image then waits with no second cycle; boots cut short and a
flapping tower likewise; core up with ping unanswered confirms through DNS;
a comparison inside the CPAS window or at the daily cap waits on the image.
Only failures in a row where stock answers quarantine an image.
The modem feature flags (v1.0.15) run against a stub modem console that prints
`vm` dumps the way the unit's does and keeps its RAM in a file: no session
before a confirmed staged boot, no write before the patch magic, then writes
read back, a config change that writes 0, and a modem restart from the kernel
log. The download clamp runs with a bogus staged module and a recording insmod
stub: it must wait for the links and then refuse the bytes, never load them.
The fast path runs first with a bogus staged module (refused before insmod),
then with the real pinned clamp and fast path modules against a stub insmod
and a fake /proc/k1fp: clamp loads before fast path, mode 2 is read back,
grant leases renew every second and revoke immediately on gate close, a change
in qctrl_present is logged, watchdog trips re-arm at most once per boot before
holding at mode 0 in state=tripped, and mode=0 rolls back live.
Since v1.0.17 both are on by default: with no config of their own they load
from a directory standing in for the image's copies, the clamp in mode 3
(read back from a fake /proc/titan_qctrl) and the fast path in mode 2, and the
latency switch file turns each off and on live. modem=off there rolls the
modem words back to 0, and on writes them again.
"""
import errno
import hashlib
import os
import json
from pathlib import Path
import shutil
import struct
import socket
import subprocess
import sys
import threading
import time

REPO = Path(__file__).resolve().parent.parent
BINARY = REPO/'userspace/target/debug/titan-pd-keeper'


def run(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL)


def main():
    if '--inner' not in sys.argv:
        if os.geteuid() != 0:
            raise SystemExit('Run as root; this test creates isolated mount/network/PID namespaces.')
        subprocess.run(['unshare', '--mount', '--net', '--pid', '--fork', '--mount-proc',
                        sys.executable, __file__, '--inner'], check=True, timeout=2700)
        return
    run('mount', '--make-rprivate', '/')
    run('mount', '-t', 'tmpfs', 'tmpfs', '/tmp')
    run('mount', '-t', 'tmpfs', 'tmpfs', '/run')
    run('mount', '-t', 'sysfs', 'sysfs', '/sys')
    Path('/tmp/bin').mkdir()
    # Keep real tools accessible after hiding the vendor-program directory.
    for name in ('ip', 'ps'):
        shutil.copy2(Path(shutil.which(name)).resolve(), '/tmp/bin/real-'+name)
    run('mount', '-t', 'tmpfs', 'tmpfs', '/usr/sbin')
    ip = '/tmp/bin/real-ip'
    run(ip, 'link', 'add', 'br0', 'type', 'bridge')
    run(ip, 'link', 'add', 'eth0', 'type', 'veth', 'peer', 'name', 'router0')
    run(ip, 'link', 'set', 'eth0', 'master', 'br0')
    run(ip, 'addr', 'add', '10.1.1.1/24', 'dev', 'br0')
    run(ip, 'netns', 'add', 'witcher-peer')
    run(ip, 'link', 'set', 'router0', 'netns', 'witcher-peer')
    run(ip, '-n', 'witcher-peer', 'addr', 'add', '172.20.64.152/28', 'dev', 'router0')
    run(ip, '-n', 'witcher-peer', 'link', 'set', 'router0', 'up')
    run(ip, '-n', 'witcher-peer', 'route', 'add', 'default', 'via', '172.20.64.151', 'dev', 'router0')
    run(ip, 'link', 'add', 'lte0pdn1', 'type', 'dummy')
    for name in ('lo', 'br0', 'eth0', 'lte0pdn1'):
        run(ip, 'link', 'set', name, 'up')
    peer_mac = bytes.fromhex(json.loads(subprocess.check_output([ip,'-n','witcher-peer','-j','link','show','router0']))[0]['address'].replace(':',''))
    peer_mac_text = ':'.join('%02x' % b for b in peer_mac)
    def exe(path, text):
        p=Path(path);p.write_text('#!/bin/sh\n'+text+'\n');p.chmod(0o755)
    exe('/tmp/bin/ip', 'exec /tmp/bin/real-ip "$@"')
    exe('/tmp/bin/ps', 'exec /tmp/bin/real-ps -eo pid,args')
    exe('/tmp/bin/nvram_get', 'case "$2" in router_disable) echo "nvram_get success: 1";; lan_management_ipaddr) echo "nvram_get success: 10.1.1.1";; pdn_data_ipaddr) echo "nvram_get success: 172.20.64.152";; wan_get_dns) echo "nvram_get success: 192.0.2.53 0.0.0.0";; sqns_connection_mediaState) echo "nvram_get success: ATTACHED";; *) echo "nvram_get success: ";; esac')
    # Deaf watchdog fixtures: a target answers while /tmp/ping-ok exists, and a reboot is only recorded.
    exe('/tmp/bin/ping', 'echo "$*" >> /tmp/ping-calls; [ -e /tmp/ping-ok ]')
    exe('/tmp/bin/reboot', 'echo "reboot $*" >> /tmp/reboot-actions')
    exe('/tmp/bin/insmod', 'echo "insmod $*" >> /tmp/insmod-calls; exit 1')
    # A modem console (DM) stand-in: `vm` dumps print most significant byte
    # first under the unit's column header, 16 bytes to a row; `wm` writes a
    # RAM file. Each patch layer's magic shows only while its marker file
    # exists. The M1 block's marker holds its build version, in hex.
    lted = Path('/tmp/bin/lted_cli')
    lted.write_text(r'''#!/usr/bin/env python3
import json, os, sys
ram = json.load(open('/tmp/dm-ram.json')) if os.path.exists('/tmp/dm-ram.json') else {}
HEADER = '           | 03 02 01 00  07 06 05 04  0B 0A 09 08  0F 0E 0D 0C'
MAGICS = {
    0x847ed600: ('/tmp/dm-magic', 0x4e345632),
    0x847ecfe8: ('/tmp/dm-magic-img4', 0x494d4734),
    0x84489a64: ('/tmp/dm-magic-n5', 0x4e35464c),
    0x8418ff00: ('/tmp/dm-magic-n6', 0x55324846),
    0x841b5900: ('/tmp/dm-magic-m1', 0x4d315049),
}
M1 = '/tmp/dm-magic-m1'
# Counters of a PIE that has run (seen, PIE drops, CE marks, hard drops, peak delay).
M1_COUNTERS = {0x841b5960: 28025, 0x841b5968: 130, 0x841b596c: 7, 0x841b5970: 90, 0x841b5980: 97612}
BOOT_DEFAULTS = {
    0x847ed608: 0x4000,
    0x847ed60c: 0x6000,
    0x84489a70: 40,
    0x84489a74: 3072,
    0x84489a78: 500,
    0x84489a7c: 10,
    0x84489a84: 0x4000,
    0x84489a88: 0x6000,
}
def word(addr):
    if addr in MAGICS:
        marker, value = MAGICS[addr]
        return value if os.path.exists(marker) else 0
    if 0x841b5900 < addr < 0x841b5a00 and os.path.exists(M1):
        if addr == 0x841b5904:
            return int(open(M1).read().strip(), 16)
        if str(addr) not in ram:
            return M1_COUNTERS.get(addr, 0)
    return ram.get(str(addr), BOOT_DEFAULTS.get(addr, 0))
def dump(addr, length):
    words = [word(addr + 4 * i) for i in range((length + 3) // 4)]
    rows = ''
    for at in range(0, len(words), 4):
        cells = [' '.join('%02x' % b for b in w.to_bytes(4, 'big')) for w in words[at:at + 4]]
        cells += ['.. .. .. ..'] * (4 - len(cells))
        rows += '\x1b[1;32m0x%08X\x1b[0m | %s \n' % (addr + 4 * at, '  '.join(cells))
    sys.stdout.write('\n-----\n HEX DUMP  | %d(0x%x) Bytes @ 0x%08X\n-----\n%s\n-----\n%s-----\nDM> ' % (length, length, addr, HEADER, rows))
for line in sys.stdin:
    line = line.strip()
    with open('/tmp/dm-log', 'a') as log:
        log.write(line + '\n')
    words = line.split()
    if line == 'exit':
        break
    if len(words) == 3 and words[0] == 'vm':
        dump(int(words[1], 16), int(words[2]))
    elif len(words) == 3 and words[0] == 'wm':
        addr, value = int(words[1], 16), int(words[2], 16)
        ram[str(addr)] = value
        with open('/tmp/dm-ram.json.tmp', 'w') as out:
            json.dump(ram, out)
        os.replace('/tmp/dm-ram.json.tmp', '/tmp/dm-ram.json')
        sys.stdout.write('\n0x%08x: 0x%08x\n\nDM> ' % (addr, value))
    else:
        sys.stdout.write('\nDM> ')
    sys.stdout.flush()
''')
    lted.chmod(0o755)
    Path('/tmp/ping-ok').write_text('')
    # The vendor ping watchdog is on in the RAM cache. The stub records each
    # write and updates the cache, as the vendor library does.
    # The SAS grant is held (Witcher's own test: both keys).
    Path('/tmp/nvram-cache').write_text('detection_interval=3\ndetection_enable=1\ncbrs_mode_grant=1\ncbrs_grant_state=2\n')
    exe('/tmp/bin/titan-nvram', 'value=$(cat); echo "$1 $2 $3 $value" >> /tmp/nvram-actions\n'
        'if [ "$1 $3" = "set detection_enable" ]; then sed -i "s/^detection_enable=.*/detection_enable=$value/" /tmp/nvram-cache; fi')
    Path('/tmp/pd').mkdir()
    Path('/tmp/pd/watchdog.conf').write_text('deaf_secs=120\n')
    # Management bearer fixture: the global is up, the kernel still accepts
    # advertisements, and the learned default route is about to expire.
    mgmt_global='2001:db8:e0:97:200:5eff:fe40:1'
    mgmt_ready=False
    try:
        run(ip, 'link', 'add', 'lte0pdn0', 'type', 'dummy')
        run(ip, 'link', 'set', 'lte0pdn0', 'up')
        Path('/proc/sys/net/ipv6/conf/lte0pdn0/accept_ra').write_text('2\n')
        run(ip, '-6', 'addr', 'add', 'fe80::200:5eff:fe40:1/64', 'dev', 'lte0pdn0', 'nodad')
        run(ip, '-6', 'addr', 'add', mgmt_global+'/64', 'dev', 'lte0pdn0', 'nodad')
        run(ip, '-6', 'route', 'add', 'default', 'via', 'fe80::1', 'dev', 'lte0pdn0', 'metric', '1024', 'expires', '600')
        Path('/tmp/pd/mgmt-iid.txt').write_text('200:5eff:fe40:1\n')
        mgmt_ready=True
    except (subprocess.CalledProcessError, OSError) as err:
        print('SKIP: this kernel namespace has no usable IPv6; management freeze not exercised:', err, flush=True)
    def mgmt_routes():
        return subprocess.check_output([ip, '-6', 'route', 'show', 'dev', 'lte0pdn0']).decode()
    def mgmt_addrs():
        return subprocess.check_output([ip, '-6', 'addr', 'show', 'dev', 'lte0pdn0']).decode()
    def accept_ra():
        return Path('/proc/sys/net/ipv6/conf/lte0pdn0/accept_ra').read_text().strip()
    # The vendor SAS SNAT rule lives in a file. A flush is the file going empty.
    sas_rule='-A POSTROUTING -s 10.1.1.1/32 -j SNAT --to-source 172.20.64.152'
    exe('/tmp/bin/iptables', 'if [ "$*" = "-t nat -S POSTROUTING" ]; then echo "-P POSTROUTING ACCEPT"; cat /tmp/nat-rules; exit 0; fi\n'
        'echo "iptables $*" >> /tmp/sas-actions\n'
        'if [ "$*" = "-t nat -I POSTROUTING -s 10.1.1.1 -j SNAT --to-source 172.20.64.152" ]; then echo "'+sas_rule+'" >> /tmp/nat-rules; exit 0; fi\nexit 1')
    # `kern netif extdev <dev> down` prints external_dev=NULL to the kernel log on a Titan,
    # `kern netif hmac <hostif> <mac>` prints the stored IPv4 host MAC,
    # and `kern eth -fc` prints the flow control report.
    exe('/tmp/bin/kern', 'if [ "$1 $2" = "netif hmac" ]; then echo "kern $*" >> /tmp/hostmac-actions; echo "4,250,3,-;$3 set host mac: $4" >> /tmp/kmsg; '
        'elif [ "$1" = netif ]; then echo "kern $*" >> /tmp/extdev-actions; echo "4,200,2,-;external_dev=NULL" >> /tmp/kmsg; '
        'elif [ "$1" = eth ]; then echo "kern $*" >> /tmp/eth-actions; echo "4,300,5,-;  dma ctrl(00203206): efc=0 rfa=1(fill=2KB) rfd=2(fill=1KB)" >> /tmp/kmsg; '
        'else echo "kern $*" >> /tmp/sas-actions; fi')
    # At boot the vendor kernel stores the first eth0 frame's MAC as its IPv4
    # host MAC: here the fixture's router.
    Path('/tmp/kmsg').write_text('6,1,1,-;booting\n6,2,2,-;usb0 set host mac: '+peer_mac_text+'\n')
    Path('/tmp/snmp6').write_text('Ip6InReceives 1\nIp6OutForwDatagrams 0\n')
    Path('/tmp/nat-rules').write_text(sas_rule+'\n')
    # Both FORWARD chains, one rule a line. Listings match ebtables v2.0.10-4
    # (`-L`: no chain name, a space at the end) and ip6tables (`-S`). A delete
    # of a rule that is not there fails, as on the unit.
    chain_stub = ('f=$1; shift; echo "$*" >> $f.calls\n'
        'case "$1 $2" in\n'
        '"-L FORWARD") printf "Bridge table: filter\\n\\nBridge chain: FORWARD, entries: %s, policy: ACCEPT\\n" "$(wc -l < $f)"; sed "s/\\$/ /" $f;;\n'
        '"-S FORWARD") echo "-P FORWARD ACCEPT"; sed "s/^/-A FORWARD /" $f;;\n'
        '"-I FORWARD") shift 3; { echo "$*"; cat $f; } > $f.new; mv $f.new $f;;\n'
        '"-A FORWARD") shift 2; echo "$*" >> $f;;\n'
        '"-D FORWARD") shift 2; n=$(grep -n -x -F -- "$*" $f | head -n 1 | cut -d: -f1); [ -n "$n" ] || exit 1; sed -i "${n}d" $f;;\n'
        '*) exit 1;;\n'
        'esac')
    exe('/tmp/bin/chain-stub', chain_stub)
    for name in ('ebt', 'ip6'):
        Path('/tmp/'+name+'-forward').write_text('')
    exe('/tmp/bin/ebtables', 'exec /tmp/bin/chain-stub /tmp/ebt-forward "$@"')
    # While /tmp/hang-ip6tables exists, the next ip6tables call hangs (a tool
    # stuck on a kernel lock) for an hour; the marker is used up by that call.
    exe('/tmp/bin/ip6tables', 'if [ -e /tmp/hang-ip6tables ]; then rm -f /tmp/hang-ip6tables; exec sleep 3600; fi\n'
        'exec /tmp/bin/chain-stub /tmp/ip6-forward "$@"')
    exe('/tmp/bin/mii-tool', 'echo "$*" >> /tmp/phy-actions; /tmp/bin/real-ip netns exec witcher-peer /bin/sh -c "echo 0 > /proc/sys/net/ipv4/conf/router0/arp_ignore"')
    exe('/usr/sbin/udhcpd', 'echo start >> /tmp/dhcp-starts; while :; do sleep 30; done')
    peer = json.loads(subprocess.check_output([ip, '-n', 'witcher-peer', '-j', '-4', 'addr', 'show', 'router0']))[0]
    run(ip, 'route', 'add', peer['addr_info'][0]['local'] + '/32', 'dev', 'br0')
    Path('/tmp/udhcpd.conf').write_text('start 172.20.64.152\nend 172.20.64.152\nmax_leases 8\ninterface br0:9\nremaining yes\noption subnet 255.255.255.240\noption router 172.20.64.151\noption lease 120\n')
    lease_state={'empty':False}
    def lease():
        if lease_state['empty']:
            # The vendor Wi-Fi server's own list: a timestamp and no lease.
            Path('/tmp/lease.new').write_bytes(struct.pack('>Q',int(time.time())))
        else:
            Path('/tmp/lease.new').write_bytes(struct.pack('>QI4B6s20s2x',int(time.time()),120,172,20,64,152,peer_mac,b'fixture'))
        Path('/tmp/lease.new').replace('/tmp/udhcpd.leases')
    lease()
    Path('/tmp/rcinit.log').write_text(' 0:00:09 >|rc.c                 1372 >|   info >| IDLE... ...\n')
    capture=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3));capture.bind(('eth0',0));capture.setblocking(False)
    packets=[]
    server=subprocess.Popen(['/usr/sbin/udhcpd','-f','/tmp/udhcpd.conf'])
    # Fake /proc/k1fp control pipe: receives keeper writes (`mode N`, `grant N`)
    # and updates /tmp/k1fp-proc atomically the way titan_k1fp does.
    os.mkfifo('/tmp/k1fp-ctl')
    fp_lock = threading.Lock()
    fp_state = {
        'mode': 0,
        'gate': 'closed',
        'grant_left_ms': 0,
        'qctrl_present': 1,
        'wd_trips': 0,
        'wd_reason': 'none',
    }
    k1fp_cmds = []

    def write_k1fp_proc():
        s = fp_state
        text = (
            "titan_k1fp v2.2\n"
            f"mode={s['mode']} lan=eth0 lan_hooked=1 wan=lte0pdn2 wan_hooked=1 br=br0 br_ports=2 ports_ok=1\n"
            f"require_grant=1 grant_left_ms={s['grant_left_ms']} gate={s['gate']} v4=1 v6=1 lease_ms=60 sample_ms=20\n"
            f"qctrl: qctrl_present={s['qctrl_present']} qctrl_dl_calls=0 qctrl_dl_drop=0 qctrl_dl_stolen=0 qctrl_ul_stock=0\n"
            f"watchdog: wd_armed={1 if s['mode'] >= 2 else 0} wd_trips={s['wd_trips']} wd_reason={s['wd_reason']} wd_mod=20 wd_mismatch=64 wd_stall_ms=500 wd_ringfull_ms=500\n"
            "safety: txirq=0 txdrain=0 dlbypass=0 pins=0 modref=0 err_tx=0\n"
            "vendor: netifq_enabled=1 net_mode=2 host_mac_learned=1 host_mac=00:11:22:33:44:55 external_dev_set=0\n"
            "brhook: external_dev_stop=0 list_nr=0 in_hold=0 held=0 holds=0\n"
            "fast_dl=0 fast_ul=0 fast_dl_KiB=0 fast_ul_KiB=0 would_fast=0 gate_closed=0 xmit_err=0\n"
        )
        Path('/tmp/k1fp-proc.tmp').write_text(text)
        Path('/tmp/k1fp-proc.tmp').replace('/tmp/k1fp-proc')

    k1fp_fd = os.open('/tmp/k1fp-ctl', os.O_RDWR)

    def k1fp_ctl_loop():
        buf = b''
        while True:
            try:
                chunk = os.read(k1fp_fd, 4096)
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
            while b'\n' in buf:
                raw, buf = buf.split(b'\n', 1)
                cmd = raw.decode('utf-8', 'replace').strip()
                if not cmd:
                    continue
                now_ts = time.monotonic()
                with fp_lock:
                    k1fp_cmds.append((now_ts, cmd))
                    parts = cmd.split()
                    if len(parts) == 2 and parts[0] == 'mode' and parts[1].isdigit():
                        fp_state['mode'] = int(parts[1])
                        write_k1fp_proc()
                    elif len(parts) == 2 and parts[0] == 'grant' and parts[1].isdigit():
                        secs = int(parts[1])
                        fp_state['grant_left_ms'] = secs * 1000
                        fp_state['gate'] = 'open' if secs > 0 else 'closed'
                        write_k1fp_proc()

    threading.Thread(target=k1fp_ctl_loop, daemon=True).start()

    # Fake /proc/titan_qctrl control pipe, like k1fp's: the keeper writes knob
    # and mode lines, and /tmp/qctrl-proc shows them as v0.3-q3 prints them.
    os.mkfifo('/tmp/qctrl-ctl')
    q_lock = threading.Lock()
    q_defaults = {'mode': 0, 'trough_ms': 4, 'target_ms': 40, 'ack_adapt': 0, 'ctrl_v3': 0,
                  'ack_ms': 6, 'ack_segs': 18, 'ack_min_kbps': 2000}
    q_state = dict(q_defaults)

    def write_qctrl_proc():
        s = q_state
        text = (
            'titan_qctrl v0.3-q3 (NF_BR_FORWARD prio=+100)\n'
            f"mode=0x{s['mode']:x} (ack_thin={s['mode'] & 1} rwnd_clamp={(s['mode'] >> 1) & 1} dl_ecn={(s['mode'] >> 2) & 1} udp_drop=0)\n"
            f"params: target_q_ms={s['target_ms']} hold_us=2500 max_ack_span=8192 phy_cap_kbps=0\n"
            f"        qsrc=0 slack_ms=10 floor_pct=30 drain=1 probe=1 trough_ms={s['trough_ms']} rtt_target_ms=15 ecn_ms=20 wfix_kb=0 rttlaw=0\n"
            f"        ack_adapt={s['ack_adapt']} ctrl_v3={s['ctrl_v3']} ack_ms={s['ack_ms']} ack_segs={s['ack_segs']} ack_min_kbps={s['ack_min_kbps']}\n"
        )
        Path('/tmp/qctrl-proc.tmp').write_text(text)
        Path('/tmp/qctrl-proc.tmp').replace('/tmp/qctrl-proc')

    qctrl_fd = os.open('/tmp/qctrl-ctl', os.O_RDWR)

    def qctrl_ctl_loop():
        buf = b''
        while True:
            try:
                chunk = os.read(qctrl_fd, 4096)
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
            while b'\n' in buf:
                raw, buf = buf.split(b'\n', 1)
                parts = raw.decode('utf-8', 'replace').split()
                with q_lock:
                    if len(parts) == 2 and parts[0] in q_state and parts[1].isdigit() and Path('/tmp/qctrl-proc').exists():
                        q_state[parts[0]] = int(parts[1])
                        write_qctrl_proc()

    threading.Thread(target=qctrl_ctl_loop, daemon=True).start()

    env=dict(os.environ,PATH='/tmp/bin:'+os.environ['PATH'],TITAN_EBTABLES='/tmp/bin/ebtables',TITAN_IP6TABLES='/tmp/bin/ip6tables',TITAN_PD_STATE='/tmp/pd',TITAN_PD_RUNTIME='/tmp/runtime',TITAN_KMSG='/tmp/kmsg',TITAN_SNMP6='/tmp/snmp6',TITAN_NVRAM='/tmp/bin/titan-nvram',TITAN_NVRAM_CACHE='/tmp/nvram-cache',TITAN_RCINIT_LOG='/tmp/rcinit.log',
             TITAN_TK_STATUS='/tmp/tk.status',TITAN_TK_RESULT='/tmp/tk.result',TITAN_TK_DIR='/tmp/tk',
             TITAN_TK_FLAGS='/tmp/tk.flags',TITAN_TK_HANDS_OFF='/tmp/tk.hands-off',TITAN_TK_M1='/tmp/tk.m1',
             TITAN_LTED_CLI='/tmp/bin/lted_cli',TITAN_DM_STEP_MS='300',
             TITAN_QCTRL_DIR='/tmp/qctrl',TITAN_QCTRL_STATUS='/tmp/qctrl.status',TITAN_QCTRL_PROC='/tmp/qctrl-proc',
             TITAN_QCTRL_PROC_WRITE='/tmp/qctrl-ctl',TITAN_MODULES_DIR='/tmp/image-modules',TITAN_LATENCY_DIR='/tmp/latency',
             TITAN_TK_QUIET_UTC='',TITAN_TK_CONFIRM_SECS='20',TITAN_TK_SEARCH_SECS='45',TITAN_TK_RECHECK_SECS='3600',TITAN_TK_PROBE_EVERY='5',
             TITAN_FASTPATH_DIR='/tmp/fastpath',TITAN_FASTPATH_STATUS='/tmp/fastpath.status',
             TITAN_FASTPATH_PROC='/tmp/k1fp-proc',TITAN_FASTPATH_PROC_WRITE='/tmp/k1fp-ctl',
             TITAN_PROC_MODULES='/tmp/proc-modules',TITAN_INSMOD='/tmp/bin/insmod',
             TITAN_CARRIER_DIR='/tmp/carrier-watch',TITAN_CBRS_LOG='/tmp/cbrslog0.txt',TITAN_CARRIER_STATUS='/tmp/carrier.status')
    keeper=subprocess.Popen([str(BINARY),'run'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    def log():
        p=Path('/tmp/pd/keeper.log');return p.read_text() if p.exists() else ''
    def ram():
        return ''.join(p.read_text() for p in (Path('/tmp/runtime/keeper.log.1'),Path('/tmp/runtime/keeper.log')) if p.exists())
    def wait_for(predicate, seconds):
        deadline=time.monotonic()+seconds
        while time.monotonic()<deadline:
            lease()
            try:
                while True:
                    frame=capture.recv(2048)
                    if frame[12:14]==b'\x08\x06': packets.append(frame.hex())
            except BlockingIOError: pass
            except OSError as err:
                # Taking eth0 down reports ENETDOWN once on a bound packet socket.
                if err.errno!=errno.ENETDOWN: raise
            if keeper.poll() is not None: raise AssertionError('keeper exited: '+log())
            if predicate(): return
            time.sleep(.25)
        raise AssertionError('Timed out: '+log()+'\nARP '+repr(packets)+'\ncarrier '+repr([Path('/sys/class/net/'+n+'/carrier').read_text() for n in ['eth0','lte0pdn1']])+'\nIP '+subprocess.check_output([ip,'-4','-o','addr','show','dev','br0']).decode()+'\nlease '+Path('/tmp/udhcpd.leases').read_bytes().hex())
    def eth_actions():
        p=Path('/tmp/eth-actions');return p.read_text().splitlines() if p.exists() else []
    def hostmac_actions():
        p=Path('/tmp/hostmac-actions');return p.read_text().splitlines() if p.exists() else []
    def nvram_actions():
        p=Path('/tmp/nvram-actions');return p.read_text().splitlines() if p.exists() else []
    try:
        # The keeper turns off PAUSE frames when it starts, and again when eth0
        # comes back up, because opening the port turns them back on.
        wait_for(lambda:eth_actions()==['kern eth -fc'] and 'no longer sends 802.3x PAUSE' in log(),10)
        run(ip, 'link', 'set', 'eth0', 'down')
        until=time.monotonic()+3
        wait_for(lambda:time.monotonic()>=until,5)
        assert eth_actions()==['kern eth -fc'], eth_actions()
        run(ip, 'link', 'set', 'eth0', 'up')
        wait_for(lambda:len(eth_actions())==2,10)
        assert eth_actions()==['kern eth -fc']*2, eth_actions()
        assert log().count('no longer sends 802.3x PAUSE')==1, log()
        print('PASS: PAUSE frames turned off at start and again after eth0 came back up, logged once.',flush=True)
        # The deaf watchdog is on, so the vendor one is turned off in RAM only.
        wait_for(lambda:'vendor ping watchdog: turned off in RAM' in log(),10)
        assert nvram_actions()==['set 0 detection_enable 0'], nvram_actions()
        assert 'detection_enable=0' in Path('/tmp/nvram-cache').read_text()
        print('PASS: vendor ping watchdog turned off in the RAM cache, with no commit.',flush=True)
        # CBRS gate. With the grant held the keeper opens it and leaves both
        # FORWARD chains without a drop rule.
        def chain(name):
            return Path('/tmp/'+name+'-forward').read_text().splitlines()
        def gate_rules():
            return [line for name in ('ebt','ip6') for line in chain(name) if 'lte0pdn+' in line]
        def set_grant(lines):
            kept=[line for line in Path('/tmp/nvram-cache').read_text().splitlines()
                  if not line.startswith(('cbrs_mode_grant=','cbrs_grant_state='))]
            Path('/tmp/nvram-cache.new').write_text('\n'.join(kept+lines)+'\n')
            Path('/tmp/nvram-cache.new').replace('/tmp/nvram-cache')
        wait_for(lambda:'CBRS gate open: SAS grant held' in log(),10)
        assert gate_rules()==[], gate_rules()
        # Transmit expiry with Witcher's Block Channel patch: the mode key stays
        # 1 and the grant state drops to 1. Customer IPv6 stops both ways,
        # bridged and routed, ahead of every other rule.
        set_grant(['cbrs_mode_grant=1','cbrs_grant_state=1'])
        lost=time.monotonic()
        wait_for(lambda:len(gate_rules())==4,10)
        took=time.monotonic()-lost
        assert took<3, took
        assert set(chain('ebt')[:2])=={'-p IPv6 -i lte0pdn+ -j DROP','-p IPv6 -o lte0pdn+ -j DROP'}, chain('ebt')
        assert set(chain('ip6')[:2])=={'-i lte0pdn+ -j DROP','-o lte0pdn+ -j DROP'}, chain('ip6')
        assert 'CBRS gate closed: no SAS grant (cbrs_mode_grant=1, cbrs_grant_state=1)' in log(), log()
        print('PASS: CBRS gate closed %.1f s after the grant state dropped: IPv6 drops in both chains, both ways.'%took,flush=True)
        # A vendor firewall restart flushes both tables and restores its own
        # IPv6 rule. The drops come back within seconds, ahead of it, and are
        # not added twice.
        Path('/tmp/ebt-forward').write_text('')
        Path('/tmp/ip6-forward').write_text('-m rt --rt-type 0 -j DROP\n')
        flushed=time.monotonic()
        wait_for(lambda:len(gate_rules())==4,10)
        took=time.monotonic()-flushed
        assert took<3, took
        assert chain('ip6')[-1]=='-m rt --rt-type 0 -j DROP', chain('ip6')
        wait_for(lambda:'CBRS gate rules put back' in log(),5)
        until=time.monotonic()+3
        wait_for(lambda:time.monotonic()>=until,5)
        assert len(gate_rules())==4, gate_rules()
        print('PASS: CBRS gate rules put back %.1f s after a vendor flush, once.'%took,flush=True)
        # The grant comes back: every drop goes, the vendor's rule stays.
        set_grant(['cbrs_mode_grant=1','cbrs_grant_state=2'])
        back=time.monotonic()
        wait_for(lambda:gate_rules()==[],10)
        took=time.monotonic()-back
        assert took<3, took
        assert chain('ip6')==['-m rt --rt-type 0 -j DROP'], chain('ip6')
        assert log().count('CBRS gate open: SAS grant held')==2, log()
        print('PASS: CBRS gate opened %.1f s after the grant came back; only its own rules removed.'%took,flush=True)
        # Grant keys missing (never set, or a torn read): closed, but only once
        # a read at least a second later agrees.
        set_grant([])
        gone=time.monotonic()
        wait_for(lambda:len(gate_rules())==4,10)
        took=time.monotonic()-gone
        assert 1<=took<5, took
        assert 'CBRS gate closed: no SAS grant (cbrs_mode_grant=unset, cbrs_grant_state=unset)' in log(), log()
        set_grant(['cbrs_mode_grant=1','cbrs_grant_state=2'])
        wait_for(lambda:gate_rules()==[],10)
        print('PASS: CBRS gate failed closed %.1f s after the grant keys went missing, and opened again.'%took,flush=True)
        # A child that hangs (v1.0.17): one ip6tables call stuck for an hour.
        # Up to v1.0.16 the keeper's loop waited on it, so the gate stayed open
        # with no grant, and the DHCP, ARP and deaf-watchdog work stopped with
        # it, until a reboot. Now the call is stopped after 10 s, the loop goes
        # on, and the gate closes.
        alive=lambda:Path('/tmp/runtime/alive').read_text() if Path('/tmp/runtime/alive').exists() else ''
        wait_for(lambda:alive()!='',15)
        beat=alive()
        Path('/tmp/hang-ip6tables').write_text('')
        set_grant(['cbrs_mode_grant=1','cbrs_grant_state=1'])
        lost=time.monotonic()
        wait_for(lambda:len(gate_rules())==4,30)
        took=time.monotonic()-lost
        assert not Path('/tmp/hang-ip6tables').exists(), 'the gate never ran ip6tables'
        assert 8<=took<25, took
        assert 'did not finish within 10 s; stopping it' in ram(), ram()
        assert alive()!=beat, 'the heartbeat stopped: '+alive()
        hung=[line for line in subprocess.check_output(['/tmp/bin/real-ps','-eo','pid,stat,args']).decode().splitlines() if 'sleep 3600' in line]
        assert not hung, ('the hung child was not stopped and reaped', hung)
        set_grant(['cbrs_mode_grant=1','cbrs_grant_state=2'])
        wait_for(lambda:gate_rules()==[],10)
        print('PASS: an ip6tables call that hung was stopped after 10 s; the loop and its heartbeat went on and the gate closed in %.1f s.'%took,flush=True)
        wait_for(lambda:'automatic recovery is armed' in log(),35)
        print('PASS: real ARP reply established the IPv4 baseline with IPv6 unset.',flush=True)
        # Steady-state packet socket audit: the keeper must never hold an
        # ETH_P_ALL (0003) tap, and /proc/net/ptype must carry no ALL handler
        # once the test's own capture socket is closed.
        keeper_inodes=set()
        for entry in Path(f'/proc/{keeper.pid}/fd').iterdir():
            try:
                target=os.readlink(entry)
            except OSError:
                continue
            if target.startswith('socket:[') and target.endswith(']'):
                keeper_inodes.add(target[8:-1])
        keeper_protos=set()
        packet_lines=Path('/proc/net/packet').read_text().splitlines()
        for row in packet_lines[1:]:
            cols=row.split()
            if len(cols)>=9 and cols[8] in keeper_inodes:
                keeper_protos.add(cols[3].lower())
        assert '0003' not in keeper_protos, ('keeper opened ETH_P_ALL', keeper_protos, packet_lines)
        assert {'0806', '0800'}.issubset(keeper_protos), ('expected ARP and IPv4 control sockets', keeper_protos, packet_lines)
        assert '86dd' not in keeper_protos, ('IPv6 control socket should stay closed when PD is off', keeper_protos, packet_lines)
        capture.close()
        ptype_lines=Path('/proc/net/ptype').read_text().splitlines()
        all_ptypes=[line for line in ptype_lines[1:] if line.split() and line.split()[0]=='ALL']
        assert not all_ptypes, ('unexpected ETH_P_ALL handler in /proc/net/ptype', ptype_lines)
        ns_all=[row for row in Path('/proc/net/packet').read_text().splitlines()[1:] if len(row.split())>=4 and row.split()[3].lower()=='0003']
        assert not ns_all, ('unexpected ETH_P_ALL socket in /proc/net/packet', ns_all)
        capture=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3));capture.bind(('eth0',0));capture.setblocking(False)
        print('PASS: steady state holds protocol-specific control sockets only (no ETH_P_ALL in /proc/net/packet or /proc/net/ptype).',flush=True)
        # The vendor Wi-Fi DHCP server writes its empty list over the shared
        # lease file every 30 s. A gap longer than the keeper's 8 s hold must
        # not start the IPv4 check over, or log a new arming.
        armed_lines=ram().count('automatic recovery is armed')
        lease_state['empty']=True
        lease()
        until=time.monotonic()+12
        wait_for(lambda:time.monotonic()>=until,15)
        lease_state['empty']=False
        until=time.monotonic()+15
        wait_for(lambda:time.monotonic()>=until,20)
        assert ram().count('automatic recovery is armed')==armed_lines, ram()
        assert log().count('automatic recovery is armed')==1, log()
        assert 'repairing DHCP first' not in log()
        print('PASS: a 12 s gap in the lease file kept the IPv4 baseline and logged no new arming.',flush=True)
        # The deaf watchdog arms on the first answer, then the target goes quiet
        # while the modem stays attached. The reboot is checked at the end.
        wait_for(lambda:'deaf watchdog armed' in log(),45)
        assert not Path('/tmp/reboot-actions').exists()
        Path('/tmp/ping-ok').unlink()
        silent_from=time.monotonic()
        print('PASS: deaf watchdog armed only after a target answered.',flush=True)
        # The LTE driver sends the router's IPv6 to the unit after the unit's
        # own ARP, and the unit forwards it. It never forwards IPv6 in
        # passthrough, so a rise is the symptom. The keeper sends the router's
        # own ARP request out the bearer.
        # Outgoing frames reach only all-protocol packet sockets.
        bearer_cap=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3));bearer_cap.bind(('lte0pdn1',0));bearer_cap.setblocking(False)
        bearer_frames=[]
        def bearer_arp():
            try:
                while True:
                    frame=bearer_cap.recv(2048)
                    if frame[12:14]==b'\x08\x06': bearer_frames.append(frame[:42])
            except BlockingIOError: pass
            return bearer_frames
        correction=b'\xff'*6+peer_mac+bytes.fromhex('08060001080006040001')+peer_mac+bytes([172,20,64,152])+bytes(6)+bytes([172,20,64,151])
        run(ip, 'link', 'set', 'lte0pdn1', 'master', 'br0')
        until=time.monotonic()+6
        wait_for(lambda:time.monotonic()>=until,10)
        assert correction not in bearer_arp(), 'corrected with no forwarding'
        assert 'wrong downlink MAC' not in log()
        Path('/tmp/snmp6').write_text('Ip6InReceives 9\nIp6OutForwDatagrams 12\n')
        wait_for(lambda:correction in bearer_arp() and 'wrong downlink MAC' in log(),10)
        sent=bearer_arp().count(correction)
        until=time.monotonic()+4
        wait_for(lambda:time.monotonic()>=until,8)
        assert bearer_arp().count(correction)==sent, 'corrected again with no new forwarding'
        run(ip, 'link', 'set', 'lte0pdn1', 'nomaster')
        print('PASS: forwarded IPv6 in passthrough sent the router\'s ARP out the bearer once, and nothing more while quiet.',flush=True)
        if mgmt_ready:
            # One advertisement was taken. The keeper closes the bearer to more
            # and takes the expiry off the learned default.
            wait_for(lambda:accept_ra()=='0' and 'expires' not in mgmt_routes(),40)
            assert 'closing lte0pdn0 to further router advertisements' in log()
            assert any('default via fe80::1' in line and 'metric 1024' in line for line in mgmt_routes().splitlines()), mgmt_routes()
            print('PASS: management bearer closed to further advertisements; learned default kept without its expiry.',flush=True)
            # Global lost (a re-attach, or the vendor lifetime timer): the bearer
            # is opened again so the vendor stack can form the address.
            run(ip, '-6', 'addr', 'del', mgmt_global+'/64', 'dev', 'lte0pdn0')
            wait_for(lambda:accept_ra()=='2' and 'ue-mgmt has no global' in log(),40)
            # The permanent default is removed first. With it in place the
            # vendor kernel rejects every advertisement.
            wait_for(lambda:not any('default via fe80::1' in line and 'metric 1024' in line for line in mgmt_routes().splitlines()),20)
            assert 'removing the permanent default' in log()
            run(ip, '-6', 'addr', 'add', mgmt_global+'/64', 'dev', 'lte0pdn0', 'nodad')
            wait_for(lambda:accept_ra()=='0',40)
            print('PASS: lost management global reopened the bearer; it closed again once the address was back.',flush=True)
            # The vendor kernel leaves the management bearer as its external
            # device. In passthrough the guard clears it and restores the MAC.
            mac_before=Path('/sys/class/net/lte0pdn0/address').read_text()
            with open('/tmp/kmsg','a') as kmsg:
                kmsg.write('6,100,1,-;set external_dev: lte0pdn0 ipv6 mask=50\n')
            guard='external device guard: the vendor kernel left lte0pdn0'
            # Until the customer bearer is a port of the bridge, the vendor's
            # own bearer setup is still running and the guard waits.
            until=time.monotonic()+8
            wait_for(lambda:time.monotonic()>=until,12)
            assert guard not in log(), log()
            assert not Path('/tmp/extdev-actions').exists()
            run(ip, 'link', 'set', 'lte0pdn1', 'master', 'br0')
            wait_for(lambda:guard in log() and Path('/tmp/extdev-actions').exists() and 'kern netif extdev lte0pdn0 down' in Path('/tmp/extdev-actions').read_text(),20)
            assert Path('/sys/class/net/lte0pdn0/address').read_text()==mac_before
            until=time.monotonic()+15
            wait_for(lambda:time.monotonic()>=until,20)
            assert log().count(guard)==1, log()
            # A bearer setup that clears it by itself is left alone.
            with open('/tmp/kmsg','a') as kmsg:
                kmsg.write('6,101,3,-;set external_dev: lte0pdn0 ipv4 mask=50\n4,102,3,-;external_dev=NULL\n')
            until=time.monotonic()+6
            wait_for(lambda:time.monotonic()>=until,10)
            assert log().count(guard)==1, log()
            run(ip, 'link', 'set', 'lte0pdn1', 'nomaster')
            print('PASS: external device guard waited for the bridge, cleared the management bearer once, and left alone a setup that clears it itself.',flush=True)
        assert not Path('/tmp/phy-actions').exists()
        # The vendor rule is present, so the keeper leaves the nat table alone.
        assert not Path('/tmp/sas-actions').exists(), Path('/tmp/sas-actions').read_text()
        # A vendor firewall restart that logs nothing the keeper reads flushes
        # it. The first missed check starts one-second checks, so it is back
        # within one normal check plus two seconds, in rcinit's order, and
        # nothing more runs once it is back.
        Path('/tmp/nat-rules').write_text('')
        flushed=time.monotonic()
        restored=['kern natq act 0','iptables -t nat -I POSTROUTING -s 10.1.1.1 -j SNAT --to-source 172.20.64.152']
        wait_for(lambda:Path('/tmp/sas-actions').exists() and len(Path('/tmp/sas-actions').read_text().splitlines())>=2,40)
        took=time.monotonic()-flushed
        assert Path('/tmp/sas-actions').read_text().splitlines()==restored, Path('/tmp/sas-actions').read_text()
        assert took<15, took
        assert 'SAS NAT rule restored' in log()
        assert 'not in the table when read back' not in log(), log()
        # Long enough for the one-second checks to end.
        until=time.monotonic()+32
        wait_for(lambda:time.monotonic()>=until,37)
        assert Path('/tmp/sas-actions').read_text().splitlines()==restored, Path('/tmp/sas-actions').read_text()
        assert not Path('/tmp/phy-actions').exists()
        print('PASS: flushed SAS SNAT rule restored once in %.1f s, with natq bridge mode first, and left alone after.'%took,flush=True)
        # An in-connection carrier change: rcinit logs it, then rebuilds its
        # firewall. No PDN goes down. The log line starts one-second checks.
        with open('/tmp/rcinit.log','a') as rcinit:
            rcinit.write(' 4:58:41 >|service.c             500 >|   info >| CBRS LTE Freq changed !\n')
        until=time.monotonic()+1.5
        wait_for(lambda:time.monotonic()>=until,4)
        Path('/tmp/nat-rules').write_text('')
        flushed=time.monotonic()
        wait_for(lambda:len(Path('/tmp/sas-actions').read_text().splitlines())>=4,10)
        took=time.monotonic()-flushed
        assert Path('/tmp/sas-actions').read_text().splitlines()==restored*2, Path('/tmp/sas-actions').read_text()
        assert took<6, took
        print('PASS: after rcinit logged a carrier change, a flushed SAS SNAT rule was restored in %.1f s.'%took,flush=True)
        until=time.monotonic()+31
        wait_for(lambda:time.monotonic()>=until,36)
        assert Path('/tmp/sas-actions').read_text().splitlines()==restored*2, Path('/tmp/sas-actions').read_text()
        # A PDN coming up starts 30 s of checks every second. A flush right
        # after it is restored within seconds. The last restore was under a
        # minute ago, but it was seen in the table, so it does not hold this one.
        with open('/tmp/kmsg','a') as kmsg:
            kmsg.write('6,103,4,-;LTE: set apn type lte0pdn1(0x1) eps_id=6 192.0.2.7 2001:db8::7\n')
        until=time.monotonic()+2
        wait_for(lambda:time.monotonic()>=until,4)
        Path('/tmp/nat-rules').write_text('')
        flushed=time.monotonic()
        wait_for(lambda:len(Path('/tmp/sas-actions').read_text().splitlines())>=6,10)
        took=time.monotonic()-flushed
        assert Path('/tmp/sas-actions').read_text().splitlines()==restored*3, Path('/tmp/sas-actions').read_text()
        assert took<6, took
        assert 'SAS NAT rule missing for 2 s in a row' in log(), log()
        until=time.monotonic()+5
        wait_for(lambda:time.monotonic()>=until,8)
        assert Path('/tmp/sas-actions').read_text().splitlines()==restored*3, Path('/tmp/sas-actions').read_text()
        print('PASS: after a PDN came up, a flushed SAS SNAT rule was restored in %.1f s.'%took,flush=True)
        if time.monotonic()-silent_from<110:
            assert not Path('/tmp/reboot-actions').exists(), 'the deaf watchdog fired before its wait'
            print('PASS: deaf watchdog held through the first %d s of silence.'%(time.monotonic()-silent_from),flush=True)
        # A missing DHCP process is restored without bouncing the port.
        server.terminate();server.wait(timeout=3)
        wait_for(lambda:Path('/tmp/dhcp-starts').read_text().count('start')>=2,20)
        assert not Path('/tmp/phy-actions').exists()
        print('PASS: missing DHCP daemon recovered without Ethernet renegotiation.',flush=True)
        # An LTE outage must not become a downstream-router fault.
        before=ram().count('automatic recovery is armed')
        run(ip, 'link', 'set', 'lte0pdn1', 'down')
        run(ip, 'netns', 'exec', 'witcher-peer', '/bin/sh', '-c', 'echo 8 > /proc/sys/net/ipv4/conf/router0/arp_ignore')
        until=time.monotonic()+35
        wait_for(lambda:time.monotonic()>=until,40)
        assert not Path('/tmp/phy-actions').exists()
        assert 'repairing DHCP first' not in log()
        run(ip, 'netns', 'exec', 'witcher-peer', '/bin/sh', '-c', 'echo 0 > /proc/sys/net/ipv4/conf/router0/arp_ignore')
        run(ip, 'link', 'set', 'lte0pdn1', 'up')
        wait_for(lambda:ram().count('automatic recovery is armed')>before,20)
        # Arming the same router again is routine: RAM log only.
        assert log().count('automatic recovery is armed')==1, log()
        print('PASS: LTE outage inhibited downstream recovery; return required a new ARP baseline, logged in RAM only.',flush=True)
        # Keep Ethernet carrier and LTE up; suppress only the router's replies.
        run(ip, 'netns', 'exec', 'witcher-peer', '/bin/sh', '-c', 'echo 8 > /proc/sys/net/ipv4/conf/router0/arp_ignore')
        wait_for(lambda:'repairing DHCP first' in log(),45)
        assert not Path('/tmp/phy-actions').exists()
        print('PASS: repeated ARP failure caused DHCP repair before a PHY action.',flush=True)
        wait_for(lambda:Path('/tmp/phy-actions').exists(),45)
        assert Path('/tmp/phy-actions').read_text().splitlines()==['-r eth0']
        assert 'link_drops=1' in Path('/tmp/pd/budget.txt').read_text()
        print('PASS: one recorded PHY renegotiation and persisted shared budget after continued failure.',flush=True)
        # The target has been silent since `silent_from` with the modem attached.
        wait_for(lambda:Path('/tmp/reboot-actions').exists(),200)
        waited=time.monotonic()-silent_from
        assert waited>=115, waited
        assert Path('/tmp/reboot-actions').read_text().splitlines()[0]=='reboot ', Path('/tmp/reboot-actions').read_text()
        assert 'rebooting (reboot 1 in a row)' in log()
        # Through the keeper's reboot gate: counted against its daily cap.
        assert Path('/tmp/pd/keeper-reboots').read_text().split()[1:]==['deaf'], Path('/tmp/pd/keeper-reboots').read_text()
        assert Path('/tmp/pd/watchdog-strikes.txt').read_text()=='strikes=1\n'
        print('PASS: deaf watchdog rebooted once after %d s of silence while attached.'%waited,flush=True)
        # Minutes of watchdog rounds later, the vendor flag was written once.
        assert nvram_actions()==['set 0 detection_enable 0'], nvram_actions()
        assert log().count('vendor ping watchdog')==1, log()
        print('PASS: the vendor ping watchdog check is a no-op once the flag is 0.',flush=True)
        # Every flash line is in the RAM log too, and the RAM status copy is live.
        ram_log=''.join(p.read_text() for p in (Path('/tmp/runtime/keeper.log.1'),Path('/tmp/runtime/keeper.log')) if p.exists())
        for line in log().splitlines():
            assert line in ram_log, line
        ram_status=json.loads(Path('/tmp/runtime/status.json').read_text())
        flash_status=json.loads(Path('/tmp/pd/status.json').read_text())
        assert set(ram_status)==set(flash_status), (ram_status, flash_status)
        assert 'periodic router advertisement' not in log()
        print('PASS: the RAM log holds every flash line; status.json has a live RAM copy.',flush=True)
        assert 'tk boot' not in log(), 'the boot confirm armed without a staged image'
        print('PASS: no staged modem firmware: the boot confirm never armed.',flush=True)
        assert not Path('/tmp/dm-log').exists(), 'a modem console session ran on a stock boot'
        assert Path('/tmp/tk.flags').read_text().startswith('state=off\n'), Path('/tmp/tk.flags').read_text()
        assert 'tk flags' not in log() and 'carrier watch' not in log() and 'latency switches' not in log(), log()
        # On by default since v1.0.17: with no config of their own the clamp
        # wants mode 3 and the fast path mode 2. The fast path waits for its
        # bridge. The clamp's links are up, but this fixture has no image
        # copies yet, so its load fails without running insmod.
        q_text=Path('/tmp/qctrl.status').read_text()
        assert q_text.split('\n')[0] in ('state=waiting', 'state=failed') and 'mode=3\n' in q_text, q_text
        f_text=Path('/tmp/fastpath.status').read_text()
        assert f_text.startswith('state=waiting\n') and 'mode=2\n' in f_text, f_text
        assert not Path('/tmp/insmod-calls').exists(), Path('/tmp/insmod-calls').read_text()
        print('PASS: stock boot: no modem console session or flags; the clamp and the fast path are on by default.',flush=True)
        # A staged modem firmware image whose boot never answers. Nothing has
        # answered since `silent_from`; the deaf watchdog of a new keeper
        # process cannot arm, so any reboot now is the boot confirm's. The
        # modem stays attached (a cell in view), so the confirm's clock runs;
        # this harness sets it to 20 s (TITAN_TK_CONFIRM_SECS).
        def restart(extra=None):
            nonlocal keeper
            keeper.terminate();keeper.wait(timeout=5)
            Path('/tmp/reboot-actions').unlink(missing_ok=True)
            # A new boot: nothing has answered through the core yet.
            Path('/tmp/runtime/heard-through-core').unlink(missing_ok=True)
            keeper=subprocess.Popen([str(BINARY),'run'],env=dict(env,**(extra or {})),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        def uptime():
            return int(float(Path('/proc/uptime').read_text().split()[0]))
        def strikes(n):
            return 'strikes=%d\nfirmware=unknown\n'%n
        def reboots():
            p=Path('/tmp/pd/keeper-reboots')
            return [line.split()[1] for line in p.read_text().splitlines()] if p.exists() else []
        def fresh_budget():
            Path('/tmp/pd/keeper-reboots').unlink(missing_ok=True)
        def quiet(seconds):
            until=time.monotonic()+seconds
            wait_for(lambda:time.monotonic()>=until or Path('/tmp/reboot-actions').exists(),seconds+5)
            assert not Path('/tmp/reboot-actions').exists(), 'rebooted while it should wait'
        bad='a'*64
        Path('/tmp/tk').mkdir()
        Path('/tmp/tk/strikes').write_text('strikes=1\n')
        Path('/tmp/tk/config').write_text('enabled=1\nsha256='+bad+'\ntarget=192.0.2.9\n')
        Path('/tmp/tk.status').write_text('state=staged\nsha256=%s\nstrikes=1\nloaded_at=%d\nsource=fs\nfirmware=clean\n'%(bad,uptime()))
        fresh_budget()
        restart()
        wait_for(lambda:Path('/tmp/reboot-actions').exists(),90)
        assert Path('/tmp/reboot-actions').read_text().splitlines()[0]=='reboot ', Path('/tmp/reboot-actions').read_text()
        assert Path('/tmp/tk/quarantine').read_text()==bad+'\n'
        assert Path('/tmp/tk/strikes').read_text()==strikes(2), Path('/tmp/tk/strikes').read_text()
        assert Path('/tmp/tk.result').read_text()=='rollback='+bad+'\n'
        assert 'a cell in view for 20 s without a management answer' in log() and 'quarantined it, rebooting onto stock modem firmware' in log(), log()
        assert any('192.0.2.9' in call for call in Path('/tmp/ping-calls').read_text().splitlines())
        assert reboots()==['away'], reboots()
        print('PASS: a staged boot with a cell in view and no answer for 20 s quarantined its image and asked for one reboot, through the reboot gate.',flush=True)
        # The same failure while the SAS CPAS window is open (here a window
        # around now): the comparison waits and records nothing, so an answer
        # meanwhile would still confirm the image.
        Path('/tmp/tk.result').unlink()
        Path('/tmp/tk/quarantine').unlink()
        Path('/tmp/tk/strikes').write_text('strikes=1\n')
        fresh_budget()
        minute=time.gmtime().tm_hour*60+time.gmtime().tm_min
        window='%02d:%02d-%02d:%02d'%(((minute-60)%1440)//60,(minute-60)%60,((minute+60)%1440)//60,(minute+60)%60)
        before=len(log())
        restart({'TITAN_TK_QUIET_UTC':window})
        wait_for(lambda:'the comparison with stock modem firmware waits: the SAS CPAS window is open' in log()[before:],90)
        quiet(8)
        assert not Path('/tmp/tk/quarantine').exists() and Path('/tmp/tk/strikes').read_text()=='strikes=1\n'
        assert not Path('/tmp/tk.result').exists() and reboots()==[]
        # Once the window is over (a keeper without it), it goes ahead.
        before=len(log())
        restart()
        wait_for(lambda:Path('/tmp/reboot-actions').exists(),90)
        assert 'quarantined it, rebooting onto stock modem firmware' in log()[before:], log()[before:]
        assert Path('/tmp/tk/quarantine').read_text()==bad+'\n'
        print('PASS: a comparison due inside the CPAS window waited and recorded nothing, and went ahead outside it.',flush=True)
        assert not Path('/tmp/dm-log').exists(), 'a modem console session ran before any boot confirm'
        # The default image (v1.0.17): no network condition may keep a unit
        # off it. The keeper reads the modem's view from the vendor cache:
        # attached with a measured RSRP, or searching. A DNS stand-in answers
        # questions to the bearer's DNS server (192.0.2.53) while /tmp/dns-ok
        # exists; the ping stand-in answers while /tmp/ping-ok exists.
        image='d'*64
        # No wm= lines: a confirmed boot here starts no modem console session.
        body='# built at boot\nenabled=1\nsha256=%s\n'%image
        operator_config=Path('/tmp/tk/config').read_text()
        Path('/tmp/tk/config').write_text('# witcher-default n6h-r4-r1 %s\n%s'%(hashlib.sha256(body.encode()).hexdigest(),body))
        run(ip,'addr','add','192.0.2.53/32','dev','lo')
        dns_sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        dns_sock.bind(('192.0.2.53',53))
        def dns_loop():
            while True:
                data,peer=dns_sock.recvfrom(512)
                if Path('/tmp/dns-ok').exists() and len(data)>=12:
                    dns_sock.sendto(data[:2]+bytes([data[2]|0x80])+data[3:],peer)
        threading.Thread(target=dns_loop,daemon=True).start()
        radio_lock=threading.Lock()
        def radio(cell):
            with radio_lock:
                kept=[line for line in Path('/tmp/nvram-cache').read_text().splitlines()
                      if not line.startswith(('sqns_connection_mediaState=','sqns_radio_RSRP='))]
                lines=['sqns_connection_mediaState=ATTACHED','sqns_radio_RSRP=-10790'] if cell else ['sqns_connection_mediaState=DISCONNECTED','sqns_radio_RSRP=']
                Path('/tmp/nvram-cache.radio').write_text('\n'.join(kept+lines)+'\n')
                Path('/tmp/nvram-cache.radio').replace('/tmp/nvram-cache')
        def core(up):
            # The management address on lte0pdn0: the bearer is up.
            have='10.200.1.2/30' in subprocess.check_output([ip,'addr','show','dev','lte0pdn0'],text=True)
            if up and not have: run(ip,'addr','add','10.200.1.2/30','dev','lte0pdn0')
            if not up and have: run(ip,'addr','del','10.200.1.2/30','dev','lte0pdn0')
        def answers(ping=False,dns=False):
            for name,on in (('/tmp/ping-ok',ping),('/tmp/dns-ok',dns)):
                if on: Path(name).write_text('')
                else: Path(name).unlink(missing_ok=True)
        def verdict():
            p=Path('/tmp/tk/verdict')
            return dict(l.split('=',1) for l in p.read_text().splitlines()) if p.exists() else {}
        def record(genuine,network,pending,outage,crashes=0,crash=0):
            return {'gzip':image,'firmware':'unknown','genuine':str(genuine),'network':str(network),'pending':str(pending),
                    'outage':str(outage),'crashes':str(crashes),'crash':str(crash)}
        def quarantined():
            p=Path('/tmp/tk/quarantine')
            return p.exists() and image in p.read_text()
        def image_boot():
            Path('/tmp/tk/strikes').write_text(strikes(1))
            Path('/tmp/tk.result').unlink(missing_ok=True)
            Path('/tmp/tk.status').write_text('state=staged\nsha256=%s\nstrikes=1\nloaded_at=%d\nsource=fs\nfirmware=clean\n'%(image,uptime()))
            before=len(log())
            restart()
            return before
        def stock_boot():
            Path('/tmp/tk.result').unlink(missing_ok=True)
            Path('/tmp/tk.status').write_text('state=stock\nreason=strikes\nloaded_at=%d\nsource=nand\nfirmware=clean\n'%max(0,uptime()-400))
            before=len(log())
            restart()
            return before
        # The tower is down at the moment of upgrade, for longer than every
        # limit here (the scaled two hours): the image waits while it sees no
        # cell, makes one comparison after 45 s of searching
        # (TITAN_TK_SEARCH_SECS), stock firmware finds no network either, and
        # the unit goes straight back onto the image, which then waits for the
        # tower with no second cycle and confirms once service returns.
        fresh_budget();radio(False);core(False);answers()
        before=image_boot()
        quiet(30)
        assert 'time with no cell is waiting, not failure' in log()[before:], log()[before:]
        wait_for(lambda:Path('/tmp/reboot-actions').exists(),60)
        assert 'no cell in view for 45 s in a row' in log()[before:] and 'quarantined it for now' in log()[before:], log()[before:]
        assert quarantined() and Path('/tmp/tk/strikes').read_text()==strikes(2) and verdict()['pending']=='1', verdict()
        before=stock_boot()
        wait_for(lambda:'rebooting back onto modem firmware' in log()[before:],60)
        assert 'was the network' in log()[before:], log()[before:]
        assert not quarantined() and bad in Path('/tmp/tk/quarantine').read_text()
        assert Path('/tmp/tk/strikes').read_text()==strikes(0)
        assert verdict()==record(0,1,0,1), verdict()
        before=image_boot()
        quiet(60)
        assert 'waits for the network' in log()[before:], log()[before:]
        radio(True);core(True);answers(ping=True)
        wait_for(lambda:'tk boot confirmed:' in log()[before:],30)
        answers()
        assert verdict()==record(0,1,0,0), verdict()
        assert not quarantined() and Path('/tmp/tk/strikes').read_text()==strikes(0)
        assert reboots()==['away','back'], reboots()
        print('PASS: tower down at the upgrade: one comparison, straight back onto the image, no second cycle while the tower stayed down, and confirmed as soon as service returned.',flush=True)
        # Power flapping at boot: two image boots ended before their confirm
        # decided (strikes at 2, no rollback recorded). The stock boot records
        # them as one rollback; here stock gets no answer either, so straight
        # back onto the image.
        radio(False);core(False);answers()
        Path('/tmp/tk/strikes').write_text(strikes(2))
        before=stock_boot()
        wait_for(lambda:'rebooting back onto modem firmware' in log()[before:],60)
        assert 'ended before their boot confirm decided' in log()[before:] and 'was the network' in log()[before:], log()[before:]
        assert not quarantined() and Path('/tmp/tk/strikes').read_text()==strikes(0)
        assert verdict()==record(0,2,0,1), verdict()
        print('PASS: two image boots cut short before their confirm were judged on the stock boot, and the unit went straight back onto the image.',flush=True)
        # A flapping tower: the cell comes and goes every 3 s and nothing ever
        # answers. Only the time with the cell counts; one comparison, one
        # way back, then the image waits without another reboot.
        fresh_budget();core(True);answers()
        Path('/tmp/tk/verdict').unlink()
        flapping=threading.Event();flapping.set()
        def flap():
            # Uneven steps, so the probe rounds do not see one phase only.
            up,step=False,0
            while flapping.is_set():
                up=not up;radio(up);time.sleep((2.5,4,3.5,2,3)[step%5]);step+=1
        flapper=threading.Thread(target=flap,daemon=True);flapper.start()
        before=image_boot()
        wait_for(lambda:Path('/tmp/reboot-actions').exists(),150)
        assert 'quarantined it for now' in log()[before:], log()[before:]
        before=stock_boot()
        wait_for(lambda:'rebooting back onto modem firmware' in log()[before:],60)
        before=image_boot()
        quiet(90)
        flapping.clear();flapper.join(timeout=10)
        assert reboots()==['away','back'], reboots()
        assert not quarantined() and verdict()['outage']=='1', verdict()
        radio(True);answers(ping=True)
        wait_for(lambda:'tk boot confirmed:' in log()[before:],30)
        answers()
        print('PASS: a flapping tower cost one comparison and one way back; then the image waited with no further reboot and confirmed once the tower settled.',flush=True)
        # Core up, ping unanswered: a carrier DNS server that ignores ping
        # still answers DNS, and that answer confirms the image.
        fresh_budget();radio(True);core(True);answers(dns=True)
        before=image_boot()
        wait_for(lambda:'tk boot confirmed:' in log()[before:],30)
        answers()
        quiet(3)
        assert reboots()==[] and not quarantined()
        print('PASS: core up with ping unanswered: a DNS answer through the core confirmed the image, with no comparison.',flush=True)
        # Stock answers where the image did not: failure 1 of 2, and with the
        # network known to be up, straight back onto the image. A tower that
        # was only late (a site power cut): the retry confirms and the failure
        # is forgotten.
        fresh_budget();radio(True);core(True);answers()
        Path('/tmp/tk/verdict').unlink(missing_ok=True)
        before=image_boot()
        wait_for(lambda:Path('/tmp/reboot-actions').exists(),60)
        answers(ping=True)
        before=stock_boot()
        wait_for(lambda:'rebooting back onto modem firmware' in log()[before:],60)
        assert 'failure 1 of 2' in log()[before:] and 'tries it again at once' in log()[before:], log()[before:]
        assert verdict()==record(1,0,0,0), verdict()
        before=image_boot()
        wait_for(lambda:'tk boot confirmed:' in log()[before:],30)
        answers()
        assert verdict()==record(0,0,0,0), verdict()
        assert reboots()==['away','back'], reboots()
        print('PASS: stock answered after a comparison; the unit went straight back onto the image, and the confirmed retry cleared the failure.',flush=True)
        # A genuinely bad image: its boots never answer and stock's do. Failure
        # 1 goes straight back onto the image, failure 2 in a row sticks, with
        # no further reboot.
        fresh_budget()
        for failure,expect in ((1,'rebooting back onto modem firmware'),(2,'it stays quarantined until Retry')):
            answers()
            before=image_boot()
            wait_for(lambda:Path('/tmp/reboot-actions').exists(),60)
            answers(ping=True)
            before=stock_boot()
            wait_for(lambda:expect in log()[before:],60)
            assert 'failure %d of 2'%failure in log()[before:], log()[before:]
        quiet(5)
        answers()
        assert 'it stays quarantined until Retry' in log()[before:], log()[before:]
        assert quarantined() and verdict()==record(2,0,0,0), verdict()
        assert reboots()==['away','back','away'], reboots()
        print('PASS: a genuinely bad image went straight back once after stock answered, and its quarantine stuck at the second failure in a row.',flush=True)
        # A modem crash while the default image runs reloads stock firmware
        # from NAND. Inside the confirm it must never confirm the image when
        # stock answers afterwards: it is judged like a rollback, on the same
        # boot, and the unit goes straight back onto the image. A confirm does
        # not clear the crash count, so the next crash in a row sticks.
        fresh_budget();radio(True);core(True);answers()
        Path('/tmp/tk/verdict').unlink(missing_ok=True)
        Path('/tmp/tk/quarantine').write_text(bad+'\n')
        before=image_boot()
        wait_for(lambda:'time with no cell is waiting' in log()[before:],30)
        with open('/tmp/kmsg','a') as kmsg: kmsg.write('6,950,1,-;read from nand mtd=tk0\n')
        wait_for(lambda:'crashed and the modem reloaded stock firmware' in log()[before:],30)
        assert quarantined() and verdict()['crash']=='1' and verdict()['pending']=='1', verdict()
        answers(ping=True)
        wait_for(lambda:'rebooting back onto modem firmware' in log()[before:],60)
        assert 'tk boot confirmed' not in log()[before:], 'the image confirmed after its modem crash'
        assert 'crash 1 of 2' in log()[before:], log()[before:]
        assert verdict()['crashes']=='1' and verdict()['genuine']=='0' and not quarantined(), verdict()
        before=image_boot()
        wait_for(lambda:'tk boot confirmed:' in log()[before:],30)
        answers()
        assert verdict()['crashes']=='1', verdict()
        with open('/tmp/kmsg','a') as kmsg: kmsg.write('6,951,1,-;read from nand mtd=tk0\n')
        wait_for(lambda:'crashed and the modem reloaded stock firmware' in log()[before:],30)
        answers(ping=True)
        wait_for(lambda:'crash 2 of 2 in a row' in log()[before:],60)
        quiet(5)
        answers()
        assert quarantined() and verdict()['crashes']=='2', verdict()
        assert reboots()==['back'], reboots()
        print('PASS: a modem crash inside the confirm was judged, not confirmed, and the unit went straight back onto the image; a second crash after a confirm stuck.',flush=True)
        # The radio guard cycles the radio on purpose: the confirm's clocks
        # stop meanwhile, as the deaf watchdog's do.
        fresh_budget();radio(True);core(True);answers()
        Path('/tmp/tk/verdict').unlink()
        Path('/tmp/tk/quarantine').write_text(bad+'\n')
        Path('/tmp/titan-pd-keeper').mkdir(exist_ok=True)
        Path('/tmp/titan-pd-keeper/radio-transition').write_text(str(int(time.monotonic())+150))
        before=image_boot()
        quiet(45)
        Path('/tmp/titan-pd-keeper/radio-transition').unlink()
        wait_for(lambda:Path('/tmp/reboot-actions').exists(),60)
        assert 'a cell in view for 20 s without a management answer' in log()[before:], log()[before:]
        print('PASS: a radio cycle of the radio guard paused the confirm; the comparison came only after it.',flush=True)
        # A strikes file that cannot be read keeps the hook on stock modem
        # firmware. The stock boot's keeper counts it as the limit, judges it,
        # repairs it, and the unit goes back onto the image.
        fresh_budget();radio(False);core(False);answers()
        Path('/tmp/tk/verdict').unlink(missing_ok=True)
        Path('/tmp/tk/quarantine').write_text(bad+'\n')
        Path('/tmp/tk/strikes').write_text('strikes=lots\n')
        before=stock_boot()
        wait_for(lambda:'rebooting back onto modem firmware' in log()[before:],60)
        assert 'ended before their boot confirm decided' in log()[before:], log()[before:]
        assert Path('/tmp/tk/strikes').read_text()==strikes(0)
        print('PASS: an unreadable strikes file was judged on the stock boot, repaired, and the unit went back onto the image.',flush=True)
        # The keeper's daily cap: with three reboots in the last day, a
        # comparison (which needs a second slot for the way back) waits on the
        # image and records nothing.
        Path('/tmp/tk/verdict').unlink()
        Path('/tmp/tk/quarantine').write_text(bad+'\n')
        Path('/tmp/pd/keeper-reboots').write_text(''.join('%d deaf\n'%(int(time.time())-60) for _ in range(3)))
        before=image_boot()
        wait_for(lambda:'reach its cap of 4' in log()[before:],60)
        quiet(5)
        assert not quarantined() and Path('/tmp/tk/strikes').read_text()==strikes(1)
        print('PASS: at the keeper\'s daily cap a comparison waited on the image and recorded nothing.',flush=True)
        core(False);answers()
        with radio_lock:
            kept=[line for line in Path('/tmp/nvram-cache').read_text().splitlines()
                  if not line.startswith(('sqns_connection_mediaState=','sqns_radio_RSRP='))]
            Path('/tmp/nvram-cache.radio').write_text('\n'.join(kept)+'\n')
            Path('/tmp/nvram-cache.radio').replace('/tmp/nvram-cache')
        assert not Path('/tmp/dm-log').exists(), 'a confirmed boot with no wm= lines started a modem console session'
        # The operator image and its quarantine again, for the sections below.
        Path('/tmp/tk/config').write_text(operator_config)
        Path('/tmp/tk/quarantine').write_text(bad+'\n')
        fresh_budget()
        # A staged image whose boot answers through the core.
        good='b'*64
        Path('/tmp/tk.result').unlink(missing_ok=True)
        Path('/tmp/tk/config').write_text('enabled=1\nsha256='+good+'\nwm=0x847ed604:0x15\nwm=0x84f93008:0x140\nwm=0x847ed608:0x1\n')
        # A staged clamp and fast path whose bytes are not the pinned modules.
        Path('/tmp/qctrl').mkdir()
        Path('/tmp/qctrl/config').write_text('mode=2\n')
        Path('/tmp/qctrl/titan_qctrl.ko').write_bytes(b'not the pinned module\n')
        Path('/tmp/fastpath').mkdir()
        Path('/tmp/fastpath/config').write_text('mode=2\n')
        Path('/tmp/fastpath/titan_k1fp.ko').write_bytes(b'not the pinned fast path\n')
        Path('/tmp/proc-modules').write_text('')
        Path('/tmp/tk/strikes').write_text('strikes=1\n')
        Path('/tmp/ping-ok').write_text('')
        if not Path('/sys/class/net/lte0pdn0').exists():
            run(ip,'link','add','lte0pdn0','type','dummy');run(ip,'link','set','lte0pdn0','up')
        run(ip,'addr','add','10.200.0.2/30','dev','lte0pdn0')
        if not Path('/sys/class/net/lte0pdn2').exists():
            run(ip,'link','add','lte0pdn2','type','dummy')
            run(ip,'link','set','lte0pdn2','master','br0')
            run(ip,'link','set','lte0pdn2','up')
        Path('/tmp/tk.status').write_text('state=staged\nsha256=%s\nstrikes=1\nloaded_at=%d\nsource=fs\nfirmware=clean\n'%(good,uptime()))
        # Only this keeper's lines: the verdict cases above confirmed a boot too.
        before_good=len(log())
        restart()
        wait_for(lambda:'tk boot confirmed' in log()[before_good:],45)
        assert Path('/tmp/tk/strikes').read_text()==strikes(0), Path('/tmp/tk/strikes').read_text()
        assert Path('/tmp/tk/confirmed').read_text()=='sha256='+good+'\n'
        assert Path('/tmp/tk.result').read_text()=='confirmed='+good+'\n'
        assert Path('/tmp/tk/quarantine').read_text()==bad+'\n'
        until=time.monotonic()+3
        wait_for(lambda:time.monotonic()>=until,5)
        assert not Path('/tmp/reboot-actions').exists()
        print('PASS: a staged boot that answered cleared its strikes and did not reboot.',flush=True)
        # Flags: the first session finds no patch magic and writes nothing.
        flags=lambda:Path('/tmp/tk.flags').read_text() if Path('/tmp/tk.flags').exists() else ''
        def dm_ram():
            try: return json.loads(Path('/tmp/dm-ram.json').read_text())
            except (FileNotFoundError, ValueError): return None
        wait_for(lambda:'state=waiting-magic' in flags(),30)
        dm=Path('/tmp/dm-log').read_text().splitlines()
        assert dm[:5]==['arm1log 2','quit 0','dbg revert','vm 0x847ed600 4','arm1log 1'], dm
        assert not any(l.startswith('wm ') for l in dm), dm
        assert not Path('/tmp/dm-ram.json').exists()
        assert 'ignored "wm=0x847ed608:0x1" in tk/config' in log(), log()
        print('PASS: confirmed boot: no flag write before the patch magic; a word off the allow-list is ignored.',flush=True)
        # The magic shows: both words are written, hold size first, and read back.
        Path('/tmp/dm-magic').write_text('')
        wait_for(lambda:'state=applied' in flags(),60)
        ram_words=dm_ram()
        assert ram_words=={str(0x84f93008):0x140,str(0x847ed604):0x15}, ram_words
        dm=Path('/tmp/dm-log').read_text().splitlines()
        writes=[l for l in dm if l.startswith('wm ')]
        assert writes==['wm 0x84f93008 0x140','wm 0x847ed604 0x15'], writes
        assert 'want=0x84f93008=0x140 0x847ed604=0x15\n' in flags(), flags()
        assert 'tk flags: written and read back' in log(), log()
        print('PASS: with the patch magic the keeper wrote both flag words and read them back.',flush=True)
        # Off through tk/config: the keeper writes 0, flags first.
        Path('/tmp/tk/config').write_text('enabled=1\nsha256='+good+'\n')
        wait_for(lambda:dm_ram()=={str(0x84f93008):0,str(0x847ed604):0} and 'state=applied' in flags(),40)
        writes=[l for l in Path('/tmp/dm-log').read_text().splitlines() if l.startswith('wm ')]
        assert writes[-2:]==['wm 0x847ed604 0','wm 0x84f93008 0'], writes
        assert 'tk/config changed' in log(), log()
        print('PASS: removing the wm= lines wrote 0 to both words and read them back.',flush=True)
        # Multi-magic N6 latency profile (10 words, split across 2 sessions) + refused words + N4 PDCP rollback.
        for marker in ('/tmp/dm-magic-img4', '/tmp/dm-magic-n5', '/tmp/dm-magic-n6'):
            Path(marker).write_text('')
        dm_before = len(Path('/tmp/dm-log').read_text().splitlines())
        Path('/tmp/tk/config').write_text(
            'enabled=1\nsha256=' + good + '\n'
            'wm=0x84f93008:0x140\n'
            'wm=0x847ed604:0x15\n'
            'wm=0x847ed548:0x1\n'
            'wm=0x847ed54c:0x1\n'
            'wm=0x847ed550:0x1\n'
            'wm=0x847ecf08:0x1\n'
            'wm=0x84489a84:0x2000\n'
            'wm=0x84489a88:0x3000\n'
            'wm=0x84489a6c:0x3\n'
            'wm=0x8418ff08:0x1\n'
            'wm=0x847ece88:0x1\n'
            'wm=0x847ecf28:0x1\n'
            'wm=0x847ecf10:0x060c\n'
            'wm=0x847ed604:0x8\n'
        )
        n6_expected = {
            str(0x84f93008): 0x140,
            str(0x847ed604): 0x15,
            str(0x847ed548): 1,
            str(0x847ed54c): 1,
            str(0x847ed550): 1,
            str(0x847ecf08): 1,
            str(0x84489a84): 0x2000,
            str(0x84489a88): 0x3000,
            str(0x84489a6c): 3,
            str(0x8418ff08): 1,
        }
        wait_for(lambda: dm_ram() == n6_expected and 'state=applied\n' in flags(), 60)
        dm_new = Path('/tmp/dm-log').read_text().splitlines()[dm_before:]
        # Split into 2 sessions (2 `arm1log 2` openings) with params written before flags.
        assert dm_new.count('arm1log 2') >= 2, dm_new
        n6_wms = [l for l in dm_new if l.startswith('wm ')]
        assert n6_wms.index('wm 0x84489a84 0x2000') < n6_wms.index('wm 0x84489a6c 0x3'), n6_wms
        assert n6_wms.index('wm 0x847ed604 0x15') < n6_wms.index('wm 0x84489a6c 0x3'), n6_wms
        assert 'ignored "wm=0x847ece88:0x1" in tk/config' in log(), log()
        assert 'ignored "wm=0x847ecf28:0x1" in tk/config' in log(), log()
        assert 'ignored "wm=0x847ecf10:0x060c" in tk/config' in log(), log()
        assert 'ignored "wm=0x847ed604:0x8" in tk/config' in log(), log()
        print('PASS: N6 latency profile applied across split sessions in safe order; forbidden words refused.', flush=True)
        # LNK=1 refused without U2_FLAGS bit 0, then accepted with U2_FLAGS=1 (and written after U2_FLAGS).
        Path('/tmp/tk/config').write_text(
            'enabled=1\nsha256=' + good + '\n'
            'wm=0x847ed554:0x1\n'
        )
        wait_for(lambda: 'ignored "wm=0x847ed554:0x1" in tk/config' in log() and dm_ram().get(str(0x8418ff08)) == 0 and 'state=applied\n' in flags(), 60)
        assert dm_ram().get(str(0x847ed554), 0) == 0, dm_ram()
        dm_lnk_before = len(Path('/tmp/dm-log').read_text().splitlines())
        Path('/tmp/tk/config').write_text(
            'enabled=1\nsha256=' + good + '\n'
            'wm=0x847ed554:0x1\n'
            'wm=0x8418ff08:0x1\n'
        )
        wait_for(lambda: 'state=applied\n' in flags() and dm_ram().get(str(0x847ed554)) == 1 and dm_ram().get(str(0x8418ff08)) == 1, 60)
        lnk_wms = [l for l in Path('/tmp/dm-log').read_text().splitlines()[dm_lnk_before:] if l.startswith('wm ')]
        assert lnk_wms.index('wm 0x8418ff08 0x1') < lnk_wms.index('wm 0x847ed554 0x1'), lnk_wms
        # Re-apply N6 latency profile for the hands-off test below (which also drops LNK back to 0).
        Path('/tmp/tk/config').write_text(
            'enabled=1\nsha256=' + good + '\n'
            'wm=0x84f93008:0x140\n'
            'wm=0x847ed604:0x15\n'
            'wm=0x847ed548:0x1\n'
            'wm=0x847ed54c:0x1\n'
            'wm=0x847ed550:0x1\n'
            'wm=0x847ecf08:0x1\n'
            'wm=0x84489a84:0x2000\n'
            'wm=0x84489a88:0x3000\n'
            'wm=0x84489a6c:0x3\n'
            'wm=0x8418ff08:0x1\n'
        )
        n6_expected_with_lnk_off = dict(n6_expected, **{str(0x847ed554): 0})
        wait_for(lambda: dm_ram() == n6_expected_with_lnk_off and 'state=applied\n' in flags(), 60)
        print('PASS: LNK=1 gated on U2_FLAGS bit 0 and N6 magic, written after U2_FLAGS.', flush=True)
        # Bench/maintenance hands-off hold: marker file stops all console sessions; removing it resumes with a fresh read.
        Path('/tmp/tk.hands-off').write_text('')
        wait_for(lambda: 'state=hands-off\n' in flags(), 10)
        dm_ho_before = len(Path('/tmp/dm-log').read_text().splitlines())
        # Simulate manual console edit while hands-off; keeper must not touch RAM.
        cur = dm_ram(); cur[str(0x8418ff08)] = 0
        Path('/tmp/dm-ram.json').write_text(json.dumps(cur))
        until = time.monotonic() + 3
        wait_for(lambda: time.monotonic() >= until, 5)
        assert len(Path('/tmp/dm-log').read_text().splitlines()) == dm_ho_before
        assert dm_ram()[str(0x8418ff08)] == 0
        Path('/tmp/tk.hands-off').unlink()
        wait_for(lambda: 'state=applied\n' in flags() and dm_ram() == n6_expected_with_lnk_off, 45)
        print('PASS: hands-off marker paused console sessions and removing it resumed with a fresh read.', flush=True)
        # manage=off in tk/config also enters state=hands-off; removing wm= restores N4 PDCP off values (0x4000/0x6000) and N5 zeros.
        Path('/tmp/tk/config').write_text(
            'enabled=1\nsha256=' + good + '\nmanage=off\nwm=0x847ed608:0x2000\nwm=0x847ed60c:0x3000\n'
        )
        wait_for(lambda: 'state=hands-off\n' in flags(), 25)
        Path('/tmp/tk/config').write_text(
            'enabled=1\nsha256=' + good + '\nwm=0x847ed608:0x2000\nwm=0x847ed60c:0x3000\n'
        )
        wait_for(lambda: 'state=applied\n' in flags() and dm_ram().get(str(0x847ed608)) == 0x2000 and dm_ram().get(str(0x84489a6c)) == 0, 60)
        Path('/tmp/tk/config').write_text('enabled=1\nsha256=' + good + '\n')
        wait_for(lambda: 'state=applied\n' in flags() and dm_ram().get(str(0x847ed608)) == 0x4000 and dm_ram().get(str(0x847ed60c)) == 0x6000, 60)
        print('PASS: manage=off held state=hands-off; config removal restored N4 PDCP 0x4000/0x6000 and N5/IMG4/N6 zeros.', flush=True)
        # M1 (Rust PIE): a build the keeper does not accept blocks every write;
        # an accepted one gets N4 AQM v2 first and the selector last, with its
        # counters in tk.m1; dropping the line writes the selector 0 first.
        assert not Path('/tmp/tk.m1').exists()
        Path('/tmp/dm-magic-m1').write_text('20261199\n')
        dm_m1_before = len(Path('/tmp/dm-log').read_text().splitlines())
        Path('/tmp/tk/config').write_text('enabled=1\nsha256=' + good + '\nwm=0x847ed604:0x15\nwm=0x841b5908:0x1\n')
        wait_for(lambda: 'shows version 0x20261199' in flags(), 45)
        assert 'state=waiting-magic\n' in flags(), flags()
        assert 'tk flags: the M1 patch at 0x841b5900 shows version 0x20261199; this keeper accepts 0x20261125, 0x20261126' in log(), log()
        dm_m1 = Path('/tmp/dm-log').read_text().splitlines()[dm_m1_before:]
        assert 'vm 0x841b5900 8' in dm_m1, dm_m1
        assert not any(l.startswith('wm ') for l in dm_m1), dm_m1
        assert not Path('/tmp/tk.m1').exists()
        Path('/tmp/dm-magic-m1').write_text('20261125\n')
        wait_for(lambda: 'state=applied\n' in flags() and (dm_ram() or {}).get(str(0x841b5908)) == 1 and Path('/tmp/tk.m1').exists(), 60)
        m1_wms = [l for l in Path('/tmp/dm-log').read_text().splitlines()[dm_m1_before:] if l.startswith('wm ')]
        assert m1_wms == ['wm 0x847ed604 0x15', 'wm 0x841b5908 0x1'], m1_wms
        m1_status = Path('/tmp/tk.m1').read_text()
        assert m1_status.startswith('version=0x20261125\nselector=1\nseen=28025\npie_drops=130\nce_marks=7\nhard_drops=90\npeak_qdelay_us=97612\nupdated='), m1_status
        Path('/tmp/tk/config').write_text('enabled=1\nsha256=' + good + '\nwm=0x847ed604:0x15\n')
        wait_for(lambda: 'state=applied\n' in flags() and dm_ram().get(str(0x841b5908)) == 0 and 'selector=0\n' in Path('/tmp/tk.m1').read_text(), 60)
        assert dm_ram().get(str(0x847ed604)) == 0x15, dm_ram()
        print('PASS: the M1 selector waited for an accepted build, went out after N4 AQM v2, reported its counters and rolled back to 0.', flush=True)
        # modem=off in the latency switches rolls every managed word back to its
        # off value, live; on again writes them back.
        Path('/tmp/latency').mkdir(exist_ok=True)
        Path('/tmp/latency/config').write_text('modem=off\n')
        wait_for(lambda: 'state=applied\n' in flags() and dm_ram().get(str(0x847ed604)) == 0, 45)
        assert 'latency switches: modem off, clamp on, fastpath on (latency/config)' in log(), log()
        Path('/tmp/latency/config').write_text('# back on\nmodem=on\n')
        wait_for(lambda: 'state=applied\n' in flags() and dm_ram().get(str(0x847ed604)) == 0x15, 45)
        assert 'latency switches: modem on, clamp on, fastpath on (latency/config)' in log(), log()
        Path('/tmp/latency/config').unlink()
        print('PASS: modem=off in the latency switches wrote the modem words to 0 live, and modem=on wrote them back.', flush=True)
        # A modem firmware load in the kernel log starts the flags over. Only
        # this keeper's lines: the boot confirm's crash cases saw restarts too.
        before_restart=len(log())
        with open('/tmp/kmsg','a') as kmsg: kmsg.write('6,900,1,-;read from nand mtd=tk0\n')
        wait_for(lambda:'modem restart seen' in log()[before_restart:],10)
        assert 'state=pending' in flags(), flags()
        print('PASS: a modem restart in the kernel log starts the flag writes over.',flush=True)
        # The clamp and fast path waited for the links, refused bogus bytes and never ran insmod.
        wait_for(lambda:'state=failed' in (Path('/tmp/qctrl.status').read_text() if Path('/tmp/qctrl.status').exists() else ''),60)
        status=Path('/tmp/qctrl.status').read_text()
        assert 'not the pinned' in status, status
        wait_for(lambda:'state=failed' in (Path('/tmp/fastpath.status').read_text() if Path('/tmp/fastpath.status').exists() else ''),60)
        fp_st=Path('/tmp/fastpath.status').read_text()
        assert 'not the pinned' in fp_st, fp_st
        assert not Path('/tmp/insmod-calls').exists(), Path('/tmp/insmod-calls').read_text()
        assert 'download clamp waiting' in log() and 'download clamp failed' in log(), log()
        assert 'fast path waiting' in log() and 'fast path failed' in log(), log()
        print('PASS: the clamp and fast path waited for the links and refused unpinned modules.',flush=True)
        # Carrier watch: compare active Band 48 transmit carriers against
        # authorized grants in /mnt/cbrslog0.txt, test dry-run hide_grant,
        # default log mode, rc_signal_done=0 wait, and mode=regrant trigger
        # (nvram_set sqns_network_cbrs=1 + SIGUSR1 to rcinit).
        rcinit_stub_path = Path('/tmp/bin/rcinit')
        rcinit_stub_path.write_text('#!/usr/bin/python3\nimport signal, time\ndef h(s, f):\n    with open("/tmp/rcinit-signals", "a") as out:\n        out.write("USR1\\n")\nsignal.signal(signal.SIGUSR1, h)\nwhile True:\n    time.sleep(60)\n')
        rcinit_stub_path.chmod(0o755)
        rcinit_stub = subprocess.Popen([str(rcinit_stub_path)])
        try:
            def cstatus():
                p = Path('/tmp/carrier.status')
                return p.read_text() if p.exists() else ''
            def rc_sigs():
                p = Path('/tmp/rcinit-signals')
                return p.read_text().splitlines() if p.exists() else []
            def write_nvram(extra):
                base = ['detection_interval=3', 'detection_enable=0'] + extra
                Path('/tmp/nvram-cache.new').write_text('\n'.join(base) + '\n')
                Path('/tmp/nvram-cache.new').replace('/tmp/nvram-cache')
            tx_exp = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(time.time() + 21600))
            gr_exp = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(time.time() + 86400 * 30))
            now_hdr = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())
            # 1. Covered: PCell 56638 (3680-3700) + ULScc 55440 (3560-3580) both granted.
            Path('/tmp/cbrslog0.txt').write_text(
                f'{now_hdr} (L1/P0/R1/G2)\n'
                f'=0(1):(3560000000-3580000000:27)(1800:{gr_exp})({tx_exp})\n'
                f'=1(1):(3680000000-3700000000:27)(1800:{gr_exp})({tx_exp})\n'
                '=(CBRS): Open Radio Traffic Channel.\n'
            )
            write_nvram([
                'sqns_radio_band=48',
                'sqns_radio_earfcnDl=56638',
                'sqns_radio_bandwidthDl=20000',
                'sqns_connection_uplinkScc=freq,pusch,prach,pucch,bw:55440,-55,-55,-55,20',
                'cbrs_mode_grant=1',
                'cbrs_grant_state=2',
                'rc_signal_done=1',
            ])
            wait_for(lambda: 'state=covered\n' in cstatus() and 'pcell=3680-3700\n' in cstatus() and 'ulscc=3560-3580\n' in cstatus(), 10)
            assert 'carrier watch' not in log(), log()
            print('PASS: carrier watch saw covered PCell+UL SCell and stayed quiet.', flush=True)
            # 2. Dry-run hide_grant=1 proves the comparator without forcing a re-grant,
            #    and logs the transition into uncovered exactly once.
            before_uncovered = log().count('carrier watch: uncovered')
            Path('/tmp/carrier-watch').mkdir()
            Path('/tmp/carrier-watch/config').write_text('mode=regrant\nquiet_utc=\nhide_grant=1\n')
            wait_for(lambda: 'state=uncovered\n' in cstatus() and 'dry-run hide_grant=1' in log(), 15)
            until = time.monotonic() + 2
            wait_for(lambda: time.monotonic() >= until, 4)
            assert log().count('carrier watch: uncovered') == before_uncovered + 1, log()
            assert rc_sigs() == [], rc_sigs()
            assert not any('sqns_network_cbrs' in a for a in nvram_actions()), nvram_actions()
            Path('/tmp/carrier-watch/config').unlink()
            wait_for(lambda: 'state=covered\n' in cstatus(), 15)
            print('PASS: carrier watch dry-run hide_grant=1 flagged uncovered without firing re-grant, and deleting config returned to covered.', flush=True)
            # 3. Real bench incident: grants hold 3620-3640 + 3680-3700 while ULScc is 55440 (3560-3580).
            # Default mode=log (no config file): logs uncovered, takes no action.
            with open('/tmp/cbrslog0.txt', 'a') as cf:
                cf.write(
                    f'{now_hdr} (L1/P0/R1/G2)\n'
                    f'=0(1):(3620000000-3640000000:27)(1800:{gr_exp})({tx_exp})\n'
                    f'=1(1):(3680000000-3700000000:27)(1800:{gr_exp})({tx_exp})\n'
                    '=(CBRS): Heartbeat1 Success!(responseCode = 0)\n'
                )
            wait_for(lambda: 'state=uncovered\n' in cstatus() and 'ulscc=3560-3580' in log(), 10)
            until = time.monotonic() + 3
            wait_for(lambda: time.monotonic() >= until, 5)
            assert rc_sigs() == [], rc_sigs()
            assert not any('sqns_network_cbrs' in a for a in nvram_actions()), nvram_actions()
            print('PASS: carrier watch default log mode flagged ungranted UL SCell and took no action.', flush=True)
            # 4. mode=regrant with rc_signal_done=0 waits, then fires once rc_signal_done=1.
            write_nvram([
                'sqns_radio_band=48',
                'sqns_radio_earfcnDl=56638',
                'sqns_radio_bandwidthDl=20000',
                'sqns_connection_uplinkScc=freq,pusch,prach,pucch,bw:55440,-55,-55,-55,20',
                'cbrs_mode_grant=1',
                'cbrs_grant_state=2',
                'rc_signal_done=0',
            ])
            Path('/tmp/carrier-watch/config').write_text('mode=regrant\nquiet_utc=\n')
            wait_for(lambda: 'waiting for rc_signal_done=1' in log(), 12)
            assert rc_sigs() == [], rc_sigs()
            write_nvram([
                'sqns_radio_band=48',
                'sqns_radio_earfcnDl=56638',
                'sqns_radio_bandwidthDl=20000',
                'sqns_connection_uplinkScc=freq,pusch,prach,pucch,bw:55440,-55,-55,-55,20',
                'cbrs_mode_grant=1',
                'cbrs_grant_state=2',
                'rc_signal_done=1',
            ])
            wait_for(lambda: 'state=regrant-pending\n' in cstatus() and rc_sigs() == ['USR1'], 10)
            assert 'set 0 sqns_network_cbrs 1' in nvram_actions(), nvram_actions()
            assert 'carrier watch: forcing re-grant' in log(), log()
            # Simulate vendor re-grant completing: cbrs_mode_grant=0, then new grants + cbrs_mode_grant=1.
            write_nvram([
                'sqns_radio_band=48',
                'sqns_radio_earfcnDl=56638',
                'sqns_radio_bandwidthDl=20000',
                'sqns_connection_uplinkScc=freq,pusch,prach,pucch,bw:55440,-55,-55,-55,20',
                'cbrs_mode_grant=0',
                'cbrs_grant_state=0',
                'rc_signal_done=1',
            ])
            until = time.monotonic() + 2
            wait_for(lambda: time.monotonic() >= until, 4)
            assert 'state=regrant-pending\n' in cstatus(), cstatus()
            with open('/tmp/cbrslog0.txt', 'a') as cf:
                cf.write(
                    f'{now_hdr} (L1/P0/R1/G2)\n'
                    f'=0(1):(3560000000-3580000000:27)(1800:{gr_exp})({tx_exp})\n'
                    f'=1(1):(3680000000-3700000000:27)(1800:{gr_exp})({tx_exp})\n'
                    '=(CBRS): Open Radio Traffic Channel.\n'
                )
            write_nvram([
                'sqns_radio_band=48',
                'sqns_radio_earfcnDl=56638',
                'sqns_radio_bandwidthDl=20000',
                'sqns_connection_uplinkScc=freq,pusch,prach,pucch,bw:55440,-55,-55,-55,20',
                'cbrs_mode_grant=1',
                'cbrs_grant_state=2',
                'rc_signal_done=1',
            ])
            wait_for(lambda: 'state=covered\n' in cstatus() and 're-grant succeeded in ' in log(), 10)
            assert 'regrants_triggered=1\n' in cstatus() and 'regrants_succeeded=1\n' in cstatus(), cstatus()
            assert rc_sigs() == ['USR1'], rc_sigs()
            print('PASS: carrier watch waited for rc_signal_done=1, fired sqns_network_cbrs=1 + SIGUSR1 to rcinit, and logged re-grant success.', flush=True)
        finally:
            if rcinit_stub.poll() is None:
                rcinit_stub.terminate()
                rcinit_stub.wait(timeout=3)
        # Real pinned clamp and fast path modules with a stub insmod and fake /proc/k1fp:
        # deterministic load order (clamp first), mode 2 read back, grant lease renewal,
        # immediate grant 0 on CBRS gate close, qctrl_present tracking, watchdog trip policy,
        # and live rollback.
        insmod_stub = Path('/tmp/bin/insmod')
        insmod_stub.write_text(r'''#!/usr/bin/env python3
import os, sys
from pathlib import Path
mod = os.path.basename(sys.argv[1])
with open('/tmp/insmod-calls', 'a') as f:
    f.write(mod + '\n')
mods = Path('/tmp/proc-modules').read_text() if Path('/tmp/proc-modules').exists() else ''
if mod == 'titan_qctrl.ko':
    # The module loads in mode 0, as v0.3-q3 does.
    Path('/tmp/qctrl-proc').write_text(
        'titan_qctrl v0.3-q3 (NF_BR_FORWARD prio=+100)\n'
        'mode=0x0 (ack_thin=0 rwnd_clamp=0 dl_ecn=0 udp_drop=0)\n'
        'params: target_q_ms=40 hold_us=2500 max_ack_span=8192 phy_cap_kbps=0\n'
        '        qsrc=0 slack_ms=10 floor_pct=30 drain=1 probe=1 trough_ms=4 rtt_target_ms=15 ecn_ms=20 wfix_kb=0 rttlaw=0\n'
        '        ack_adapt=0 ctrl_v3=0 ack_ms=6 ack_segs=18 ack_min_kbps=2000\n'
    )
    if 'titan_qctrl ' not in mods:
        mods += 'titan_qctrl 47104 0 - Live 0x7f0b4000\n'
        Path('/tmp/proc-modules').write_text(mods)
elif mod == 'titan_k1fp.ko':
    qpresent = 1 if 'titan_qctrl ' in mods else 0
    Path('/tmp/k1fp-proc').write_text(
        'titan_k1fp v2.2\n'
        'mode=0 lan=eth0 lan_hooked=1 wan=lte0pdn2 wan_hooked=1 br=br0 br_ports=2 ports_ok=1\n'
        'require_grant=1 grant_left_ms=0 gate=closed v4=1 v6=1 lease_ms=60 sample_ms=20\n'
        f'qctrl: qctrl_present={qpresent} qctrl_dl_calls=0 qctrl_dl_drop=0 qctrl_dl_stolen=0 qctrl_ul_stock=0\n'
        'watchdog: wd_armed=0 wd_trips=0 wd_reason=none wd_mod=20 wd_mismatch=64 wd_stall_ms=500 wd_ringfull_ms=500\n'
        'safety: txirq=0 txdrain=0 dlbypass=0 pins=0 modref=0 err_tx=0\n'
        'vendor: netifq_enabled=1 net_mode=2 host_mac_learned=1 host_mac=00:11:22:33:44:55 external_dev_set=0\n'
        'brhook: external_dev_stop=0 list_nr=0 in_hold=0 held=0 holds=0\n'
        'fast_dl=0 fast_ul=0 fast_dl_KiB=0 fast_ul_KiB=0 would_fast=0 gate_closed=0 xmit_err=0\n'
    )
    if 'titan_k1fp ' not in mods:
        mods += 'titan_k1fp 32768 0 - Live 0x7f0c0000\n'
        Path('/tmp/proc-modules').write_text(mods)
else:
    sys.exit(1)
''')
        insmod_stub.chmod(0o755)
        shutil.copy2(REPO/'device/qctrl/payload/titan_qctrl.ko', '/tmp/qctrl/titan_qctrl.ko')
        shutil.copy2(REPO/'device/fastpath/payload/titan_k1fp.ko', '/tmp/fastpath/titan_k1fp.ko')
        Path('/tmp/qctrl/config').write_text('mode=2\n')
        Path('/tmp/fastpath/config').write_text('mode=2\n')
        for p in ('/tmp/proc-modules', '/tmp/qctrl-proc', '/tmp/k1fp-proc', '/tmp/insmod-calls'):
            Path(p).unlink(missing_ok=True)
        Path('/tmp/proc-modules').write_text('')
        with fp_lock:
            fp_state.update(mode=0, gate='closed', grant_left_ms=0, qctrl_present=1, wd_trips=0, wd_reason='none')
            k1fp_cmds.clear()
        with q_lock:
            q_state.update(q_defaults)
        fp_status = lambda: Path('/tmp/fastpath.status').read_text() if Path('/tmp/fastpath.status').exists() else ''
        q_status = lambda: Path('/tmp/qctrl.status').read_text() if Path('/tmp/qctrl.status').exists() else ''
        restart()
        wait_for(lambda: 'state=applied\n' in fp_status(), 60)
        calls = Path('/tmp/insmod-calls').read_text().splitlines()
        assert calls == ['titan_qctrl.ko', 'titan_k1fp.ko'], calls
        st = fp_status()
        assert 'mode=2\n' in st and 'active_mode=2\n' in st and 'gate=open\n' in st and 'qctrl_present=1\n' in st, st
        print('PASS: deterministic load order (clamp then fast path) and mode 2 applied.',flush=True)
        # Grant lease renews once per second while the SAS grant is held.
        with fp_lock:
            before_renew = len(k1fp_cmds)
        until = time.monotonic() + 2.5
        wait_for(lambda: time.monotonic() >= until, 5)
        with fp_lock:
            renews = [c for _, c in k1fp_cmds[before_renew:] if c == 'grant 5']
        assert len(renews) >= 2, (renews, k1fp_cmds)
        print('PASS: fast path grant lease renewed every second while SAS grant held (%d writes).' % len(renews), flush=True)
        # Dropping the SAS grant writes `grant 0` immediately, updates status to gate=closed, and stops renewals until restored.
        with fp_lock:
            before_close = len(k1fp_cmds)
        set_grant(['cbrs_mode_grant=1', 'cbrs_grant_state=1'])
        wait_for(lambda: any(c == 'grant 0' for _, c in k1fp_cmds[before_close:]), 10)
        wait_for(lambda: len(gate_rules()) == 4, 10)
        wait_for(lambda: 'gate=closed\n' in fp_status(), 20)
        until = time.monotonic() + 2.2
        wait_for(lambda: time.monotonic() >= until, 5)
        with fp_lock:
            after_close = [c for _, c in k1fp_cmds[before_close:]]
            idx0 = after_close.index('grant 0')
            assert 'grant 5' not in after_close[idx0:], after_close
        set_grant(['cbrs_mode_grant=1', 'cbrs_grant_state=2'])
        with fp_lock:
            before_reopen = len(k1fp_cmds)
        wait_for(lambda: any(c == 'grant 5' for _, c in k1fp_cmds[before_reopen:]), 10)
        wait_for(lambda: gate_rules() == [], 10)
        wait_for(lambda: 'gate=open\n' in fp_status(), 20)
        print('PASS: SAS gate close sent grant 0 immediately, updated fastpath status to gate=closed, then resumed to gate=open.', flush=True)
        # Clamp unload later: keeper notices qctrl_present=1 -> 0 and logs it.
        with fp_lock:
            fp_state['qctrl_present'] = 0
            write_k1fp_proc()
        wait_for(lambda: 'fast path: download clamp unloaded (qctrl_present=0)' in log(), 25)
        assert 'qctrl_present=0\n' in fp_status(), fp_status()
        print('PASS: fast path noticed and logged qctrl_present change.', flush=True)
        # Watchdog trip #1: keeper logs reason and re-arms mode 2 once.
        with fp_lock:
            fp_state['mode'] = 0
            fp_state['wd_trips'] = 1
            fp_state['wd_reason'] = 'tx_stall'
            write_k1fp_proc()
        wait_for(lambda: 'tx_stall' in log() and fp_state['mode'] == 2 and 'state=applied\n' in fp_status() and 'wd_trips=1\n' in fp_status(), 25)
        assert 're-arming mode 2' in log(), log()
        print('PASS: first watchdog trip logged reason and re-armed once.', flush=True)
        # Watchdog trip #2: keeper does NOT re-arm; stays at mode 0 in state=tripped.
        with fp_lock:
            fp_state['mode'] = 0
            fp_state['wd_trips'] = 2
            fp_state['wd_reason'] = 'ring_full'
            write_k1fp_proc()
        wait_for(lambda: 'state=tripped\n' in fp_status(), 25)
        assert 'ring_full' in log() and fp_state['mode'] == 0, (fp_state, fp_status())
        assert 'active_mode=0\n' in fp_status(), fp_status()
        until = time.monotonic() + 16
        wait_for(lambda: time.monotonic() >= until, 20)
        assert 'state=tripped\n' in fp_status() and fp_state['mode'] == 0, (fp_state, fp_status())
        assert log().count('ring_full') == 1, log()
        print('PASS: second watchdog trip stayed at mode 0 in state=tripped and logged once.', flush=True)
        # Live rollback via config change: mode=0 clears tripped state to off.
        Path('/tmp/fastpath/config').write_text('mode=0\n')
        wait_for(lambda: 'state=off\n' in fp_status(), 25)
        assert fp_state['mode'] == 0 and 'mode=0\n' in fp_status(), (fp_state, fp_status())
        print('PASS: live rollback (mode=0 in fastpath/config) moved fast path to state=off.', flush=True)
        # Adopting an already-loaded titan_k1fp v2.2 module (loaded by hand, even
        # without a staged .ko): keeper logs adoption, does not run insmod, takes
        # over mode and drives the 1 Hz grant lease.
        Path('/tmp/fastpath/titan_k1fp.ko').unlink(missing_ok=True)
        Path('/tmp/fastpath/config').write_text('mode=2\n')
        Path('/tmp/insmod-calls').unlink(missing_ok=True)
        Path('/tmp/proc-modules').write_text(
            'titan_qctrl 47104 0 - Live 0x7f0b4000\n'
            'titan_k1fp 32768 0 - Live 0x7f0c0000\n'
        )
        with fp_lock:
            fp_state.update(mode=2, gate='closed', grant_left_ms=0, qctrl_present=1, wd_trips=0, wd_reason='none')
            write_k1fp_proc()
            k1fp_cmds.clear()
        restart()
        wait_for(lambda: 'fast path: adopted a loaded module' in log() and 'state=applied\n' in fp_status(), 30)
        assert not Path('/tmp/insmod-calls').exists(), Path('/tmp/insmod-calls').read_text()
        assert 'mode=2\n' in fp_status() and 'active_mode=2\n' in fp_status() and 'gate=open\n' in fp_status(), fp_status()
        with fp_lock:
            before_adopt_renew = len(k1fp_cmds)
        until = time.monotonic() + 2.5
        wait_for(lambda: time.monotonic() >= until, 5)
        with fp_lock:
            adopt_renews = [c for _, c in k1fp_cmds[before_adopt_renew:] if c == 'grant 5']
        assert len(adopt_renews) >= 2, (adopt_renews, k1fp_cmds)
        print('PASS: adopted pre-loaded titan_k1fp v2.2 without insmod and drove the grant lease.', flush=True)
        # Wrong version string in /proc/k1fp is still refused (never adopted).
        Path('/tmp/fastpath.status').unlink(missing_ok=True)
        before_refuse_log = len(log())
        Path('/tmp/k1fp-proc').write_text(
            'titan_k1fp v2.1\n'
            'mode=0 lan=eth0 lan_hooked=1 wan=lte0pdn2 wan_hooked=1 br=br0 br_ports=2 ports_ok=1\n'
        )
        with fp_lock:
            k1fp_cmds.clear()
        restart()
        wait_for(lambda: 'state=failed\n' in fp_status() and 'titan_k1fp v2.1' in fp_status(), 30)
        assert 'fast path: adopted a loaded module' not in log()[before_refuse_log:], log()[before_refuse_log:]
        assert not Path('/tmp/insmod-calls').exists(), Path('/tmp/insmod-calls').read_text()
        with fp_lock:
            assert k1fp_cmds == [], k1fp_cmds
        # Another *k1fp* module name is still refused (never adopted).
        Path('/tmp/fastpath.status').unlink(missing_ok=True)
        before_other_log = len(log())
        Path('/tmp/proc-modules').write_text('titan_k1fp_v1 20000 0 - Live 0x7f0c0000\n')
        Path('/tmp/k1fp-proc').unlink(missing_ok=True)
        restart()
        wait_for(lambda: 'state=failed\n' in fp_status() and 'titan_k1fp_v1' in fp_status(), 30)
        assert 'fast path: adopted a loaded module' not in log()[before_other_log:], log()[before_other_log:]
        assert not Path('/tmp/insmod-calls').exists(), Path('/tmp/insmod-calls').read_text()
        print('PASS: refused wrong version string and other *k1fp* module without adopting.', flush=True)
        # v1.0.17 defaults: no qctrl/config, no fastpath/config and no staged
        # copies. Both modules load from the image's copies, the clamp in mode 3
        # and the fast path in mode 2.
        for staged in ('/tmp/qctrl', '/tmp/fastpath'):
            shutil.rmtree(staged, ignore_errors=True)
        Path('/tmp/image-modules').mkdir()
        shutil.copy2(REPO/'device/qctrl/payload/titan_qctrl.ko', '/tmp/image-modules/titan_qctrl.ko')
        shutil.copy2(REPO/'device/fastpath/payload/titan_k1fp.ko', '/tmp/image-modules/titan_k1fp.ko')
        for stale in ('/tmp/qctrl-proc', '/tmp/k1fp-proc', '/tmp/insmod-calls', '/tmp/qctrl.status', '/tmp/fastpath.status'):
            Path(stale).unlink(missing_ok=True)
        Path('/tmp/proc-modules').write_text('')
        with fp_lock:
            fp_state.update(mode=0, gate='closed', grant_left_ms=0, qctrl_present=1, wd_trips=0, wd_reason='none')
            k1fp_cmds.clear()
        with q_lock:
            q_state.update(q_defaults)
        before_defaults = len(log())
        restart()
        wait_for(lambda: 'state=applied\n' in fp_status() and 'state=applied\n' in q_status(), 90)
        assert Path('/tmp/insmod-calls').read_text().splitlines() == ['titan_qctrl.ko', 'titan_k1fp.ko']
        new_log = log()[before_defaults:]
        assert 'download clamp: loaded titan_qctrl v0.3-q3 from the firmware image' in new_log, new_log
        assert 'fast path: loaded titan_k1fp v2.2 from the firmware image' in new_log, new_log
        assert 'mode=3\n' in q_status() and 'the firmware default' in q_status() and q_state['mode'] == 3, (q_status(), q_state)
        assert 'mode=2\n' in fp_status() and 'active_mode=2\n' in fp_status() and 'the firmware default' in fp_status(), fp_status()
        print('PASS: with no config of their own the clamp (mode 3) and the fast path (mode 2) loaded from the image.', flush=True)
        # The latency switches turn both off live, and on again without a reload.
        Path('/tmp/latency').mkdir(exist_ok=True)
        Path('/tmp/latency/config').write_text('clamp=off\nfastpath=off\n')
        wait_for(lambda: 'state=off\n' in fp_status() and 'state=off\n' in q_status(), 30)
        assert fp_state['mode'] == 0 and q_state['mode'] == 0, (fp_state, q_state)
        assert 'clamp=off in latency/config' in q_status() and 'fastpath=off in latency/config' in fp_status(), (q_status(), fp_status())
        assert 'latency switches: modem on, clamp off, fastpath off (latency/config)' in log(), log()
        Path('/tmp/latency/config').write_text('clamp=on\nfastpath=on\n')
        wait_for(lambda: 'state=applied\n' in fp_status() and 'state=applied\n' in q_status(), 30)
        assert fp_state['mode'] == 2 and q_state['mode'] == 3, (fp_state, q_state)
        assert Path('/tmp/insmod-calls').read_text().splitlines() == ['titan_qctrl.ko', 'titan_k1fp.ko'], 'no reload'
        print('PASS: clamp=off and fastpath=off turned both to mode 0 live, and on again put back 3 and 2.', flush=True)
        # The default clamp stands aside while a radio profile's CAKE is loaded.
        Path('/tmp/proc-modules').write_text(Path('/tmp/proc-modules').read_text() + 'sch_cake 31676 0 - Live 0x7f0a0000\n')
        wait_for(lambda: 'state=off\n' in q_status() and 'CAKE' in q_status(), 30)
        assert q_state['mode'] == 0, q_state
        Path('/tmp/proc-modules').write_text(Path('/tmp/proc-modules').read_text().replace('sch_cake 31676 0 - Live 0x7f0a0000\n', ''))
        wait_for(lambda: 'state=applied\n' in q_status() and q_state['mode'] == 3, 30)
        Path('/tmp/latency/config').unlink()
        print('PASS: the default clamp stood aside while sch_cake was loaded and came back after.', flush=True)
        # Router swap, last, so no timed step above moves against the deaf
        # watchdog's rounds. The vendor kernel addresses the bearer's IPv4 to the MAC
        # it stored at boot, the router's here, so with the bearer bridged the
        # keeper runs nothing. Then the log shows another MAC, as after a swap
        # to a router the kernel never stores: the keeper points it at the router
        # that holds the lease with the vendor's own command, once.
        assert hostmac_actions()==[], hostmac_actions()
        run(ip, 'link', 'set', 'lte0pdn1', 'master', 'br0')
        until=time.monotonic()+4
        wait_for(lambda:time.monotonic()>=until,8)
        assert hostmac_actions()==[], hostmac_actions()
        with open('/tmp/kmsg','a') as kmsg:
            kmsg.write('6,120,4,-;usb0 set host mac: 02:00:5e:00:53:01\n')
        swapped=time.monotonic()
        pointed='router swap: the vendor kernel addressed customer IPv4 to 02:00:5e:00:53:01; pointed it at '+peer_mac_text
        wait_for(lambda:hostmac_actions()==['kern netif hmac usb0 '+peer_mac_text] and pointed in log(),15)
        took=time.monotonic()-swapped
        until=time.monotonic()+8
        wait_for(lambda:time.monotonic()>=until,12)
        assert hostmac_actions()==['kern netif hmac usb0 '+peer_mac_text], hostmac_actions()
        assert log().count('router swap:')==1, log()
        run(ip, 'link', 'set', 'lte0pdn1', 'nomaster')
        print('PASS: after a router swap the keeper pointed the vendor IPv4 host MAC at the leased router in %.1f s, once.'%took,flush=True)
        print(log(),flush=True)
    finally:
        keeper.terminate();keeper.wait(timeout=5)
        if server.poll() is None: server.terminate();server.wait(timeout=3)
        # Namespace PID 1 exiting terminates remaining fixture daemon children.

if __name__=='__main__': main()
