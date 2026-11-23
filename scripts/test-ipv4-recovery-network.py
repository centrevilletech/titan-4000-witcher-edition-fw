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
decisions and commands, not the kernel tables.
The boot confirm for a staged modem firmware image reads a status file standing
in for the boot hook's and runs against the ping and reboot stubs: the main run
has no staged image and must never reboot for it, then one staged boot gets no
answer (quarantine, one reboot) and one gets an answer (strikes cleared).
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
"""
import errno
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
                        sys.executable, __file__, '--inner'], check=True, timeout=900)
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
    # first under the unit's column header; `wm` writes a RAM file. Each patch
    # layer's magic shows only while its marker file exists.
    lted = Path('/tmp/bin/lted_cli')
    lted.write_text(r'''#!/usr/bin/env python3
import json, os, sys
ram = json.load(open('/tmp/dm-ram.json')) if os.path.exists('/tmp/dm-ram.json') else {}
HEADER = '           | 03 02 01 00  07 06 05 04  0B 0A 09 08  0F 0E 0D 0C'
MAGICS = {
    0x847ed600: ('/tmp/dm-magic', '4e 34 56 32'),
    0x847ecfe8: ('/tmp/dm-magic-img4', '49 4d 47 34'),
    0x84489a64: ('/tmp/dm-magic-n5', '4e 35 46 4c'),
    0x8418ff00: ('/tmp/dm-magic-n6', '55 32 48 46'),
}
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
def dump(addr, shown):
    sys.stdout.write('\n-----\n HEX DUMP  | 4(0x4) Bytes @ 0x%08X\n-----\n%s\n-----\n\x1b[1;32m0x%08X\x1b[0m | %s  .. .. .. ..  .. .. .. ..  .. .. .. .. \n-----\nDM> ' % (addr, HEADER, addr, shown))
for line in sys.stdin:
    line = line.strip()
    with open('/tmp/dm-log', 'a') as log:
        log.write(line + '\n')
    words = line.split()
    if line == 'exit':
        break
    if len(words) == 3 and words[0] == 'vm':
        addr = int(words[1], 16)
        if addr in MAGICS:
            marker, text = MAGICS[addr]
            dump(addr, text if os.path.exists(marker) else '00 00 00 00')
        else:
            val = ram.get(str(addr), BOOT_DEFAULTS.get(addr, 0))
            dump(addr, ' '.join('%02x' % b for b in val.to_bytes(4, 'big')))
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
    # and `kern eth -fc` prints the flow control report.
    exe('/tmp/bin/kern', 'if [ "$1" = netif ]; then echo "kern $*" >> /tmp/extdev-actions; echo "4,200,2,-;external_dev=NULL" >> /tmp/kmsg; '
        'elif [ "$1" = eth ]; then echo "kern $*" >> /tmp/eth-actions; echo "4,300,5,-;  dma ctrl(00203206): efc=0 rfa=1(fill=2KB) rfd=2(fill=1KB)" >> /tmp/kmsg; '
        'else echo "kern $*" >> /tmp/sas-actions; fi')
    Path('/tmp/kmsg').write_text('6,1,1,-;booting\n')
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
    exe('/tmp/bin/ip6tables', 'exec /tmp/bin/chain-stub /tmp/ip6-forward "$@"')
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
            "titan_k1fp v2.0\n"
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

    env=dict(os.environ,PATH='/tmp/bin:'+os.environ['PATH'],TITAN_EBTABLES='/tmp/bin/ebtables',TITAN_IP6TABLES='/tmp/bin/ip6tables',TITAN_PD_STATE='/tmp/pd',TITAN_PD_RUNTIME='/tmp/runtime',TITAN_KMSG='/tmp/kmsg',TITAN_SNMP6='/tmp/snmp6',TITAN_NVRAM='/tmp/bin/titan-nvram',TITAN_NVRAM_CACHE='/tmp/nvram-cache',TITAN_RCINIT_LOG='/tmp/rcinit.log',
             TITAN_TK_STATUS='/tmp/tk.status',TITAN_TK_RESULT='/tmp/tk.result',TITAN_TK_DIR='/tmp/tk',
             TITAN_TK_FLAGS='/tmp/tk.flags',TITAN_TK_HANDS_OFF='/tmp/tk.hands-off',
             TITAN_LTED_CLI='/tmp/bin/lted_cli',TITAN_DM_STEP_MS='300',
             TITAN_QCTRL_DIR='/tmp/qctrl',TITAN_QCTRL_STATUS='/tmp/qctrl.status',TITAN_QCTRL_PROC='/tmp/qctrl-proc',
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
        assert 'tk flags' not in log() and 'download clamp' not in log() and 'carrier watch' not in log() and 'fast path' not in log(), log()
        assert Path('/tmp/qctrl.status').read_text().startswith('state=off\n'), Path('/tmp/qctrl.status').read_text()
        assert Path('/tmp/fastpath.status').read_text().startswith('state=off\n'), Path('/tmp/fastpath.status').read_text()
        print('PASS: stock boot: no modem console session, flags, clamp and fast path off and silent.',flush=True)
        # A staged modem firmware image whose boot never answers. Nothing has
        # answered since `silent_from`; the deaf watchdog of a new keeper
        # process cannot arm, so any reboot now is the boot confirm's.
        def restart():
            nonlocal keeper
            keeper.terminate();keeper.wait(timeout=5)
            Path('/tmp/reboot-actions').unlink(missing_ok=True)
            keeper=subprocess.Popen([str(BINARY),'run'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        def uptime():
            return int(float(Path('/proc/uptime').read_text().split()[0]))
        bad='a'*64
        Path('/tmp/tk').mkdir()
        Path('/tmp/tk/strikes').write_text('strikes=1\n')
        Path('/tmp/tk/config').write_text('enabled=1\nsha256='+bad+'\ntarget=192.0.2.9\n')
        up=uptime()
        Path('/tmp/tk.status').write_text('state=staged\nsha256=%s\nstrikes=1\nloaded_at=%d\nsource=fs\nfirmware=clean\n'%(bad,max(0,up-400)))
        restart()
        wait_for(lambda:Path('/tmp/reboot-actions').exists(),max(90,300-up+90))
        assert Path('/tmp/reboot-actions').read_text().splitlines()[0]=='reboot ', Path('/tmp/reboot-actions').read_text()
        assert Path('/tmp/tk/quarantine').read_text()==bad+'\n'
        assert Path('/tmp/tk/strikes').read_text()=='strikes=2\n'
        assert Path('/tmp/tk.result').read_text()=='rollback='+bad+'\n'
        assert 'quarantined it, rebooting onto stock modem firmware' in log()
        assert any('192.0.2.9' in call for call in Path('/tmp/ping-calls').read_text().splitlines())
        print('PASS: a staged boot with no answer quarantined its image and asked for one reboot.',flush=True)
        assert not Path('/tmp/dm-log').exists(), 'a modem console session ran before any boot confirm'
        # A staged image whose boot answers through the core.
        good='b'*64
        Path('/tmp/tk.result').unlink()
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
        restart()
        wait_for(lambda:'tk boot confirmed' in log(),45)
        assert Path('/tmp/tk/strikes').read_text()=='strikes=0\n'
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
        # A modem firmware load in the kernel log starts the flags over.
        with open('/tmp/kmsg','a') as kmsg: kmsg.write('6,900,1,-;read from nand mtd=tk0\n')
        wait_for(lambda:'modem restart seen' in log(),10)
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
    Path('/tmp/qctrl-proc').write_text(
        'titan_qctrl v0.2-o1b (NF_BR_FORWARD prio=+100)\n'
        'mode=0x2 (ack_thin=0 rwnd_clamp=1 dl_ecn=0 udp_drop=0)\n'
        'params: target_q_ms=40 hold_us=2500 max_ack_span=8192 phy_cap_kbps=0\n'
        '        qsrc=0 slack_ms=10 floor_pct=30 drain=1 probe=1 trough_ms=4 rtt_target_ms=15 ecn_ms=20 wfix_kb=0 rttlaw=0\n'
    )
    if 'titan_qctrl ' not in mods:
        mods += 'titan_qctrl 47104 0 - Live 0x7f0b4000\n'
        Path('/tmp/proc-modules').write_text(mods)
elif mod == 'titan_k1fp.ko':
    qpresent = 1 if 'titan_qctrl ' in mods else 0
    Path('/tmp/k1fp-proc').write_text(
        'titan_k1fp v2.0\n'
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
        fp_status = lambda: Path('/tmp/fastpath.status').read_text() if Path('/tmp/fastpath.status').exists() else ''
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
        # Adopting an already-loaded titan_k1fp v2.0 module (loaded by hand, even
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
        print('PASS: adopted pre-loaded titan_k1fp v2.0 without insmod and drove the grant lease.', flush=True)
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
        print(log(),flush=True)
    finally:
        keeper.terminate();keeper.wait(timeout=5)
        if server.poll() is None: server.terminate();server.wait(timeout=3)
        # Namespace PID 1 exiting terminates remaining fixture daemon children.

if __name__=='__main__': main()
