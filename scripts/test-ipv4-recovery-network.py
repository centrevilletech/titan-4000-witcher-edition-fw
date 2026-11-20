#!/usr/bin/env python3
"""Run the real keeper against a veth ARP peer. No host or Titan networking.

Requires root namespace capabilities. PHY action is a recording stub: this
proves packet detection/escalation, not a physical Titan cable disconnect.
The SAS NAT repair runs against recording iptables and kern stubs: this proves
the keeper's decision and commands, not the vendor NAT path itself.
The management advertisement freeze runs against a dummy lte0pdn0 and the real
kernel. The external-device guard reads a file standing in for the kernel log
and runs a recording `kern` stub. The deaf watchdog runs against ping,
modem-state and reboot stubs.
"""
import os
import json
from pathlib import Path
import shutil
import struct
import socket
import subprocess
import sys
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
                        sys.executable, __file__, '--inner'], check=True, timeout=480)
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
    exe('/tmp/bin/ip', 'if [ "$1" = route ]; then cat /tmp/routes; else exec /tmp/bin/real-ip "$@"; fi')
    exe('/tmp/bin/ps', 'exec /tmp/bin/real-ps -eo pid,args')
    exe('/tmp/bin/nvram_get', 'case "$2" in router_disable) echo "nvram_get success: 1";; lan_management_ipaddr) echo "nvram_get success: 10.1.1.1";; pdn_data_ipaddr) echo "nvram_get success: 172.20.64.152";; wan_get_dns) echo "nvram_get success: 192.0.2.53 0.0.0.0";; sqns_connection_mediaState) echo "nvram_get success: ATTACHED";; *) echo "nvram_get success: ";; esac')
    # Deaf watchdog fixtures: a target answers while /tmp/ping-ok exists, and a reboot is only recorded.
    exe('/tmp/bin/ping', 'echo "$*" >> /tmp/ping-calls; [ -e /tmp/ping-ok ]')
    exe('/tmp/bin/reboot', 'echo "reboot $*" >> /tmp/reboot-actions')
    Path('/tmp/ping-ok').write_text('')
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
    # `kern netif extdev <dev> down` prints external_dev=NULL to the kernel log on a Titan.
    exe('/tmp/bin/kern', 'if [ "$1" = netif ]; then echo "kern $*" >> /tmp/extdev-actions; echo "4,200,2,-;external_dev=NULL" >> /tmp/kmsg; else echo "kern $*" >> /tmp/sas-actions; fi')
    Path('/tmp/kmsg').write_text('6,1,1,-;booting\n')
    Path('/tmp/nat-rules').write_text(sas_rule+'\n')
    exe('/tmp/bin/ebtables', 'exit 0')
    exe('/tmp/bin/mii-tool', 'echo "$*" >> /tmp/phy-actions; /tmp/bin/real-ip netns exec witcher-peer /bin/sh -c "echo 0 > /proc/sys/net/ipv4/conf/router0/arp_ignore"')
    exe('/usr/sbin/udhcpd', 'echo start >> /tmp/dhcp-starts; while :; do sleep 30; done')
    Path('/tmp/routes').write_text('172.20.64.152 dev br0 scope link\ndefault via 172.20.64.151 dev lte0pdn1\n')
    Path('/tmp/udhcpd.conf').write_text('start 172.20.64.152\nend 172.20.64.152\nmax_leases 8\ninterface br0:9\nremaining yes\noption subnet 255.255.255.240\noption router 172.20.64.151\noption lease 120\n')
    def lease():
        Path('/tmp/lease.new').write_bytes(struct.pack('>QI4B6s20s2x',int(time.time()),120,172,20,64,152,peer_mac,b'fixture'))
        Path('/tmp/lease.new').replace('/tmp/udhcpd.leases')
    lease()
    capture=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3));capture.bind(('eth0',0));capture.setblocking(False)
    packets=[]
    server=subprocess.Popen(['/usr/sbin/udhcpd','-f','/tmp/udhcpd.conf'])
    env=dict(os.environ,PATH='/tmp/bin:'+os.environ['PATH'],TITAN_EBTABLES='/tmp/bin/ebtables',TITAN_PD_STATE='/tmp/pd',TITAN_PD_RUNTIME='/tmp/runtime',TITAN_KMSG='/tmp/kmsg')
    keeper=subprocess.Popen([str(BINARY),'run'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    def log():
        p=Path('/tmp/pd/keeper.log');return p.read_text() if p.exists() else ''
    def wait_for(predicate, seconds):
        deadline=time.monotonic()+seconds
        while time.monotonic()<deadline:
            lease()
            try:
                while True:
                    frame=capture.recv(2048)
                    if frame[12:14]==b'\x08\x06': packets.append(frame.hex())
            except BlockingIOError: pass
            if keeper.poll() is not None: raise AssertionError('keeper exited: '+log())
            if predicate(): return
            time.sleep(.25)
        raise AssertionError('Timed out: '+log()+'\nARP '+repr(packets)+'\ncarrier '+repr([Path('/sys/class/net/'+n+'/carrier').read_text() for n in ['eth0','lte0pdn1']])+'\nIP '+subprocess.check_output([ip,'-4','-o','addr','show','dev','br0']).decode()+'\nlease '+Path('/tmp/udhcpd.leases').read_bytes().hex())
    try:
        wait_for(lambda:'automatic recovery is armed' in log(),25)
        print('PASS: real ARP reply established the IPv4 baseline with IPv6 unset.',flush=True)
        # The deaf watchdog arms on the first answer, then the target goes quiet
        # while the modem stays attached. The reboot is checked at the end.
        wait_for(lambda:'deaf watchdog armed' in log(),45)
        assert not Path('/tmp/reboot-actions').exists()
        Path('/tmp/ping-ok').unlink()
        silent_from=time.monotonic()
        print('PASS: deaf watchdog armed only after a target answered.',flush=True)
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
        # A vendor firewall restart flushes it. Two missed checks restore it,
        # in rcinit's order, and nothing more runs once it is back.
        Path('/tmp/nat-rules').write_text('')
        restored=['kern natq act 0','iptables -t nat -I POSTROUTING -s 10.1.1.1 -j SNAT --to-source 172.20.64.152']
        wait_for(lambda:Path('/tmp/sas-actions').exists() and len(Path('/tmp/sas-actions').read_text().splitlines())>=2,40)
        assert Path('/tmp/sas-actions').read_text().splitlines()==restored, Path('/tmp/sas-actions').read_text()
        assert 'SAS NAT rule restored' in log()
        until=time.monotonic()+25
        wait_for(lambda:time.monotonic()>=until,30)
        assert Path('/tmp/sas-actions').read_text().splitlines()==restored, Path('/tmp/sas-actions').read_text()
        assert not Path('/tmp/phy-actions').exists()
        print('PASS: flushed SAS SNAT rule restored once, with natq bridge mode first, and left alone after.',flush=True)
        if time.monotonic()-silent_from<110:
            assert not Path('/tmp/reboot-actions').exists(), 'the deaf watchdog fired before its wait'
            print('PASS: deaf watchdog held through the first %d s of silence.'%(time.monotonic()-silent_from),flush=True)
        # A missing DHCP process is restored without bouncing the port.
        server.terminate();server.wait(timeout=3)
        wait_for(lambda:Path('/tmp/dhcp-starts').read_text().count('start')>=2,20)
        assert not Path('/tmp/phy-actions').exists()
        print('PASS: missing DHCP daemon recovered without Ethernet renegotiation.',flush=True)
        # An LTE outage must not become a downstream-router fault.
        before=log().count('automatic recovery is armed')
        run(ip, 'link', 'set', 'lte0pdn1', 'down')
        run(ip, 'netns', 'exec', 'witcher-peer', '/bin/sh', '-c', 'echo 8 > /proc/sys/net/ipv4/conf/router0/arp_ignore')
        until=time.monotonic()+35
        wait_for(lambda:time.monotonic()>=until,40)
        assert not Path('/tmp/phy-actions').exists()
        assert 'repairing DHCP first' not in log()
        run(ip, 'netns', 'exec', 'witcher-peer', '/bin/sh', '-c', 'echo 0 > /proc/sys/net/ipv4/conf/router0/arp_ignore')
        run(ip, 'link', 'set', 'lte0pdn1', 'up')
        wait_for(lambda:log().count('automatic recovery is armed')>before,20)
        print('PASS: LTE outage inhibited downstream recovery; return required a new ARP baseline.',flush=True)
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
        print(log(),flush=True)
    finally:
        keeper.terminate();keeper.wait(timeout=5)
        if server.poll() is None: server.terminate();server.wait(timeout=3)
        # Namespace PID 1 exiting terminates remaining fixture daemon children.

if __name__=='__main__': main()
