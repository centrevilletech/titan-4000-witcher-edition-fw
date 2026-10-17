#!/usr/bin/env python3
"""Run the real keeper against a veth ARP peer. No host or Titan networking.

Requires root namespace capabilities. PHY action is a recording stub: this
proves packet detection/escalation, not a physical Titan cable disconnect.
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
                        sys.executable, __file__, '--inner'], check=True, timeout=210)
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
    exe('/tmp/bin/nvram_get', 'echo 1')
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
    env=dict(os.environ,PATH='/tmp/bin:'+os.environ['PATH'],TITAN_EBTABLES='/tmp/bin/ebtables',TITAN_PD_STATE='/tmp/pd',TITAN_PD_RUNTIME='/tmp/runtime')
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
        assert not Path('/tmp/phy-actions').exists()
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
        print(log(),flush=True)
    finally:
        keeper.terminate();keeper.wait(timeout=5)
        if server.poll() is None: server.terminate();server.wait(timeout=3)
        # Namespace PID 1 exiting terminates remaining fixture daemon children.

if __name__=='__main__': main()
