#!/usr/bin/env python3
"""Real packet and helper tests. Run as root through `unshare -n` ONLY.

All interfaces, routes and firewall changes stay in disposable namespaces.
The host-built helper runs in a temporary chroot with fixture authentication.
"""
import http.server
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import threading
import time

REPO = Path(__file__).resolve().parent.parent
assert os.geteuid() == 0, 'Run in an isolated root network namespace'
assert os.readlink('/proc/self/ns/net') != os.readlink(f'/proc/{os.getppid()}/ns/net'), 'Refusing to change the parent network namespace'
os.environ['PATH'] = '/usr/sbin:/usr/bin:/sbin:/bin'
children = []


def run(*args, **kw):
    result = subprocess.run(args, capture_output=True, text=True, **kw)
    if result.returncode:
        print(result.stderr, flush=True)
        result.check_returncode()
    return result.stdout.strip()


def copy_binary(source, root, destination):
    target = root / destination.lstrip('/')
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    target.chmod(0o755)
    output = run('ldd', str(source))
    for name in re.findall(r'(/[^\s()]+)', output):
        dep = root / name.lstrip('/')
        dep.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(name, dep)
        dep.chmod(0o755)


def client(interface, server_ip, client_ip, bridge=False):
    process = subprocess.Popen(['unshare', '-n', 'sleep', '600'])
    children.append(process)
    end = time.monotonic() + 5
    while os.readlink(f'/proc/{process.pid}/ns/net') == os.readlink('/proc/self/ns/net'):
        assert time.monotonic() < end
        time.sleep(0.01)
    peer = 'p' + interface
    run('ip', 'link', 'add', interface, 'type', 'veth', 'peer', 'name', peer)
    run('ip', 'link', 'set', peer, 'netns', str(process.pid))
    if bridge:
        run('ip', 'link', 'set', interface, 'master', 'br0')
    run('ip', 'link', 'set', interface, 'up')
    run('ip', 'addr', 'add', server_ip + '/24', 'dev', 'br0' if bridge else interface)
    run('nsenter', '-t', str(process.pid), '-n', 'ip', 'link', 'set', 'lo', 'up')
    run('nsenter', '-t', str(process.pid), '-n', 'ip', 'addr', 'add', client_ip + '/24', 'dev', peer)
    run('nsenter', '-t', str(process.pid), '-n', 'ip', 'link', 'set', peer, 'up')
    return process.pid, server_ip


def request(peer, port, method='GET', payload=None):
    pid, address = peer
    code = '''import http.client,json,sys
address,port,method,body=sys.argv[1],int(sys.argv[2]),sys.argv[3],sys.argv[4]
authority=address if port==80 else f'{address}:{port}'
conn=http.client.HTTPConnection(address,port,timeout=4)
conn.request(method,'/configure' if method=='POST' else '/',body=body or None,
 headers={'Host':authority,'Origin':'http://'+authority,'Content-Type':'application/json','X-Witcher-Setup':'1'})
r=conn.getresponse(); data=r.read().decode(); print(json.dumps({'status':r.status,'body':data}))
'''
    result = run('nsenter', '-t', str(pid), '-n', 'python3', '-c', code,
                 address, str(port), method, json.dumps(payload) if payload else '', timeout=8)
    return json.loads(result)


def apply_rules(script):
    run('sh', str(script), 'all')


def legacy_blocks():
    for chain in ('INPUT', 'OUTPUT'):
        run('iptables', '-I', chain, '1', '-p', 'tcp', '-j', 'DROP')
        match = '--ip-dport' if chain == 'INPUT' else '--ip-sport'
        run('ebtables', '-I', chain, '1', '-p', 'IPv4', '--ip-proto', '6', match, '80', '-j', 'DROP')
    run('iptables', '-t', 'nat', '-I', 'PREROUTING', '1', '-p', 'tcp', '--dport', '80', '-j', 'REDIRECT', '--to-ports', '9999')


def start_helper(root, mode):
    process = subprocess.Popen(['chroot', str(root), '/helper', mode], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    children.append(process)
    time.sleep(0.15)
    assert process.poll() is None, process.stderr.read().decode() if process.poll() is not None else ''
    return process


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'fixture service'
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


try:
    with tempfile.TemporaryDirectory(prefix='witcher-network-') as temp:
        root = Path(temp)
        for directory in ('tmp', 'dev', 'mnt/titan-api', 'etc/init.d', 'usr/lib/titan-api'):
            (root / directory).mkdir(parents=True, exist_ok=True)
        (root/'mnt/titan-api').chmod(0o700)
        import stat
        os.mknod(root/'dev/null', stat.S_IFCHR | 0o666, os.makedev(1, 3))
        copy_binary(Path('/bin/sh').resolve(), root, '/bin/sh')
        copy_binary(REPO/'userspace/target/debug/witcher-firstboot', root, '/helper')
        # Rules are installed and tested in the parent namespace. Only the
        # helper's fixed command paths and NVRAM password source are fixtures.
        for name, body in {
            'etc/init.d/witcher-management-access': 'exit 0',
            'etc/init.d/titan-api': 'echo "$1" > /tmp/action',
            'usr/lib/titan-api/titan-nvram': 'echo \'{"http_passwd":"fixture-password"}\'',
        }.items():
            p = root/name
            p.write_text('#!/bin/sh\n' + body + '\n')
            p.chmod(0o755)
        # Relocate only tool paths and the RAM lock; execute the real rule script.
        script = root/'access.sh'
        source = (REPO/'overlay/etc/init.d/witcher-management-access').read_text()
        source = source.replace('/tmp/witcher-management-access.lock', str(root/'access.lock'))
        for binary in ('iptables-restore', 'iptables', 'ebtables'):
            source = re.sub(r'/(?:usr/)?bin/' + re.escape(binary) + r'(?=\n)', shutil.which(binary), source)
        script.write_text(source)
        run('ip', 'link', 'set', 'lo', 'up')
        run('ip', 'link', 'add', 'br0', 'type', 'bridge')
        run('ip', 'link', 'set', 'br0', 'up')
        lan = client('eth0', '192.168.0.1', '192.168.0.2', bridge=True)
        # Native HTTPS and SSH listeners are represented by TCP/HTTP fixtures;
        # setup/recovery below use the real compiled firstboot program.
        for port in (443, 2222):
            server = http.server.ThreadingHTTPServer(('0.0.0.0', port), Handler)
            threading.Thread(target=server.serve_forever, daemon=True).start()
        recovery = start_helper(root, 'recovery')
        peers = [lan]
        for topology in ('NAT, no APN', 'NAT, single APN', 'NAT, dual APN', 'passthrough, dual APN'):
            if topology == 'NAT, single APN':
                peers.append(client('lte0pdn1', '172.20.64.141', '172.20.64.1'))
            elif topology == 'NAT, dual APN':
                peers.append(client('lte0pdn0', '172.20.0.141', '172.20.0.1'))
            elif topology.startswith('passthrough'):
                run('ip', 'addr', 'flush', 'dev', 'lte0pdn1')
                run('ip', 'link', 'set', 'lte0pdn1', 'master', 'br0')
                run('ip', 'addr', 'add', '172.20.64.141/24', 'dev', 'br0')
            legacy_blocks()
            forwarded_before = run('iptables', '-S', 'FORWARD')
            bridge_before = run('ebtables', '-L', 'FORWARD')
            apply_rules(script)
            apply_rules(script)  # repeated maintenance must not undo access
            assert run('iptables', '-S', 'FORWARD') == forwarded_before
            assert run('ebtables', '-L', 'FORWARD') == bridge_before
            setup = start_helper(root, 'setup')
            for peer in peers:
                for port in (80, 443, 8081, 2222):
                    result = request(peer, port)
                    assert result['status'] == 200, (topology, peer, port, result)
                    if port in (80, 8081):
                        assert 'Witcher v' in result['body']
                if topology == 'NAT, no APN':
                    result = request(peer, 8081, 'POST', {'password':'wrong', 'action':'native'})
                    assert result['status'] == 401
            if topology.startswith('passthrough'):
                result = request(peers[-1], 8081, 'POST', {'password':'fixture-password', 'action':'native'})
                assert result['status'] == 200
            seed = os.urandom(64)
            result = request(peers[-1], 80, 'POST', {'password':'fixture-password', 'action':'setup', 'seed':seed.hex()})
            assert result['status'] == 200
            assert setup.wait(timeout=3) == 0
            saved = root/'mnt/titan-api/seed'
            assert saved.read_bytes() == seed
            assert saved.stat().st_mode & 0o777 == 0o600
            saved.unlink()
            print('PASS:', topology, 'all assigned addresses; authenticated setup/recovery; inherited blocks overridden; forwarding unchanged', flush=True)
finally:
    for process in reversed(children):
        if process.poll() is None:
            process.terminate()
    for process in reversed(children):
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
