#!/usr/bin/env python3
"""Probe server for the Witcher carrier picker (radio profile `carrier_pick`).

Run it on a host the units reach through their management bearer, such as the
packet core. Each unit opens one TCP control connection per measurement:

  WITCHER-PROBE 1 DL <ms> <kbps> <udp_port>  ->  OK, a UDP burst to the unit,
                                                  then DONE <bytes_sent>
  WITCHER-PROBE 1 UL <ms>                    ->  OK <udp_port>, count the
                                                  unit's burst, then
                                                  RESULT <bytes> <span_ms>

A download burst only ever goes to the address that opened the connection,
and rate, duration and concurrency are capped. The unit measures a download at
its bearer's receive counter, so offer more than any carrier rate.

  carrier-probe-server.py --listen 0.0.0.0:5310 --allow 172.20.0.0/16 \\
      --ul-port 5311

Open TCP on the listen port and UDP on the upload port to the units'
management addresses. Python 3.8 or later, standard library only.
"""
import argparse
import ipaddress
import socket
import socketserver
import threading
import time

MAGIC = ('WITCHER-PROBE', '1')
PAYLOAD = b'\0' * 1300


def parse_args(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('--listen', default='0.0.0.0:5310', help='address:port for control connections')
    ap.add_argument('--allow', action='append', default=[], help='client network, repeatable (default: any)')
    ap.add_argument('--ul-port', type=int, default=0, help='fixed UDP port for uploads (default: ephemeral)')
    ap.add_argument('--max-ms', type=int, default=5000, help='longest burst')
    ap.add_argument('--max-dl-kbps', type=int, default=400_000, help='highest download offer')
    ap.add_argument('--max-tests', type=int, default=2, help='bursts at the same time')
    return ap.parse_args(argv)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, args):
        host, port = args.listen.rsplit(':', 1)
        self.args = args
        self.allowed = [ipaddress.ip_network(n, strict=False) for n in args.allow]
        self.slots = threading.BoundedSemaphore(args.max_tests)
        self.ul_lock = threading.Lock()
        super().__init__((host, int(port)), Handler)


class Handler(socketserver.StreamRequestHandler):
    timeout = 10

    def reply(self, text):
        self.wfile.write((text + '\n').encode())
        self.wfile.flush()

    def handle(self):
        srv, args = self.server, self.server.args
        peer = self.client_address[0]
        try:
            line = self.rfile.readline(256).decode('ascii', 'replace').split()
        except (OSError, socket.timeout):
            return
        if srv.allowed and not any(ipaddress.ip_address(peer) in n for n in srv.allowed):
            return self.reply('ERR not allowed')
        if len(line) < 4 or tuple(line[:2]) != MAGIC:
            return self.reply('ERR bad request')
        try:
            numbers = [int(x) for x in line[3:]]
        except ValueError:
            return self.reply('ERR bad request')
        kind = line[2]
        if not srv.slots.acquire(blocking=False):
            return self.reply('ERR busy')
        try:
            if kind == 'DL' and len(numbers) == 3:
                ms, kbps, port = numbers
                if not (100 <= ms <= args.max_ms and 1000 <= kbps <= args.max_dl_kbps and 0 < port < 65536):
                    return self.reply('ERR out of range')
                self.reply('OK')
                self.reply('DONE %d' % send_burst(self.request.getsockname()[0], (peer, port), ms, kbps))
            elif kind == 'UL' and len(numbers) == 1:
                ms = numbers[0]
                if not 100 <= ms <= args.max_ms:
                    return self.reply('ERR out of range')
                with srv.ul_lock if args.ul_port else nullcontext():
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
                    sock.bind((self.request.getsockname()[0], args.ul_port))
                    try:
                        self.reply('OK %d' % sock.getsockname()[1])
                        self.reply('RESULT %d %d' % count_burst(sock, peer, ms))
                    finally:
                        sock.close()
            else:
                self.reply('ERR bad request')
        except OSError:
            pass
        finally:
            srv.slots.release()


class nullcontext:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def send_burst(local_ip, dest, ms, kbps):
    """Paced UDP for ms at kbps to dest only. Returns bytes sent."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((local_ip, 0))
    per_ms = kbps * 1000 / 8 / 1000 / len(PAYLOAD)
    start = time.monotonic()
    sent = 0
    owed = 0.0
    try:
        while True:
            elapsed = time.monotonic() - start
            if elapsed * 1000 >= ms:
                break
            owed = elapsed * 1000 * per_ms - sent / len(PAYLOAD)
            for _ in range(int(owed)):
                try:
                    sent += sock.sendto(PAYLOAD, dest)
                except (BlockingIOError, OSError):
                    break
            time.sleep(0.001)
    finally:
        sock.close()
    return sent


def count_burst(sock, peer, ms):
    """Bytes from peer and the first-to-last arrival span in ms."""
    sock.settimeout(0.2)
    deadline = time.monotonic() + ms / 1000 + 1.5
    first = last = None
    total = 0
    while time.monotonic() < deadline:
        try:
            data, addr = sock.recvfrom(65536)
        except socket.timeout:
            if last is not None and time.monotonic() - last > 1.0:
                break
            continue
        if addr[0] != peer:
            continue
        now = time.monotonic()
        first = now if first is None else first
        last = now
        total += len(data)
    span = int(round((last - first) * 1000)) if first is not None else 0
    return total, span


def main(argv=None):
    args = parse_args(argv)
    server = Server(args)
    print('carrier probe server on %s' % args.listen, flush=True)
    server.serve_forever()


if __name__ == '__main__':
    main()
