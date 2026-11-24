#!/usr/bin/env python3
"""The carrier picker's probe server, on loopback: a download burst arrives at
the asked rate and only at the caller, an upload is counted, and bad, oversized
or excess requests are refused. Standard library only; no root."""
import importlib.util
import socket
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('probe', HERE / 'carrier-probe-server.py')
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


def start(*extra):
    args = probe.parse_args(['--listen', '127.0.0.1:0', '--max-tests', '1', *extra])
    server = probe.Server(args)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


def control(port, line):
    c = socket.create_connection(('127.0.0.1', port), timeout=10)
    c.sendall(line.encode())
    return c, c.makefile('r')


def main():
    server, port = start()
    # Download: 800 ms at 20 Mbps to our UDP socket.
    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 << 20)
    rx.bind(('127.0.0.1', 0))
    rx.settimeout(0.3)
    c, f = control(port, 'WITCHER-PROBE 1 DL 800 20000 %d\n' % rx.getsockname()[1])
    assert f.readline().strip() == 'OK'
    got = 0
    end = time.monotonic() + 2
    while time.monotonic() < end:
        try:
            got += len(rx.recv(65536))
        except socket.timeout:
            if got:
                break
    done = f.readline().split()
    assert done[0] == 'DONE', done
    sent = int(done[1])
    assert 1_400_000 <= sent <= 2_600_000, sent
    assert got >= sent * 0.9, (got, sent)
    c.close()
    print('PASS: a download burst arrived at the asked rate (%d bytes in 0.8 s).' % sent, flush=True)

    # Upload: we send about 1 MB over 0.8 s; the server counts it.
    c, f = control(port, 'WITCHER-PROBE 1 UL 800\n')
    ok = f.readline().split()
    assert ok[0] == 'OK' and int(ok[1]) > 0, ok
    tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = b'\0' * 1000
    for _ in range(40):
        for _ in range(25):
            tx.sendto(payload, ('127.0.0.1', int(ok[1])))
        time.sleep(0.02)
    result = f.readline().split()
    assert result[0] == 'RESULT', result
    counted, span = int(result[1]), int(result[2])
    assert counted >= 900_000 and 600 <= span <= 1200, (counted, span)
    c.close()
    print('PASS: an upload burst was counted (%d bytes over %d ms).' % (counted, span), flush=True)

    # Refusals: bad magic, out of range, unknown kind.
    for line, want in [('HELLO\n', 'ERR bad request'),
                       ('WITCHER-PROBE 1 DL 60000 20000 5000\n', 'ERR out of range'),
                       ('WITCHER-PROBE 1 DL 800 900000 5000\n', 'ERR out of range'),
                       ('WITCHER-PROBE 1 UL 50\n', 'ERR out of range'),
                       ('WITCHER-PROBE 1 XX 800\n', 'ERR bad request')]:
        c, f = control(port, line)
        assert f.readline().strip() == want, line
        c.close()
    print('PASS: malformed and oversized requests are refused.', flush=True)

    # One slot: a second burst while one runs is refused.
    c1, f1 = control(port, 'WITCHER-PROBE 1 UL 1500\n')
    assert f1.readline().startswith('OK')
    c2, f2 = control(port, 'WITCHER-PROBE 1 UL 800\n')
    assert f2.readline().strip() == 'ERR busy'
    c1.close()
    c2.close()
    print('PASS: bursts beyond the concurrency limit are refused.', flush=True)
    server.shutdown()

    # An allow-list that excludes loopback refuses everything.
    server, port = start('--allow', '192.0.2.0/24')
    c, f = control(port, 'WITCHER-PROBE 1 UL 800\n')
    assert f.readline().strip() == 'ERR not allowed'
    c.close()
    server.shutdown()
    print('PASS: clients outside the allow-list are refused.', flush=True)


if __name__ == '__main__':
    main()
