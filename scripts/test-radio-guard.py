#!/usr/bin/env python3
"""Run the real keeper's radio profile guard against a stub modem console.

v1.0.17 (lane F1): no transient condition may leave a radio profile off once
it clears. This drives `titan-pd-keeper opt-guard` and its workers in their own
mount, network and PID namespaces:

- the vendor RAM cache `/tmp/nvram.cfg` and the `lted` socket on fresh tmpfs
  mounts, a dummy `lte0pdn0` with an address for the management bearer;
- a stub `lted_cli` that keeps the modem's carrier cap and RRC counter in a
  file, refuses the stock cap while `/tmp/refuse-stock` exists, and records
  every command and any two sessions open at once;
- `ping` answers while `/tmp/ping-ok` exists; `pidof` and `reboot` are stubs.

It checks, against the landmines lane L1/L2/L3 found:

1. a tower down at boot is "not tried": nothing written or counted, and the
   profile applies once the unit attaches;
2. a record a v1.0.16 unit left (a bare `3`, which locked) reads as none;
3. a management blip while the profile runs reverts nothing;
4. a held modem console (a flag session) judges nothing, and no two console
   sessions ever overlap;
5. three boots whose trials a power cut ends never lock the profile, and the
   next boot confirms it;
6. a failed stock restore keeps the operator's saved profile, never reboots
   on its own, and is retried until stock settings are back;
7. a lock clears itself on a new firmware.

The old guard cannot run here (it needs the ubifs Witcher volume). Lane L3's
`models/radio_guard_model.py` reproduces its locks; the Rust model tests in
`pd-model/src/radio_guard.rs` cover the same scenarios with the timings.
"""
import fcntl
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import time

REPO = Path(__file__).resolve().parent.parent
BINARY = REPO/'userspace/target/debug/titan-pd-keeper'
RAM = Path('/tmp/titan-pd-keeper')
DISK = Path('/tmp/radio')
PROFILE = {
    'version': 1,
    'management_probe': '192.0.2.1',
    'actions': [{'kind': 'carrier_aggregation', 'carriers': 2}],
}

LTED_CLI = r'''#!/usr/bin/env python3
import json, os, sys
STATE = '/tmp/modem.json'
def load():
    try:
        return json.load(open(STATE))
    except (OSError, ValueError):
        return {'cap': 4, 'failures': 0}
def save(s):
    open(STATE + '.tmp', 'w').write(json.dumps(s))
    os.replace(STATE + '.tmp', STATE)
try:
    os.close(os.open('/tmp/console-active', os.O_CREAT | os.O_EXCL))
except FileExistsError:
    open('/tmp/console-overlap', 'a').write('overlap\n')
log = open('/tmp/console-log', 'a')
for line in sys.stdin:
    cmd = line.strip()
    if cmd == 'exit':
        break
    log.write(cmd + '\n'); log.flush()
    s = load()
    out = []
    if cmd.startswith('arm1log'):
        pass
    elif cmd == 'AT%GCACTRL?':
        n = s['cap']
        out = ['%%GCACTRL: %d, 4, 3, %d' % (0 if n == 1 else 3, n), 'OK']
    elif cmd.startswith('AT%GCACTRL='):
        value = cmd.split('=', 1)[1]
        if value == '3,4' and os.path.exists('/tmp/refuse-stock'):
            out = ['ERROR']
        else:
            s['cap'] = 1 if value == '0' else int(value.split(',')[1])
            save(s)
            out = ['OK']
    elif cmd == 'rrc dm reest stat ?':
        out = ['      - Reconfig Failure   : %d' % s['failures']]
    elif cmd.startswith(('AT+CFUN=', 'AT%GLOCKPCELL=')):
        out = ['OK']
    elif cmd == 'AT%GLOCKPCELL?':
        out = ['%GLOCKPCELL: 0', 'OK']
    else:
        out = ['ERROR']
    for o in out:
        print(o)
    sys.stdout.flush()
os.unlink('/tmp/console-active')
'''


def run(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL)


def exe(path, text):
    p = Path(path)
    p.write_text(text)
    p.chmod(0o755)


def nvram(media):
    Path('/tmp/nvram.cfg.new').write_text('\n'.join([
        'sqns_identity_boardName=GDM7243AP-ODU-E-B48',
        'sqns_connection_mediaState=' + media,
        'cbrs_mode_grant=1',
        'cbrs_grant_state=2',
        'sqns_connection_sccInfo=-',
    ]) + '\n')
    Path('/tmp/nvram.cfg.new').replace('/tmp/nvram.cfg')


def modem():
    return json.loads(Path('/tmp/modem.json').read_text()) if Path('/tmp/modem.json').exists() else {'cap': 4, 'failures': 0}


def set_modem(**values):
    state = modem()
    state.update(values)
    Path('/tmp/modem.json').write_text(json.dumps(state))


def console_log():
    p = Path('/tmp/console-log')
    return p.read_text().splitlines() if p.exists() else []


def status():
    try:
        return json.loads((RAM/'radio-status').read_text())
    except (OSError, ValueError):
        return {}


def record():
    p = DISK/'strikes'
    return dict(line.split('=', 1) for line in p.read_text().splitlines() if '=' in line) if p.exists() else {}


def log():
    p = Path('/tmp/pd/keeper.log')
    return p.read_text() if p.exists() else ''


class Guard:
    def __init__(self, env):
        self.env = env
        self.proc = None

    def start(self):
        self.proc = subprocess.Popen([str(RAM/'titan-pd-keeper'), 'opt-guard'], env=self.env,
                                     stdout=subprocess.DEVNULL, stderr=open('/tmp/guard.err', 'a'),
                                     start_new_session=True)

    def kill(self):
        """A power cut: the guard, its workers and their consoles die."""
        if self.proc and self.proc.poll() is None:
            os.killpg(self.proc.pid, signal.SIGKILL)
            self.proc.wait()
        subprocess.run(['pkill', '-KILL', '-f', 'radio-worker'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1)
        Path('/tmp/console-active').unlink(missing_ok=True)

    def reboot(self):
        """A reboot: RAM state and modem RAM go, the volume stays."""
        self.kill()
        for p in RAM.iterdir():
            if p.name != 'titan-pd-keeper':
                p.unlink()
        set_modem(cap=4, failures=0)


def wait_for(what, predicate, seconds, guard=None):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        if guard and guard.proc.poll() is not None:
            raise AssertionError('guard exited: ' + Path('/tmp/guard.err').read_text() + log())
        time.sleep(0.5)
    raise AssertionError('Timed out waiting for %s: status %r record %r modem %r\n%s\n%s' % (
        what, status(), record(), modem(), '\n'.join(console_log()[-20:]), log()))


def hold_for(predicate_seconds, guard):
    """Watch for this long that the profile stays up."""
    until = time.monotonic() + predicate_seconds
    while time.monotonic() < until:
        assert status().get('phase') == 'active', status()
        assert modem()['cap'] == 2, modem()
        if guard.proc.poll() is not None:
            raise AssertionError('guard exited: ' + Path('/tmp/guard.err').read_text())
        time.sleep(0.5)


def main():
    if '--inner' not in sys.argv:
        if os.geteuid() != 0:
            raise SystemExit('Run as root; this test creates isolated mount/network/PID namespaces.')
        subprocess.run(['unshare', '--mount', '--net', '--pid', '--fork', '--mount-proc',
                        sys.executable, __file__, '--inner'], check=True, timeout=1800)
        return
    run('mount', '--make-rprivate', '/')
    for point in ('/tmp', '/var/tmp', '/run'):
        run('mount', '-t', 'tmpfs', 'tmpfs', point)
    run('mount', '-t', 'sysfs', 'sysfs', '/sys')
    ip = shutil.which('ip')
    run(ip, 'link', 'set', 'lo', 'up')
    run(ip, 'link', 'add', 'lte0pdn0', 'type', 'dummy')
    run(ip, 'addr', 'add', '192.0.2.2/24', 'dev', 'lte0pdn0')
    run(ip, 'link', 'set', 'lte0pdn0', 'up')
    Path('/tmp/bin').mkdir()
    exe('/tmp/bin/lted_cli', LTED_CLI)
    exe('/tmp/bin/ping', '#!/bin/sh\n[ -e /tmp/ping-ok ]\n')
    exe('/tmp/bin/pidof', '#!/bin/sh\nexit 0\n')
    exe('/tmp/bin/reboot', '#!/bin/sh\necho "reboot $*" >> /tmp/reboot-calls\n')
    lted = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    lted.bind('/var/tmp/lted-daemon')
    RAM.mkdir(mode=0o700)
    shutil.copy2(BINARY, RAM/'titan-pd-keeper')
    DISK.mkdir()
    Path('/tmp/pd').mkdir()
    Path('/tmp/witcher-release').write_text('witcher v1.0.17 test build A\n')
    env = dict(os.environ, PATH='/tmp/bin:' + os.environ['PATH'], TITAN_RADIO_DIR=str(DISK),
               TITAN_PD_STATE='/tmp/pd', TITAN_PD_RUNTIME=str(RAM), TITAN_LTED_CLI='/tmp/bin/lted_cli',
               TITAN_WITCHER_RELEASE='/tmp/witcher-release', TITAN_TK_QUIET_UTC='')
    guard = Guard(env)
    try:
        # 1. The tower is down at boot. A v1.0.16 record says 3 strikes,
        # which locked the profile for good there.
        nvram('SEARCHING')
        Path('/tmp/ping-ok').touch()
        (DISK/'profile.json').write_text(json.dumps(PROFILE))
        (DISK/'strikes').write_text('3')
        guard.start()
        wait_for('not tried', lambda: 'not attached' in status().get('detail', ''), 60, guard)
        time.sleep(35)
        assert status()['phase'] == 'waiting' and 'not tried' in status()['detail'], status()
        assert not any(c.startswith('AT%GCACTRL=') for c in console_log()), console_log()
        assert (DISK/'strikes').read_text() == '3', 'a trial that never started wrote its record'
        print('PASS: a tower down at boot is not tried: no write to the modem, nothing counted.', flush=True)
        nvram('ATTACHED')
        attached = time.monotonic()
        wait_for('the profile confirmed', lambda: status().get('phase') == 'active', 150, guard)
        took = time.monotonic() - attached
        assert modem()['cap'] == 2, modem()
        assert record().get('strikes') == '0' and record().get('tries') == '0', record()
        print('PASS: once attached the profile applied and confirmed in %.0f s; the v1.0.16 record of 3 strikes read as none.' % took, flush=True)

        # 2. A management blip while the profile runs: under v1.0.16 one
        # missed check (two pings 3 s apart) reverted it for the boot.
        Path('/tmp/ping-ok').unlink()
        wait_for('a missed check', lambda: 'not answering' in status().get('detail', ''), 60, guard)
        hold_for(20, guard)
        Path('/tmp/ping-ok').touch()
        wait_for('answers again', lambda: status().get('detail') == 'management answers again', 60, guard)
        assert modem()['cap'] == 2 and 'AT%GCACTRL=3,4' not in console_log(), console_log()
        print('PASS: a management blip of a minute reverted nothing; the guard waits for 5 minutes of loss.', flush=True)

        # 3. A flag session holds the modem console across a check.
        lock = os.open(RAM/'console.lock', os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX)
        held_at = len(console_log())
        hold_for(45, guard)
        assert len(console_log()) == held_at, 'a console session ran while another held the console'
        fcntl.flock(lock, fcntl.LOCK_UN)
        os.close(lock)
        wait_for('the next check', lambda: len(console_log()) > held_at, 60, guard)
        assert status()['phase'] == 'active', status()
        assert not Path('/tmp/console-overlap').exists(), 'two console sessions overlapped'
        print('PASS: a held modem console judged nothing, no session ran meanwhile, and none ever overlapped.', flush=True)

        # 4. Flapping power: three boots whose trial a power cut ends.
        # Under v1.0.16 each counted a strike before the trial, and three
        # locked the profile until an operator saved Off.
        for boot in range(1, 4):
            guard.reboot()
            nvram('ATTACHED')
            writes = console_log().count('AT%GCACTRL=3,2')
            guard.start()
            wait_for('trial %d writing' % boot, lambda: console_log().count('AT%GCACTRL=3,2') > writes, 1500, guard)
            guard.kill()
            assert record().get('strikes') == '0' and record().get('tries') == str(boot), record()
        guard.reboot()
        nvram('ATTACHED')
        uptime = float(Path('/proc/uptime').read_text().split()[0])
        guard.start()
        # The next trial waits 20 minutes of uptime after three cut short.
        wait_for('the profile after the storm', lambda: status().get('phase') == 'active', max(0, 1200 - uptime) + 150, guard)
        assert record().get('strikes') == '0' and record().get('tries') == '0', record()
        print('PASS: three boots cut short by power cuts never locked the profile; the next boot confirmed it.', flush=True)

        # 5. A failed stock restore. Under v1.0.16 one failure overwrote the
        # saved profile with an empty one and rebooted at once, at any hour.
        saved = (DISK/'profile.json').read_bytes()
        Path('/tmp/refuse-stock').touch()
        set_modem(failures=modem()['failures'] + 2)
        wait_for('a failed restore', lambda: status().get('phase') == 'recovery', 90, guard)
        wait_for('a second restore', lambda: 'failed 2 times' in status().get('detail', ''), 120, guard)
        assert (DISK/'profile.json').read_bytes() == saved, 'the saved profile was changed'
        assert not Path('/tmp/reboot-calls').exists(), Path('/tmp/reboot-calls').read_text()
        assert record().get('strikes') == '0', record()
        Path('/tmp/refuse-stock').unlink()
        wait_for('stock settings back', lambda: modem()['cap'] == 4, 600, guard)
        wait_for('the restore settled', lambda: not (RAM/'radio-journal').exists(), 60, guard)
        assert (DISK/'profile.json').read_bytes() == saved
        assert not Path('/tmp/reboot-calls').exists()
        assert not (RAM/'radio-reboot').exists(), 'a restart was asked for before ten minutes of failures'
        print('PASS: a failed stock restore kept the saved profile, never rebooted, and was retried until stock was back.', flush=True)

        # 6. A lock that comparative strikes set clears itself on a new
        # firmware build.
        guard.kill()
        stamp = record()
        assert stamp.get('profile') and stamp.get('firmware'), stamp
        (DISK/'strikes').write_text('strikes=3\ntries=0\nprofile=%s\nfirmware=%s\n' % (stamp['profile'], stamp['firmware']))
        guard.reboot()
        nvram('ATTACHED')
        guard.start()
        wait_for('locked', lambda: status().get('phase') == 'locked', 60, guard)
        guard.reboot()
        Path('/tmp/witcher-release').write_text('witcher v1.0.17 test build B\n')
        nvram('ATTACHED')
        guard.start()
        wait_for('the profile on a new firmware', lambda: status().get('phase') == 'active', 150, guard)
        print('PASS: a locked profile stayed locked under the same firmware and applied on a new one.', flush=True)
        assert not Path('/tmp/console-overlap').exists(), 'two console sessions overlapped'
    finally:
        guard.kill()


if __name__ == '__main__':
    main()
