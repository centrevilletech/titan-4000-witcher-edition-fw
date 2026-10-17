#!/usr/bin/env python3
"""Run real first-boot shell code against a temporary fake device. No host mounts."""
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile
import time
import unittest

REPO = Path(__file__).resolve().parent.parent


class FirstBootTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in ('bin', 'tmp', 'mnt', 'proc', 'sys/class/ubi/ubi1', 'sys/class/ubi/ubi1_0'):
            (self.root / name).mkdir(parents=True, exist_ok=True)
        self.env = dict(os.environ, FIXTURE_ROOT=str(self.root), PATH=f'{self.root}/bin:{os.environ["PATH"]}')
        self.write('proc/mounts', f'ubi1:cbrs {self.root}/mnt ubifs rw 0 0\n')
        self.write('proc/mtd', 'mtd20: 04000000 00020000 "user"\n')
        for name, value in [('ubi1/mtd_num', '20'), ('ubi1/avail_eraseblocks', '451'),
                            ('ubi1/eraseblock_size', '126976'), ('ubi1_0/name', 'cbrs')]:
            self.write('sys/class/ubi/' + name, value + '\n')
        for name, source in {
            'id': 'echo 0', 'chown': 'exit 0', 'sync': 'exit 0', 'sleep': 'exit 0',
            'ubimkvol': 'echo "$*" >> "$FIXTURE_ROOT/allocations"; mkdir -p "$FIXTURE_ROOT/sys/class/ubi/ubi1_1"; echo data > "$FIXTURE_ROOT/sys/class/ubi/ubi1_1/name"',
            'mount': '[ "${FAIL_MOUNT:-0}" = 0 ] || exit 1; echo "ubi1:data $FIXTURE_ROOT/mnt/titan-api ubifs rw 0 0" >> "$FIXTURE_ROOT/proc/mounts"',
            'openssl': 'if [ "$1" = rand ]; then printf "%032x" $$; exit 0; fi; [ "$1" != req ] || echo generate >> "$FIXTURE_ROOT/tls-calls"; while [ "$#" -gt 0 ]; do case "$1" in -keyout) shift; echo private > "$1";; -out) shift; [ "${FAIL_CERT:-0}" = 0 ] || exit 1; echo certificate > "$1";; esac; shift; done',
        }.items():
            path = self.write('bin/' + name, '#!/bin/sh\nset -eu\n' + source + '\n')
            path.chmod(0o755)

    def write(self, name, text):
        p = self.root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        return p

    def run_script(self, name, *args, **env):
        text = (REPO / 'overlay' / name).read_text()
        text = text.replace('export PATH=/sbin:/usr/sbin:/bin:/usr/bin', '')
        text = re.sub(r'/(?:mnt|sys|proc|tmp)(?=[/\s\"\'])', lambda m: str(self.root) + m.group(), text)
        script = self.write('fixture.sh', text)
        return subprocess.run(['sh', str(script), *args], env=dict(self.env, **env), capture_output=True, text=True, timeout=10)

    def state(self, **env):
        return self.run_script('etc/init.d/witcher-state', 'mount', **env)

    def test_fresh_storage_and_repeat_preserve_data(self):
        result = self.state()
        self.assertEqual(result.returncode, 0, result.stderr)
        key = self.write('mnt/titan-api/ssh/operator-key', 'keep me')
        self.assertEqual(self.state().returncode, 0)
        self.assertEqual(key.read_text(), 'keep me')
        self.assertEqual(len((self.root/'allocations').read_text().splitlines()), 1)
        self.assertEqual((self.root/'mnt/titan-api').stat().st_mode & 0o777, 0o700)

    def test_interrupted_mount_reuses_existing_volume(self):
        self.assertNotEqual(self.state(FAIL_MOUNT='1').returncode, 0)
        self.assertEqual(self.state().returncode, 0)
        self.assertEqual(len((self.root/'allocations').read_text().splitlines()), 1)

    def test_wrong_partition_or_low_space_never_allocates(self):
        for name, value in [('sys/class/ubi/ubi1/mtd_num', '16'), ('sys/class/ubi/ubi1/avail_eraseblocks', '4')]:
            path = self.root/name
            original = path.read_text()
            path.write_text(value)
            self.assertNotEqual(self.state().returncode, 0)
            self.assertFalse((self.root/'allocations').exists())
            path.write_text(original)

    def test_unmounted_legacy_state_is_not_hidden_or_overwritten(self):
        old = self.write('mnt/titan-api/seed', 'old seed')
        self.assertNotEqual(self.state().returncode, 0)
        self.assertEqual(old.read_text(), 'old seed')
        self.assertFalse((self.root/'allocations').exists())

    def test_symlink_state_is_rejected(self):
        (self.root/'mnt/titan-api').symlink_to(self.root/'tmp', target_is_directory=True)
        self.assertNotEqual(self.state().returncode, 0)
        self.assertFalse((self.root/'allocations').exists())

    def tls(self, **env):
        return self.run_script('usr/lib/titan-api/prepare-tls.sh', **env)

    def test_tls_published_as_pair_and_reused(self):
        (self.root/'mnt/titan-api/tls').mkdir(parents=True)
        result = self.tls()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.tls().returncode, 0)
        self.assertEqual((self.root/'tls-calls').read_text(), 'generate\n')
        current = self.root/'mnt/titan-api/tls/current'
        self.assertEqual((current/'key.pem').stat().st_mode & 0o777, 0o600)
        self.assertTrue((current/'cert.pem').is_file())

    def test_tls_generation_failure_leaves_no_partial_identity(self):
        tls = self.root/'mnt/titan-api/tls'
        tls.mkdir(parents=True)
        self.assertNotEqual(self.tls(FAIL_CERT='1').returncode, 0)
        self.assertFalse((tls/'current').exists())
        self.assertEqual(self.tls().returncode, 0)

    def test_real_certificate_uses_named_curve_and_clock_independent_dates(self):
        # Exercise the real script/tool interaction, not just the OpenSSL stub.
        (self.root/'bin/openssl').unlink()
        (self.root/'mnt/titan-api/tls').mkdir(parents=True)
        result = self.tls()
        self.assertEqual(result.returncode, 0, result.stderr)
        pair = self.root/'mnt/titan-api/tls/current'
        details = subprocess.check_output(['openssl', 'x509', '-in', str(pair/'cert.pem'), '-noout', '-text'], text=True)
        self.assertIn('ASN1 OID: prime256v1', details)
        self.assertIn('Jan  1 00:00:00 1970 GMT', details)
        self.assertIn('Dec 31 23:59:59 2099 GMT', details)
        certificate = (pair/'cert.pem').read_bytes()
        self.assertEqual(self.tls().returncode, 0)
        self.assertEqual((pair/'cert.pem').read_bytes(), certificate)
        public_cert = subprocess.check_output(['openssl', 'x509', '-in', str(pair/'cert.pem'), '-pubkey', '-noout'])
        public_key = subprocess.check_output(['openssl', 'pkey', '-in', str(pair/'key.pem'), '-pubout'])
        self.assertEqual(public_cert, public_key)

    def test_existing_incomplete_tls_is_preserved(self):
        key = self.write('mnt/titan-api/tls/key.pem', 'existing private key')
        self.assertNotEqual(self.tls().returncode, 0)
        self.assertEqual(key.read_text(), 'existing private key')
        self.assertFalse((self.root/'tls-calls').exists())


class LauncherOrderTests(unittest.TestCase):
    write = FirstBootTests.write

    def setUp(self):
        FirstBootTests.setUp(self)
        self.bundle = self.root/'usr/lib/titan-api'
        (self.bundle/'ui').mkdir(parents=True)
        for folder in (self.bundle, self.bundle/'ui'):
            folder.chmod(0o755)
        self.write('usr/lib/titan-api/ui/index.html', 'fixture').chmod(0o644)
        self.write('sys/class/net/eth0/address', '44:6f:d8:80:11:de\n')
        for name in ('titan-api', 'titan-nvram', 'titan-device-helper', 'titan-maintenance', 'titan-seed-rng', 'collect.sh'):
            body = '#!/bin/sh\nexit 0\n'
            if name == 'titan-nvram':
                body = '#!/bin/sh\necho \'{"sqns_identity_serialNumber":"FIXTURE","http_enable":"0","https_enable":"0"}\'\n'
            if name == 'titan-api':
                body = '#!/bin/sh\necho entropy >> "$FIXTURE_ROOT/order"\nexit "${FAIL_SEED:-0}"\n'
            self.write('usr/lib/titan-api/'+name, body).chmod(0o755)
        # Stop immediately after observing the TLS call, before any service forks.
        self.write('usr/lib/titan-api/prepare-tls.sh', '#!/bin/sh\necho tls >> "$FIXTURE_ROOT/order"\nexit 1\n').chmod(0o755)
        text = (REPO/'overlay/usr/lib/titan-api/start-titan-api.sh').read_text()
        text = re.sub(r'/(?:mnt|tmp|sys|etc)(?=[/\s\"\'])', lambda m: str(self.root)+m.group(), text)
        text = text.replace('[ "$3" = 500 ]', f'[ "$3" = {os.getuid()} ]')
        self.launcher = self.write('usr/lib/titan-api/start-titan-api.sh', text)
        self.launcher.chmod(0o755)

    def test_entropy_precedes_every_tls_generation(self):
        result = subprocess.run(['sh', str(self.launcher), 'start', 'production'], env=self.env, capture_output=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.root/'order').read_text().splitlines(), ['entropy', 'tls'])
        mac = self.root/'tmp/witcher-api/device-mac.txt'
        self.assertEqual(mac.read_text(), '44:6F:D8:80:11:DE\n')
        self.assertEqual(mac.stat().st_mode & 0o777, 0o644)

    def test_failed_entropy_never_reaches_tls(self):
        result = subprocess.run(['sh', str(self.launcher), 'start', 'production'], env=dict(self.env, FAIL_SEED='1'), capture_output=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.root/'order').read_text().splitlines(), ['entropy'])

    def test_no_modem_serial_does_not_block_unconfigured_unit(self):
        helper = self.bundle/'titan-nvram'
        helper.write_text(helper.read_text().replace('"FIXTURE"', '""'))
        result = subprocess.run(['sh', str(self.launcher), 'start', 'production'], env=self.env, capture_output=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)  # fixture stops at TLS
        self.assertEqual((self.root/'order').read_text().splitlines(), ['entropy', 'tls'])

    def test_explicit_serial_mismatch_still_fails(self):
        result = subprocess.run(['sh', str(self.launcher), 'start', 'production'], env=dict(self.env, TITAN_EXPECTED_SERIAL='OTHER'), capture_output=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root/'order').exists())


class ServiceControlTests(unittest.TestCase):
    write = FirstBootTests.write

    def setUp(self):
        FirstBootTests.setUp(self)
        self.processes = []
        self.addCleanup(self.stop_processes)
        for name in ('mnt/titan-api', 'usr/lib/titan-api', 'etc/init.d', 'usr/sbin'):
            (self.root/name).mkdir(parents=True, exist_ok=True)
        self.write('mnt/titan-api/seed', 'fixture only')
        self.write('tmp/nvram.cfg', 'ready')
        self.exe('usr/lib/titan-api/start-titan-api.sh', '''echo "$*" >> "$FIXTURE_ROOT/launcher-calls"
case "$1" in start) [ "${FAIL_NATIVE:-0}" = 0 ];; *) exit 0;; esac''')
        self.exe('usr/lib/titan-api/titan-nvram', 'cat >/dev/null')
        for name in ('witcher-state', 'witcher-recovery-files', 'titan-sshd', 'titan-pd-keeper'):
            self.exe('etc/init.d/' + name, 'echo "${0##*/} $*" >> "$FIXTURE_ROOT/service-calls"')
        self.exe('bin/wget', '[ ! -f "$FIXTURE_ROOT/fail-health" ] || exit 1; echo \'{"service":"titan-api"}\'')
        self.exe('bin/pidof', '[ ! -f "$FIXTURE_ROOT/vendor.pid" ] || cat "$FIXTURE_ROOT/vendor.pid"')
        # Real private child process, so /proc executable identity and signals are tested.
        source = self.write('vendor.c', '''#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main(void) { char path[4096]; snprintf(path,sizeof(path),"%s/vendor.pid",getenv("FIXTURE_ROOT"));
FILE *f=fopen(path,"w"); if(!f)return 1;fprintf(f,"%d",getpid());fclose(f);for(;;)pause(); }
''')
        subprocess.run(['cc', str(source), '-o', str(self.root/'usr/sbin/httpd')], check=True)
        script = (REPO/'overlay/etc/init.d/titan-api').read_text()
        script = re.sub(r'/(?:mnt|tmp|etc|usr)(?=[/\s\"\'])', lambda m: str(self.root)+m.group(), script)
        script = re.sub(r'^vendor_path=.*$', 'vendor_path=' + self.env['PATH'], script, flags=re.M)
        # Keep the monitor's scheduling, accelerate bounded retry delays.
        script = script.replace('sleep 10', '/bin/sleep 0.05')
        self.control = self.write('etc/init.d/titan-api', script)

    def exe(self, name, source):
        path = self.write(name, '#!/bin/sh\n' + source + '\n')
        path.chmod(0o755)

    def stop_processes(self):
        for process in self.processes:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)

    def launch(self, action='boot', **env):
        process = subprocess.Popen(['sh', str(self.control), action], env=dict(self.env, **env),
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        self.processes.append(process)
        return process

    def wait_for(self, predicate):
        end = time.monotonic() + 5
        while time.monotonic() < end:
            if predicate(): return
            time.sleep(0.02)
        self.fail('Service control did not reach the expected state')

    def test_autonomous_seed_skips_browser_setup(self):
        (self.root/'mnt/titan-api/seed').unlink()
        self.exe('usr/lib/titan-api/witcher-firstboot', 'echo "$1" >> "$FIXTURE_ROOT/firstboot-calls"; [ "$1" != bootstrap ] || echo seed > "$FIXTURE_ROOT/mnt/titan-api/seed"')
        process = self.launch()
        self.wait_for(lambda: (self.root/'tmp/titan-api-boot.log').exists() and 'Native web service active' in (self.root/'tmp/titan-api-boot.log').read_text())
        self.assertIsNone(process.poll())
        self.assertEqual((self.root/'firstboot-calls').read_text().splitlines(), ['bootstrap'])

    def test_failed_autonomous_seed_keeps_browser_fallback(self):
        (self.root/'mnt/titan-api/seed').unlink()
        self.exe('usr/lib/titan-api/witcher-firstboot', 'echo "$1" >> "$FIXTURE_ROOT/firstboot-calls"; [ "$1" != bootstrap ] || exit 1; exit 1')
        process = self.launch()
        self.assertEqual(process.wait(timeout=5), 1)
        self.assertEqual((self.root/'firstboot-calls').read_text().splitlines(), ['bootstrap', 'setup'])
        self.assertFalse((self.root/'mnt/titan-api/seed').exists())
        self.wait_for(lambda: (self.root/'vendor.pid').exists())

    def test_failed_native_start_restores_factory_server(self):
        process = self.launch(FAIL_NATIVE='1')
        self.assertEqual(process.wait(timeout=5), 1)
        self.wait_for(lambda: (self.root/'vendor.pid').exists())
        calls = (self.root/'launcher-calls').read_text().splitlines()
        self.assertEqual(calls.count('start production'), 3)
        self.assertIn('witcher-state mount', (self.root/'service-calls').read_text())
        self.assertIn('witcher-recovery-files ', (self.root/'service-calls').read_text())

    def test_late_panel_failure_restores_factory_server(self):
        process = self.launch()
        self.wait_for(lambda: (self.root/'tmp/titan-api-boot.log').exists() and 'Native web service active' in (self.root/'tmp/titan-api-boot.log').read_text())
        self.assertIsNone(process.poll())
        self.write('fail-health', 'now')
        self.assertEqual(process.wait(timeout=5), 1)
        self.wait_for(lambda: (self.root/'vendor.pid').exists())

    def test_recovery_vendor_selection_stops_native_monitor(self):
        process = self.launch()
        self.wait_for(lambda: (self.root/'tmp/titan-api-boot.log').exists() and 'Native web service active' in (self.root/'tmp/titan-api-boot.log').read_text())
        self.write('mnt/titan-api/use-vendor-ui', '')
        recovery = self.launch('vendor')
        self.assertEqual(recovery.wait(timeout=5), 0)
        self.wait_for(lambda: process.poll() is not None)
        self.assertTrue((self.root/'vendor.pid').exists())

    def test_missing_modem_identity_does_not_hold_boot(self):
        launcher = self.root/'usr/lib/titan-api/start-titan-api.sh'
        launcher.write_text(launcher.read_text().replace('case "$1" in start)', 'case "$1" in identity) exit 1;; start)'))
        process = self.launch()
        self.wait_for(lambda: (self.root/'tmp/titan-api-boot.log').exists() and 'Native web service active' in (self.root/'tmp/titan-api-boot.log').read_text())
        self.assertIsNone(process.poll())


class IndependentBootTests(unittest.TestCase):
    write = FirstBootTests.write
    exe = ServiceControlTests.exe
    wait_for = ServiceControlTests.wait_for
    stop_processes = ServiceControlTests.stop_processes

    def test_web_failure_does_not_prevent_keeper_ssh_recovery_or_access_rules(self):
        FirstBootTests.setUp(self)
        self.processes = []
        self.addCleanup(self.stop_processes)
        for name in ('witcher-management-access', 'titan-sshd', 'titan-pd-keeper'):
            self.exe('etc/init.d/'+name, 'echo "${0##*/} $*" >> "$FIXTURE_ROOT/independent"')
        self.exe('etc/init.d/titan-api', 'echo web-failed >> "$FIXTURE_ROOT/independent"; exit 1')
        self.exe('usr/lib/titan-api/witcher-firstboot', 'echo recovery >> "$FIXTURE_ROOT/independent"; while :; do /bin/sleep 1; done')
        source = (REPO/'overlay/etc/init.d/witcher-boot').read_text()
        source = re.sub(r'/(?:tmp|etc|usr)(?=[/\s\"\'])', lambda m: str(self.root)+m.group(), source)
        boot = self.write('etc/init.d/witcher-boot', source)
        process = subprocess.Popen(['sh', str(boot), 'boot'], env=self.env,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        self.processes.append(process)
        self.assertEqual(process.wait(timeout=5), 1)
        self.wait_for(lambda: (self.root/'independent').exists() and all(
            entry in (self.root/'independent').read_text()
            for entry in ('web-failed', 'titan-sshd boot', 'titan-pd-keeper start', 'recovery', 'witcher-management-access all')))


if __name__ == '__main__':
    unittest.main()
