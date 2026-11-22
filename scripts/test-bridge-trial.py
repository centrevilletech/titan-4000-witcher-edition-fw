#!/usr/bin/env python3
"""Run the trial against recorded commands and a regular file for the switch."""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'overlay/usr/lib/titan-api/bench-bridge-ipv4.sh'


class Trial(unittest.TestCase):
    def test_default_off_then_grant_loss(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            knob = root / 'knob'
            knob.write_text('1\n')
            flag = root / 'br0/bridge/nf_call_iptables'
            flag.parent.mkdir(parents=True)
            flag.write_text('0\n')
            def executable(name, body):
                dest = root / name
                dest.write_text('#!/bin/sh\n' + body)
                dest.chmod(0o755)
            executable('keeper', 'read -r mode < "$ROOT/knob"\n[ "$mode" = 1 ] || exit 1\necho "lte0pdn1 client server"\n')
            executable('ebt', '''read -r mode < "$ROOT/knob"
echo "$mode $*" >> "$ROOT/actions"
case "$*" in
  *"-L PREROUTING"*) echo "-A PREROUTING -j WITCHER_SAS_TEST";;
  *"-L WITCHER_SAS_TEST"*) echo "-A WITCHER_SAS_TEST -j redirect";;
esac
''')
            text = SCRIPT.read_text().replace('/proc/sys/net/bridge/bridge-nf-call-iptables', str(knob))
            for src, dst in [('/sys/class/net/*', str(root/'*')),
                             ('/usr/lib/titan-api/titan-pd-keeper', str(root/'keeper')),
                             ('/usr/bin/ebtables', str(root/'ebt')),
                             ('/tmp/witcher-bridge-trial', str(root/'lock'))]:
                text = text.replace(src, dst)
            executable('trial', text)
            env = dict(os.environ, ROOT=directory, WITCHER_BENCH_BRIDGE_IPV4='0')
            args = ['sh', str(root/'trial'), 'server', '55000']
            self.assertEqual(subprocess.run(args, env=env).returncode, 64)
            self.assertFalse((root/'actions').exists())
            env['WITCHER_BENCH_BRIDGE_IPV4'] = '1'
            self.assertNotEqual(subprocess.run(args, env=env, timeout=10).returncode, 0)
            actions = (root/'actions').read_text()
            self.assertIn('1 -t nat -I PREROUTING 1', actions)
            self.assertIn('0 -t nat -L PREROUTING', actions)
            self.assertIn('1 -t nat -D PREROUTING', actions)
            self.assertEqual(knob.read_text(), '1\n')
            self.assertFalse((root/'lock').exists())


if __name__ == '__main__':
    unittest.main()
