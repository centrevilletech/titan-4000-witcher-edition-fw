#!/usr/bin/env python3
"""The monitor patch changes only its two strings and refuses any other binary.
Uses a synthetic file; the packed image is checked by test-monitor-counters.py."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('patch_monitor', HERE/'patch-monitor.py')
patch_monitor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(patch_monitor)


def synthetic():
    data = bytearray(b'\xa5' * 0x4400)
    for offset, old, _ in patch_monitor.PATCHES:
        data[offset:offset + len(old) + 1] = old + b'\0'
    return bytes(data)


class PatchMonitorTests(unittest.TestCase):
    def test_only_the_two_strings_change(self):
        stock = synthetic()
        patched = patch_monitor.patch(stock)
        changed = [i for i in range(len(stock)) if stock[i] != patched[i]]
        spans = [(offset, offset + len(old) + 1) for offset, old, _ in patch_monitor.PATCHES]
        self.assertTrue(changed)
        self.assertTrue(all(any(lo <= i < hi for lo, hi in spans) for i in changed))
        for offset, old, new in patch_monitor.PATCHES:
            self.assertEqual(patched[offset:offset + len(old) + 1], new + b'\0' * (len(old) + 1 - len(new)))
            self.assertIn(b'%1e9}', new)
            self.assertTrue(new.startswith(b'grep eth0 /proc/net/dev | awk '))

    def test_patching_twice_is_a_no_op(self):
        once = patch_monitor.patch(synthetic())
        self.assertEqual(patch_monitor.patch(once), once)

    def test_a_half_patched_file_is_completed(self):
        stock = synthetic()
        offset, old, new = patch_monitor.PATCHES[0]
        half = bytearray(stock)
        half[offset:offset + len(old) + 1] = new + b'\0' * (len(old) + 1 - len(new))
        self.assertEqual(patch_monitor.patch(bytes(half)), patch_monitor.patch(stock))

    def test_another_binary_is_refused(self):
        data = bytearray(synthetic())
        data[0x4234 + 4] ^= 0x20
        with self.assertRaises(ValueError):
            patch_monitor.patch(bytes(data))

    def test_the_command_line_refuses_a_binary_that_is_not_stock(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary)/'monitor'
            source.write_bytes(synthetic())
            result = subprocess.run([sys.executable, str(HERE/'patch-monitor.py'), str(source), '-o', str(source) + '.out'],
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('not the stock 4172 binary', result.stderr)
            self.assertFalse(Path(str(source) + '.out').exists())


if __name__ == '__main__':
    unittest.main()
