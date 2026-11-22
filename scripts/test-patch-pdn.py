#!/usr/bin/env python3
"""The rcinit and ucid patches change only their listed bytes and refuse any
file that is not a pinned input. Uses synthetic files; the packed image is
checked by verify-firmware.py and scripts/emulate-pdn-paths.py."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import vendor_patch  # noqa: E402


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


RCINIT = load('patch-rcinit')
UCID = load('patch-ucid')
DOC = (HERE.parent / 'docs/pdn-bounce.md').read_text()


def synthetic(module, size):
    data = bytearray(b'\xa5' * size)
    for patch in module.PATCHES:
        offset = patch.va - module.BASE
        data[offset:offset + len(patch.old)] = patch.old
    return bytes(data)


class PatchTableTests(unittest.TestCase):
    def test_each_patch_keeps_length_and_changes_bytes(self):
        for module in (RCINIT, UCID):
            for patch in module.PATCHES:
                self.assertEqual(len(patch.old), len(patch.new), patch.label)
                self.assertNotEqual(patch.old, patch.new, patch.label)

    def test_code_patches_replace_a_call_with_a_no_op(self):
        for module in (RCINIT, UCID):
            for patch in module.PATCHES:
                if patch.va == UCID.POLL_ACCEPT or len(patch.old) != 4:
                    continue
                self.assertEqual(patch.old[3], 0xeb, f'{patch.label}: stock word is not a bl')
                self.assertEqual(patch.new, vendor_patch.NOP, patch.label)

    def test_rcinit_call_targets_are_the_audited_functions(self):
        targets = {0xd508: 0xa2a8, 0xd510: 0xa4c4, 0xd548: 0xa2a8, 0xdc48: 0x30cbc,
                   0x3ab38: 0xa4c4, 0xf268: 0xa4c4, 0xd578: 0xa4c4}
        for patch in RCINIT.PATCHES:
            if patch.va in targets:
                self.assertEqual(vendor_patch.arm_branch_target(patch.va, patch.old), targets.pop(patch.va), patch.label)
        self.assertEqual(targets, {})

    def test_ucid_call_targets_and_branch(self):
        for patch in UCID.PATCHES:
            if patch.va == UCID.POLL_ACCEPT:
                self.assertEqual(patch.old, bytes.fromhex('2c0207e3'))  # movw r0, #0x722c
                self.assertEqual(patch.new, bytes.fromhex('7c0000ea'))
                self.assertEqual(vendor_patch.arm_branch_target(patch.va, patch.new), UCID.POLL_SUCCESS)
            else:
                self.assertEqual(vendor_patch.arm_branch_target(patch.va, patch.old), 0xa45c)  # sleep@plt

    def test_log_line_has_no_format_directive(self):
        patch = next(p for p in RCINIT.PATCHES if p.va == 0x3f854)
        self.assertNotIn(b'%', patch.new)
        self.assertTrue(patch.new.startswith(RCINIT.NEW_LOG))
        self.assertTrue(patch.new[len(RCINIT.NEW_LOG):].strip(b'\0') == b'')

    def test_pins_are_distinct_sha256_values(self):
        values = [RCINIT.STOCK_SHA256, RCINIT.WITCHER_SHA256, RCINIT.STOCK_PATCHED_SHA256,
                  RCINIT.WITCHER_PATCHED_SHA256, UCID.STOCK_SHA256, UCID.STOCK_PATCHED_SHA256]
        self.assertEqual(len(set(values)), len(values))
        for value in values:
            self.assertRegex(value, r'^[0-9a-f]{64}$')

    def test_every_patch_address_is_documented(self):
        for module in (RCINIT, UCID):
            for patch in module.PATCHES:
                self.assertIn(f'0x{patch.va:x}', DOC, patch.label)


class ApplyTests(unittest.TestCase):
    def test_only_listed_bytes_change(self):
        for module, size in ((RCINIT, 0x48000), (UCID, 0x40000)):
            stock = synthetic(module, size)
            patched = vendor_patch.apply(stock, module.PATCHES, module.BASE)
            spans = [(p.va - module.BASE, p.va - module.BASE + len(p.old)) for p in module.PATCHES]
            changed = [i for i in range(size) if stock[i] != patched[i]]
            self.assertTrue(changed)
            self.assertTrue(all(any(lo <= i < hi for lo, hi in spans) for i in changed))

    def test_wrong_stock_bytes_are_refused(self):
        stock = bytearray(synthetic(UCID, 0x40000))
        stock[UCID.POLL_ACCEPT - UCID.BASE] ^= 1
        with self.assertRaises(ValueError):
            vendor_patch.apply(bytes(stock), UCID.PATCHES, UCID.BASE)

    def test_pinned_input_output_and_pass_through(self):
        stock = synthetic(UCID, 0x40000)
        patched = vendor_patch.apply(stock, UCID.PATCHES, UCID.BASE)
        pins = {vendor_patch.sha256(stock): vendor_patch.sha256(patched)}
        self.assertEqual(vendor_patch.patch_pinned(stock, UCID.PATCHES, UCID.BASE, pins, 'ucid'), patched)
        self.assertEqual(vendor_patch.patch_pinned(patched, UCID.PATCHES, UCID.BASE, pins, 'ucid'), patched)

    def test_wrong_output_pin_is_refused(self):
        stock = synthetic(UCID, 0x40000)
        pins = {vendor_patch.sha256(stock): '0' * 64}
        with self.assertRaises(ValueError):
            vendor_patch.patch_pinned(stock, UCID.PATCHES, UCID.BASE, pins, 'ucid')

    def test_unpinned_input_is_refused(self):
        for module, size in ((RCINIT, 0x48000), (UCID, 0x40000)):
            with self.assertRaises(ValueError):
                vendor_patch.patch_pinned(synthetic(module, size), module.PATCHES, module.BASE, module.PINS, 'x')

    def test_branch_encoding(self):
        for source, target in ((0x24458, 0x24650), (0x1000, 0x800), (0x8000, 0x8008)):
            word = vendor_patch.arm_branch(source, target)
            self.assertEqual(word[3], 0xea)
            self.assertEqual(vendor_patch.arm_branch_target(source, word), target)
        with self.assertRaises(ValueError):
            vendor_patch.arm_branch(0x1000, 0x1002)


class CommandLineTests(unittest.TestCase):
    def test_both_scripts_refuse_a_binary_that_is_not_pinned(self):
        for script, module, size in (('patch-rcinit.py', RCINIT, 0x48000), ('patch-ucid.py', UCID, 0x40000)):
            with tempfile.TemporaryDirectory() as temporary:
                source = Path(temporary) / 'binary'
                source.write_bytes(synthetic(module, size))
                out = Path(temporary) / 'out'
                result = subprocess.run([sys.executable, str(HERE / script), str(source), '-o', str(out)],
                                        capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('not a pinned stock input', result.stderr)
                self.assertFalse(out.exists())

    def test_build_patches_before_the_strip_steps(self):
        build = (HERE / 'build-firmware.sh').read_text()
        self.assertLess(build.index('patch-rcinit.py'), build.index('strip-root-password.py'))
        self.assertLess(build.index('patch-rcinit.py'), build.index('strip-vendor-host-keys.py'))
        self.assertIn('patch-ucid.py', build)


if __name__ == '__main__':
    unittest.main()
