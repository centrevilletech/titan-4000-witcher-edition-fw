#!/usr/bin/env python3
"""Locking and leak-detection regressions use synthetic credentials only."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from credential_policy import credential_findings, legacy_credentials

spec = importlib.util.spec_from_file_location('lock', Path(__file__).with_name('strip-root-password.py'))
lock = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lock)


key_spec = importlib.util.spec_from_file_location('keys', Path(__file__).with_name('strip-vendor-host-keys.py'))
keys = importlib.util.module_from_spec(key_spec)
key_spec.loader.exec_module(keys)


class Credentials(unittest.TestCase):
    def fixture(self, root):
        # Deliberately synthetic crypt-shaped data, not a usable fleet hash.
        credential = b'$' + b'1$fixture$' + b'A' * 22
        board = root / 'etc/sysconfig/board.conf'
        binary = root / 'usr/sbin/rcinit'
        board.parent.mkdir(parents=True)
        binary.parent.mkdir(parents=True)
        board.write_bytes(b'echo "root:' + credential.replace(b'$', b'\\$') + b':0:0:root:/root:/bin/sh" > /var/tmp/passwd\n')
        binary.write_bytes(b'ELF-fixture\x00root:' + credential + b':0:0:root:/:/bin/sh\n\x00unchanged-tail')
        return board, binary

    def test_locks_both_writers_preserves_binary_size_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); board, binary = self.fixture(root)
            length = binary.stat().st_size
            lock.lock_root(root)
            self.assertEqual(board.read_bytes(), lock.BOARD_NEW)
            self.assertEqual(binary.stat().st_size, length)
            self.assertIn(lock.RCINIT_NEW, binary.read_bytes())
            before = binary.read_bytes(); lock.lock_root(root)
            self.assertEqual(before, binary.read_bytes())
            self.assertEqual(credential_findings(root), [])

    def test_mismatch_fails_without_mutating_either_writer(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); board, binary = self.fixture(root)
            board.write_bytes(board.read_bytes().replace(b'fixture', b'different'))
            before = board.read_bytes(), binary.read_bytes()
            with self.assertRaises(ValueError): lock.lock_root(root)
            self.assertEqual(before, (board.read_bytes(), binary.read_bytes()))

    def test_embedded_hash_and_key_are_detected_without_following_symlinks(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); _, binary = self.fixture(root)
            self.assertIn('usr/sbin/rcinit', credential_findings(root))
            lock.lock_root(root)
            (root/'key').write_bytes(b'-----BEGIN '+b'PRIVATE KEY-----\n' + b'A' * 80 + b'\n-----END '+b'PRIVATE KEY-----')
            (root/'outside').symlink_to('/dev/zero')
            self.assertEqual(credential_findings(root), ['key'])

    def test_secret_required_and_never_echoed_on_parse_failure(self):
        with patch.dict(os.environ, {'WITCHER_REQUIRE_CREDENTIAL_DENYLIST':'1', 'WITCHER_CREDENTIAL_DENYLIST_JSON':''}):
            with self.assertRaisesRegex(ValueError, 'unavailable'): legacy_credentials()
        with patch.dict(os.environ, {'WITCHER_CREDENTIAL_DENYLIST_JSON':'private-invalid-value'}):
            with self.assertRaises(ValueError) as error: legacy_credentials()
            self.assertNotIn('private-invalid-value', str(error.exception))

    def test_vendor_key_removal_preserves_offsets_and_ignores_delimiters(self):
        def pem(kind):
            label = kind + b' PRIVATE KEY'
            return b'-----BEGIN ' + label + b'-----\n' + b'A' * 80 + b'\n-----END ' + label + b'-----'
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)/'rcinit'
            original = b'before\0' + pem(b'RSA') + b'\0middle\0' + pem(b'DSA') + b'\0after'
            p.write_bytes(original)
            self.assertEqual(keys.strip_keys(p), 2)
            self.assertEqual(p.stat().st_size, len(original))
            self.assertTrue(p.read_bytes().startswith(b'before\0'))
            self.assertTrue(p.read_bytes().endswith(b'\0after'))
            self.assertEqual(keys.strip_keys(p), 0)
            self.assertEqual(credential_findings(d), [])
            p.write_bytes(b'-----BEGIN ' + b'PRIVATE KEY-----\0format only')
            self.assertEqual(credential_findings(d), [])

    def test_secret_scans_binary_content(self):
        with tempfile.TemporaryDirectory() as d, patch.dict(os.environ, {'WITCHER_CREDENTIAL_DENYLIST_JSON':json.dumps(['fixture-only-secret'])}):
            (Path(d)/'binary').write_bytes(b'\0fixture-only-secret\0')
            self.assertEqual(credential_findings(d), ['binary'])


if __name__ == '__main__': unittest.main()
