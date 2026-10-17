#!/usr/bin/env python3
"""Regression cases for boot failures missed by the original release verifier."""
import copy
import stat
import unittest
from rootfs_metadata import boot_errors, resolve, WITCHER_BOOT_SCRIPTS, WITCHER_BUNDLE_SCRIPTS


class BootMetadataTests(unittest.TestCase):
    def setUp(self):
        self.stock = {}
        for path in ('/', '/bin', '/etc', '/etc/init.d', '/etc/sysconfig',
                     '/usr', '/usr/sbin'):
            self.stock[path] = dict(mode=stat.S_IFDIR | 0o775, uid=500, gid=500)
        for path in ('/bin/busybox', '/bin/bash', '/etc/init.d/rcS',
                     '/etc/sysconfig/board.conf', '/usr/sbin/rcinit'):
            self.stock[path] = dict(mode=stat.S_IFREG | 0o775, uid=500, gid=500)
        for path, target in (('/sbin', 'bin'), ('/bin/init', '../bin/busybox'),
                             ('/bin/sh', 'bash')):
            self.stock[path] = dict(mode=stat.S_IFLNK | 0o777, target=target)
        self.stock['/dev/console'] = dict(mode=stat.S_IFCHR | 0o664,
                                        uid=500, gid=500, device=[5, 1])

    def test_stock_aliases_resolve(self):
        self.assertEqual(resolve(self.stock, '/sbin/init'), self.stock['/bin/busybox'])
        self.assertEqual(boot_errors(self.stock, self.stock), [])

    def test_released_init_modes_fail(self):
        for mode in (0o600, 0o644):
            with self.subTest(mode=oct(mode)):
                built = copy.deepcopy(self.stock)
                built['/bin/busybox']['mode'] = stat.S_IFREG | mode
                errors = boot_errors(self.stock, built)
                self.assertIn(f'/sbin/init: not executable (mode {mode:04o})', errors)

    def test_witcher_startup_scripts(self):
        baseline = copy.deepcopy(self.stock)
        for path in ('/etc/sysconfig/script', '/usr/lib', '/usr/lib/titan-api',
                     '/usr/lib/titan-api/ui'):
            baseline[path] = dict(mode=stat.S_IFDIR | 0o755, uid=500, gid=500)
        scripts = WITCHER_BOOT_SCRIPTS + WITCHER_BUNDLE_SCRIPTS + ('/usr/lib/titan-api/witcher-firstboot', '/usr/lib/titan-api/witcher-entropy')
        for path in scripts:
            baseline[path] = dict(mode=stat.S_IFREG | 0o700, uid=500, gid=500)
        # Root can execute 0700; reject only missing/non-executable targets.
        self.assertEqual(boot_errors(self.stock, baseline, witcher=True), [])
        for path in scripts:
            for mode in (None, 0o600, 0o644, stat.S_IFDIR | 0o755):
                with self.subTest(path=path, mode=mode):
                    built = copy.deepcopy(baseline)
                    if mode is None:
                        del built[path]
                    else:
                        built[path]['mode'] = mode if stat.S_ISDIR(mode) else stat.S_IFREG | mode
                    errors = boot_errors(self.stock, built, witcher=True)
                    self.assertTrue(any(error.startswith(path + ':') for error in errors), errors)

    def test_broken_init_link(self):
        built = copy.deepcopy(self.stock)
        built['/bin/init']['target'] = 'missing'
        self.assertIn('/sbin/init: missing or broken symlink', boot_errors(self.stock, built))

    def test_cyclic_init_link(self):
        built = copy.deepcopy(self.stock)
        built['/bin/init']['target'] = 'init'
        self.assertIn('/sbin/init: missing or broken symlink', boot_errors(self.stock, built))

    def test_device_count_alone_is_not_enough(self):
        for key, value in (('device', [5, 2]), ('gid', 0),
                           ('mode', stat.S_IFBLK | 0o664)):
            with self.subTest(key=key):
                built = copy.deepcopy(self.stock)
                built['/dev/console'][key] = value
                self.assertTrue(any('Device paths' in e for e in boot_errors(self.stock, built)))

    def test_unprivileged_web_ancestors(self):
        built = copy.deepcopy(self.stock)
        for path in ('/', '/usr', '/usr/lib', '/usr/lib/titan-api', '/usr/lib/titan-api/ui'):
            built[path] = dict(mode=stat.S_IFDIR | 0o755, uid=500, gid=500)
        built['/usr/lib/titan-api/ui/index.html'] = dict(mode=stat.S_IFREG | 0o644)
        self.assertEqual(boot_errors(self.stock, built), [])
        built['/usr']['mode'] = stat.S_IFDIR | 0o700
        self.assertIn('/usr: not traversable by the web worker', boot_errors(self.stock, built))


if __name__ == '__main__':
    unittest.main()
