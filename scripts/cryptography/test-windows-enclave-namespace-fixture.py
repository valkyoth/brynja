#!/usr/bin/env python3
"""Check native probe assembly; these tests are not native execution evidence."""
import importlib.util
from pathlib import Path
import unittest


def load():
    spec = importlib.util.spec_from_file_location('probe', Path(__file__).with_name(
        'test-windows-enclave-nt-namespace.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FixtureTests(unittest.TestCase):
    def test_complete_lifetime_probe(self):
        probe = load()
        probe.configure()
        for token in ('nt_shadow::preclaimed', 'nt_shadow::Shadow::globalroot',
                      'nt_shadow::held_alias', 'nt_shadow::released_alias',
                      'struct Redirect', 'drop(_shadow);'):
            self.assertEqual(probe.base.FIXTURE.count(token), 1)
        self.assertIn('NtCreateSymbolicLinkObject', probe.base.SHADOW)
        self.assertLess(probe.base.FIXTURE.index('held_alias'),
                        probe.base.FIXTURE.index('drop(pin);'))
        self.assertGreater(probe.base.FIXTURE.index('released_alias'),
                           probe.base.FIXTURE.index('drop(pin);'))

    def test_missing_and_duplicate_anchors_reject(self):
        anchors = ('        let pin = pin::Pin::open',
                   'crate::shadow::Shadow::globalroot(&canonical, &args[2])',
                   'let shadow = if globalroot {', '            shadow\n',
                   'drop(shadow);', 'drop(pin);', 'assert_eq!(std::fs::read(&path)')
        for anchor in anchors:
            for duplicate in (False, True):
                probe = load()
                source = probe.base.FIXTURE
                probe.base.FIXTURE = source + anchor if duplicate else source.replace(anchor, '')
                with self.subTest(anchor=anchor, duplicate=duplicate), self.assertRaises(AssertionError):
                    probe.configure()


if __name__ == '__main__':
    unittest.main()
