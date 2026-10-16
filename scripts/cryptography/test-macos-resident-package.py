#!/usr/bin/env python3
"""Cheap population/oracle and unsupported-host regressions; no crypto subprocesses."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import macos_resident_oracle as oracle
import macos_resident_keyed_oracle as keyed

spec = importlib.util.spec_from_file_location('resident_package',
    Path(__file__).with_name('check-macos-resident-package.py'))
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


class ResidentPackageTests(unittest.TestCase):
    def test_keyed_population_strength_partial_bits_and_routes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'src').mkdir()
            with patch('subprocess.run', side_effect=AssertionError('unexpected subprocess')):
                self.assertEqual(keyed.write_consumer(root), 512)
            for name in ('kmac', 'tuplehash'):
                lines = (root/f'src/{name}.txt').read_text().splitlines()
                self.assertEqual(len(lines), 256)
                self.assertEqual(len({row.split()[0] for row in lines}), 4)
            for row in (root/'src/kmac.txt').read_text().splitlines():
                c = row.split()
                self.assertGreaterEqual(int(c[1]), 256)
                if 'xof' not in c[0]:
                    self.assertGreaterEqual(int(c[7]), 256)
                self.assertEqual(len(b'' if c[8]=='-' else bytes.fromhex(c[8])), (int(c[7])+7)//8)
            source = (root/'src/keyed.rs').read_text()
            for name in ('k', 't'):
                self.assertIn(name+'::Session::new', source)
                self.assertIn(name+'::CompiledSession::new', source)
                self.assertIn(name+'::Kernel::ArmKeccak', source)

    def test_keyed_cannot_silently_omit_accelerated_comparison(self):
        with self.assertRaisesRegex(ValueError, 'requires --accelerated'):
            package.execute('1.99.1', Path('/unused'), keyed=True)

    def test_exact_population_and_official_oracle_cross_checks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'src').mkdir()
            with patch('subprocess.run', side_effect=AssertionError('unexpected subprocess')):
                self.assertEqual(oracle.write_consumer(root), 662)
            hashes = (root/'src/hashes.txt').read_text().splitlines()
            cshake = (root/'src/cshake.txt').read_text().splitlines()
            self.assertEqual(len(hashes), 180)
            self.assertEqual(len({line.split()[0] for line in hashes}), 12)
            self.assertEqual(len(cshake), 482)
            self.assertEqual(len({line.split()[0] for line in cshake}), 2)
            self.assertIn('0 - 120 456d61696c205369676e6174757265 32 00010203', cshake[-1])
            for line in cshake:
                columns = line.split()
                self.assertEqual(len(columns), 9)
                output = b'' if columns[-1] == '-' else bytes.fromhex(columns[-1])
                self.assertEqual(len(output), (int(columns[-2])+7)//8)

    def test_accelerated_oracle_requires_each_arm_route(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'src').mkdir()
            self.assertEqual(oracle.write_consumer(root, True), 662)
            source = (root/'src/families.rs').read_text()
            self.assertNotIn('::Session::new(', source)
            for kernel in ('ArmSha256', 'ArmSha512', 'ArmKeccak'):
                self.assertIn(kernel, source)
            self.assertEqual(source.count('::CompiledSession::new('), 3)

    def test_wrong_host_never_reaches_packaging(self):
        with patch('subprocess.check_output', return_value='host: x86_64-unknown-linux-gnu\n'):
            with patch('subprocess.run', side_effect=AssertionError('unexpected subprocess')):
                with self.assertRaisesRegex(ValueError, 'requires native Apple Silicon'):
                    package.execute('1.99.1', Path('/unused'))


if __name__ == '__main__':
    unittest.main()
