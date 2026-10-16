#!/usr/bin/env python3
"""Cheap batch oracle, host admission and exact-population regressions."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import macos_resident_batch_oracle as oracle

spec = importlib.util.spec_from_file_location('batch_package',
    Path(__file__).with_name('check-macos-resident-batch-package.py'))
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


class BatchPackageTests(unittest.TestCase):
    def test_host_rejection_before_any_packaging(self):
        for host in ('x86_64-unknown-linux-gnu', 'x86_64-apple-darwin', 'aarch64-unknown-linux-gnu'):
            with patch('subprocess.check_output', return_value='host: ' + host + '\n'):
                with patch('subprocess.run', side_effect=AssertionError('unexpected subprocess')):
                    with self.assertRaisesRegex(ValueError, 'native Apple Silicon'):
                        package.execute('1.99.1', Path('/unused'))

    def test_oracle_population_without_subprocesses(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root/'src').mkdir()
            with patch('subprocess.run', side_effect=AssertionError('unexpected subprocess')):
                self.assertEqual(oracle.write_consumer(root), 662)
            lines = (root/'src/hashes.txt').read_text().splitlines()
            self.assertEqual(len(lines), 180)
            self.assertEqual(len({line.split()[0] for line in lines}), 12)
            self.assertEqual(len((root/'src/cshake.txt').read_text().splitlines()), 482)
            source = (root/'src/main.rs').read_text()
            for token in ('(662,616,46)', 'execute(&raw,&out,false)', 'execute(&raw,&out,true)',
                          'Sha256Kernel::Neon', 'Sha512Kernel::Neon', 'KeccakKernel::Neon',
                          'for i in 0..capacity', 'report.kernel'):
                self.assertIn(token, source)
            self.assertNotIn('Mode::Prefer', source)


if __name__ == '__main__':
    unittest.main()
