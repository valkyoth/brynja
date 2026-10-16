#!/usr/bin/env python3
"""Resident ParallelHash oracle/admission populations without native execution."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import macos_resident_parallel_oracle as oracle

spec = importlib.util.spec_from_file_location('parallel_package',
    Path(__file__).with_name('check-macos-resident-parallel-package.py'))
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


class ParallelPackageTests(unittest.TestCase):
    def test_host_rejection_precedes_packaging(self):
        for host in ('x86_64-unknown-linux-gnu', 'x86_64-apple-darwin', 'aarch64-unknown-linux-gnu'):
            with patch('subprocess.check_output', return_value='host: ' + host + '\n'):
                with patch('subprocess.run', side_effect=AssertionError('unexpected subprocess')):
                    with self.assertRaisesRegex(ValueError, 'native Apple Silicon'):
                        package.execute('1.99.1', Path('/unused'))

    def test_independent_population_and_nist_anchors(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root/'src').mkdir()
            with patch('subprocess.run', side_effect=AssertionError('unexpected subprocess')):
                self.assertEqual(oracle.write_consumer(root), 274)
            lines = (root/'src/vectors.txt').read_text().splitlines()
            self.assertEqual(len(lines), 274)
            self.assertEqual({line.split()[0] for line in lines},
                             {'parallel128', 'parallel256', 'parallelxof128', 'parallelxof256'})
            self.assertEqual(sum(int(line.split()[3]) > 32000 for line in lines), 16)
            source = (root/'src/main.rs').read_text()
            for token in ('for workers in [1,3]', 'Session::new(a,limits(workers))',
                          'LeafRoute::Single(Kernel::ArmKeccak)', 'LeafRoute::Batch(BatchKernel::Neon)',
                          'assert_eq!(output.expose(),expected)', 'assert_eq!(counts,[548;3])'):
                self.assertIn(token, source)
            self.assertNotIn('Mode::Prefer', source)
        original = oracle.reference.parallel_hash
        def corrupt(rate, message, block, custom, bits, xof):
            output = original(rate, message, block, custom, bits, xof)
            return bytes([output[0] ^ 1]) + output[1:] if output else output
        with patch.object(oracle.reference, 'cases', return_value=[]):
            with patch.object(oracle.reference, 'parallel_hash', side_effect=corrupt):
                with self.assertRaisesRegex(ValueError, 'disagrees with NIST'):
                    oracle.vectors()


if __name__ == '__main__':
    unittest.main()
