#!/usr/bin/env python3
"""Compile the actual direct-copy worker and reject broken copy/cleanup variants."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import windows_enclave_borrowed_worker_build as build


class Tests(unittest.TestCase):
    def test_worker_and_mutants(self):
        identity = subprocess.check_output(['rustc', '+1.98.1', '-vV'], text=True)
        target = next(line[6:] for line in identity.splitlines() if line.startswith('host: '))
        expected = {'missing-clear': 'public_export_then_replay_is_spent',
                    'ignore-copy': 'input_copy_failures_skip_hash_and_result_offers',
                    'reread': 'public_export_then_replay_is_spent',
                    'full-capacity': 'public_export_then_replay_is_spent'}
        with tempfile.TemporaryDirectory(prefix='brynja-borrowed-worker-') as temporary:
            for optimization in ('0', '2'):
                folder = Path(temporary) / optimization
                build.build(folder, target, testing=True, optimization=optimization)
                for variant in build.VARIANTS:
                    binary = folder / (variant + '-worker' + ('.exe' if os.name == 'nt' else ''))
                    result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=30)
                    if variant == 'normal':
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                        self.assertIn('7 passed', result.stdout)
                    else:
                        self.assertNotEqual(result.returncode, 0, variant)
                        self.assertIn(expected[variant] + ' ... FAILED', result.stdout)
        print('Direct-copy worker: seven tests at O0/O2; four mutants rejected at each level.')


if __name__ == '__main__':
    unittest.main()
