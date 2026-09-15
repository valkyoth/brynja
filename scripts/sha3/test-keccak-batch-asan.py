#!/usr/bin/env python3
"""Exercise fatal sanitizer exits, hostile environment and actual SIMD markers."""
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('batch_asan', Path(__file__).with_name('check-keccak-batch-asan.py'))
asan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(asan)


class SanitizerTests(unittest.TestCase):
    def test_enforcement_and_runtime_failures(self):
        for machine, features, kernel, width, flags in (
                ('x86_64', '+avx,+avx2', 'Avx2', 4, 'flags\t: avx avx2'),
                ('aarch64', '+neon', 'Neon', 2, 'Features\t: asimd')):
            good = f'KECCAK_BATCH_NATIVE: {kernel}; calls=1024; width={width}\nKECCAK_BATCH_API: {kernel}; comparisons=512\n'
            for status, output in ((0, good), (23, good), (1, good), (0, ''), (0, good.replace('1024', '0'))):
                def child(args, **kwargs):
                    env = kwargs['env']
                    self.assertEqual(env['ASAN_OPTIONS'], 'detect_leaks=1:halt_on_error=1:exitcode=1')
                    self.assertEqual(env['LSAN_OPTIONS'], 'exitcode=23')
                    self.assertEqual(env['RUSTFLAGS'], '-Zsanitizer=address -C target-feature=' + features)
                    self.assertNotIn('CARGO_ENCODED_RUSTFLAGS', env)
                    self.assertIn(machine + '-unknown-linux-gnu', args)
                    self.assertIn('--show-output', args)
                    return subprocess.CompletedProcess(args, status, output, 'runtime diagnostic')
                with self.subTest(machine=machine, status=status, output=output), \
                     patch.dict(os.environ, {'ASAN_OPTIONS': 'detect_leaks=0:exitcode=0',
                         'LSAN_OPTIONS': 'exitcode=0:suppressions=untrusted', 'CARGO_ENCODED_RUSTFLAGS': 'hostile'}), \
                     patch.object(asan.platform, 'system', return_value='Linux'), \
                     patch.object(asan.platform, 'machine', return_value=machine), \
                     patch.object(asan.Path, 'read_text', return_value=flags), \
                     patch.object(asan.command.subprocess, 'run', side_effect=child), \
                     contextlib.redirect_stdout(io.StringIO()):
                    if status or output != good:
                        with self.assertRaises(ValueError): asan.main()
                    else: asan.main()

    def test_missing_cpu_bundle_never_runs(self):
        for flags in ('', 'flags\t: avx', 'flags\t: avx avx2\nflags\t: avx'):
            with patch.object(asan.platform, 'system', return_value='Linux'), \
                 patch.object(asan.platform, 'machine', return_value='x86_64'), \
                 patch.object(asan.Path, 'read_text', return_value=flags), \
                 patch.object(asan.command, 'run', side_effect=AssertionError('must not execute')):
                with self.assertRaises(ValueError): asan.main()


if __name__ == '__main__': unittest.main()
