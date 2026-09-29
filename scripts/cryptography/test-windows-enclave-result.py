#!/usr/bin/env python3
"""Compile/run scoped result regressions and reject real ownership/mutation probes."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import windows_enclave_result_build as build


class ResultTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        identity = subprocess.check_output(['rustc', '+1.98.1', '-vV'], text=True)
        cls.target = next(line.removeprefix('host: ') for line in identity.splitlines() if line.startswith('host: '))
        cls.temporary = tempfile.TemporaryDirectory(prefix='brynja-enclave-result-')
        cls.directory = Path(cls.temporary.name)
        cls.commands = build.build(cls.directory, cls.target, testing=True)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_six_rust_tests_and_four_compiled_mutants(self):
        self.assertEqual(len(self.commands), 18)
        self.assertFalse(any('feature=' in arg for command in self.commands for arg in command))
        tests = {'reusable': 'successful_export_is_single_use_and_clears',
                 'forgotten': 'successful_export_is_single_use_and_clears',
                 'wrong-token': 'wrong_identity_stale_future_and_missing_flag_are_terminal',
                 'implicit-public': 'wrong_identity_stale_future_and_missing_flag_are_terminal'}
        for variant in build.VARIANTS:
            binary = self.directory / (variant + ('.exe' if os.name == 'nt' else ''))
            result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=30)
            if variant == 'normal':
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('6 passed', result.stdout)
            else:
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(tests[variant] + ' ... FAILED', result.stdout)
            worker = self.directory / (variant + '-worker' + ('.exe' if os.name == 'nt' else ''))
            result = subprocess.run([str(worker)], capture_output=True, text=True, timeout=30)
            if variant == 'normal':
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('3 passed', result.stdout)
            else:
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('fixed_ownership_modes ... FAILED', result.stdout)

    def compile(self, body):
        source = self.directory / 'consumer.rs'
        source.write_text('use enclave_result::{Issuer, ResultHandle, PUBLIC_OUTPUT};\n'
                          'use brynja_hash_sha2::hardened_in_place::Sha256Workspace;\n' + body)
        return subprocess.run(['rustc', '+1.98.1', '--edition=2024', '--target', self.target,
            '--crate-type', 'lib', '--emit=metadata', str(source),
            '--extern', 'enclave_result=' + str(self.directory / 'libnormal.rlib'),
            '--extern', 'brynja_hash_sha2=' + str(self.directory / 'dependencies/libbrynja_hash_sha2.rlib'),
            '-L', 'dependency=' + str(self.directory / 'dependencies'),
            '-o', str(self.directory / 'consumer.rmeta')], capture_output=True, text=True, timeout=30)

    def test_ownership_negatives_have_real_positive_control(self):
        begin = ('fn probe() { let mut issuer = Issuer::new(7).unwrap(); '
                 'let mut workspace = Sha256Workspace::new(); let mut bytes = [0; 32]; ')
        positive = begin + ('issuer.sha256(&mut workspace, &mut bytes, b"abc", |handle| '
                    '{ handle.cancel(handle.token()).unwrap(); }).unwrap(); assert_eq!(bytes, [0;32]); }')
        result = self.compile(positive)
        self.assertEqual(result.returncode, 0, result.stderr)
        negatives = []
        for kind in ('Issuer', "ResultHandle<'static>"):
            for bound in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug'):
                negatives.append((f'fn bound<T: {bound}>() {{}} fn probe() {{ bound::<{kind}>(); }}', 'E0277'))
        negatives.extend([
            (begin + 'let _escape = issuer.sha256(&mut workspace, &mut bytes, b"a", |h| h).unwrap(); }', 'lifetime'),
            (begin + 'issuer.sha256(&mut workspace, &mut bytes, b"a", |_h| bytes[0] = 9).unwrap(); }', 'E0499'),
            (begin + 'issuer.sha256(&mut workspace, &mut bytes, b"a", |_h| { let mut b = [0;32]; let mut w = Sha256Workspace::new(); issuer.sha256(&mut w, &mut b, b"a", |_| ()).unwrap(); }).unwrap(); }', 'E0499'),
            ('fn probe(h: &mut ResultHandle) { h.output = None; }', 'E0616'),
            ('fn probe(h: &mut ResultHandle) { h.token = [1, 1]; }', 'E0616'),
            ('fn probe(i: &mut Issuer) { i.last = 0; }', 'E0616'),
            (begin + 'let mut exposed = None; issuer.sha256(&mut workspace, &mut bytes, b"a", |h| { h.export_public(h.token(), PUBLIC_OUTPUT, |data| { exposed = Some(data); true }).unwrap(); }).unwrap(); }', 'E0521'),
        ])
        for source, diagnostic in negatives:
            result = self.compile(source)
            self.assertNotEqual(result.returncode, 0, source)
            self.assertIn(diagnostic, result.stderr, result.stderr)
        self.assertEqual(len(negatives), 17)


if __name__ == '__main__':
    unittest.main()
