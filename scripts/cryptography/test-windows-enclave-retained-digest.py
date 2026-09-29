#!/usr/bin/env python3
"""Retained SHA-256 component tests; not native protected-memory evidence."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import windows_enclave_retained_build as build


class Tests(unittest.TestCase):
    def test_real_hashes_lifecycle_and_four_compiled_mutants(self):
        identity = subprocess.check_output(['rustc', '+1.98.1', '-vV'], text=True)
        target = next(line[6:] for line in identity.splitlines() if line.startswith('host: '))
        with tempfile.TemporaryDirectory(prefix='brynja-retained-digest-') as tmp:
            path = Path(tmp)
            for level in ('0', '2'):
                build.build(path, target, testing=True, level=level)
                for variant in build.VARIANTS:
                    binary = path / (variant + ('.exe' if os.name == 'nt' else ''))
                    result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=30)
                    if variant == 'normal':
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                        self.assertIn('4 passed', result.stdout)
                    else:
                        self.assertNotEqual(result.returncode, 0, variant)
                        expected = ('export_requires_public_acknowledgment_and_quarantine_is_terminal'
                                    if variant == 'public' else 'cancel_reuse_abandonment_and_busy_preserve_ownership')
                        self.assertIn(expected + ' ... FAILED', result.stdout)
            print('Retained SHA-256: four tests at O0/O2, twenty independent digests; four mutants rejected per level.')

    def test_owner_privacy_and_lifetime(self):
        identity = subprocess.check_output(['rustc', '+1.98.1', '-vV'], text=True)
        target = next(line[6:] for line in identity.splitlines() if line.startswith('host: '))
        with tempfile.TemporaryDirectory(prefix='brynja-retained-owner-') as tmp:
            path = Path(tmp)
            build.build(path, target)
            def compile(body):
                source = path / 'consumer.rs'
                source.write_text('use retained_digest::Owner;\n' + body)
                return subprocess.run(['rustc', '+1.98.1', '--edition=2024', '--crate-type', 'lib',
                    '--emit=metadata', '-L', 'dependency=' + str(path),
                    '--extern', 'retained_digest=' + str(path / 'libretained_digest_normal.rlib'),
                    str(source), '-o', str(path / 'consumer.rmeta')],
                    capture_output=True, text=True, timeout=30)
            prefix = 'fn check() { let mut bytes=[0;32]; let mut owner=Owner::new(&mut bytes,[7,9]).unwrap(); '
            result = compile(prefix + 'owner.close(); drop(owner); bytes[0]=1; }')
            self.assertEqual(result.returncode, 0, result.stderr)
            cases = [(f'fn bound<T:{trait}>() {{}} fn check() {{ bound::<Owner>(); }}', 'E0277')
                     for trait in ('Send', 'Sync', 'Clone', 'Copy', 'core::fmt::Debug')]
            cases += [
                (prefix + 'bytes[0]=1; owner.close(); }', 'E0506'),
                ("fn check() -> Owner<'static> { let mut bytes=[0;32]; Owner::new(&mut bytes,[7,9]).unwrap() }", 'E0515'),
                (prefix + 'let _ = owner.slot; }', 'E0616'),
                (prefix + 'let _ = owner.expose(); }', 'E0599'),
                (prefix + 'let mut escaped=None; let _=owner.export_public([7,9,1,1],0,|b| { escaped=Some(b); true }); }', 'E0521'),
            ]
            for body, diagnostic in cases:
                result = compile(body)
                self.assertNotEqual(result.returncode, 0, body)
                self.assertIn(diagnostic, result.stderr)
            print('Retained SHA-256: positive owner consumer; ten ownership/privacy/escape rejections.')

    def test_digest_copy_is_load_bearing(self):
        identity = subprocess.check_output(['rustc', '+1.98.1', '-vV'], text=True)
        target = next(line[6:] for line in identity.splitlines() if line.startswith('host: '))
        with tempfile.TemporaryDirectory(prefix='brynja-retained-copy-') as tmp:
            path = Path(tmp)
            commands = build.build(path, target, testing=True)
            source = path / 'retained_digest.rs'
            original = source.read_text()
            anchor = 'destination.copy_from_slice(output.expose());'
            self.assertEqual(original.count(anchor), 1)
            source.write_text(original.replace(anchor,
                'destination.copy_from_slice(output.expose()); destination[0] ^= 1;'))
            command = next(c for c in commands if '--test' in c)
            result = subprocess.run(command, capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
            binary = path / ('normal.exe' if os.name == 'nt' else 'normal')
            result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=30)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('independent_twenty_vector_oracle_retains_digest_after_worker_exit ... FAILED', result.stdout)


if __name__ == '__main__':
    unittest.main()
