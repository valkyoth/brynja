#!/usr/bin/env python3
"""Affine ownership model regressions; does not emulate/qualify OS teardown."""
from pathlib import Path
import subprocess
import tempfile
import unittest

import windows_enclave_retained_host_build as build


def host():
    identity = subprocess.check_output(['rustc', '+1.98.1', '-vV'], text=True)
    return next(line[6:] for line in identity.splitlines() if line.startswith('host: '))


class Tests(unittest.TestCase):
    def test_thread_marker_is_not_hidden_by_the_mock_driver(self):
        with tempfile.TemporaryDirectory(prefix='retained-host-thread-marker-') as tmp:
            directory = Path(tmp)
            build.prepare(directory, fixture=True)
            path = directory / 'retained_host.rs'
            original = path.read_text()
            anchor = 'thread_bound: PhantomData<*mut ()>'
            self.assertEqual(original.count(anchor), 1)
            for mutant in (False, True):
                path.write_text(original.replace(anchor, 'thread_bound: PhantomData<()>') if mutant else original)
                result = build.run(build.command(directory, host()))
                self.assertEqual(result.returncode, 0, result.stderr)
                for expression in ('owner', 'owner.begin(PublicVector::new(1).unwrap()).unwrap()'):
                    consumer = directory / 'thread.rs'
                    consumer.write_text('use retained_host::{fixture, PublicVector}; '
                        'fn bound<T:Send+Sync>(_:T) {} fn test() { let mut owner=fixture(); bound(' + expression + '); }')
                    result = build.run(['rustc', '+1.98.1', '--edition=2024', '--crate-type', 'lib',
                        '--emit=metadata', '--extern', 'retained_host=' + str(directory / 'libretained_host.rlib'),
                        str(consumer), '-o', str(directory / 'thread.rmeta')])
                    self.assertEqual(result.returncode == 0, mutant, result.stderr)
                    if not mutant:
                        self.assertIn('E0277', result.stderr)

    def test_lifecycle_receipts_and_four_compiled_mutants(self):
        target = host()
        with tempfile.TemporaryDirectory(prefix='retained-host-lifecycle-') as tmp:
            directory = Path(tmp)
            build.prepare(directory)
            failures = {'early': 'every_receipt_field_is_bound_and_output_is_transactional',
                        'reopen': 'abandonment_and_forget_never_reopen_or_drop_resource_early',
                        'receipt': 'every_receipt_field_is_bound_and_output_is_transactional',
                        'release': 'unconfirmed_release_never_claims_closed_or_destruction'}
            for level in ('0', '2'):
                for name, cfg in build.VARIANTS.items():
                    result = build.run(build.command(directory, target, level, True, cfg))
                    self.assertEqual(result.returncode, 0, result.stderr)
                    result = build.run([str(directory / ('test.exe' if 'windows' in target else 'test'))])
                    self.assertEqual(result.returncode == 0, name == 'normal', result.stdout + result.stderr)
                    self.assertIn('7 passed' if name == 'normal' else failures[name] + ' ... FAILED', result.stdout)

    def test_resource_and_result_cannot_escape_or_be_forged(self):
        target = host()
        with tempfile.TemporaryDirectory(prefix='retained-host-ownership-') as tmp:
            directory = Path(tmp)
            build.prepare(directory, fixture=True)
            result = build.run(build.command(directory, target))
            self.assertEqual(result.returncode, 0, result.stderr)
            start = 'let mut owner=fixture(); '
            pending = start + 'let pending=owner.begin(PublicVector::new(1).unwrap()).unwrap(); '
            cases = []
            for trait in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug'):
                for value, setup in [('owner', start), ('pending', pending)]:
                    cases.append((f'fn bound<T:{trait}>(_:T) {{}} fn test() {{ {setup} bound({value}); }}', 'E0277'))
            cases += [
                ('fn test() { ' + pending + 'drop(owner); pending.cancel().unwrap(); }', 'E0505'),
                ('fn test() { ' + pending + 'owner.close().unwrap(); pending.cancel().unwrap(); }', 'E0499'),
                ('fn test() { ' + pending + 'let _other=owner.begin(PublicVector::new(2).unwrap()); pending.cancel().unwrap(); }', 'E0499'),
                ('fn test() { ' + pending + 'pending.cancel().unwrap(); pending.cancel().unwrap(); }', 'E0382'),
                ('fn test() { ' + pending + 'core::mem::forget(owner); pending.cancel().unwrap(); }', 'E0505'),
                ('fn test() { ' + start + 'let _=owner.driver; }', 'E0616'),
                ('fn test() { ' + start + 'let _=owner.identity; }', 'E0616'),
                ('fn test() { ' + pending + 'let _=pending.session; }', 'E0616'),
                ('fn test() { ' + pending + 'let _=pending.token; }', 'E0609'),
                ('fn test() { ' + start + 'owner.complete(); }', 'E0599'),
                ("fn test() -> impl Sized + 'static { " + pending + 'pending }', 'E0515'),
                ('use retained_host::transport::Driver;', 'E0603'),
                ('fn test() { let _=PublicVector(1); }', 'E0423'),
            ]
            positive = ('fn test() { let mut owner=fixture(); let mut out=[0;32]; '
                        'owner.begin(PublicVector::new(1).unwrap()).unwrap().export_public(&mut out).unwrap(); '
                        'let pending=owner.begin(PublicVector::new(2).unwrap()).unwrap(); core::mem::forget(pending); '
                        'owner.close().unwrap(); }')
            for source, diagnostic in [(positive, None)] + cases:
                path = directory / 'consumer.rs'
                path.write_text('use retained_host::{fixture, PublicVector};\n' + source)
                result = build.run(['rustc', '+1.98.1', '--edition=2024', '--crate-type', 'lib',
                    '--emit=metadata', '--extern', 'retained_host=' + str(directory / 'libretained_host.rlib'),
                    str(path), '-o', str(directory / 'consumer.rmeta')])
                if diagnostic:
                    self.assertNotEqual(result.returncode, 0, source)
                    self.assertIn(diagnostic, result.stderr)
                else:
                    self.assertEqual(result.returncode, 0, result.stderr)
            print(f'Retained host: positive consumer and {len(cases)} ownership/forgery rejections.')


if __name__ == '__main__':
    unittest.main()
