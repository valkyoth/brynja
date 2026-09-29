#!/usr/bin/env python3
"""Concrete facade behavior and downstream surface regressions."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
import windows_enclave_retained_facade_build as build
import windows_enclave_retained_facade_run as native

spec = importlib.util.spec_from_file_location('lifetime_tests', Path(__file__).with_name('test-windows-enclave-retained-lifetime.py'))
support = importlib.util.module_from_spec(spec); spec.loader.exec_module(support)


class Tests(unittest.TestCase):
    def test_behavior_and_mutants(self):
        with tempfile.TemporaryDirectory(prefix='retained-facade-') as tmp:
            root = Path(tmp); build.prepare(root); support.adapter_tests(root)
            path = root/'retained_native_adapter_tests.rs'
            with path.open('a') as output:
                output.write((build.SOURCE/'retained_facade_tests.rs').read_text())
            for level in ('0', '2'):
                for cfg, failure in [(None, None),
                    ('probe_retained_host_early_commit', 'facade_rejects_failure_without_public_commit'),
                    ('probe_retained_host_ignore_receipt', 'facade_rejects_failure_without_public_commit'),
                    ('probe_retained_host_reopen_abandoned', 'facade_abandon_forget_unwind')]:
                    command = ['rustc', '+1.98.1', '--edition=2024', '--test', '-D', 'warnings',
                        '-C', 'opt-level='+level, str(root/'retained_native_host.rs'), '-o', str(root/'tests')]
                    if cfg: command += ['--cfg', cfg]
                    result = subprocess.run(command, capture_output=True, text=True, timeout=60)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    result = subprocess.run([str(root/'tests')], capture_output=True, text=True, timeout=30)
                    self.assertEqual(result.returncode == 0, failure is None, result.stdout+result.stderr)
                    self.assertIn('19 passed' if failure is None else failure, result.stdout)

    def test_downstream_surface(self):
        with tempfile.TemporaryDirectory(prefix='retained-facade-api-') as tmp:
            root = Path(tmp); build.prepare(root)
            result = subprocess.run(['rustc', '+1.98.1', '--edition=2024', '--crate-type', 'rlib',
                '--crate-name', 'candidate', '--emit=metadata', '-D', 'warnings',
                str(root/'retained_native_host.rs'), '-o', str(root/'libcandidate.rmeta')],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
            positive = '''pub fn use_api(s: &mut Session, input: &[u8], out: &mut [u8;32]) -> Result<(), Error> {
                s.hash(input)?.rehash()?.declassify(out, PublicDeclassification::acknowledge())?;
                s.hash(input)?.cancel()?; let _ = s.state(); s.close()
            }'''
            cases = [(positive, None)]
            for trait in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug'):
                for ty in ('Session', "Digest<'static>"):
                    cases.append(('pub fn bad(){ fn need<T:'+trait+'>(){} need::<'+ty+'>(); }', 'E0277'))
            cases += [
                ('pub fn bad(){let _ = Session::new();}', 'E0599'),
                ('pub fn bad(){let _ = Session::from_retained(todo!());}', 'E0624'),
                ('pub fn bad(s: &Session){let _ = &s.inner;}', 'E0616'),
                ('pub fn bad(d: Digest){let _ = d.inner;}', 'E0616'),
                ('pub fn bad(d: Digest){let _ = d.expose();}', 'E0599'),
                ('pub fn bad(d: Digest){let _: &[u8] = d.as_ref();}', 'E0599'),
                ('pub fn bad(d: Digest){let _ = *d;}', 'E0614'),
                ('pub fn bad(d: Digest, out: &mut [u8;32]){let _ = d.declassify(out);}', 'E0061'),
                ('pub fn bad(d: Digest, out: &mut [u8;31]){let _ = d.declassify(out, PublicDeclassification::acknowledge());}', 'E0308'),
                ('pub fn bad(){let _ = PublicDeclassification(());}', 'E0423'),
                ('pub fn bad(){let _ = candidate::open(&[0],0);}', 'E0603'),
                ('pub fn bad(s: &mut Session){let d=s.hash(b"abc").unwrap(); s.close().unwrap(); drop(d);}', 'E0499'),
                ('pub fn bad(mut s: Session){let d=s.hash(b"abc").unwrap(); drop(s); drop(d);}', 'E0505'),
                ('pub fn bad(s: &mut Session){let d=s.hash(b"abc").unwrap(); let _second=s.hash(b"def"); drop(d);}', 'E0499'),
                ('pub fn bad(s: &mut Session){let d=s.hash(b"abc").unwrap(); d.cancel().unwrap(); let _=d.rehash();}', 'E0382')]
            for body, diagnostic in cases:
                (root/'consumer.rs').write_text('#![no_std]\nuse candidate::retained_facade::*;\n'+body)
                result = subprocess.run(['rustc', '+1.98.1', '--edition=2024', '--crate-type', 'lib',
                    '--emit=metadata', '--extern', 'candidate='+str(root/'libcandidate.rmeta'),
                    str(root/'consumer.rs'), '-o', str(root/'consumer.rmeta')],
                    capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode == 0, diagnostic is None, result.stderr)
                if diagnostic: self.assertIn(diagnostic, result.stderr)
            self.assertEqual(len(cases), 26)

    def test_capture_schema(self):
        for expected in native.EXPECTED.values():
            value = dict(zip(native.FIELDS, expected[1:])); native.validate(value, expected[0], expected)
            for field in native.FIELDS:
                for bad in (value[field]+1, bool(value[field])):
                    with self.assertRaises(ValueError): native.validate(dict(value, **{field:bad}), expected[0], expected)
            with self.assertRaises(ValueError): native.validate(value, expected[0]+1, expected)


if __name__ == '__main__': unittest.main()
