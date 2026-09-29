#!/usr/bin/env python3
"""Direct-borrow input lifecycle, first-party hashing, mutants and privacy probes."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import windows_enclave_borrowed_build as build

MUTANTS = {
    'probe_borrowed_skip_clear': 'every_length_has_one_bounded_copy_no_reread_and_full_cleanup',
    'probe_borrowed_ignore_copy': 'copy_errors_partial_writes_and_both_unwind_paths_clear_capacity',
    'probe_borrowed_reread': 'every_length_has_one_bounded_copy_no_reread_and_full_cleanup',
    'probe_borrowed_full_capacity': 'every_length_has_one_bounded_copy_no_reread_and_full_cleanup',
}


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='brynja-borrowed-input-')
        cls.path = Path(cls.temporary.name)
        cls.identity = subprocess.check_output(['rustc', '+1.98.1', '-vV'], text=True)
        cls.target = next(line[6:] for line in cls.identity.splitlines() if line.startswith('host: '))
        build.prepare(cls.path, cls.target)
        cls.command = build.arguments(cls.path, cls.target)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_lifecycle_crypto_and_four_compiled_mutants_at_two_levels(self):
        for optimization in ('0', '2'):
            for mutant in [None, *MUTANTS]:
                executable = self.path / ('test.exe' if os.name == 'nt' else 'test')
                command = self.command + ['-C', 'opt-level=' + optimization, '--test',
                    str(self.path / 'borrowed_input.rs'), '-o', str(executable)]
                if mutant:
                    command += ['--cfg', mutant]
                result = subprocess.run(command, capture_output=True, text=True, timeout=60)
                self.assertEqual(result.returncode, 0, result.stderr)
                run = subprocess.run([str(executable)], capture_output=True, text=True, timeout=30)
                if mutant:
                    self.assertNotEqual(run.returncode, 0, mutant)
                    self.assertIn(MUTANTS[mutant] + ' ... FAILED', run.stdout)
                else:
                    self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
                    self.assertIn('4 passed', run.stdout)
        print('Borrowed input: four Rust tests at O0/O2, all 1025 lengths, twenty independent digests; '
              'four compiled mutants rejected at each level.')

    def test_real_borrow_lifetimes_and_private_storage(self):
        library = self.path / 'libenclave_borrowed.rlib'
        subprocess.run(self.command + ['--crate-type', 'rlib', str(self.path / 'borrowed_input.rs'),
            '-o', str(library)], capture_output=True, check=True, timeout=30)
        def compile(body):
            source = self.path / 'consumer.rs'
            source.write_text('use enclave_borrowed::{Request, Snapshot};\n' + body)
            return subprocess.run(['rustc', '+1.98.1', '--edition=2024', '--crate-type', 'lib',
                '--emit=metadata', '-L', 'dependency=' + str(self.path),
                '--extern', 'enclave_borrowed=' + str(library), str(source),
                '-o', str(self.path / 'consumer.rmeta')], capture_output=True, text=True, timeout=30)
        result = compile('fn ok(input: &[u8]) { let request = Request::new(input, 4096).unwrap(); '
                         'let mut snapshot = Snapshot::new(); '
                         'let _ = snapshot.with(request.metadata(), |_, _| false, |bytes, _| bytes.len()); }')
        self.assertEqual(result.returncode, 0, result.stderr)
        cases = []
        for kind in ("Request<'static>", 'Snapshot'):
            for bound in ('Send', 'Sync', 'Clone', 'Copy', 'core::fmt::Debug'):
                cases.append((f'fn bound<T: {bound}>() {{}} fn bad() {{ bound::<{kind}>(); }}', 'E0277'))
        cases += [
            ('fn bad() { let mut data = [1;32]; let request = Request::new(&data,4096).unwrap(); '
             'data[0] = 2; let _ = request.metadata(); }', 'E0506'),
            ("fn bad() -> Request<'static> { let data = [1;32]; Request::new(&data,4096).unwrap() }", 'E0515'),
            ('fn bad() { let request = Request::new(b"x",4096).unwrap(); let _ = request.header; }', 'E0616'),
            ('fn bad() { let snapshot = Snapshot::new(); let _ = snapshot.bytes; }', 'E0616'),
            ('fn bad() { let mut snapshot = Snapshot::new(); let request = Request::new(b"x",4096).unwrap(); '
             'let _ = snapshot.with(request.metadata(), |_, _| true, |bytes, _| bytes); }', 'lifetime may not live long enough'),
            ('fn bad() { let mut saved = None; let mut snapshot = Snapshot::new(); '
             'let request = Request::new(b"x",4096).unwrap(); '
             'let _ = snapshot.with(request.metadata(), |_, bytes| { saved = Some(bytes); true }, |_, _| ()); }', 'E0521'),
        ]
        for body, diagnostic in cases:
            result = compile(body)
            self.assertNotEqual(result.returncode, 0, body)
            self.assertIn(diagnostic, result.stderr)
        print('Borrowed input: positive consumer compiled; sixteen ownership/privacy/escape cases rejected.')


if __name__ == '__main__':
    unittest.main()
