#!/usr/bin/env python3
"""Research-only retained storage model: lifecycle, ownership and compiled mutants."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import windows_enclave_borrowed_build as build

MUTANTS = {
    'probe_persistent_skip_clear': 'abandonment_cancellation_close_and_lost_completion_clear',
    'probe_persistent_reuse_generation': 'survives_worker_scope_and_metadata_move_then_exports_once',
    'probe_persistent_ignore_token': 'wrong_identity_generation_slot_and_public_flag_are_terminal',
    'probe_persistent_implicit_public': 'wrong_identity_generation_slot_and_public_flag_are_terminal',
}
SOURCE = build.SOURCE / 'persistent_result.rs'


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='brynja-persistent-result-')
        cls.path = Path(cls.temporary.name)
        identity = subprocess.check_output(['rustc', '+1.98.1', '-vV'], text=True)
        cls.target = next(line[6:] for line in identity.splitlines() if line.startswith('host: '))
        build.prepare(cls.path, cls.target)
        cls.command = ['rustc', '+1.98.1', '--edition=2024', '--crate-name', 'persistent_result',
                       '-D', 'warnings', '-C', 'overflow-checks=yes',
                       '--extern', 'brynja_core=' + str(cls.path / 'libbrynja_core.rlib')]

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_two_optimization_levels_and_mutations(self):
        binary = self.path / ('test.exe' if os.name == 'nt' else 'test')
        for level in ('0', '2'):
            for mutant in (None, *MUTANTS):
                command = self.command + ['-C', 'opt-level=' + level, '--test', str(SOURCE), '-o', str(binary)]
                if mutant:
                    command += ['--cfg', mutant]
                result = subprocess.run(command, capture_output=True, text=True, timeout=60)
                self.assertEqual(result.returncode, 0, result.stderr)
                result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=30)
                if mutant:
                    self.assertNotEqual(result.returncode, 0, mutant)
                    self.assertIn(MUTANTS[mutant] + ' ... FAILED', result.stdout)
                else:
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn('6 passed', result.stdout)

    def test_ownership_and_non_escape(self):
        library = self.path / 'libpersistent_result.rlib'
        subprocess.run(self.command + ['--crate-type', 'rlib', str(SOURCE), '-o', str(library)],
                       check=True, capture_output=True, timeout=30)

        def compile(body):
            source = self.path / 'consumer.rs'
            source.write_text('use persistent_result::{Slot, PUBLIC_OUTPUT};\n' + body)
            return subprocess.run(['rustc', '+1.98.1', '--edition=2024', '--crate-type', 'lib',
                '--emit=metadata', '-L', 'dependency=' + str(self.path),
                '--extern', 'persistent_result=' + str(library), str(source),
                '-o', str(self.path / 'consumer.rmeta')], capture_output=True, text=True, timeout=30)

        prefix = 'fn probe() { let mut bytes = [0;32]; let mut s = Slot::new(&mut bytes,[1,2]).unwrap(); '
        positive = prefix + 'let t = s.fill(|b| { b.fill(4); true }).unwrap(); s.cancel(t).unwrap(); drop(s); bytes[0]=1; }'
        result = compile(positive)
        self.assertEqual(result.returncode, 0, result.stderr)
        negatives = [(f'fn bound<T: {trait}>() {{}} fn probe() {{ bound::<Slot>(); }}', 'E0277')
                     for trait in ('Send', 'Sync', 'Clone', 'Copy', 'core::fmt::Debug')]
        negatives += [
            (prefix + 'bytes[0]=1; s.close(); }', 'E0506'),
            ("fn probe() -> Slot<'static> { let mut b=[0;32]; Slot::new(&mut b,[1,2]).unwrap() }", 'E0515'),
            (prefix + 'let _ = s.bytes; }', 'E0616'),
            (prefix + 's.generation=0; }', 'E0616'),
            (prefix + 'let mut saved=None; s.fill(|b| { saved=Some(b); true }).unwrap(); }', 'E0521'),
            (prefix + 'let t=s.fill(|b| { b.fill(1); true }).unwrap(); let mut saved=None; '
             's.export_public(t,PUBLIC_OUTPUT,|b| { saved=Some(b); true }).unwrap(); }', 'E0521'),
        ]
        for body, diagnostic in negatives:
            result = compile(body)
            self.assertNotEqual(result.returncode, 0, body)
            self.assertIn(diagnostic, result.stderr)
        print('Persistent result model: positive consumer and 11 ownership/escape rejections.')


if __name__ == '__main__':
    unittest.main()
