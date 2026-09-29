#!/usr/bin/env python3
"""Compile host-lifetime regressions, mutants and ownership-negative consumers."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import windows_enclave_host_replay as replay
import windows_enclave_host_pair as pair

ROOT = replay.ROOT
VARIANTS = {
    'normal': None,
    'identity': ('probe_host_ignore_identity', 'stale_future_and_changed_identity_quarantine'),
    'epoch': ('probe_host_ignore_epoch', 'stale_future_and_changed_identity_quarantine'),
    'cleanup': ('probe_host_ignore_cleanup', 'missing_spent_or_cleanup_confirmation_never_commits'),
    'spent': ('probe_host_ignore_spent', 'missing_spent_or_cleanup_confirmation_never_commits'),
    'incomplete': ('probe_host_reuse_incomplete', 'aborted_or_unwinding_exchange_quarantines_and_never_commits'),
    'early-output': ('probe_host_commit_early', 'aborted_or_unwinding_exchange_quarantines_and_never_commits'),
}


class HostSessionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='brynja-enclave-host-')
        cls.path = Path(cls.temporary.name)
        cls.compiler = subprocess.check_output(['rustc', '+1.98.1', '-vV'], text=True)
        cls.target = next(line[6:] for line in cls.compiler.splitlines() if line.startswith('host: '))
        cls.base = ['rustc', '+1.98.1', '--edition=2024', '--target', cls.target, '-C', 'overflow-checks=yes']
        source = ROOT / 'assurance/windows-enclave-probe'
        for name in ('host_session_wire.rs', 'host_session_tests.rs'):
            shutil.copyfile(source / name, cls.path / name)
        cls.source = cls.path / 'host_session.rs'
        cls.source.write_text((source / 'host_session.rs').read_text() + replay.rust_test() +
            '\n#[cfg(test)]\n#[path = "host_pair_tests.rs"]\nmod paired;\n')
        cls.paired = pair.build(cls.path, cls.target)
        cls.library = cls.path / 'libenclave_host.rlib'
        subprocess.run(cls.base + ['--crate-name', 'enclave_host', '--crate-type', 'rlib',
            str(cls.source), '-o', str(cls.library)], capture_output=True, text=True, check=True, timeout=30)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_runtime_replay_and_six_real_compiled_mutants(self):
        for optimization in ('0', '2'):
            for name, mutation in VARIANTS.items():
                binary = self.path / (name + '-O' + optimization + ('.exe' if os.name == 'nt' else ''))
                command = self.base + self.paired + ['-C', 'opt-level=' + optimization,
                            '--test', str(self.source), '-o', str(binary)]
                if mutation:
                    command += ['--cfg', mutation[0]]
                compiled = subprocess.run(command, capture_output=True, text=True, timeout=30)
                self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
                result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=30)
                if name == 'normal':
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn('10 passed', result.stdout)
                else:
                    self.assertNotEqual(result.returncode, 0, name)
                    self.assertIn(mutation[1] + ' ... FAILED', result.stdout)
        print('Host model: 10 Rust tests at O0/O2; six compiled mutants rejected at both levels; '
              '42 saved native transcripts replayed locally and 61 paired Rust operations per level. '
              'New native execution: NO; Windows strict qualification: NO.')

    def compile(self, body):
        source = self.path / 'consumer.rs'
        source.write_text('use enclave_host::{Session, Pending, Disposition, PublicInput, State};\n' + body)
        return subprocess.run(self.base + ['--crate-type', 'lib', '--emit=metadata', str(source),
            '--extern', 'enclave_host=' + str(self.library), '-o', str(self.path / 'consumer.rmeta')],
            capture_output=True, text=True, timeout=30)

    def test_real_positive_consumer_and_ownership_rejections(self):
        prefix = ('fn probe() { let mut session = Session::new(); let mut input = [1;8]; '
                  'let mut output = [0;32]; ')
        prepare = ('let mut pending = session.prepare(PublicInput::acknowledge(&input), '
                   'Disposition::ExportPublic(&mut output)).unwrap(); ')
        positive = prefix + prepare + 'drop(pending); assert_eq!(session.state(), State::Ready); }'
        result = self.compile(positive)
        self.assertEqual(result.returncode, 0, result.stderr)
        negatives = []
        for kind in ('Session', "Pending<'static,'static,'static>"):
            for bound in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug'):
                negatives.append((f'fn bound<T: {bound}>() {{}} fn probe() {{ bound::<{kind}>(); }}', 'E0277'))
        for body, diagnostic in (
            ('drop(session); drop(pending);', 'E0505'),
            ('input[0] = 9; drop(pending);', 'E0506'),
            ('output[0] = 9; drop(pending);', 'E0506'),
            ('let _again = session.prepare(PublicInput::acknowledge(&input), Disposition::Cancel); drop(pending);', 'E0499'),
            ('pending.staging[0] = 9;', 'E0616'),
            ('pending.token = Some([1;4]);', 'E0616'),
            ('pending.enter(1,2).unwrap();', 'E0624'),
            ('pending.offer(&[0;64]).unwrap();', 'E0624'),
            ('pending.receive_public(&[0;32]).unwrap();', 'E0624'),
            ('pending.finish(1,21,true,true).unwrap();', 'E0624'),
        ):
            negatives.append((prefix + prepare + body + '}', diagnostic))
        for field, value in (('epoch', '0'), ('namespace', 'Some([1;2])'), ('state', 'State::Ready')):
            negatives.append((prefix + f'session.{field} = {value};' + '}', 'E0616'))
        negatives.append(("fn escape() -> Pending<'static,'static,'static> { let mut session = Session::new(); "
                          'session.prepare(PublicInput::acknowledge(b""), Disposition::Cancel).unwrap() }', 'E0515'))
        for body, diagnostic in negatives:
            result = self.compile(body)
            self.assertNotEqual(result.returncode, 0, body)
            self.assertIn(diagnostic, result.stderr)
        self.assertEqual(len(negatives), 24)
        print('Host ownership: positive consumer compiled; 24 privacy/lifetime/trait violations rejected.')

    def test_native_record_binding_cannot_silently_change(self):
        # Local corruption controls for the reader: no real observation is edited.
        from unittest.mock import patch
        original = Path.read_text
        def changed(path, *args, **kwargs):
            text = original(path, *args, **kwargs)
            if path.name == 'window-wire-publish-53ec2efe.json':
                value = json.loads(text)
                value['source_sha256'][next(iter(value['source_sha256']))] = '0' * 64
                return json.dumps(value)
            return text
        with patch.object(Path, 'read_text', changed):
            with self.assertRaisesRegex(ValueError, 'source binding'):
                replay.records()


if __name__ == '__main__':
    unittest.main()
