#!/usr/bin/env python3
"""Negative controls for the identity-bound AES differential runner."""
import contextlib
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('aes_differential', Path(__file__).with_name('check-aes-differential.py'))
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class DifferentialTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.exe = Path(self.temp.name) / 'openssl'
        self.exe.write_bytes(b'public test executable')
        self.exe.chmod(0o755)

    def fake_run(self, command, **kwargs):
        if command[0] == 'cargo':
            self.assertEqual(kwargs['env']['BRYNJA_OPENSSL'], str(self.exe))
            self.assertIn('--locked', command)
            self.assertIn('--offline', command)
            return subprocess.CompletedProcess(command, 0)
        self.assertEqual(command[0], str(self.exe))
        self.assertEqual(kwargs['env']['OPENSSL_CONF'], '/dev/null')
        self.assertTrue(kwargs['check'])
        if command[1] == 'version':
            return subprocess.CompletedProcess(command, 0, b'OpenSSL test fixture\n')
        bits = int(command[2].split('-')[2])
        self.assertEqual(command[command.index('-K') + 1], bytes(range(bits // 8)).hex())
        plain = bytes.fromhex('00112233445566778899aabbccddeeff')
        cipher = bytes.fromhex(runner.VECTORS[bits])
        self.assertEqual(kwargs['input'], cipher if command[-1] == '-d' else plain)
        return subprocess.CompletedProcess(command, 0, plain if command[-1] == '-d' else cipher)

    def test_select_resolves_symlink_once(self):
        link = self.exe.with_name('link')
        link.symlink_to(self.exe)
        with patch.object(runner.shutil, 'which', return_value=str(link)):
            self.assertEqual(runner.select({'PATH': self.temp.name}), self.exe)

    def test_missing_oracle_rejected(self):
        with patch.object(runner.shutil, 'which', return_value=None), self.assertRaises(ValueError):
            runner.select({'PATH': ''})

    def test_nonexecutable_rejected(self):
        self.exe.chmod(0o644)
        with patch.object(runner.shutil, 'which', return_value=str(self.exe)), self.assertRaises(ValueError):
            runner.select({})

    def test_directory_rejected(self):
        with patch.object(runner.shutil, 'which', return_value=self.temp.name), self.assertRaises(ValueError):
            runner.select({})

    def test_environment_override_rejected_even_empty(self):
        self.assertTrue({'LD_PRELOAD', 'LD_LIBRARY_PATH', 'LD_AUDIT', 'OPENSSL_ia32cap'} <= set(runner.FORBIDDEN))
        for name in runner.FORBIDDEN:
            for value in ('', '/tmp/untrusted'):
                with self.subTest(name=name, value=value), self.assertRaisesRegex(ValueError, name):
                    runner.select({name: value})

    def test_real_digest(self):
        self.assertEqual(runner.digest(self.exe), hashlib.sha256(self.exe.read_bytes()).hexdigest())

    def test_success_binds_both_suites_and_logs_identity(self):
        self.assertIn('executable identity', runner.SUCCESS)
        self.assertIn('shared libraries not measured', runner.SUCCESS)
        for suite, target in (('128', 'aes128_differential'), ('wide', 'aes_wide_differential')):
            output = io.StringIO()
            with patch.dict(os.environ, {}, clear=True), \
                 patch.object(runner.shutil, 'which', return_value=str(self.exe)), \
                 patch.object(runner.subprocess, 'run', side_effect=self.fake_run) as run, \
                 contextlib.redirect_stdout(output):
                runner.run(suite)
            self.assertEqual(run.call_count, 8)  # version, six known answers, cargo
            self.assertIn(target, run.call_args.args[0])
            self.assertIn(runner.digest(self.exe), output.getvalue())
            self.assertIn(str(self.exe), output.getvalue())
            self.assertTrue(output.getvalue().endswith(runner.SUCCESS + '\n'))

    def test_preflight_wrong_output_prevents_cargo(self):
        def broken(command, **kwargs):
            result = self.fake_run(command, **kwargs)
            if command[1] == 'enc':
                result.stdout = kwargs['input']  # echo is not a known answer
            return result
        with patch.dict(os.environ, {}, clear=True), \
             patch.object(runner.shutil, 'which', return_value=str(self.exe)), \
             patch.object(runner.subprocess, 'run', side_effect=broken) as run, \
             contextlib.redirect_stdout(io.StringIO()), self.assertRaisesRegex(ValueError, 'known-answer'):
            runner.run('wide')
        self.assertEqual(run.call_count, 2)

    def test_wrong_version_prevents_known_answers(self):
        with patch.object(runner.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'fake')), \
             self.assertRaisesRegex(ValueError, 'version'):
            runner.preflight(self.exe, {})

    def test_nonzero_and_timeout_never_print_completion(self):
        for failure_at in ('version', 'enc', 'cargo'):
            for failure in (subprocess.CalledProcessError(1, 'test'), subprocess.TimeoutExpired('test', 1)):
                def fail(command, **kwargs):
                    if command[0] == failure_at or command[1] == failure_at:
                        raise failure
                    return self.fake_run(command, **kwargs)
                output = io.StringIO()
                with self.subTest(at=failure_at, error=type(failure)), patch.dict(os.environ, {}, clear=True), \
                     patch.object(runner.shutil, 'which', return_value=str(self.exe)), \
                     patch.object(runner.subprocess, 'run', side_effect=fail), \
                     contextlib.redirect_stdout(output), self.assertRaises(type(failure)):
                    runner.run('wide')
                self.assertNotIn(runner.SUCCESS, output.getvalue())

    def test_changed_binary_never_prints_completion(self):
        output = io.StringIO()
        with patch.dict(os.environ, {}, clear=True), \
             patch.object(runner.shutil, 'which', return_value=str(self.exe)), \
             patch.object(runner.subprocess, 'run', side_effect=self.fake_run), \
             patch.object(runner, 'digest', side_effect=['before', 'after']), \
             contextlib.redirect_stdout(output), self.assertRaisesRegex(ValueError, 'changed'):
            runner.run('wide')
        self.assertNotIn(runner.SUCCESS, output.getvalue())

    def test_invalid_suite_prevents_execution(self):
        with patch.object(runner.subprocess, 'run') as run, self.assertRaises(ValueError):
            runner.run('anything')
        run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
