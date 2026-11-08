#!/usr/bin/env python3
"""Fail-closed lifecycle completion and packaged fixture regression tests."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import tomllib
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('lifecycle', Path(__file__).with_name('check-aes-linked-lifecycle.py'))
lifecycle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lifecycle)


class LinkedLifecycleTests(unittest.TestCase):
    def test_exact_owner_and_panic_population(self):
        self.assertEqual(len(lifecycle.OWNERS), 6)
        for panic in ('abort', 'unwind'):
            lines = lifecycle.output_lines(panic)
            output = '\n'.join(lines) + '\n'
            lifecycle.output_check(output, panic)
            for bad in (output + output, '\n'.join(lines[:-1]), '\n'.join(reversed(lines)),
                        output.replace('Aes256Key', 'Aes192Key'), output + 'extra\n',
                        '\n'.join(lifecycle.output_lines('abort' if panic == 'unwind' else 'unwind'))):
                with self.assertRaisesRegex(ValueError, 'lifecycle markers'):
                    lifecycle.output_check(bad, panic)
        with self.assertRaisesRegex(ValueError, 'unsupported'):
            lifecycle.output_lines('other')

    def test_negative_control_must_fail_for_exact_reason(self):
        good = subprocess.CompletedProcess([], 101, '', 'unexpected panic payload')
        lifecycle.negative_result(good, 'unexpected panic payload')
        for status, stdout, stderr in ((0, '', good.stderr), (-6, '', good.stderr),
                                       (1, '', good.stderr), (101, 'PASS', good.stderr),
                                       (101, '', 'unrelated assertion')):
            with self.assertRaisesRegex(ValueError, 'negative control'):
                lifecycle.negative_result(subprocess.CompletedProcess([], status, stdout, stderr),
                                          'unexpected panic payload')

    def test_prepare_preserves_original_fixture_and_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            (directory / 'Cargo.toml').write_text('[profile.release]\noverflow-checks=true\n')
            lifecycle.prepare(directory)
            self.assertEqual((directory / 'src/bin/lifecycle.rs').read_bytes(), lifecycle.FIXTURE.read_bytes())
            self.assertEqual((directory / 'src/bin/linked.rs').read_bytes(), lifecycle.linked.FIXTURE.read_bytes())
            self.assertEqual(tomllib.loads((directory / 'Cargo.toml').read_text())['profile']['release'],
                             {'overflow-checks': True, 'opt-level': 3, 'lto': 'fat', 'codegen-units': 1, 'strip': False})

    def test_missing_or_symlinked_fixture_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            alias = directory / 'alias.rs'
            for exists in (False, True):
                if exists:
                    alias.symlink_to(lifecycle.FIXTURE)
                with patch.object(lifecycle, 'FIXTURE', alias), self.assertRaisesRegex(ValueError, 'fixture'):
                    lifecycle.prepare(directory)

    def test_host_and_ambient_overrides_rejected_before_packaging(self):
        with patch.object(lifecycle.platform, 'machine', return_value='aarch64'), self.assertRaisesRegex(ValueError, 'native'):
            lifecycle.check('1.90.0')
        with patch.object(lifecycle.platform, 'system', return_value='Linux'), \
                patch.object(lifecycle.platform, 'machine', return_value='x86_64'):
            for name in lifecycle.linked.REJECT:
                with patch.dict('os.environ', {name: 'override'}, clear=True), \
                        patch.object(lifecycle.packaged, 'package_sources') as package:
                    with self.assertRaisesRegex(ValueError, 'remove ambient'):
                        lifecycle.check('1.90.0')
                    package.assert_not_called()

    def test_registry_binds_all_configurations_and_sources(self):
        registry = tomllib.loads((lifecycle.linked.ROOT / 'verification/checks.toml').read_text())
        for suffix, compiler in (('msrv', '1.90.0'), ('current', '1.99.1')):
            check = next(c for c in registry['checks'] if c['component'] == 'aes' and c['id'] == 'packaged-lifecycle-' + suffix)
            self.assertEqual(check['command'], ['python3', 'scripts/aes/check-aes-linked-lifecycle.py', '--toolchain', compiler])
            self.assertEqual(check['platform'], 'linux-x86_64')
            self.assertEqual(set(check['reject_environment']), set(lifecycle.linked.REJECT))
            self.assertTrue({'aes-packaged', 'aes-linked', 'aes-linked-lifecycle', 'aes-dataflow', 'hkdf-public-api-modern',
                             'compiler', 'hkdf-msrv'} <= set(check['inputs']))
            self.assertEqual(check['success']['unique_lines'], [lifecycle.marker(compiler, route, panic)
                             for route in ('direct', 'facade') for panic in ('abort', 'unwind')] +
                             [f'AES linked lifecycle completed: {compiler}; four binaries; 288 normal cases; 96 caller unwinds; 4 panic controls; 276 machine mutations rejected'])
        self.assertEqual(set(registry['groups']['aes-linked-lifecycle']['paths']), {
            'assurance/aes-linked/lifecycle.rs', 'scripts/aes/check-aes-linked-lifecycle.py',
            'scripts/aes/test-aes-linked-lifecycle.py', 'scripts/aes/aes_linked_cleanup.py',
            'scripts/aes/test-aes-linked-cleanup.py'})

    def test_missing_inspection_tools_fail_before_packaging(self):
        with patch.dict('os.environ', {}, clear=True), \
                patch.object(lifecycle.platform, 'system', return_value='Linux'), \
                patch.object(lifecycle.platform, 'machine', return_value='x86_64'), \
                patch.object(lifecycle.shutil, 'which', return_value=None), \
                patch.object(lifecycle.packaged, 'package_sources') as package:
            with self.assertRaisesRegex(ValueError, 'missing llvm-nm'):
                lifecycle.check('1.90.0')
            package.assert_not_called()


if __name__ == '__main__':
    unittest.main()
