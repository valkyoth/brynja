#!/usr/bin/env python3
"""Offline regressions for native Darwin CI wiring and fail-closed execution."""
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('resident_ci', ROOT / 'scripts/cryptography/check-macos-resident-ci.py')
ci = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ci)
spec = importlib.util.spec_from_file_location('resident_codegen', ROOT / 'scripts/cryptography/check-macos-resident-codegen.py')
codegen = importlib.util.module_from_spec(spec)
spec.loader.exec_module(codegen)


class ResidentCiTests(unittest.TestCase):
    def test_exact_outlined_attribute_helper_is_load_bearing(self):
        root = 'define void @_RNroot() {\n call void @_RNmacos_resident_10Attributes3new()\n ret void\n}'
        helper = ('define void @_RNmacos_resident_10Attributes3new() {\n'
                  ' call i32 @pthread_attr_init()\n call i32 @pthread_attr_setstack()\n ret void\n}')
        llvm = root + '\n' + helper
        assembly = ('__RNroot:\n bl __RNmacos_resident_10Attributes3new\n ret\n'
                    '__RNmacos_resident_10Attributes3new:\n bl _pthread_attr_init\n'
                    ' bl _pthread_attr_setstack\n ret\n')
        codegen.attribute_setup(llvm, assembly, root)
        cases = [(llvm, assembly, root.replace('call void', '; absent')),
                 (llvm + '\n' + helper, assembly, root),
                 (llvm, assembly.replace('bl __RNmacos', 'bl __removed'), root)]
        for name in ('pthread_attr_init', 'pthread_attr_setstack'):
            cases += [(llvm.replace('@' + name, '@removed'), assembly, root),
                      (llvm, assembly.replace('_' + name, '_removed'), root)]
        for changed in cases:
            with self.assertRaises(ValueError):
                codegen.attribute_setup(*changed)

    def test_workflow_runs_native_job_and_regressions(self):
        workflow = (ROOT / '.github/workflows/qualification.yml').read_text()
        job = workflow.split('  macos-resident:\n', 1)[1].split('\n  host:', 1)[0]
        self.assertIn('runs-on: macos-latest', job)
        self.assertIn('run: python3 scripts/cryptography/check-macos-resident-ci.py --stage tests\n', job)
        self.assertNotIn('continue-on-error', job)
        self.assertIn('python3 scripts/repository/test-macos-resident-ci.py',
                      (ROOT / 'scripts/checks.sh').read_text())

    def test_host_and_missing_capabilities_reject_before_cargo(self):
        for system, machine in (('Linux', 'aarch64'), ('Darwin', 'x86_64')):
            with patch.object(ci.platform, 'system', return_value=system), \
                 patch.object(ci.platform, 'machine', return_value=machine), \
                 patch.object(ci, 'run', side_effect=AssertionError('cargo executed')):
                with self.assertRaises(ValueError):
                    ci.execute('all', Path('/unused'))
        for missing in range(4):
            values = ['1'] * 4
            values[missing] = '0'
            with patch.object(ci.platform, 'system', return_value='Darwin'), \
                 patch.object(ci.platform, 'machine', return_value='arm64'), \
                 patch.object(ci.subprocess, 'check_output', side_effect=values):
                with self.assertRaises(ValueError):
                    ci.require_host()

    def test_push_stage_keeps_native_debug_release_and_lint(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(ci, 'require_host'), patch.object(ci, 'run') as run:
            ci.execute('tests', Path(directory))
        commands = [call.args[0] for call in run.call_args_list]
        self.assertEqual(len(commands), 4)
        tests = [command for command in commands if 'test' in command]
        self.assertEqual(len(tests), 2)
        self.assertEqual(sum('--release' in command for command in tests), 1)
        for command in tests:
            self.assertIn('--all-features', command)
            self.assertIn('brynja-crypto-cpu-std', command)
            self.assertIn('brynja-hash-parallel-std', command)
        self.assertEqual(sum('clippy' in command for command in commands), 1)

    def test_complete_matrix_and_clean_environment(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(ci, 'require_host'), patch.object(ci, 'run') as run, \
             patch.dict(os.environ, {'CARGO_ENCODED_RUSTFLAGS': 'bad',
                                     'CARGO_BUILD_BUILD_DIR': '/stale', 'RUSTFLAGS': '-Zsanitizer=address'}):
            ci.execute('all', Path(directory))
        commands = [call.args[0] for call in run.call_args_list]
        self.assertEqual(len(commands), 24)  # fetch, 2 tests, clippy, 8 build/check pairs, 4 packages
        checks = [c for c in commands if any('codegen.py' in str(x) for x in c)]
        self.assertEqual(len(checks), 8)
        targets = set()
        for call in run.call_args_list:
            command, env = call.args
            self.assertNotIn('CARGO_ENCODED_RUSTFLAGS', env)
            self.assertNotIn('CARGO_BUILD_BUILD_DIR', env)
            self.assertIn(ci.FEATURES, env['RUSTFLAGS'])
            if 'build' in command:
                targets.add(env['CARGO_TARGET_DIR'])
                self.assertIn('--emit=llvm-ir,asm', env['RUSTFLAGS'])
        self.assertEqual(len(targets), 8)
        self.assertTrue(any('--keyed' in c and '--accelerated' in c for c in commands))
        self.assertTrue(any('clippy' in c and '--all-targets' in c for c in commands))
        for command in commands:
            if 'test' in command:
                self.assertIn('brynja-crypto-cpu', command)

    def test_command_failure_is_fatal(self):
        with patch.object(ci.subprocess, 'run', side_effect=subprocess.CalledProcessError(1, ['cargo'])):
            with self.assertRaises(subprocess.CalledProcessError):
                ci.run(['cargo', 'test'], {})


if __name__ == '__main__':
    unittest.main()
