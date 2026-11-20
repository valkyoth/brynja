#!/usr/bin/env python3
"""Runner regressions; do not execute the large experiment in these tests."""
import importlib.util
import contextlib
import io
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('fault_data', Path(__file__).with_name('check-aes-fault-data.py'))
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


def transcript(full):
    names = (runner.FULL,) if full else runner.SMALL
    count, ignored = (1, 0) if full else (4, 1)
    lines = [f'test {runner.PREFIX}{name} ... ok' for name in names]
    if full:
        lines.insert(0, runner.MARKER)
    lines.append(f'test result: ok. {count} passed; 0 failed; {ignored} ignored; '
                 '0 measured; 39 filtered out; finished in 0.01s')
    return '\n'.join(lines)


class RunnerTests(unittest.TestCase):
    def run_main(self, results):
        out, err = io.StringIO(), io.StringIO()
        with patch.object(runner.sys, 'argv', ['check-aes-fault-data.py']), \
                patch.dict(runner.os.environ, {}, clear=True), \
                patch.object(runner.subprocess, 'run', side_effect=results) as execute, \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            status = runner.main()
        return status, out.getvalue(), execute.call_count

    def test_main_requires_both_phases_before_completion(self):
        results = [subprocess.CompletedProcess([], 0, transcript(full), '')
                   for full in (False, True)]
        status, output, count = self.run_main(results)
        self.assertEqual((status, count), (0, 2))
        self.assertIn('experiment complete; NOT fault-profile qualification.', output)

    def test_cargo_failure_cannot_pass_even_with_valid_output(self):
        status, output, count = self.run_main([
            subprocess.CompletedProcess([], 1, transcript(False), 'failure')])
        self.assertEqual((status, count), (2, 1))
        self.assertNotIn('experiment complete;', output)

    def test_timeout_or_missing_cargo_never_reports_completion(self):
        for error in (subprocess.TimeoutExpired(['cargo'], 300), OSError('missing cargo')):
            status, output, count = self.run_main([error])
            self.assertEqual((status, count), (2, 1))
            self.assertNotIn('experiment complete;', output)

    def test_second_phase_zero_tests_never_reports_completion(self):
        status, output, count = self.run_main([
            subprocess.CompletedProcess([], 0, transcript(False), ''),
            subprocess.CompletedProcess([], 0, 'running 0 tests', '')])
        self.assertEqual((status, count), (2, 2))
        self.assertNotIn('experiment complete;', output)

    def test_exact_populations_and_named_tests(self):
        for full in (False, True):
            runner.validate_output(transcript(full), full)

    def test_zero_tests_and_missing_summary_are_rejected(self):
        for full in (False, True):
            for output in ('', 'test result: ok. 0 passed; 0 failed; 0 ignored; '
                               '0 measured; 44 filtered out; finished in 0.01s'):
                with self.assertRaises(ValueError):
                    runner.validate_output(output, full)

    def test_missing_or_duplicate_named_result_is_rejected(self):
        for full in (False, True):
            good = transcript(full)
            name = runner.FULL if full else runner.SMALL[0]
            line = f'test {runner.PREFIX}{name} ... ok'
            for output in (good.replace(line, ''), good + '\n' + line):
                with self.assertRaises(ValueError):
                    runner.validate_output(output, full)

    def test_missing_changed_or_duplicate_population_marker_is_rejected(self):
        good = transcript(True)
        for output in (good.replace(runner.MARKER, ''),
                       good.replace('638976', '1'), good + '\n' + runner.MARKER):
            with self.assertRaises(ValueError):
                runner.validate_output(output, True)

    def test_extra_summary_or_unexpected_full_run_is_rejected(self):
        for output in (transcript(False) + '\n' + transcript(False),
                       transcript(False) + '\n' + runner.MARKER):
            with self.assertRaises(ValueError):
                runner.validate_output(output, False)

    def test_command_uses_full_path_and_isolates_evidence_artifact(self):
        args = runner.command('1.90.0', True)
        self.assertIn(runner.PREFIX + runner.FULL, args)
        self.assertIn('--exact', args)
        self.assertIn('--ignored', args)
        self.assertIn('--release', args)
        self.assertIn('--lib', args)
        self.assertIn('--locked', args)
        self.assertTrue(args[args.index('--target-dir') + 1].endswith('aes-fault-data-1.90.0'))
        with self.assertRaises(ValueError):
            runner.command('unlisted', True)

    def test_environment_rejects_overrides_and_removes_empty_encoded_flags(self):
        for key in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC', 'RUSTC_WRAPPER',
                    'RUSTC_WORKSPACE_WRAPPER', 'CARGO_BUILD_RUSTFLAGS',
                    'CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS'):
            with self.assertRaises(ValueError):
                runner.environment({key: 'override'})
        env = runner.environment({'CARGO_ENCODED_RUSTFLAGS': ''})
        self.assertNotIn('CARGO_ENCODED_RUSTFLAGS', env)
        self.assertEqual(env['RUSTFLAGS'], '--cfg brynja_fault_profile_research --cfg brynja_fault_evidence')


if __name__ == '__main__':
    unittest.main()
