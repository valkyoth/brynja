#!/usr/bin/env python3
"""DIT runner cannot confuse skipped/emulated execution with a native pass."""
import importlib.util
from pathlib import Path
import tomllib
import unittest
import tempfile
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('dit', Path(__file__).with_name('check-aes-dit.py'))
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


class DitTests(unittest.TestCase):
    def test_output_is_captured_until_each_test_finishes(self):
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(RUNNER.STATIC, 'ROOT', Path(temporary)), \
             patch.object(RUNNER.os, 'environ', {}), \
             patch('sys.argv', ['check-aes-dit.py', '--toolchain', '1.99.1', '--qemu-aarch64']), \
             patch.object(RUNNER.STATIC, 'run', side_effect=[
                 'test result: ok. 5 passed; 0 failed; 0 ignored;\n' + RUNNER.MARKER + '\n',
                 'test result: ok. 6 passed; 0 failed; 0 ignored;\nAES_DIT_HOSTED_ABSENT_PASS\n',
             ]) as run:
            RUNNER.main()
            self.assertEqual(run.call_count, 2)
            for call in run.call_args_list:
                self.assertEqual(call.args[0][-3:], ['--', '--show-output', '--test-threads=1'])
                self.assertNotIn('--nocapture', call.args[0])

    def test_interleaved_marker_is_not_silently_accepted(self):
        output = ('test another_test ... AES_DIT_HOSTED_ABSENT_PASS\nok\n'
                  'test result: ok. 6 passed; 0 failed; 0 ignored;\n')
        with self.assertRaises(ValueError):
            RUNNER.validate_absent(output)

    def test_absent_hardware_must_be_exercised_not_skipped(self):
        summary = 'test result: ok. 6 passed; 0 failed; 0 ignored;\n'
        marker = 'AES_DIT_HOSTED_ABSENT_PASS\n'
        RUNNER.validate_absent(summary + marker)
        for bad in (summary, summary + marker * 2, summary + marker + 'AES_DIT_HOSTED_PRESENT_PASS'):
            with self.assertRaises(ValueError):
                RUNNER.validate_absent(bad)

    def test_markers_and_exact_population(self):
        for native, count in ((False, 4), (True, 5)):
            good = f'test result: ok. {count} passed; 0 failed; 0 ignored;\n'
            if native:
                good += RUNNER.MARKER + '\n'
            RUNNER.validate(good, native)
            for bad in ('', good.replace(f'{count} passed', '0 passed'),
                        good + RUNNER.MARKER, good + 'AES_DIT_NATIVE_UNAVAILABLE',
                        good.replace('0 ignored', '1 ignored')):
                with self.assertRaises(ValueError):
                    RUNNER.validate(bad, native)

    def test_registry_modes_are_explicit(self):
        registry = tomllib.loads((RUNNER.STATIC.ROOT/'verification/checks.toml').read_text())
        checks = [c for c in registry['checks'] if c.get('category') == 'aes-dit']
        self.assertEqual(len(checks), 4)
        for check in checks:
            emulated = '--qemu-aarch64' in check['command']
            self.assertEqual(check['success']['exact_tests'], 11 if emulated else 4)
            self.assertTrue({'aes-dit', 'cpu-source', 'hosted-cpu-source'} <= set(check['inputs']))
            self.assertEqual(check['platform'], 'linux-x86_64')


if __name__ == '__main__':
    unittest.main()
