#!/usr/bin/env python3
"""Check that native teardown results cannot pass with missing cases or wrong faults."""
import importlib.util
from pathlib import Path
import unittest

path = Path(__file__).with_name('test-windows-enclave-native-teardown.py')
spec = importlib.util.spec_from_file_location('teardown', path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class Results(unittest.TestCase):
    def output(self):
        rows = ['running 1 test']
        for case in ('normal', 'bad-version', 'bad-sequence', 'bad-receipt', 'unwind'):
            for explicit in ('false', 'true'):
                rows.append(f'NATIVE_TEARDOWN: {case}; explicit={explicit}; mapping=free; pin=released')
        rows.append('NATIVE_TEARDOWN: fresh-owner=PASS; cases=10; erasure=NOT_PROVEN')
        rows[1] = 'test name ... ' + rows[1]
        return '\n'.join(rows)

    def test_complete(self):
        module.validate_result('normal', 0, self.output())

    def test_every_missing_case(self):
        rows = self.output().splitlines()
        for index in range(len(rows)):
            with self.subTest(index=index), self.assertRaises(AssertionError):
                module.validate_result('normal', 0, '\n'.join(rows[:index] + rows[index + 1:]))

    def test_duplicate_or_failure(self):
        output = self.output()
        for code, value in ((101, output), (0, output + '\n' + output.splitlines()[1]),
                            (0, output.replace('bad-version', 'bad-sequence'))):
            with self.subTest(code=code), self.assertRaises(AssertionError):
                module.validate_result('normal', code, value)

    def test_mutants_require_specific_assertions(self):
        for label, reason in (('skip-destruction', 'enclave mapping retained'),
                              ('fake-destruction', 'enclave mapping retained'),
                              ('clear-quarantine', 'destruction must not clear quarantine')):
            output = 'running 1 test\npanicked at fixture:1\n' + reason
            module.validate_result(label, 101, output)
            for code, value in ((0, output), (101, output.replace(reason, 'unrelated failure')),
                                (101, reason), (1, output)):
                with self.subTest(label=label, code=code), self.assertRaises(AssertionError):
                    module.validate_result(label, code, value)


if __name__ == '__main__':
    unittest.main()
