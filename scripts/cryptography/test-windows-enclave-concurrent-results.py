#!/usr/bin/env python3
"""Reject incomplete concurrent native teardown and incorrect mutant failures."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('native', Path(__file__).with_name(
    'test-windows-enclave-concurrent-teardown.py'))
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)


class Tests(unittest.TestCase):
    def test_instrumentation_anchor(self):
        source = (native.ROOT / native.SOURCE).read_text()
        fixture = (native.ROOT / native.FIXTURE).read_text()
        changed = native.instrument(source, fixture)
        self.assertEqual(changed.count(native.AFTER), 1)
        for invalid in ('', source.replace(native.BEFORE, ''), source + native.BEFORE):
            with self.assertRaises(ValueError):
                native.instrument(invalid, fixture)

    def test_campaign_requires_rejected_and_successful_cases(self):
        start = 'running 1 test\ntest result: ok. 1 passed; 0 failed; 0 ignored;\n'
        line = 'CONCURRENT_TEARDOWN: operation; rejected={}; mapping=free; pin=released\n'
        output = start + line.format('false') * 64 + line.format('true') * 4 + 'PARALLEL_CONCURRENT_HOST: cases=68;'
        native.validate('campaign', 0, output)
        for bad in (output.replace('running 1 test', ''), output.replace('cases=68;', ''),
                    output.replace('rejected=true', 'rejected=false'), output + line.format('true'),
                    output.replace('mapping=free', 'mapping=retained')):
            with self.assertRaises(ValueError):
                native.validate('campaign', 0, bad)
        with self.assertRaises(ValueError):
            native.validate('campaign', 101, output)

    def test_mutant_requires_retained_mapping(self):
        output = 'running 1 test\npanicked at\nconcurrent enclave mapping retained'
        native.validate('skip-teardown', 101, output)
        for code, bad in ((0, output), (101, 'panicked at'), (101, output.replace('mapping retained', 'unrelated'))):
            with self.assertRaises(ValueError):
                native.validate('skip-teardown', code, bad)


if __name__ == '__main__':
    unittest.main()
