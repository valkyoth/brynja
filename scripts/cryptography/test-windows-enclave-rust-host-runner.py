"""Mutation edits must preserve Windows newlines and reject uncertain anchors."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('rust_host_runner',
    Path(__file__).with_name('test-windows-enclave-parallel-rust-host.py'))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class Mutations(unittest.TestCase):
    def test_lf_and_crlf_are_preserved(self):
        for newline in (b'\n', b'\r\n'):
            original = b'//! Public image\xc2\xa0only' + newline + b'check();' + newline
            self.assertEqual(runner.mutant_bytes(original, 'check()', 'reject()'),
                             original.replace(b'check()', b'reject()'))

    def test_missing_and_duplicate_anchors_reject(self):
        for original in (b'no match\n', b'check();\r\ncheck();\r\n'):
            with self.assertRaises(ValueError):
                runner.mutant_bytes(original, 'check()', 'reject()')

    def test_invalid_utf8_rejects(self):
        with self.assertRaises(UnicodeDecodeError):
            runner.mutant_bytes(b'\xffcheck()', 'check()', 'reject()')


if __name__ == '__main__': unittest.main()
