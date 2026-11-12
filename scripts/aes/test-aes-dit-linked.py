#!/usr/bin/env python3
"""DIT review policy regression tests; real-image byte mutations run in the reviewer."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('dit_linked_tests', Path(__file__).with_name('check-aes-dit-linked.py'))
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)


def table():
    rows = []
    for i, (kind, bits) in enumerate((k, b) for k in ('expand', 'encrypt', 'decrypt') for b in (128, 192, 256)):
        name = f'_ZN17brynja_crypto_cpu3aes7Session{len(kind) + 3}{kind}{bits}17h0123456789abcdefE'
        rows.append(f'{0x1000 + i * 0x200:016x} 0000000000000100 T {name}')
    return '\n'.join(rows)


class DitLinkedTests(unittest.TestCase):
    def test_exact_nine_sessions_and_non_overlapping_extents(self):
        original = table()
        self.assertEqual(len(r.candidates(original)), 9)
        for bad in ('', '\n'.join(original.splitlines()[1:]), original + '\n' + original.splitlines()[0],
                    original.replace('expand128', 'expand129'), original.replace(' T ', ' U ', 1),
                    original.replace('0000000000001200', '0000000000001004', 1)):
            with self.subTest(bad=bad), self.assertRaises(ValueError): r.candidates(bad)

    def test_unreviewed_configurations_and_call_sets_fail_before_decoding(self):
        for compiler, kind, targets in (('1.91.0', 'expand', {}), ('1.90.0', 'unknown', {}),
                                        ('1.90.0', 'expand', {'kernel': ()}),
                                        ('1.99.1', 'expand', {'kernel': (), 'resume': ()})):
            with patch.object(r.arm, 'observe') as observe, self.assertRaises(ValueError):
                r.check([], b'', (), b'', targets, compiler, kind)
            observe.assert_not_called()

    def test_whole_body_policy_checks_every_summary_field(self):
        for compiler, entries in r.POLICY.items():
            for kind, (count, branches, calls, text, encoded) in entries.items():
                expected = dict(instructions=count, branches=branches, calls=calls, constants=0,
                                text_sha256=text, encoding_sha256=encoded)
                targets = {'kernel': (), **({'resume': ()} if compiler == '1.90.0' else {})}
                args = ([], b'', (), b'', targets, compiler, kind)
                with patch.object(r.arm, 'observe', return_value=(expected, [], [])):
                    self.assertEqual(r.check(*args), expected)
                for key in expected:
                    changed = {**expected, key: 'changed'}
                    with patch.object(r.arm, 'observe', return_value=(changed, [], [])), self.assertRaisesRegex(ValueError, 'stream changed'):
                        r.check(*args)


if __name__ == '__main__':
    unittest.main()
