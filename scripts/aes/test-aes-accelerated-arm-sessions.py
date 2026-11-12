#!/usr/bin/env python3
"""Session selector/dependency negative controls; synthetic code is not approval."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


r = module('arm_sessions_tests', 'aes_accelerated_linked_arm_sessions.py')
fixtures = module('arm_sessions_fixtures', 'test-aes-accelerated-arm-cached.py')


def symbols(current=False):
    rows = []
    for i, (direction, bits) in enumerate((d, b) for d in ('encrypt', 'decrypt') for b in (128, 192, 256)):
        name = (f'_RNvMsa_NtCs123_17brynja_crypto_cpu3aesNtB5_7Session10{direction}{bits}' if current else
                f'_ZN17brynja_crypto_cpu3aes7Session10{direction}{bits}17h0000000000000000E')
        rows.append(f'{0x1500+i*0x100:016x} 0000000000000004 t {name}')
    return '\n'.join(rows)


def synthetic(unwind):
    _, _, _, original, targets = fixtures.synthetic('public', unwind)
    del targets['zeroize']
    lines, raw = [], bytearray()
    for name, address, _ in targets.values():
        delta = address - (0x1500 + len(raw))
        raw.extend((0x94000000 | ((delta // 4) & 0x3ffffff)).to_bytes(4, 'little'))
        lines.append(f'bl 0x{address:x} <{name}>')
    raw.extend(bytes.fromhex('c0035fd6')); lines.append('ret')
    image = bytearray(original); image[0x500:0x500+len(raw)] = raw
    return lines, bytes(raw), ('session', 0x1500, len(raw)), bytes(image), targets


class AcceleratedArmSessionTests(unittest.TestCase):
    def test_policy_population_and_separate_direction_admission(self):
        expected = {(c, a, p, d) for c in ('1.90.0', '1.99.1') for a in ('static', 'hosted')
                    for p in ('abort', 'unwind') for d in ('encrypt', 'decrypt')}
        self.assertEqual(set(r.POLICY), {'/'.join(row) for row in expected})
        for c, a, p, d in expected:
            value = r.policy(d, c, p, a)
            self.assertEqual(set(value), {'instructions', 'branches', 'calls', 'constants', 'text_sha256', 'encoding_sha256'})
            self.assertEqual(value['constants'], 0)
            self.assertGreaterEqual(value['instructions'], 26)
            self.assertGreaterEqual(value['branches'], 4)
            self.assertEqual(value['calls'], 2 if (c, p) == ('1.90.0', 'unwind') else 1)
            for key in ('text_sha256', 'encoding_sha256'):
                self.assertRegex(value[key], r'^[0-9a-f]{64}$')
                self.assertNotEqual(value[key], r.policy('decrypt' if d == 'encrypt' else 'encrypt', c, p, a)[key])
                self.assertNotEqual(value[key], r.policy(d, c, p, 'hosted' if a == 'static' else 'static')[key])

    def test_selector_requires_exact_six_aligned_nonoverlapping_bodies(self):
        for current in (False, True):
            table = symbols(current)
            self.assertEqual(len(r.candidates(table)), 6)
            for bad in ('', table+'\n'+table.splitlines()[0], '\n'.join(table.splitlines()[1:]),
                        table.replace('encrypt192', 'encrypt128'), table.replace('10encrypt', '11encrypt'),
                        table.replace(' t ', ' D '), table.replace('0000000000001600', '0000000000001500'),
                        table.replace('0000000000000004 t', '0000000000000000 t'),
                        table.replace('0000000000000004 t', '0000000000000003 t'),
                        table.replace('0000000000001500', '0000000000001501')):
                with self.assertRaises(ValueError): r.candidates(bad)

    def test_synthetic_never_matches_real_policies(self):
        for c in ('1.90.0', '1.99.1'):
            for p in ('abort', 'unwind'):
                for a in ('static', 'hosted'):
                    for d in ('encrypt', 'decrypt'):
                        with self.assertRaisesRegex(ValueError, 'session stream changed'):
                            r.check(*synthetic((c, p) == ('1.90.0', 'unwind')), d, c, p, a)

    def test_instruction_bytes_and_call_roles_fail_closed(self):
        for unwind in (False, True):
            lines, raw, row, image, targets = args = synthetic(unwind)
            actual = r.constructors.portable.observe(*args)[0]
            config = 'encrypt', '1.90.0', 'unwind' if unwind else 'abort', 'static'
            with patch.object(r, 'policy', return_value=actual):
                self.assertEqual(r.constructors.mutations(r.check, *args, *config), len(lines)+len(raw))
                for role, target in targets.items():
                    for bad in ((target[0], target[1]+4, 4), ('wrong', target[1], 4), row):
                        with self.assertRaises(ValueError):
                            r.check(lines, raw, row, image, {**targets, role: bad}, *config)
                    with self.assertRaisesRegex(ValueError, 'call population changed'):
                        r.check(lines, raw, row, image, {k:v for k,v in targets.items() if k != role}, *config)
                if unwind:
                    with self.assertRaisesRegex(ValueError, 'session stream changed'):
                        r.check(lines, raw, row, image, {'kernel': targets['resume'], 'resume': targets['kernel']}, *config)

    def test_unknown_configuration_fails(self):
        valid = ['encrypt', '1.99.1', 'abort', 'static']
        for i in range(len(valid)):
            changed = valid.copy(); changed[i] = 'unknown'
            with self.assertRaises(ValueError): r.policy(*changed)

    def test_missing_or_duplicate_kernel_prevents_session_review(self):
        for rows in ([], [('one', 0x3000, 4), ('two', 0x3004, 4)]):
            with patch.object(r.kernels, 'select', return_value=rows), \
                    patch.object(r.kernels, 'decode', return_value=([], b'', [])), \
                    patch.object(r.kernels, 'check', return_value={'bits': 128}), patch.object(r, 'check') as check:
                with self.assertRaisesRegex(ValueError, 'ARM session kernel'):
                    r.inspect(symbols(), '', b'', '1.99.1', 'abort', 'static')
                check.assert_not_called()


if __name__ == '__main__':
    unittest.main()
