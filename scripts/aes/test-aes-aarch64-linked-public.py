#!/usr/bin/env python3
"""Bounded public ARM policy tests, independent of local retained archives."""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import tomllib
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('arm_public_fixtures', Path(__file__).with_name('test-aes-aarch64-linked.py'))
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)
p = fixtures.runner.public


def constructor_fixture():
    # Actual MSRV abort constructor, relocated to a small synthetic RX image.
    raw = bytearray.fromhex('fd7bbda9f65701a9f44f02a9fd030091f40301aaf50300aae00302aa01028052f30302aa1602805236000094e00313aae10314aa020280523a000094b3da00a9f44f42a9bf0200f9f65741a9fd7bc3a8c0035fd6')
    struct.pack_into('<I', raw, 40, 0x94000016)
    struct.pack_into('<I', raw, 56, 0x9400001a)
    lines = ['stp x29, x30, [sp, #-48]!', 'stp x22, x21, [sp, #16]',
             'stp x20, x19, [sp, #32]', 'mov x29, sp', 'mov x20, x1',
             'mov x21, x0', 'mov x0, x2', 'mov w1, #16', 'mov x19, x2',
             'mov w22, #16', 'bl 0x1080 <zeroize>', 'mov x0, x19',
             'mov x1, x20', 'mov w2, #16', 'bl 0x10a0 <copy>',
             'stp x19, x22, [x21, #8]', 'ldp x20, x19, [sp, #32]',
             'str xzr, [x21]', 'ldp x22, x21, [sp, #16]',
             'ldp x29, x30, [sp], #48', 'ret']
    return lines, bytes(raw), ('new128', 0x1000, len(raw)), fixtures.image(raw), {
        'zeroize': ('zeroize', 0x1080, 4), 'copy': ('copy', 0x10a0, 4)}


class Aarch64LinkedPublicTests(unittest.TestCase):
    def test_real_constructor_and_every_instruction_deletion(self):
        self.assertEqual(p.check(*constructor_fixture(), 'new128', '1.90.0', 'abort')['instructions'], 21)
        self.assertEqual(p.mutations(*constructor_fixture(), 'new128', '1.90.0', 'abort'), 45)

    def test_every_constructor_encoding_bit_is_bound(self):
        lines, raw, row, image, targets = constructor_fixture()
        policy = json.loads(p.POLICY.read_text())
        for byte in range(len(raw)):
            for bit in range(8):
                changed = bytearray(raw); changed[byte] ^= 1 << bit
                with self.subTest(byte=byte, bit=bit), self.assertRaises(ValueError):
                    p.check(lines, changed, row, fixtures.image(changed), targets,
                            'new128', '1.90.0', 'abort', policy)

    def test_role_profile_and_call_edges_are_not_interchangeable(self):
        args = constructor_fixture()
        for role, compiler, panic in (('new192', '1.90.0', 'abort'),
                                     ('new128', '1.90.0', 'unwind'),
                                     ('new128', '1.99.1', 'abort'),
                                     ('new128', 'stable', 'abort'),
                                     ('unknown', '1.90.0', 'abort')):
            with self.assertRaises(ValueError): p.check(*args, role, compiler, panic)
        changed = dict(args[-1]); changed['expand128'] = ('expand128', 0x10c0, 4)
        with self.assertRaises(ValueError):
            p.check(*args[:-1], changed, 'new128', '1.90.0', 'abort')

    def test_policy_scope_and_population_fail_closed(self):
        policy = json.loads(p.POLICY.read_text())
        for key, value in (('schema', 2), ('target', 'x86_64'), ('profile', 'debug'), ('review', 'wrong')):
            changed = copy.deepcopy(policy); changed[key] = value
            with self.assertRaises(ValueError): p.check(*constructor_fixture(), 'new128', '1.90.0', 'abort', changed)
        for kind in ('configuration', 'role', 'body'):
            changed = copy.deepcopy(policy)
            if kind == 'configuration': del changed['configurations']['1.99.1/unwind']
            elif kind == 'role': del changed['configurations']['1.90.0/abort']['public128']
            else: changed['bodies']['unused'] = next(iter(changed['bodies'].values()))
            with self.assertRaises(ValueError): p.check(*constructor_fixture(), 'new128', '1.90.0', 'abort', changed)

    def test_public_bodies_cannot_overlap_helpers(self):
        selected = {role: (role, 0x2000 + i * 0x100, 4) for i, role in enumerate(p.EDGES)}
        with patch.object(p.names, 'candidates', return_value=selected):
            self.assertEqual(p.select('', {'copy': ('copy', 0x1000, 4)}), selected)
            with self.assertRaises(ValueError): p.select('', {'copy': ('copy', 0x2000, 4)})

    def test_registration_fingerprints_public_review(self):
        registry = tomllib.loads((fixtures.runner.ROOT / 'verification/checks.toml').read_text())
        paths = registry['groups']['aes-arm-linked-review']['paths']
        for name in ('aes_aarch64_linked_public.py', 'aarch64-linked-public-review.json', 'test-aes-aarch64-linked-public.py'):
            self.assertIn('scripts/aes/' + name, paths)


if __name__ == '__main__':
    unittest.main()
