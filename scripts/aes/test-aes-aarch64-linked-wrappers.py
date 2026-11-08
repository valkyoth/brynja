#!/usr/bin/env python3
"""Regression checks for retained ARM secret-output wrapper policies."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('arm_wrapper_fixtures', Path(__file__).with_name('test-aes-aarch64-linked.py'))
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)
w = fixtures.runner.wrappers
r = fixtures.r


def copy_fixture():
    raw = bytes.fromhex('e5031faae60302aadf2000f1e3000054246865f8046825f8a5200091c62000d1df2000f162ffff54c60000b42468653804682538a5040091c60400d186ffffb5e4031faae5031faae6031faaff031febc0035fd6')
    lines = ['mov x5, xzr', 'mov x6, x2', 'cmp x6, #8', 'b.lo 0x1028 <copy+0x28>',
             'ldr x4, [x1, x5]', 'str x4, [x0, x5]', 'add x5, x5, #8', 'sub x6, x6, #8',
             'cmp x6, #8', 'b.hs 0x1010 <copy+0x10>', 'cbz x6, 0x1040 <copy+0x40>',
             'ldrb w4, [x1, x5]', 'strb w4, [x0, x5]', 'add x5, x5, #1', 'sub x6, x6, #1',
             'cbnz x6, 0x102c <copy+0x2c>', 'mov x4, xzr', 'mov x5, xzr', 'mov x6, xzr',
             'cmp xzr, xzr', 'ret']
    return lines, raw, ('copy', 0x1000, len(raw)), fixtures.image(raw), {}


class Aarch64LinkedWrapperTests(unittest.TestCase):
    def test_real_copy_policy_all_profiles_and_mutations(self):
        args = copy_fixture()
        for compiler in ('1.90.0', '1.99.1'):
            for panic in ('abort', 'unwind'):
                self.assertEqual(w.check(*args, 'copy', compiler, panic)['instructions'], 21)
                self.assertEqual(w.mutations(*args, 'copy', compiler, panic), 19)

    def test_every_copy_encoding_bit_is_bound(self):
        lines, raw, row, image, targets = copy_fixture()
        policy = json.loads(w.POLICY.read_text())
        for byte in range(len(raw)):
            for bit in range(8):
                changed = bytearray(raw); changed[byte] ^= 1 << bit
                # Coherently alter both ELF and printed instruction bytes.
                with self.subTest(byte=byte, bit=bit), self.assertRaises(ValueError):
                    w.check(lines, changed, row, fixtures.image(changed), targets,
                            'copy', '1.90.0', 'abort', policy)

    def test_copy_erasure_bounds_and_addresses_cannot_change(self):
        lines, *rest = copy_fixture()
        for index, value in ((2, 'cmp x6, #16'), (4, 'ldr x4, [x1, x4]'),
                             (5, 'str x4, [x1, x5]'), (6, 'add x5, x5, #16'),
                             (16, 'mov x4, x1'), (19, 'nop')):
            changed = list(lines); changed[index] = value
            with self.assertRaisesRegex(ValueError, 'policy changed'):
                w.check(changed, *rest, 'copy', '1.90.0', 'abort')

    def test_policy_scope_population_and_profile_are_bound(self):
        args = copy_fixture()
        policy = json.loads(w.POLICY.read_text())
        for key, value in (('schema', 2), ('target', 'x86_64'), ('profile', 'debug'), ('review', 'wrong')):
            changed = copy.deepcopy(policy); changed[key] = value
            with self.assertRaises(ValueError): w.check(*args, 'copy', '1.90.0', 'abort', changed)
        changed = copy.deepcopy(policy); del changed['configurations']['1.90.0/unwind']
        with self.assertRaises(ValueError): w.check(*args, 'copy', '1.90.0', 'abort', changed)
        changed = copy.deepcopy(policy); changed['bodies']['unused'] = changed['bodies']['copy']
        with self.assertRaises(ValueError): w.check(*args, 'copy', '1.90.0', 'abort', changed)
        for role, compiler, panic in (('unknown', '1.90.0', 'abort'), ('copy', 'stable', 'abort'), ('copy', '1.90.0', 'other')):
            with self.assertRaises(ValueError): w.check(*args, role, compiler, panic)
        with self.assertRaises(ValueError):
            w.check(*args[:-1], {'zeroize': ('wrong', 0x1080, 4)}, 'copy', '1.90.0', 'abort')

    def test_wide_secret_identity_binds_call_and_generic_width(self):
        targets = {'transform192': ('transform192', 0x1100, 4), 'transform256': ('transform256', 0x1200, 4)}
        line = 'bl 0x1100 <transform192>'
        self.assertEqual(w.secret_role([line], '_RIwideKj18_Kjd0_Kjc_', targets), 'secret192')
        for lines, symbol in (([], 'secret'), ([line, line], 'secret'),
                              ([line, 'bl 0x1200 <transform256>'], 'secret'),
                              (['bl 0x1104 <transform192>'], 'secret'),
                              ([line], '_RIwideKj20_Kjf0_Kje_')):
            with self.assertRaises(ValueError): w.secret_role(lines, symbol, targets)

    def test_selected_wrappers_cannot_alias_helpers_or_duplicate_widths(self):
        selected = {role: (role, 0x2000 + i * 0x100, 4)
                    for i, role in enumerate(('key128', 'key192', 'key256', 'cached128', 'copy'))}
        secrets = [('secret-a', 0x2500, 4), ('secret-b', 0x2600, 4)]
        portable = {'transform192': ('transform192', 0x1100, 4), 'transform256': ('transform256', 0x1200, 4)}
        def decode(_, row):
            name, address, _ = portable['transform192' if row[0] == 'secret-a' else 'transform256']
            return [f'bl 0x{address:x} <{name}>'], b''
        with patch.object(w.names, 'candidates', side_effect=lambda _: (dict(selected), list(secrets))), patch.object(w.image_review, 'decode', side_effect=decode):
            self.assertEqual(set(w.select('', '', portable)), set(w.EDGES))
            with patch.object(w.image_review, 'decode', return_value=decode('', secrets[0])):
                with self.assertRaises(ValueError): w.select('', '', portable)
            portable['transform192'] = ('transform192', 0x2000, 4)
            with self.assertRaises(ValueError): w.select('', '', portable)

    def test_registration_fingerprints_wrapper_checker_and_policy(self):
        import tomllib
        registry = tomllib.loads((fixtures.runner.ROOT / 'verification/checks.toml').read_text())
        paths = registry['groups']['aes-arm-linked-review']['paths']
        for name in ('aes_aarch64_linked_wrappers.py', 'aarch64-linked-wrappers-review.json', 'test-aes-aarch64-linked-wrappers.py'):
            self.assertIn('scripts/aes/' + name, paths)


if __name__ == '__main__':
    unittest.main()
