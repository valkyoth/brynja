#!/usr/bin/env python3
"""Public caller review controls; synthetic policies cannot approve real builds."""
import importlib.util
from pathlib import Path
import tomllib
import unittest
from unittest.mock import patch


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


review = module('ephemeral_public_tests', 'aes_accelerated_linked_ephemeral_public.py')
prior = module('ephemeral_public_fixture', 'test-aes-accelerated-ephemeral.py')
runner = prior.runner


def fixture():
    table, _, original, cases = prior.fixture()
    image = bytearray(original)
    result = []
    for lines, raw, sizes, row, targets, bits in cases:
        name = f'_ZN30brynja_aes_accelerated_fixture9public{bits}17h0000000000000000E'
        table = table.replace(row[0], name)
        lines = [line.replace(row[0], name) for line in lines]
        raw, cursor = bytearray(raw), 0
        for index, size in enumerate(sizes):
            if '<copy>' in lines[index]:
                clear, address, _ = targets['zeroize']
                lines[index] = f'callq 0x{address:x} <{clear}>'
                raw[cursor:cursor + size] = b'\xe8' + (address - row[1] - cursor - size).to_bytes(4, 'little', signed=True)
            cursor += size
        pos = review.kernels.mapped(original, review.TARGET, row[1], row[2])
        image[pos:pos + len(raw)] = raw
        result.append((lines, bytes(raw), sizes, (name, *row[1:]),
                       {role: target for role, target in targets.items() if role != 'copy'}, bits))
    return table, bytes(image), result


class AcceleratedEphemeralPublicTests(unittest.TestCase):
    def test_synthetic_streams_rejected_by_production_policies(self):
        _, image, cases = fixture()
        for lines, raw, sizes, row, targets, bits in cases:
            for tc, panic in review.POLICY:
                with self.assertRaises(ValueError):
                    review.check(lines, raw, sizes, row, image, targets, bits, tc, panic)

    def test_instruction_byte_and_callee_controls_with_test_only_policy(self):
        _, image, cases = fixture()
        policies = {bits: review.image_review.observe(lines, raw, sizes, row[0], row[1], image, targets)[0]
                    for lines, raw, sizes, row, targets, bits in cases}
        with patch.object(review, 'POLICY', {('test', 'abort'): policies}):
            for lines, raw, sizes, row, targets, bits in cases:
                self.assertEqual(review.mutations(lines, raw, sizes, row, image, targets, bits, 'test', 'abort'),
                                 len(lines) + len(raw))
                for role in targets:
                    wrong = dict(targets)
                    other = cases[1 if bits == 128 else 0][4]
                    wrong[role] = other['expand' if role == 'zeroize' else role]
                    with self.assertRaises(ValueError):
                        review.check(lines, raw, sizes, row, image, wrong, bits, 'test', 'abort')
                for wrong in ({k: v for k, v in targets.items() if k != 'expand'},
                              {**targets, 'extra': ('extra', 0x1920, 1)}):
                    with self.assertRaises(ValueError):
                        review.check(lines, raw, sizes, row, image, wrong, bits, 'test', 'abort')

    def test_symbol_population_and_extent_fail_closed(self):
        table, _, _ = fixture()
        self.assertEqual(set(review.candidates(table)), {128, 192, 256})
        for changed in ('\n'.join(table.splitlines()[:-1]), table + '\n' + table.splitlines()[-1],
                        table.replace('9public128', '9public999'), table.replace(' t ', ' D '),
                        table.replace('0000000000001600', '0000000000001501'),
                        table.replace('17h0000000000000000E', '17h_bad')):
            with self.assertRaises(ValueError):
                review.candidates(changed)

    def test_current_mangling_and_unreviewed_suffix(self):
        table, _, _ = fixture()
        for bits in (128, 192, 256):
            table = table.replace(f'_ZN30brynja_aes_accelerated_fixture9public{bits}17h0000000000000000E',
                                  f'_RNvCs123_30brynja_aes_accelerated_fixture9public{bits}')
        self.assertEqual(set(review.candidates(table)), {128, 192, 256})
        with self.assertRaises(ValueError):
            review.candidates(table.replace('9public128', '9public128.clone'))

    def test_policy_population_and_mutation_counts(self):
        expected = {('1.90.0', 'abort'): 1392, ('1.90.0', 'unwind'): 1755,
                    ('1.99.1', 'abort'): 1407, ('1.99.1', 'unwind'): 1389}
        self.assertEqual(set(review.POLICY), set(expected))
        for config, policies in review.POLICY.items():
            self.assertEqual(set(policies), {128, 192, 256})
            self.assertEqual(sum(p['instructions'] + p['symbol_bytes'] for p in policies.values()), expected[config])
            self.assertEqual({p['constant_loads'] for p in policies.values()}, {0})

    def test_dependency_failure_cannot_be_skipped(self):
        with patch.object(review.secret, 'inspect', side_effect=ValueError('dependency rejected')) as dependency:
            with patch.object(review, 'candidates') as candidates:
                with self.assertRaisesRegex(ValueError, 'dependency rejected'):
                    review.inspect('', '', b'', '1.99.1', 'abort')
                dependency.assert_called_once()
                candidates.assert_not_called()

    def test_invalid_modes_rejected_before_packaging(self):
        for mode, admission, capture, public, secret, ephemeral in (
                ('arm-qemu', 'static', False, False, False, False),
                ('arm-qemu', 'hosted', False, False, False, False),
                ('native', 'static', True, False, False, False),
                ('native', 'static', False, True, False, False),
                ('native', 'static', False, False, True, False),
                ('native', 'static', False, False, False, True)):
            with patch.object(runner.packaged, 'package_sources') as package, self.assertRaises(ValueError):
                runner.check('1.99.1', mode, admission, capture, public, secret, ephemeral, review_ephemeral_public=True)
            package.assert_not_called()

    def test_registry_exact_selection_and_dependency_closure(self):
        registry = tomllib.loads((runner.ROOT / 'verification/checks.toml').read_text())
        checks = {c['id']: c for c in registry['checks'] if c.get('category') == 'aes-linked-ephemeral-public'}
        self.assertEqual(set(checks), {'accelerated-ephemeral-public-linked-msrv', 'accelerated-ephemeral-public-linked-current'})
        for endpoint, tc in (('msrv', '1.90.0'), ('current', '1.99.1')):
            check = checks['accelerated-ephemeral-public-linked-' + endpoint]
            self.assertEqual(check['command'], ['python3', 'scripts/aes/check-aes-accelerated-linked.py',
                '--toolchain', tc, '--mode', 'native', '--admission', 'static', '--review-ephemeral-public'])
            for group in ('aes-build', 'aes-accelerated-ephemeral-public', 'aes-accelerated-ephemeral',
                          'aes-accelerated-secret', 'aes-accelerated-linked', 'aes-accelerated-campaigns', 'aes-linked', 'aes-dataflow'):
                self.assertIn(group, check['inputs'])
            self.assertEqual(check['success']['unique_lines'], [f'AES_ACCELERATED_EPHEMERAL_PUBLIC_LINKED_PASS: {tc}; four consumers; x86 per-operation public wrappers and replayed operation dependency closure'])


if __name__ == '__main__':
    unittest.main()
