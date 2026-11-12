#!/usr/bin/env python3
"""Fail-closed constructor/destruction controls, not synthetic build approval."""
import importlib.util
from pathlib import Path
import tempfile
import tomllib
import unittest
from unittest.mock import patch


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


review = module('lifecycle_test_review', 'aes_accelerated_linked_lifecycle.py')
prior = module('lifecycle_kernel_fixture', 'test-aes-accelerated-linked.py')
runner = prior.runner


def symbols(current=False):
    rows = []
    for index, (role, suffix) in enumerate(review.ROLES.items()):
        name = (('_RNvNt' + ('' if role[0] == 'destroy_block' else 'Nt') +
                 'Cs123_30brynja_aes_accelerated_fixture9lifecycle' + suffix) if current else
                '_ZN30brynja_aes_accelerated_fixture9lifecycle' + suffix + '17h0000000000000000E')
        rows.append(f'{0x1100 + index * 0x100:016x} 0000000000000010 t {name}')
    return '\n'.join(rows)


def constructor_fixture(cached, resume=False):
    _, _, original, _ = prior.fixture(review.TARGET)
    image = bytearray(original)
    targets = {'zeroize': ('zeroize', 0x1900, 1), 'copy': ('copy', 0x1920, 1)}
    if cached:
        targets['expand'] = ('expand', 0x1940, 1)
    if resume:
        targets['resume'] = ('resume', 0x1960, 1)
    raw, lines, sizes = bytearray(), [], []
    start = 0x1500
    for role, (name, address, _) in targets.items():
        raw += b'\xe8' + (address - start - len(raw) - 5).to_bytes(4, 'little', signed=True)
        lines.append(f'callq 0x{address:x} <{name}>')
        sizes.append(5)
    raw += b'\xc3'; lines.append('retq'); sizes.append(1)
    image[start - 0x1000:start - 0x1000 + len(raw)] = raw
    row = ('synthetic_constructor', start, len(raw))
    return lines, bytes(raw), sizes, row, bytes(image), targets


def destruction_fixture(compiler, panic):
    _, _, original, _ = prior.fixture(review.TARGET)
    row = ('synthetic_destructor', 0x1500, 24 if (compiler, panic) == ('1.99.1', 'unwind') else 10)
    clear = ('zeroize', 0x1900, 1)
    lines, raw, sizes = review.destruction_template(row, clear, compiler, panic)
    image = bytearray(original)
    image[0x500:0x500 + len(raw)] = raw
    return lines, raw, sizes, row, bytes(image), clear, compiler, panic


class AcceleratedLifecycleTests(unittest.TestCase):
    def test_exact_constructor_and_merged_destruction_population(self):
        for current in (False, True):
            table = symbols(current)
            self.assertEqual(set(review.candidates(table)), set(review.ROLES))
            for changed in ('\n'.join(table.splitlines()[:-1]), table + '\n' + table.splitlines()[-1],
                            table.replace('7new_key', '7new_bad'), table.replace(' t ', ' D '),
                            table.replace('0000000000001200', '0000000000001101'),
                            table.replace('0000000000000010 t', '0000000000000000 t'),
                            table.replace('6aes12811destroy_key', '6aes19211destroy_key')):
                with self.assertRaises(ValueError):
                    review.candidates(changed)

    def test_synthetic_constructors_rejected_by_every_production_policy(self):
        for cached in (False, True):
            args = constructor_fixture(cached)
            for compiler, panic in review.POLICY:
                for bits in (128, 192, 256):
                    with self.assertRaises(ValueError):
                        review.constructor(*args, ('new_cached' if cached else 'new_key', bits), compiler, panic)

    def test_constructor_mutations_and_target_binding_with_test_only_policy(self):
        for cached in (False, True):
            lines, raw, sizes, row, image, targets = args = constructor_fixture(cached)
            role = ('new_cached' if cached else 'new_key', 128)
            policy = review.image_review.observe(lines, raw, sizes, row[0], row[1], image, targets,
                                                  tail_calls=('zeroize',))[0]
            with patch.dict(review.POLICY, {('test', 'abort'): {role: policy}}):
                self.assertEqual(review.mutations(review.constructor, *args, role, 'test', 'abort'), len(lines) + len(raw))
                for name in targets:
                    wrong = dict(targets)
                    wrong[name] = ('wrong', 0x1960, 1)
                    with self.assertRaises(ValueError):
                        review.constructor(lines, raw, sizes, row, image, wrong, role, 'test', 'abort')
                with self.assertRaises(ValueError):
                    review.constructor(lines, raw, sizes, row, image, {}, role, 'test', 'abort')

    def test_destruction_each_instruction_and_encoded_byte_is_bound(self):
        for compiler, panic in review.POLICY:
            args = destruction_fixture(compiler, panic)
            self.assertEqual(review.mutations(review.destruction, *args), len(args[0]) + len(args[1]))
            result = review.destruction(*args)
            self.assertEqual(result['clear_edges'], 2 if (compiler, panic) == ('1.99.1', 'unwind') else 1)

    def test_destruction_mapping_target_partition_and_configuration_rejection(self):
        lines, raw, sizes, row, image, clear, compiler, panic = destruction_fixture('1.99.1', 'unwind')
        cases = [(*row[:2], row[2] + 1), (row[0], clear[1], row[2])]
        for wrong in cases:
            with self.assertRaises(ValueError):
                review.destruction(lines, raw, sizes, wrong, image, clear, compiler, panic)
        for wrong in (('other', clear[1], 1), (clear[0], clear[1] + 1, 1), (clear[0], row[1], row[2])):
            with self.assertRaises(ValueError):
                review.destruction(lines, raw, sizes, row, image, wrong, compiler, panic)
        with self.assertRaises(ValueError):
            review.destruction(lines, raw, sizes[::-1], row, image, clear, compiler, panic)
        with self.assertRaises(ValueError):
            review.destruction(lines, raw, sizes, row, b'bad ELF', clear, compiler, panic)
        with self.assertRaises(ValueError):
            review.destruction(lines, raw, sizes, row, image, clear, 'unreviewed', panic)
        with self.assertRaises(ValueError):
            review.destruction_template(row, ('far', 2**63, 1), compiler, panic)

    def test_destruction_template_has_independent_branch_encoding_checks(self):
        # Do not only validate a template against fixtures made from itself.
        for compiler, panic in review.POLICY:
            row, clear = ('drop', 0x1500, 24), ('zeroize', 0x1900, 1)
            _, raw, _ = review.destruction_template(row, clear, compiler, panic)
            if (compiler, panic) == ('1.99.1', 'unwind'):
                self.assertEqual(raw, bytes.fromhex('85d2740a4885ff0f85f3030000c34885ff74fae9e8030000'))
                self.assertEqual(4 + int.from_bytes(raw[3:4], 'little', signed=True), 14)
                self.assertEqual(19 + int.from_bytes(raw[18:19], 'little', signed=True), 13)
            else:
                self.assertEqual(raw, bytes.fromhex('4885ff0f85f7030000c3'))

    def test_policy_counts_and_no_dependency_shortcut(self):
        counts = {('1.90.0', 'abort'): 1962, ('1.90.0', 'unwind'): 2238,
                  ('1.99.1', 'abort'): 1962, ('1.99.1', 'unwind'): 1962}
        self.assertEqual(set(review.POLICY), set(counts))
        expected = {(role, bits) for role in ('new_key', 'new_cached') for bits in (128, 192, 256)}
        for config, policies in review.POLICY.items():
            self.assertEqual(set(policies), expected)
            self.assertEqual(sum(p['instructions'] + p['symbol_bytes'] for p in policies.values()), counts[config])
        with patch.object(review.operations, 'inspect', side_effect=ValueError('dependency rejected')):
            with patch.object(review, 'candidates') as candidates:
                with self.assertRaisesRegex(ValueError, 'dependency rejected'):
                    review.inspect('', '', b'', '1.99.1', 'abort')
                candidates.assert_not_called()

    def test_cached_unwind_resume_is_bound_and_mutated(self):
        lines, raw, sizes, row, image, targets = args = constructor_fixture(True, resume=True)
        role = ('new_cached', 128)
        for compiler, panic in review.POLICY:
            with self.assertRaises(ValueError):
                review.constructor(*args, role, compiler, panic)
        policy = review.image_review.observe(lines, raw, sizes, row[0], row[1], image, targets,
                                             tail_calls=('zeroize',))[0]
        with patch.dict(review.POLICY, {('1.90.0', 'unwind'): {role: policy}}):
            self.assertEqual(review.mutations(review.constructor, *args, role, '1.90.0', 'unwind'), len(lines) + len(raw))
            for wrong in ({k: v for k, v in targets.items() if k != 'resume'},
                          {**targets, 'resume': ('wrong_resume', 0x1980, 1)}):
                with self.assertRaises(ValueError):
                    review.constructor(lines, raw, sizes, row, image, wrong, role, '1.90.0', 'unwind')

    def test_profiles_are_not_interchangeable(self):
        for bits in (128, 192, 256):
            raw_role, cached_role = ('new_key', bits), ('new_cached', bits)
            for compiler in ('1.90.0', '1.99.1'):
                self.assertEqual(review.POLICY[compiler, 'abort'][raw_role], review.POLICY[compiler, 'unwind'][raw_role])
            self.assertNotEqual(review.POLICY['1.90.0', 'abort'][cached_role], review.POLICY['1.90.0', 'unwind'][cached_role])
            self.assertEqual(review.POLICY['1.99.1', 'abort'][cached_role], review.POLICY['1.99.1', 'unwind'][cached_role])

    def test_cached_unwind_import_validation_cannot_be_skipped(self):
        with patch.object(review.operations, 'inspect'), patch.object(review, 'candidates', return_value={}), \
             patch.object(review.secret.cached, 'candidates'), patch.object(review.secret, 'expansion_candidates'), \
             patch.object(review.secret.cached.public.cleanup, 'resume_target', side_effect=ValueError('invalid resume import')) as resume:
            with self.assertRaisesRegex(ValueError, 'invalid resume import'):
                review.inspect('', '', b'', '1.90.0', 'unwind', 'bad relocations')
            resume.assert_called_once_with('', 'bad relocations', b'')

    def test_review_modes_reject_before_packaging(self):
        modes = [('arm-qemu', 'static', False), ('arm-qemu', 'hosted', False), ('native', 'static', True)]
        for mode, admission, capture in modes:
            with patch.object(runner.packaged, 'package_sources') as package, self.assertRaises(ValueError):
                runner.check('1.99.1', mode, admission, capture, review_lifecycle=True)
            package.assert_not_called()
        for other in ('review_cached_public', 'review_cached_secret', 'review_ephemeral_secret', 'review_ephemeral_public'):
            with patch.object(runner.packaged, 'package_sources') as package, self.assertRaises(ValueError):
                runner.check('1.99.1', 'native', 'static', review_lifecycle=True, **{other: True})
            package.assert_not_called()

    def test_package_fixture_includes_the_lifecycle_module(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with patch.object(runner.campaigns, 'manifest', return_value=''):
                runner.prepare(directory, {}, 'direct', 'static')
            self.assertEqual((directory / 'src/lifecycle.rs').read_bytes(),
                             (runner.ROOT / 'assurance/aes-accelerated-campaigns/lifecycle.rs').read_bytes())

    def test_registry_exact_scope_and_dependency_closure(self):
        registry = tomllib.loads((runner.ROOT / 'verification/checks.toml').read_text())
        checks = {c['id']: c for c in registry['checks'] if c.get('category') == 'aes-linked-lifecycle'}
        self.assertEqual(set(checks), {'accelerated-lifecycle-linked-msrv', 'accelerated-lifecycle-linked-current'})
        self.assertIn('assurance/aes-accelerated-campaigns/lifecycle.rs', registry['groups']['aes-accelerated-linked']['paths'])
        for endpoint, tc in (('msrv', '1.90.0'), ('current', '1.99.1')):
            check = checks['accelerated-lifecycle-linked-' + endpoint]
            self.assertEqual(check['command'], ['python3', 'scripts/aes/check-aes-accelerated-linked.py',
                '--toolchain', tc, '--mode', 'native', '--admission', 'static', '--review-lifecycle'])
            for group in ('aes-build', 'aes-accelerated-lifecycle', 'aes-accelerated-ephemeral-public',
                          'aes-accelerated-ephemeral', 'aes-accelerated-secret', 'aes-accelerated-linked',
                          'aes-accelerated-campaigns', 'aes-linked', 'aes-dataflow'):
                self.assertIn(group, check['inputs'])
            self.assertEqual(check['success']['unique_lines'], [f'AES_ACCELERATED_LIFECYCLE_LINKED_PASS: {tc}; four consumers; x86 constructors, retained destruction bodies and replayed operation closure'])


if __name__ == '__main__':
    unittest.main()
