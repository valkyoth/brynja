#!/usr/bin/env python3
"""ARM cached caller regression controls; synthetic code cannot approve a build."""
import hashlib
import importlib.util
from pathlib import Path
import tomllib
import unittest
from unittest.mock import patch


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


r = module('arm_cached_tests', 'aes_accelerated_linked_arm_cached.py')
fixture = module('arm_cached_fixture', 'test-aes-accelerated-linked.py')
runner = fixture.runner


def symbols(current=False):
    rows = []
    for i, (kind, bits) in enumerate((k, b) for k in ('public', 'secret') for b in (128, 192, 256)):
        owner = f'17Aes{bits}ExpandedKey' + ('20encrypt_block_public' if kind == 'public' else '6secret')
        name = ('_RNvMsa_NtNtCs123_13brynja_crypto3aes9executionNtB5_' + owner if current else
                '_ZN13brynja_crypto3aes9execution' + owner + '17h0000000000000000E')
        rows.append(f'{0x1500 + i*0x100:016x} 0000000000000004 t {name}')
    return '\n'.join(rows)


def synthetic(kind, unwind=False):
    _, _, original, _ = fixture.fixture(r.TARGET)
    image = bytearray(original)
    targets = {'kernel': ('kernel', 0x1600, 4), 'zeroize': ('clear', 0x1620, 4)}
    if kind == 'secret':
        targets['copy'] = ('copy', 0x1640, 4)
    if unwind:
        targets['resume'] = ('_Unwind_Resume', 0x1680, 4)
    lines, raw = [], bytearray()
    for name, address, _ in targets.values():
        delta = address - (0x1500 + len(raw))
        raw.extend((0x94000000 | ((delta // 4) & 0x3ffffff)).to_bytes(4, 'little'))
        lines.append(f'bl 0x{address:x} <{name}>')
    raw.extend(bytes.fromhex('c0035fd6')); lines.append('ret')
    image[0x500:0x500+len(raw)] = raw
    return lines, bytes(raw), ('caller', 0x1500, len(raw)), bytes(image), targets


class AcceleratedArmCachedTests(unittest.TestCase):
    def test_policy_population_and_counts(self):
        expected = {(c, a, p, k, str(b)) for c in ('1.90.0', '1.99.1') for a in ('static', 'hosted')
                    for p in ('abort', 'unwind') for k in ('public', 'secret') for b in (128, 192, 256)}
        self.assertEqual(set(r.POLICY), {'/'.join(row) for row in expected})
        for c, a, p, k, b in expected:
            policy = r.policy(k, int(b), c, p, a)
            self.assertEqual(set(policy), {'instructions', 'branches', 'calls', 'constants',
                                          'tail_calls', 'text_sha256', 'encoding_sha256'})
            self.assertEqual(policy['constants'], 0)
            self.assertEqual(policy['tail_calls'], int(k == 'secret' and (c, p) != ('1.90.0', 'unwind')))
            self.assertRegex(policy['text_sha256'], r'^[0-9a-f]{64}$')
            self.assertRegex(policy['encoding_sha256'], r'^[0-9a-f]{64}$')
            self.assertGreater(policy['instructions'], 40)
        for a in ('static', 'hosted'):
            for k in ('public', 'secret'):
                for b in (128, 192, 256):
                    self.assertEqual(r.policy(k, b, '1.99.1', 'abort', a), r.policy(k, b, '1.99.1', 'unwind', a))

    def test_selector_requires_all_six_exact_nonoverlapping_symbols(self):
        for current in (False, True):
            table = symbols(current)
            self.assertEqual(len(r.candidates(table)), 6)
            for bad in (table + '\n' + table.splitlines()[0], '\n'.join(table.splitlines()[1:]),
                        table.replace('Aes192', 'Aes128'), table.replace(' t ', ' D '),
                        table.replace('0000000000001600', '0000000000001500'),
                        table.replace('20encrypt_block_public', '21encrypt_block_public'),
                        table.replace('0000000000000004 t', '0000000000000003 t')):
                with self.assertRaises(ValueError): r.candidates(bad)

    def test_synthetic_code_never_matches_production_policy(self):
        for c in ('1.90.0', '1.99.1'):
            for p in ('abort', 'unwind'):
                for a in ('static', 'hosted'):
                    for k in ('public', 'secret'):
                        args = synthetic(k, (c, p) == ('1.90.0', 'unwind'))
                        for b in (128, 192, 256):
                            with self.assertRaisesRegex(ValueError, 'cached stream changed'):
                                r.check(*args, k, b, c, p, a)

    def test_instruction_byte_and_call_target_mutations(self):
        for k in ('public', 'secret'):
            for unwind in (False, True):
                lines, raw, row, image, targets = args = synthetic(k, unwind)
                actual = r.prior.portable.observe(*args, tail_calls=('zeroize',))[0]
                config = k, 128, '1.90.0', 'unwind' if unwind else 'abort', 'static'
                with patch.object(r, 'policy', return_value=actual):
                    self.assertEqual(r.prior.mutations(r.check, *args, *config), len(lines) + len(raw))
                    for role, target in targets.items():
                        for changed in ((target[0], target[1]+4, 4), ('wrong', target[1], 4), row):
                            bad = {**targets, role: changed}
                            with self.assertRaises(ValueError): r.check(lines, raw, row, image, bad, *config)
                        with self.assertRaisesRegex(ValueError, 'call population changed'):
                            r.check(lines, raw, row, image, {n:v for n,v in targets.items() if n != role}, *config)

    def test_runtime_requires_exact_symbol_mapping_and_bytes(self):
        _, _, image, _ = fixture.fixture(r.TARGET)
        table = '0000000000001500 00000000000000b8 T _Unwind_Resume'
        with self.assertRaisesRegex(ValueError, 'runtime image changed'):
            r.resume_target(table, image, 'static')
        digest = hashlib.sha256(image[0x500:0x5b8]).hexdigest()
        with patch.dict(r.RESUME, {'static': digest}):
            self.assertEqual(r.resume_target(table, image, 'static'), ('_Unwind_Resume', 0x1500, 184))
            self.assertEqual(r.resume_mutations(table, image, 'static'), 184)
            for bad in ('', table + '\n' + table, table.replace(' T ', ' t '),
                        table.replace('00b8', '00b4'), table.replace('1500', '1501'),
                        table.replace('1500', '2500'), table.replace('Resume', 'Resume@plt')):
                with self.assertRaises(ValueError): r.resume_target(bad, image, 'static')
        with self.assertRaises(ValueError): r.resume_target(table, image, 'other')

    def test_unknown_configuration_fails_closed(self):
        valid = ['public', 128, '1.99.1', 'abort', 'static']
        for i in range(len(valid)):
            changed = valid.copy(); changed[i] = 'unknown'
            with self.assertRaises(ValueError): r.policy(*changed)

    def test_failed_constructor_dependency_prevents_caller_review(self):
        with patch.object(r.prior, 'inspect', side_effect=ValueError('constructor rejected')):
            with patch.object(r, 'candidates') as select, patch.object(r, 'check') as check:
                with self.assertRaisesRegex(ValueError, 'constructor rejected'):
                    r.inspect('', '', b'', '1.99.1', 'abort', 'static')
                select.assert_not_called(); check.assert_not_called()

    def test_duplicate_kernel_width_prevents_caller_review(self):
        with patch.object(r.prior, 'inspect', return_value={}):
            with patch.object(r.prior, 'candidates', return_value={}):
                with patch.object(r.prior.cleanup, 'candidates', return_value={}):
                    with patch.object(r.kernels, 'select', return_value=[('one', 0, 4), ('two', 4, 4)]):
                        with patch.object(r.kernels, 'decode', return_value=([], b'', [])):
                            with patch.object(r.kernels, 'check', return_value={'bits': 128}):
                                with self.assertRaisesRegex(ValueError, 'duplicate ARM cached kernel width'):
                                    r.inspect(symbols(), '', b'', '1.99.1', 'abort', 'static')

    def test_runner_requires_exclusive_emulated_mode(self):
        cases = [dict(mode='native', admission='static'), dict(mode='arm-qemu', admission='hosted', capture_only=True)]
        for other in ('review_lifecycle', 'review_arm_cleanup', 'review_arm_constructors', 'review_cached_public',
                      'review_cached_secret', 'review_ephemeral_public', 'review_ephemeral_secret'):
            cases.append(dict(mode='arm-qemu', admission='static', **{other: True}))
        for options in cases:
            with patch.object(runner.packaged, 'package_sources') as package, self.assertRaises(ValueError):
                runner.check('1.99.1', review_arm_cached=True, **options)
            package.assert_not_called()

    def test_registry_binds_all_review_inputs_and_exact_markers(self):
        registry = tomllib.loads((runner.ROOT / 'verification/checks.toml').read_text())
        checks = {c['id']: c for c in registry['checks'] if c.get('category') == 'aes-linked-arm-cached'}
        self.assertEqual(set(checks), {f'accelerated-arm-cached-{a}-{e}'
                                     for a in ('static', 'hosted') for e in ('msrv', 'current')})
        for endpoint, tc in (('msrv', '1.90.0'), ('current', '1.99.1')):
            for a in ('static', 'hosted'):
                check = checks[f'accelerated-arm-cached-{a}-{endpoint}']
                self.assertEqual(check['command'], ['python3', 'scripts/aes/check-aes-accelerated-linked.py',
                    '--toolchain', tc, '--mode', 'arm-qemu', '--admission', a, '--review-arm-cached'])
                self.assertTrue({'aes-build', 'aes-accelerated-arm-cached', 'aes-accelerated-arm-constructors',
                    'aes-accelerated-arm-cleanup', 'aes-accelerated-linked', 'aes-accelerated-campaigns',
                    'compiler', 'hkdf-msrv', 'aes-kernel-qemu'} <= set(check['inputs']))
                self.assertEqual(check['success']['unique_lines'], [f'AES_ACCELERATED_ARM_CACHED_LINKED_PASS: {tc} {a}; four emulated consumers; cached public/secret callers and replayed constructor closure'])
        self.assertEqual(set(registry['groups']['aes-accelerated-arm-cached']['paths']), {
            'scripts/aes/aes_accelerated_linked_arm_cached.py', 'scripts/aes/accelerated-arm-cached-review.json',
            'scripts/aes/test-aes-accelerated-arm-cached.py', 'docs/assurance/aes-accelerated-linked-arm-cached.md'})


if __name__ == '__main__':
    unittest.main()
