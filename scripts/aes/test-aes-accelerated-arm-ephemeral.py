#!/usr/bin/env python3
"""ARM per-operation review regression controls, not production approval fixtures."""
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


r = module('arm_ephemeral_tests', 'aes_accelerated_linked_arm_ephemeral.py')
fixtures = module('arm_ephemeral_fixture', 'test-aes-accelerated-arm-cached.py')
runner = fixtures.runner


def symbols(current=False):
    rows = []
    for i, (kind, bits) in enumerate((k, b) for k in ('public', 'secret') for b in (128, 192, 256)):
        if kind == 'public':
            name = (f'_RNvCs123_30brynja_aes_accelerated_fixture9public{bits}' if current else
                    f'_ZN30brynja_aes_accelerated_fixture9public{bits}17h0000000000000000E')
        else:
            name = (f'_RNvMsa_NtNtCs123_13brynja_crypto3aes9executionNtB5_9Aes{bits}Key6secret' if current else
                    f'_ZN13brynja_crypto3aes9execution9Aes{bits}Key6secret17h0000000000000000E')
        rows.append(f'{0x1500 + i*0x100:016x} 0000000000000004 t {name}')
    return '\n'.join(rows)


def synthetic(kind, unwind=False):
    _, _, _, original, targets = fixtures.synthetic(kind, unwind)
    targets['expand'] = ('expand', 0x16c0, 4)
    if kind == 'secret':
        del targets['kernel']
        targets.update(encrypt=('encrypt', 0x16e0, 4), decrypt=('decrypt', 0x1700, 4))
    lines, raw = [], bytearray()
    for name, address, _ in targets.values():
        delta = address - (0x1500 + len(raw))
        raw.extend((0x94000000 | ((delta // 4) & 0x3ffffff)).to_bytes(4, 'little'))
        lines.append(f'bl 0x{address:x} <{name}>')
    raw.extend(bytes.fromhex('c0035fd6')); lines.append('ret')
    image = bytearray(original); image[0x500:0x500+len(raw)] = raw
    return lines, bytes(raw), ('caller', 0x1500, len(raw)), bytes(image), targets


class AcceleratedArmEphemeralTests(unittest.TestCase):
    def test_policy_population_and_counts(self):
        expected = {(c, a, p, k, str(b)) for c in ('1.90.0', '1.99.1') for a in ('static', 'hosted')
                    for p in ('abort', 'unwind') for k in ('public', 'secret') for b in (128, 192, 256)}
        self.assertEqual(set(r.POLICY), {'/'.join(row) for row in expected})
        for c, a, p, k, b in expected:
            policy = r.policy(k, int(b), c, p, a)
            self.assertEqual(set(policy), {'instructions', 'branches', 'calls', 'constants',
                                          'text_sha256', 'encoding_sha256'})
            self.assertEqual(policy['constants'], 0)
            self.assertGreater(policy['instructions'], 100)
            self.assertGreater(policy['calls'], 4)
            for name in ('text_sha256', 'encoding_sha256'):
                self.assertRegex(policy[name], r'^[0-9a-f]{64}$')

    def test_selector_requires_all_six_exact_nonoverlapping_symbols(self):
        for current in (False, True):
            table = symbols(current)
            self.assertEqual(len(r.candidates(table)), 6)
            for bad in (table + '\n' + table.splitlines()[0], '\n'.join(table.splitlines()[1:]),
                        table.replace('public192', 'public128'), table.replace(' t ', ' D '),
                        table.replace('0000000000001600', '0000000000001500'),
                        table.replace('9public', '10public'), table.replace('9Aes192', '10Aes192'),
                        table.replace('0000000000000004 t', '0000000000000003 t')):
                with self.assertRaises(ValueError): r.candidates(bad)
            # Other API bodies cannot substitute for per-operation callers.
            with self.assertRaises(ValueError): r.candidates(fixtures.symbols(current))

    def test_synthetic_code_never_matches_production_policy(self):
        for c in ('1.90.0', '1.99.1'):
            for p in ('abort', 'unwind'):
                for a in ('static', 'hosted'):
                    for k in ('public', 'secret'):
                        args = synthetic(k, (c, p) == ('1.90.0', 'unwind'))
                        for b in (128, 192, 256):
                            with self.assertRaisesRegex(ValueError, 'ephemeral stream changed'):
                                r.check(*args, k, b, c, p, a)

    def test_instruction_byte_and_call_target_mutations(self):
        for k in ('public', 'secret'):
            for unwind in (False, True):
                lines, raw, row, image, targets = args = synthetic(k, unwind)
                actual = r.constructors.portable.observe(*args)[0]
                config = k, 128, '1.90.0', 'unwind' if unwind else 'abort', 'static'
                with patch.object(r, 'policy', return_value=actual):
                    self.assertEqual(r.constructors.mutations(r.check, *args, *config), len(lines) + len(raw))
                    for role, target in targets.items():
                        for changed in ((target[0], target[1]+4, 4), ('wrong', target[1], 4), row):
                            with self.assertRaises(ValueError):
                                r.check(lines, raw, row, image, {**targets, role: changed}, *config)
                        with self.assertRaisesRegex(ValueError, 'call population changed'):
                            r.check(lines, raw, row, image, {n:v for n,v in targets.items() if n != role}, *config)

    def test_swapped_expansion_and_kernel_roles_fail(self):
        lines, raw, row, image, targets = args = synthetic('public')
        actual = r.constructors.portable.observe(*args)[0]
        with patch.object(r, 'policy', return_value=actual):
            with self.assertRaisesRegex(ValueError, 'ephemeral stream changed'):
                r.check(lines, raw, row, image, {**targets, 'expand': targets['kernel'], 'kernel': targets['expand']},
                        'public', 128, '1.99.1', 'abort', 'static')

    def test_swapped_session_directions_fail(self):
        lines, raw, row, image, targets = args = synthetic('secret')
        actual = r.constructors.portable.observe(*args)[0]
        with patch.object(r, 'policy', return_value=actual):
            with self.assertRaisesRegex(ValueError, 'ephemeral stream changed'):
                r.check(lines, raw, row, image,
                        {**targets, 'encrypt': targets['decrypt'], 'decrypt': targets['encrypt']},
                        'secret', 128, '1.99.1', 'abort', 'static')

    def test_unknown_configuration_fails_closed(self):
        valid = ['public', 128, '1.99.1', 'abort', 'static']
        for i in range(len(valid)):
            changed = valid.copy(); changed[i] = 'unknown'
            with self.assertRaises(ValueError): r.policy(*changed)

    def test_failed_cached_dependency_prevents_caller_review(self):
        with patch.object(r.prior, 'inspect', side_effect=ValueError('cached rejected')):
            with patch.object(r, 'candidates') as select, patch.object(r, 'check') as check:
                with self.assertRaisesRegex(ValueError, 'cached rejected'):
                    r.inspect('', '', b'', '1.99.1', 'abort', 'static')
                select.assert_not_called(); check.assert_not_called()

    def test_duplicate_kernel_width_prevents_caller_review(self):
        with patch.object(r.prior, 'inspect', return_value={}), patch.object(r.prior, 'candidates', return_value={}), \
                patch.object(r.sessions, 'inspect', return_value={}), patch.object(r.sessions, 'candidates', return_value={}):
            with patch.object(r.constructors, 'candidates', return_value={}):
                with patch.object(r.constructors.cleanup, 'candidates', return_value={}):
                    with patch.object(r.kernels, 'select', return_value=[('one', 0, 4), ('two', 4, 4)]):
                        with patch.object(r.kernels, 'decode', return_value=([], b'', [])):
                            with patch.object(r.kernels, 'check', return_value={'bits': 128}):
                                with self.assertRaisesRegex(ValueError, 'duplicate ARM ephemeral kernel width'):
                                    r.inspect(symbols(), '', b'', '1.99.1', 'abort', 'static')

    def test_failed_session_dependency_prevents_caller_review(self):
        with patch.object(r.prior, 'inspect', return_value={}):
            with patch.object(r.sessions, 'inspect', side_effect=ValueError('session rejected')):
                with patch.object(r, 'candidates') as select, patch.object(r, 'check') as check:
                    with self.assertRaisesRegex(ValueError, 'session rejected'):
                        r.inspect('', '', b'', '1.99.1', 'abort', 'static')
                    select.assert_not_called(); check.assert_not_called()

    def test_runner_requires_exclusive_emulated_mode(self):
        cases = [dict(mode='native', admission='static'), dict(mode='arm-qemu', admission='hosted', capture_only=True)]
        for other in ('review_lifecycle', 'review_arm_cleanup', 'review_arm_constructors', 'review_arm_cached',
                      'review_cached_public', 'review_cached_secret', 'review_ephemeral_public', 'review_ephemeral_secret'):
            cases.append(dict(mode='arm-qemu', admission='static', **{other: True}))
        for options in cases:
            with patch.object(runner.packaged, 'package_sources') as package, self.assertRaises(ValueError):
                runner.check('1.99.1', review_arm_ephemeral=True, **options)
            package.assert_not_called()

    def test_registry_binds_all_review_inputs_and_exact_markers(self):
        registry = tomllib.loads((runner.ROOT / 'verification/checks.toml').read_text())
        checks = {c['id']: c for c in registry['checks'] if c.get('category') == 'aes-linked-arm-ephemeral'}
        self.assertEqual(set(checks), {f'accelerated-arm-ephemeral-{a}-{e}'
                                     for a in ('static', 'hosted') for e in ('msrv', 'current')})
        for endpoint, tc in (('msrv', '1.90.0'), ('current', '1.99.1')):
            for a in ('static', 'hosted'):
                check = checks[f'accelerated-arm-ephemeral-{a}-{endpoint}']
                self.assertEqual(check['command'], ['python3', 'scripts/aes/check-aes-accelerated-linked.py',
                    '--toolchain', tc, '--mode', 'arm-qemu', '--admission', a, '--review-arm-ephemeral'])
                self.assertTrue({'aes-build', 'aes-accelerated-arm-ephemeral', 'aes-accelerated-arm-cached',
                    'aes-accelerated-arm-constructors', 'aes-accelerated-arm-cleanup', 'aes-accelerated-linked',
                    'aes-accelerated-campaigns', 'compiler', 'hkdf-msrv', 'aes-kernel-qemu'} <= set(check['inputs']))
                self.assertEqual(check['success']['unique_lines'], [f'AES_ACCELERATED_ARM_EPHEMERAL_LINKED_PASS: {tc} {a}; four emulated consumers; per-operation public/secret callers and replayed cached closure'])
        self.assertEqual(set(registry['groups']['aes-accelerated-arm-ephemeral']['paths']), {
            'scripts/aes/aes_accelerated_linked_arm_ephemeral.py', 'scripts/aes/accelerated-arm-ephemeral-review.json',
            'scripts/aes/aes_accelerated_linked_arm_sessions.py', 'scripts/aes/accelerated-arm-session-review.json',
            'scripts/aes/test-aes-accelerated-arm-sessions.py',
            'scripts/aes/test-aes-accelerated-arm-ephemeral.py', 'docs/assurance/aes-accelerated-linked-arm-ephemeral.md'})


if __name__ == '__main__':
    unittest.main()
