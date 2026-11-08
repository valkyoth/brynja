#!/usr/bin/env python3
"""Fail-closed controls for the bounded AArch64 compile-only review."""
import importlib.util
import json
from pathlib import Path
import tempfile
import tomllib
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('arm_flow_tests', Path(__file__).with_name('check-aes-aarch64-dataflow.py'))
arm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(arm)
machine = arm.machine


def assembly(extra=''):
    saves = ['str x27, [sp, #-80]!'] + sorted(machine.SAVE - {'str x27, [sp, #-80]!'})
    restores = sorted(machine.RESTORE - {'ldr x27, [sp], #80'}) + ['ldr x27, [sp], #80']
    return ('inverse:\n.cfi_startproc\n' + '\n'.join(saves) + '\n' + extra
            + 'eor w0, w0, w1\n' * 101 + '\n'.join(restores)
            + '\nret\n.cfi_endproc\n.Lfunc_end123:\n.size inverse, .-inverse\n')


def policy(asm):
    value = json.loads(machine.POLICY.read_text())
    digest, _ = machine.fingerprint(asm, 'inverse')
    value['compilers'] = {c: {p: digest for p in ('abort', 'unwind')}
                          for c in ('1.90.0', '1.99.1')}
    return value


class Aarch64DataflowTests(unittest.TestCase):
    def test_review_policy_covers_exact_compilers_and_profiles(self):
        value = json.loads(machine.POLICY.read_text())
        self.assertEqual(set(value['compilers']), {'1.90.0', '1.99.1'})
        self.assertNotEqual(value['compilers']['1.90.0']['abort'], value['compilers']['1.90.0']['unwind'])
        for profiles in value['compilers'].values():
            self.assertEqual(set(profiles), {'abort', 'unwind'})
            for digest in profiles.values():
                self.assertRegex(digest, '^[0-9a-f]{64}$')
        self.assertTrue((arm.flow.ROOT / machine.REVIEW).is_file())

    def test_immediates_preserved_and_nonexecuting_metadata_ignored(self):
        original = assembly()
        annotated = original.replace('#-80]!', '#-80]! // frame')
        self.assertEqual(machine.fingerprint(original, 'inverse'), machine.fingerprint(annotated, 'inverse'))
        self.assertIn('str x27, [sp, #-80]!', machine.body(annotated, 'inverse'))
        self.assertEqual(machine.check(original, 'inverse', '1.90.0', 'abort', policy(original)), 112)

    def test_reviewed_register_arithmetic_is_accepted(self):
        value = assembly('and w0, w1, w2, asr #7\nlsl w0, w0, #31\nsxtb w0, w1\n'
                         'sbfx w0, w1, #31, #1\nmov w8, #27\ncmn w0, #1\ncsel w0, wzr, w1, gt\n')
        machine.check(value, 'inverse', '1.99.1', 'unwind', policy(value))

    def test_unreviewed_instructions_and_operands_fail_closed(self):
        for instruction in ('b.eq .Lother', 'bl other', 'br x0', 'udiv w0, w0, w1',
                            'ldr w0, [x0]', 'ldr w0, [sp, x0]', 'mov sp, x0',
                            'lsl w0, w0, w1', 'lsl w0, w0, #32', 'csel x0, xzr, x0, gt',
                            '.word 0', '.inst 0', 'str w0, [sp, #8]', 'mov w0, #28',
                            'sbfx w0, w1, #31, #2', 'sbfx w0, w1, #0, #0'):
            with self.subTest(instruction=instruction), self.assertRaises(ValueError):
                machine.fingerprint(assembly(instruction + '\n'), 'inverse')

    def test_frame_return_and_symbol_population_fail_closed(self):
        original = assembly()
        for changed in (original.replace('ret\n', ''), original.replace('ret\n', 'ret\nret\n'),
                        original.replace('#-80', '#-96'), original.replace('stp x26, x25, [sp, #16]', ''),
                        original + original, original.replace('inverse:', 'different:')):
            with self.subTest(changed=changed[:50]), self.assertRaises(ValueError):
                machine.fingerprint(changed, 'inverse')

    def test_admitted_arithmetic_change_still_requires_review(self):
        original = assembly()
        with self.assertRaisesRegex(ValueError, 'instruction stream changed'):
            machine.check(assembly('mov w8, #27\n'), 'inverse', '1.90.0', 'abort', policy(original))

    def test_configuration_and_policy_cannot_widen_silently(self):
        original = assembly()
        for field, value in (('target', 'x86_64-unknown-linux-gnu'), ('schema', 2),
                             ('panics', ['abort']), ('review', 'other')):
            changed = policy(original)
            changed[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'scope changed'):
                machine.check(original, 'inverse', '1.90.0', 'abort', changed)
        for compiler, panic in (('stable', 'abort'), ('1.90.0', 'other')):
            with self.assertRaisesRegex(ValueError, 'unreviewed configuration'):
                machine.check(original, 'inverse', compiler, panic, policy(original))
        changed = policy(original)
        del changed['compilers']['1.90.0']['abort']
        with self.assertRaisesRegex(ValueError, 'invalid fingerprint'):
            machine.check(original, 'inverse', '1.90.0', 'abort', changed)

    def test_missing_or_duplicate_artifacts_cannot_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            with patch.object(arm.flow.verifier, 'run', return_value='mock compiler'), patch('builtins.print') as emit:
                with self.assertRaisesRegex(ValueError, 'missing/ambiguous'):
                    arm.collect(directory, '1.90.0', 'abort')
                paths = directory / 'target' / arm.TARGET / 'release/deps'
                paths.mkdir(parents=True)
                for name in ('brynja_crypto-one.ll', 'brynja_crypto-two.ll'):
                    (paths / name).touch()
                with self.assertRaisesRegex(ValueError, 'missing/ambiguous'):
                    arm.collect(directory, '1.90.0', 'abort')
                self.assertFalse(any('PASS' in str(call) for call in emit.call_args_list))

    def test_rejected_environment_stops_before_build(self):
        for name in arm.REJECT:
            with patch.dict('os.environ', {name: 'override'}, clear=True), \
                    patch('sys.argv', ['check-aes-aarch64-dataflow.py']), \
                    patch.object(arm, 'collect') as collect:
                with self.assertRaisesRegex(ValueError, 'remove ambient'):
                    arm.main()
                collect.assert_not_called()

    def test_core_emission_requires_unique_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            with patch.object(arm.flow.verifier, 'run', return_value='mock compiler'), patch('builtins.print'):
                with self.assertRaisesRegex(ValueError, 'missing/ambiguous AArch64 core artifact'):
                    arm.collect_core(directory, {}, '1.90.0', 'abort', {})
                paths = directory / 'target' / arm.TARGET / 'release/deps'
                paths.mkdir(parents=True)
                for name in ('brynja_core-one.ll', 'brynja_core-two.ll'):
                    (paths / name).touch()
                with self.assertRaisesRegex(ValueError, 'missing/ambiguous AArch64 core artifact'):
                    arm.collect_core(directory, {}, '1.90.0', 'abort', {})

    def test_core_build_failure_propagates(self):
        with patch.object(arm.flow.verifier, 'run', side_effect=RuntimeError('core build failed')), patch('builtins.print') as emit:
            with self.assertRaisesRegex(RuntimeError, 'core build failed'):
                arm.collect_core(Path('/unused'), {}, '1.99.1', 'unwind', {})
            emit.assert_not_called()

    def test_build_failure_never_emits_completion_marker(self):
        with patch.dict('os.environ', {}, clear=True), \
                patch('sys.argv', ['check-aes-aarch64-dataflow.py']), \
                patch.object(arm, 'collect', side_effect=ValueError('failed model')), patch('builtins.print') as emit:
            with self.assertRaisesRegex(ValueError, 'failed model'):
                arm.main()
            self.assertFalse(any(arm.MARKER in str(call) for call in emit.call_args_list))

    def test_registry_pins_scope_inputs_and_complete_population(self):
        registry = tomllib.loads((arm.flow.ROOT / 'verification/checks.toml').read_text())
        check = next(c for c in registry['checks'] if c['component'] == 'aes' and c['id'] == 'aarch64-dataflow-review')
        self.assertEqual(check['command'], ['python3', 'scripts/aes/check-aes-aarch64-dataflow.py'])
        self.assertEqual(check['platform'], 'linux-x86_64')
        self.assertEqual(set(check['reject_environment']), set(arm.REJECT))
        self.assertTrue({'aes-build', 'aes-dataflow', 'aes-aarch64-dataflow', 'asan-source-core', 'compiler', 'hkdf-msrv'} <= set(check['inputs']))
        self.assertEqual(check['success']['unique_lines'], [arm.MARKER] + [
            f'AES AArch64 configuration: PASS; {c}; {p}; 11 LLVM helpers; {n} inverse instructions; ten additional assembly helpers; six secret wrappers; six public boundaries; six constructors; twelve secret entry points; seven matched core bodies; 804 rejected mutations'
            for c, n in (('1.90.0', 596), ('1.99.1', 599)) for p in ('abort', 'unwind')])
        self.assertEqual(set(registry['groups']['aes-aarch64-dataflow']['paths']), {
            'scripts/aes/check-aes-aarch64-dataflow.py', 'scripts/aes/aes_aarch64_review.py',
            'scripts/aes/test-aes-aarch64-dataflow.py', 'scripts/aes/aarch64-inverse-review.json', machine.REVIEW,
            'scripts/aes/aes_aarch64_helpers.py', 'scripts/aes/test-aes-aarch64-helpers.py',
            'scripts/aes/aes_aarch64_rounds.py', 'scripts/aes/test-aes-aarch64-rounds.py',
            'scripts/aes/aarch64-rounds-review.json', 'scripts/aes/aes_aarch64_wrappers.py',
            'scripts/aes/test-aes-aarch64-wrappers.py', 'scripts/aes/aarch64-wrappers-review.json',
            'scripts/aes/aes_aarch64_core.py', 'scripts/aes/test-aes-aarch64-core.py',
            'scripts/aes/aarch64-core-review.json', 'scripts/aes/aes_aarch64_public.py',
            'scripts/aes/test-aes-aarch64-public.py', 'scripts/aes/aarch64-public-review.json',
            'scripts/aes/aes_aarch64_constructors.py', 'scripts/aes/test-aes-aarch64-constructors.py',
            'scripts/aes/aarch64-constructors-review.json', 'scripts/aes/aes_aarch64_callers.py',
            'scripts/aes/test-aes-aarch64-callers.py', 'scripts/aes/aarch64-callers-review.json'})

    def test_arm_review_edits_do_not_invalidate_packaged_checks(self):
        registry = tomllib.loads((arm.flow.ROOT / 'verification/checks.toml').read_text())
        arm_paths = set(registry['groups']['aes-aarch64-dataflow']['paths'])
        package_paths = set(registry['groups']['aes-packaged']['paths'])
        self.assertFalse(arm_paths & package_paths)


if __name__ == '__main__':
    unittest.main()
