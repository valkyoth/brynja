#!/usr/bin/env python3
"""Fail-closed AES runner regressions; fake compilers/verifiers, no crypto runs."""
from contextlib import nullcontext, redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


api = load('check-aes-api')
kani = load('check-aes-kani')
mutation = load('check-aes-mutations')
owner = load('check-aes-owner-cleanup')
operation = load('check-aes-operation-cleanup')


class ScratchTests(unittest.TestCase):
    def result(self):
        message = {'level': 'error', 'code': {'code': 'E0080'},
                   'message': 'evaluation panicked: AES scratch must not be empty',
                   'spans': [{'is_primary': True, 'file_name': 'src/aes.rs'}]}
        return SimpleNamespace(returncode=101, stdout=json.dumps({'reason': 'compiler-message', 'message': message}), stderr='')

    def test_exact_scratch_diagnostic(self):
        result = self.result()
        self.assertTrue(mutation.scratch_rejected(result))
        for code, output in [(0, result.stdout), (-9, result.stdout), (101, ''), (101, 'null'),
                             (101, result.stdout.replace('E0080', 'E0432')),
                             (101, result.stdout.replace('src/aes.rs', 'src/other.rs')),
                             (101, result.stdout + '\n' + result.stdout)]:
            self.assertFalse(mutation.scratch_rejected(SimpleNamespace(returncode=code, stdout=output)))

    def test_scratch_source_restored_even_on_wrong_failure(self):
        for accepted in (True, False):
            with tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                (directory / 'src').mkdir()
                source = directory / 'src/aes.rs'
                source.write_text('original')
                with patch.object(mutation.verifier, 'run') as run, \
                     patch.object(mutation.subprocess, 'run', return_value=self.result()), \
                     patch.object(mutation, 'scratch_rejected', return_value=accepted), \
                     patch('builtins.print') as emit:
                    if accepted:
                        mutation.scratch_contract(directory, '1.99.1')
                        self.assertEqual(run.call_count, 2)
                        emit.assert_called_once_with(mutation.SCRATCH_MARKER, flush=True)
                    else:
                        with self.assertRaises(ValueError):
                            mutation.scratch_contract(directory, '1.99.1')
                        emit.assert_not_called()
                self.assertEqual(source.read_text(), 'original')

    def test_scratch_macro_must_originate_in_production_source(self):
        result = self.result()
        row = json.loads(result.stdout)
        span = row['message']['spans'][0]
        span.update(file_name='/rustc/core/panic.rs', expansion={'span': {'file_name': 'src/aes.rs'}})
        result.stdout = json.dumps(row)
        self.assertTrue(mutation.scratch_rejected(result))
        span['expansion']['span']['file_name'] = 'src/other.rs'
        result.stdout = json.dumps(row)
        self.assertFalse(mutation.scratch_rejected(result))


def diagnostic(code='E0277', source='probe.rs', primary=True, status=1):
    message = {'$message_type': 'diagnostic', 'level': 'error', 'code': {'code': code},
               'spans': [{'file_name': str(source), 'is_primary': primary}]}
    return SimpleNamespace(returncode=status, stderr=json.dumps(message))


class ApiTests(unittest.TestCase):
    def test_population_and_nearby_controls(self):
        cases = api.probes()
        self.assertEqual(len(cases), 58)
        self.assertEqual(len({c[0] for c in cases}), 58)
        for name, negative, positive, code in cases:
            self.assertNotEqual(negative, positive, name)
            self.assertRegex(code, '^E[0-9]{4}$')

    def test_exact_code_and_primary_source_required(self):
        self.assertTrue(api.diagnostic_matches(diagnostic(), 'E0277', Path('probe.rs')))
        for result in (diagnostic('E0463'), diagnostic(source='dependency.rs'),
                       diagnostic(primary=False), diagnostic(status=0), diagnostic(status=-9)):
            self.assertFalse(api.diagnostic_matches(result, 'E0277', Path('probe.rs')))

    def test_empty_malformed_duplicate_or_uncoded_error_rejected(self):
        original = diagnostic()
        for text in ('', 'not json', 'null', original.stderr + '\n' + original.stderr,
                     json.dumps({'$message_type': 'diagnostic', 'level': 'error', 'code': None, 'spans': []})):
            self.assertFalse(api.diagnostic_matches(SimpleNamespace(returncode=1, stderr=text), 'E0277', Path('probe.rs')))

    def test_abort_summary_is_not_an_extra_error(self):
        result = diagnostic()
        result.stderr += '\n' + json.dumps({'$message_type': 'diagnostic', 'level': 'error',
                                             'code': None, 'spans': [], 'message': 'aborting due to 1 previous error'})
        self.assertTrue(api.diagnostic_matches(result, 'E0277', Path('probe.rs')))

    def invoke(self, *, positive_fails=False, wrong_negative=False, missing_artifact=False):
        commands = []
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            deps = directory / 'target/debug/deps'
            deps.mkdir(parents=True)
            artifact = deps / 'libbrynja_crypto-test.rlib'
            cases = {negative: code for _, negative, _, code in api.probes()}

            def run(command, *_args):
                commands.append(command)
                if command[0] == 'cargo':
                    if missing_artifact:
                        return ''
                    return json.dumps({'reason': 'compiler-artifact', 'target': {'name': 'brynja_crypto'},
                                       'filenames': [str(artifact)]})
                if positive_fails:
                    raise RuntimeError('positive control failed')
                return ''

            def compile_negative(command, **_kwargs):
                commands.append(command)
                source = Path(command[-1])
                return diagnostic('E0463' if wrong_negative else cases[source.read_text()], source)

            with (patch.object(api.verifier, 'run', side_effect=run),
                  patch.object(api.subprocess, 'run', side_effect=compile_negative),
                  redirect_stdout(io.StringIO()) as output):
                api.run_probes('1.99.1', directory, {})
            return commands, output.getvalue()

    def test_every_positive_and_negative_runs(self):
        commands, output = self.invoke()
        self.assertEqual(len(commands), 117)
        self.assertIn('--locked', commands[0])
        self.assertIn('--offline', commands[0])
        self.assertTrue(all(c[1] == '+1.99.1' for c in commands))
        self.assertEqual(output.count('AES_API_CASE:'), 58)
        self.assertIn('AES_API_PASS: 1.99.1 58 paired probes', output)

    def test_positive_failure_propagates(self):
        with self.assertRaises(RuntimeError):
            self.invoke(positive_fails=True)

    def test_wrong_negative_error_fails(self):
        with self.assertRaises(ValueError):
            self.invoke(wrong_negative=True)

    def test_missing_artifact_fails(self):
        with self.assertRaises(ValueError):
            self.invoke(missing_artifact=True)


class KaniTests(unittest.TestCase):
    def test_inventory_is_production_and_dependency_free(self):
        kani.policy()

    def test_summary_is_exact_and_unique(self):
        self.assertTrue(kani.successful(kani.SUMMARY))
        for text in ('No harnesses', kani.SUMMARY + '\n' + kani.SUMMARY,
                     'Complete - 2 successfully verified harnesses, 0 failures, 2 total.',
                     kani.SUMMARY + '\nVERIFICATION:- FAILED'):
            self.assertFalse(kani.successful(text))

    def invoke(self, output=None, bad_version=False, failure=False):
        commands = []

        def run(command, _env):
            commands.append(command)
            if command[-1] == '--version':
                return 'wrong' if bad_version else 'Kani Rust Verifier 0.68.0 (cargo plugin)\nCBMC 6.11.0'
            if failure:
                raise RuntimeError('verifier failed')
            return kani.SUMMARY if output is None else output

        with (patch.object(kani.sys, 'argv', ['check-aes-kani.py']),
              patch.object(kani.verifier, 'tool', return_value={'version': '0.68.0', 'execution_toolchain': '1.90.0'}),
              patch.object(kani.verifier, 'environment', return_value={}),
              patch.object(kani.verifier.cargo_environment, 'private_directory', return_value=nullcontext('/tmp')),
              patch.object(kani.verifier, 'run', side_effect=run), redirect_stdout(io.StringIO()) as captured):
            kani.main()
        return commands, captured.getvalue()

    def test_five_exact_harnesses_execute(self):
        commands, output = self.invoke()
        self.assertEqual(len(commands), 6)
        self.assertEqual([c[-2:] for c in commands[1:]],
                         [['proofs::' + n, '--exact'] for n in kani.HARNESSES])
        self.assertIn(kani.MARKER, output)

    def test_failure_or_bad_identity_never_passes(self):
        for kwargs in ({'output': ''}, {'bad_version': True}, {'failure': True}):
            with self.subTest(kwargs=kwargs), self.assertRaises((ValueError, RuntimeError)):
                self.invoke(**kwargs)

    def test_policy_only_never_executes(self):
        with (patch.object(kani.sys, 'argv', ['check-aes-kani.py', '--policy-only']),
              patch.object(kani.verifier, 'run') as run, redirect_stdout(io.StringIO()) as output):
            kani.main()
        run.assert_not_called()
        self.assertIn('NOT executed', output.getvalue())


class MutationTests(unittest.TestCase):
    def test_population_and_nonvacuous_anchors(self):
        self.assertEqual(len(mutation.MUTATIONS), 18)
        self.assertEqual(len({m[0] for m in mutation.MUTATIONS}), 18)
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            mutation.prepare(directory)
            for name, relative, old, new, _selection in mutation.MUTATIONS:
                source = (directory / relative).read_text()
                self.assertNotEqual(mutation.mutate(source, old, new), source, name)

    def test_missing_duplicate_or_unchanged_anchor_fails(self):
        for source, old, new in [('abc', 'd', 'x'), ('aa', 'a', 'b'), ('abc', 'a', 'a')]:
            with self.assertRaises(ValueError):
                mutation.mutate(source, old, new)

    def test_only_named_assertion_failure_is_a_kill(self):
        output = 'running 1 test\ntest expected ... FAILED\nassertion failed: wrong value\ntest result: FAILED. 0 passed; 1 failed; 0 ignored;'
        good = SimpleNamespace(returncode=101, stdout=output, stderr='')
        self.assertTrue(mutation.rejected(good, 'expected'))
        for result in (
            SimpleNamespace(returncode=0, stdout=output, stderr=''),
            SimpleNamespace(returncode=-6, stdout=output, stderr=''),
            SimpleNamespace(returncode=101, stdout='', stderr='could not compile'),
            SimpleNamespace(returncode=101, stdout=output.replace('expected', 'other'), stderr=''),
            SimpleNamespace(returncode=101, stdout=output.replace('assertion', 'panic'), stderr=''),
            SimpleNamespace(returncode=101, stdout=output.replace('running 1 test', 'running 0 tests'), stderr=''),
        ):
            self.assertFalse(mutation.rejected(result, 'expected'))

    def test_compile_failure_aborts_campaign_before_any_kill(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source_before = (mutation.ROOT / 'crates/brynja-crypto/src/aes/portable/field.rs').read_text()

            def run(command, *_args):
                if '--no-run' in command:
                    raise RuntimeError('mutant does not compile')
                if 'generate-lockfile' in command:
                    return ''
                count = 4 if 'aes_wide_kat' in command else (6 if '--test' in command else 17)
                return f'test result: ok. {count} passed; 0 failed; 0 ignored;'

            with (patch.object(mutation.verifier, 'environment', return_value={}),
                  patch.object(mutation.verifier, 'run', side_effect=run),
                  patch.object(mutation.subprocess, 'run') as execute,
                  self.assertRaises(RuntimeError)):
                mutation.campaign(directory, '1.99.1')
            execute.assert_not_called()
            self.assertEqual((directory / 'src/aes/portable/field.rs').read_text(), source_before)

    def test_surviving_mutant_aborts_and_restores_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source_before = (mutation.ROOT / 'crates/brynja-crypto/src/aes/portable/field.rs').read_text()

            def run(command, *_args):
                if '--no-run' in command or 'generate-lockfile' in command:
                    return ''
                count = 4 if 'aes_wide_kat' in command else (6 if '--test' in command else 17)
                return f'test result: ok. {count} passed; 0 failed; 0 ignored;'

            with (patch.object(mutation.verifier, 'environment', return_value={}),
                  patch.object(mutation.verifier, 'run', side_effect=run),
                  patch.object(mutation.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout='passed', stderr='')),
                  self.assertRaises(ValueError)):
                mutation.campaign(directory, '1.99.1')
            self.assertEqual((directory / 'src/aes/portable/field.rs').read_text(), source_before)


class OwnerCodegenTests(unittest.TestCase):
    @staticmethod
    def fixture(panic):
        # Synthetic parser regression fixture, not claimed compiler evidence.
        destructor = '@_RNvXs1_NtCs7Vl0w07Jv9F_11brynja_core13secret_memoryNtB5_17OwnedSecretRegionNtNtNtCskADBYZwJmSU_4core3ops4drop4Drop4drop'
        body = ('start:\n  %owner = alloca [16 x i8], align 8\n'
                '  store ptr %0, ptr %owner, align 8\n'
                '  %2 = getelementptr inbounds i8, ptr %owner, i64 8\n'
                '  store i64 %1, ptr %2, align 8\n')
        if panic == 'unwind':
            body += ('  invoke void %observer(ptr %owner)\n'
                     '    to label %normal unwind label %cleanup\nnormal:\n')
        else:
            body += '  call void %observer(ptr %owner)\n'
        body += f'  call void {destructor}(ptr %owner)\n  ret void\n'
        if panic == 'unwind':
            body += ('cleanup:\n  %3 = landingpad { ptr, i32 }\n  cleanup\n'
                     f'  call void {destructor}(ptr %owner)\n  resume {{ ptr, i32 }} %3\n')
        text = 'target triple = "x86_64-unknown-linux-gnu"\n'
        for name in owner.PROBES:
            text += f'define void @_RNvCsTest_24brynja_aes_owner_cleanup{len(name)}{name}(ptr %0, i64 %1, ptr %observer) {{\n{body}}}\n'
        return text

    def test_build_policy(self):
        owner.policy()

    def test_both_exit_models_and_all_negative_controls(self):
        for panic in ('abort', 'unwind'):
            llvm = self.fixture(panic)
            self.assertEqual(owner.check(llvm, panic), 7)
            self.assertEqual(owner.negative_controls(llvm, panic), 12)

    def test_wrong_panic_profile_or_missing_probe_fails(self):
        for text, panic in ((self.fixture('abort'), 'unwind'),
                            (self.fixture('unwind'), 'abort'),
                            (self.fixture('abort').replace('key_drop', 'unknown_key'), 'abort')):
            with self.assertRaises(ValueError):
                owner.check(text, panic)

    def test_every_named_owner_is_required(self):
        for probe in owner.PROBES:
            # Preserve other probes, including aliases with shared bodies.
            suffix = str(len(probe)) + probe
            text = self.fixture('abort').replace(suffix + '(', suffix + '_missing(')
            with self.subTest(probe=probe), self.assertRaises(ValueError):
                owner.check(text, 'abort')


class OperationCodegenTests(unittest.TestCase):
    CLEAR = '@_RNvNtCsTest_11brynja_core13secret_memory18clear_owned_region'
    OWNER_CLEAR = '@_RNvMs0_NtCsTest_11brynja_core13secret_memoryNtB5_17OwnedSecretRegion5clear'

    @classmethod
    def fixture(cls, panic):
        # Synthetic graphs test the checker, never counted as compiler evidence.
        symbols = {role: '_ZN13brynja_crypto3aes' + str(len(owner)) + owner +
                   str(len(method)) + method + '17h0123456789abcdefE'
                   for role, (owner, method) in operation.METHODS.items()}
        text = 'target triple = "x86_64-unknown-linux-gnu"\n'
        for role, symbol in symbols.items():
            args = ''
            body = 'start:\n'
            if role.endswith('-clear'):
                args = 'ptr %self.0, i64 %self.1'
                body += f'  tail call void {cls.OWNER_CLEAR}(ptr %self.0, i64 %self.1)\n'
            elif role in ('encrypt', 'decrypt', 'cached-encrypt', 'cached-decrypt'):
                target = 'cached-secret' if role.startswith('cached-') else 'secret'
                body += f'  call void @{symbols[target]}()\n'
            else:
                pointers = {f'%{name}' + (f'.i{n}' if count > 1 else ''): size
                            for name, (size, count) in operation.ROLES[role].items() for n in range(count)}
                if role in ('secret', 'cached-secret', 'cached-new'):
                    body += '  %destination = alloca [24 x i8], align 8\n'
                for pointer, size in pointers.items():
                    body += f'  {pointer} = alloca [{size} x i8], align 1\n'
                    body += f'  call void @llvm.lifetime.start.p0(ptr {pointer})\n'
                    body += f'  store i8 1, ptr {pointer}, align 1\n'
                if role in ('public', 'secret', 'cached-new'):
                    if role == 'cached-new' and panic == 'unwind':
                        body += f'  invoke void @{symbols["expand"]}()\n    to label %normal unwind label %cleanup\nnormal:\n'
                    else:
                        body += f'  call void @{symbols["expand"]}()\n'
                if role in ('public', 'secret', 'cached-public', 'cached-secret'):
                    if panic == 'unwind':
                        body += f'  invoke void @{symbols["rounds"]}()\n    to label %normal unwind label %cleanup\nnormal:\n'
                    else:
                        body += f'  call void @{symbols["rounds"]}()\n'
                clears = ''.join(f'  call i8 {cls.CLEAR}(ptr {pointer}, i64 {size})\n'
                                 f'  call void @llvm.lifetime.end.p0(ptr {pointer})\n'
                                 for pointer, size in pointers.items())
                body += clears
                if panic == 'unwind' and role in ('public', 'secret', 'cached-public', 'cached-secret', 'cached-new'):
                    body += '  ret void\ncleanup:\n  %ex = landingpad { ptr, i32 }\n  cleanup\n'
                    body += clears + '  resume { ptr, i32 } %ex\n'
            if not body.endswith(' %ex\n'):
                body += '  ret void\n'
            text += f'define void @{symbol}({args}) {{\n{body}}}\n'
        return text

    def test_both_graphs_and_all_mutants(self):
        for panic in ('abort', 'unwind'):
            selected = operation.check(self.fixture(panic), panic)
            self.assertEqual(len(selected), 14)
            self.assertEqual(operation.negative_controls(selected), 75)

    def test_wrong_target_profile_population_and_call_edges(self):
        good = self.fixture('abort')
        mutants = [good.replace('x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-gnu'),
                   good.replace('Aes128Key5clear', 'Aes128Key5other'),
                   good.replace('%previous.i3 = alloca [16 x i8]', '%missing = alloca [16 x i8]'),
                   good.replace('call void @_ZN13brynja_crypto3aes9Aes128Key9transform',
                                'call void @wrong_transform')]
        for mutant in mutants:
            with self.assertRaises(ValueError):
                operation.check(mutant, 'abort')
        with self.assertRaises(ValueError):
            operation.check(good, 'unwind')
        with self.assertRaises(ValueError):
            operation.check(good, 'unknown')

    def test_unwind_edge_cannot_bypass_clearing(self):
        good = self.fixture('unwind')
        mutant = good.replace('cleanup:\n', 'cleanup:\n  resume { ptr, i32 } undef\n')
        with self.assertRaises(ValueError):
            operation.check(mutant, 'unwind')

    def test_cached_operation_cannot_reexpand(self):
        good = self.fixture('abort')
        selected = operation.select(good)
        for role in ('cached-secret', 'cached-public'):
            body = selected[role][2]
            changed = body.replace('start:', 'start:\n  call void @' + selected['expand'][0] + '()')
            with self.assertRaisesRegex(ValueError, 're-expands'):
                operation.check(good.replace(body, changed), 'abort')

    def test_public_error_branch_cannot_return_with_live_scratch(self):
        body = operation.select(self.fixture('abort'))['public'][2]
        body = body.replace('  call i8 ' + self.CLEAR, '  br i1 %error, label %bad, label %good\nbad:\n  ret void\ngood:\n  call i8 ' + self.CLEAR, 1)
        with self.assertRaises(ValueError):
            operation.check_body(body, 'public')

    def test_multiple_shift_lifetimes_checked_independently(self):
        body = operation.select(self.fixture('abort'))['rounds'][2]
        for index in range(4):
            changed = body.replace(f'{self.CLEAR}(ptr %previous.i{index}, i64 16)',
                                   f'{self.CLEAR}(ptr %previous.i{index}, i64 15)')
            with self.assertRaises(ValueError):
                operation.check_body(changed, 'rounds')

    def test_repeated_lifetime_must_clear_every_iteration(self):
        body = ('start:\n  %word = alloca [4 x i8], align 1\n  br label %loop\nloop:\n'
                '  call void @llvm.lifetime.start.p0(ptr %word)\n'
                '  store i8 1, ptr %word, align 1\n'
                f'  call i8 {self.CLEAR}(ptr %word, i64 4)\n'
                '  call void @llvm.lifetime.end.p0(ptr %word)\n'
                '  br i1 %again, label %loop, label %done\ndone:\n  ret void\n')
        operation.check_body(body, 'expand')
        with self.assertRaises(ValueError):
            operation.check_body(body.replace(f'  call i8 {self.CLEAR}(ptr %word, i64 4)\n', ''), 'expand')

    def test_clear_rejects_abi_unknown_instruction_and_extra_calls(self):
        _, args, body = operation.select(self.fixture('abort'))['key-clear']
        for new_args, new_body in ((args.replace('i64', 'i32'), body),
                                   (args, body.replace('  ret void', '  fence seq_cst\n  ret void')),
                                   (args, body.replace('  ret void', '  call void @unexpected()\n  ret void'))):
            with self.assertRaises(ValueError):
                operation.check_clear(new_args, new_body)

    def test_vacuous_mutation_is_rejected(self):
        selected = operation.select(self.fixture('abort'))
        name, args, body = selected['public']
        selected['public'] = name, args, body.replace('clear_owned_region', 'other_owned_region')
        with self.assertRaises(ValueError):
            operation.negative_controls(selected)

    def test_driver_runs_only_four_scoped_configurations(self):
        with (patch.object(operation.sys, 'argv', ['check-aes-operation-cleanup.py']),
              patch.object(operation.verifier.cargo_environment, 'private_directory', return_value=nullcontext('/tmp')),
              patch.object(operation, 'collect') as collect, redirect_stdout(io.StringIO()) as output):
            operation.main()
        self.assertEqual([call.args[1:] for call in collect.call_args_list],
                         [(compiler, panic) for compiler in ('1.90.0', '1.99.1') for panic in ('abort', 'unwind')])
        self.assertIn(operation.MARKER, output.getvalue())

    def test_driver_failure_cannot_emit_completion(self):
        with (patch.object(operation.sys, 'argv', ['check-aes-operation-cleanup.py']),
              patch.object(operation.verifier.cargo_environment, 'private_directory', return_value=nullcontext('/tmp')),
              patch.object(operation, 'collect', side_effect=RuntimeError('compiler failed')),
              redirect_stdout(io.StringIO()) as output, self.assertRaises(RuntimeError)):
            operation.main()
        self.assertNotIn(operation.MARKER, output.getvalue())


if __name__ == '__main__':
    unittest.main()
