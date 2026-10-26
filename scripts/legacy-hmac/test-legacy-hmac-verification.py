#!/usr/bin/env python3
"""Legacy-family selection and fail-closed verifier regression tests; no campaign."""
from contextlib import nullcontext, redirect_stdout
import importlib.util
import io
import os
import re
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import legacy_hmac_verifiers as verifier

ROOT = verifier.ROOT
sys.path.append(str(ROOT / 'scripts/release'))
import verification_commands as commands
import detached_catalog as catalog
import detached_manifest as records
import verification_carry_forward as carry
import miri_tasks
import scope_inputs
import push_ci


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


asan = load('check-legacy-hmac-asan')
kani = load('check-legacy-hmac-kani')


class ScopeTests(unittest.TestCase):
    def test_own_changes_never_select_upstream_or_modern_hmac(self):
        for path in ('crates/brynja-legacy-hmac/src/engine.rs',
                     'crates/brynja-legacy-hmac-std/src/strict_execution/mod.rs',
                     'scripts/legacy-hmac/check-legacy-hmac-hosted-cleanup.py',
                     'scripts/cryptography/legacy_hmac_owner_contract.py',
                     'scripts/cryptography/legacy_hmac_owner_tests.py',
                     'security/legacy-hmac/record.json',
                     'assurance/legacy-hmac-policy/src/lib.rs'):
            self.assertEqual(commands.scope.select([path]), (False, ('legacy_hmac',)))
        for source in ('md5', 'sha1', 'static_cpu', 'core'):
            self.assertIn('legacy_hmac', commands.scope.closure({source}))
        self.assertNotIn('legacy_hmac', commands.scope.closure({'hmac'}))
        self.assertNotIn('legacy_hmac', commands.scope.closure({'sha2'}))
        self.assertEqual(commands.scope.select(['scripts/hmac/hmac_verifiers.py']),
                         (False, ('hmac', 'legacy_hmac')))
        self.assertTrue(commands.scope.select(['crates/unknown/src/worker.rs'])[0])

    def test_fixture_locks_are_bound_to_real_workspace_dependencies(self):
        workspace = (ROOT / 'Cargo.lock').read_bytes()
        for fixture in ('cleanup', 'engine-cleanup', 'execution-cleanup', 'md5-cleanup',
                        'hosted-cleanup', 'timing', 'policy'):
            directory = ROOT / ('assurance/legacy-hmac-' + fixture)
            manifest = (directory / 'Cargo.toml').read_bytes()
            lock = (directory / 'Cargo.lock').read_bytes()
            scope_inputs.fixture_lock(lock, workspace, manifest)
            self.assertEqual(commands.scope.select([str(directory.relative_to(ROOT) / 'Cargo.lock')]),
                             (False, ('legacy_hmac',)))
            for mutant in (lock.replace(b'name = "brynja-core"', b'name = "unreviewed-core"'),
                           lock.replace(b'version = "0.9.0"', b'version = "99.0.0"'),
                           b'version=4\npackage="invalid"\n'):
                self.assertNotEqual(mutant, lock)
                with self.assertRaises((ValueError, TypeError)):
                    scope_inputs.fixture_lock(mutant, workspace, manifest)

    def test_miri_tasks_preserve_bounded_cases_and_are_additive(self):
        tasks = miri_tasks.inventory(ROOT, 'legacy_hmac')
        self.assertEqual(len(tasks), 11)
        bounded = [argv for argv in tasks if '--test' in argv]
        self.assertEqual({argv[-3] for argv in bounded},
                         {'md5_short', 'sha1_short', 'md5_long', 'sha1_long', 'output_unwind'})
        self.assertTrue(all(argv[-2:] == ['--', '--exact'] for argv in bounded))
        self.assertFalse(any('contracts' in argv or 'rfc2202' in argv for argv in tasks))
        self.assertEqual([argv[-1] for argv in tasks if '--lib' in argv], [
            'execution::retained::tests', 'metadata_and_preselected_tag_policy',
            'batch_metadata_and_public_admission', 'only_pre_entry_thread_errors_are_reusable',
            'missing_native', 'unsupported_target_or_model_never_falls_back'])
        for profile in ('routine', 'extended', 'existing-full'):
            self.assertEqual(len(miri_tasks.task_inventory(ROOT, 'legacy_hmac', profile)), 11)
        runner = (ROOT / 'scripts/zeroization/check-zeroization-miri.sh').read_bytes()
        start, end = runner.index(b'quick_legacy_hmac()'), runner.index(b'all_groups=')
        old = (runner[:start] + runner[end:]).replace(b'hmac legacy_hmac)', b'hmac)')
        self.assertEqual(scope_inputs.runner_groups(old, runner), {'legacy_hmac'})
        with self.assertRaises(ValueError):
            scope_inputs.runner_groups(runner, old)

    def test_catalog_ownership_and_push_partition(self):
        inventory = push_ci.catalog()
        full = commands.repository_commands()
        cheap = 'python3 scripts/legacy-hmac/test-legacy-hmac-verification.py'
        self.assertIn(cheap, inventory['affected'])
        expected = {str(path.relative_to(ROOT)) for path in (ROOT / 'scripts/legacy-hmac').glob('test-*.py')}
        for path in expected:
            command = 'python3 ' + path
            self.assertEqual(full.count(command), 1)
            self.assertEqual(commands.owners(command), {'legacy_hmac'})
            self.assertNotIn(command, commands.selected(full, ['hmac']))
            if command != cheap:
                self.assertIn(command, inventory['qualification'])
        for driver in ('cleanup', 'engine-cleanup', 'execution-cleanup', 'md5-cleanup', 'hosted-cleanup'):
            for suffix in ('', ' --target aarch64-unknown-linux-gnu --toolchain 1.99.1',
                           ' --target aarch64-apple-darwin --toolchain 1.99.1'):
                command = 'python3 scripts/legacy-hmac/check-legacy-hmac-' + driver + '.py' + suffix
                self.assertIn(command, inventory['qualification'])
                if driver in ('md5-cleanup', 'hosted-cleanup'):
                    self.assertIn(command + (' --simd' if driver == 'md5-cleanup' else ' --generic'),
                                  inventory['qualification'])
        sanitizer = commands.catalog(ROOT / 'scripts/zeroization/check-zeroization-sanitizer.sh')
        self.assertEqual(commands.selected(sanitizer, ['legacy_hmac']),
                         ['python3 scripts/legacy-hmac/check-legacy-hmac-asan.py'])
        matrix = [command for command, _ in commands.matrix_commands()]
        selected = [command for command in commands.selected(matrix, ['legacy_hmac'])
                    if commands.owners(command)]
        self.assertTrue(selected)
        self.assertTrue(all('-p brynja-legacy-hmac ' in c or '-p brynja-legacy-hmac-std ' in c for c in selected))

    def test_receipts_and_partitioning_cannot_substitute_existing_families(self):
        own = 'python3 scripts/legacy-hmac/check-legacy-hmac-kani.py'
        self.assertEqual(commands.kani_commands(['legacy_hmac']), [own])
        self.assertEqual(commands.kani_commands(['sha1', 'hmac', 'legacy_hmac']), [
            'scripts/assurance/check-kani.sh --required-groups sha1',
            'python3 scripts/hmac/check-hmac-kani.py', own])
        self.assertEqual(set(records.verifier_commands(ROOT, [{'argv': own.split()}])), {'verifier:kani'})
        self.assertEqual(records.verifier_commands(ROOT, [{'argv': own.split() + ['--policy-only']}]), {})
        entry = {'phase': 'kani', 'command': own, 'argv': own.split(), 'stdin': None, 'environment': {}}
        for previous in ('python3 scripts/hmac/check-hmac-kani.py',
                         'scripts/assurance/check-kani.sh --required-groups sha1 md5'):
            self.assertFalse(carry.covered(entry, [{**entry, 'command': previous, 'argv': previous.split()}]))
        self.assertTrue(carry.covered(entry, [entry]))
        plan = {'groups': ['legacy_hmac'],
                'verifiers': {phase: ['legacy_hmac'] for phase in ('miri', 'kani', 'asan')}}
        with patch.object(catalog.plans, 'authorize'), patch.object(catalog.plans, 'requires_full', return_value=False):
            for partitions in (1, 2, 8):
                rows = catalog.selected(plan, ['miri', 'kani', 'asan'], None, partitions,
                                        miri_tasks=True, miri_profile='routine')
                self.assertEqual(len(rows), 13)
                self.assertEqual([row['command'] for row in rows if row['phase'] == 'kani'], [own])


class VerifierTests(unittest.TestCase):
    def test_failures_are_fatal_even_when_output_contains_success(self):
        for code in (1, 23, -6):
            result = subprocess.CompletedProcess([], code, 'test result: ok. 5 passed; 0 failed; 0 ignored;', '')
            with patch.object(verifier.cargo_environment, 'check'), \
                    patch.object(verifier._shared.subprocess, 'run', return_value=result), self.assertRaises(RuntimeError):
                verifier.run(['cargo'], {})

    def test_asan_enforces_leaks_and_every_population(self):
        populations = {'bounded': 5, 'rfc2202': 2, 'contracts': 6, 'execution::retained::tests': 3,
                       'metadata_and_preselected_tag_policy': 2, 'batch_metadata_and_public_admission': 2,
                       'only_pre_entry_thread_errors_are_reusable': 2, 'missing_native': 4}
        hostile = {'ASAN_OPTIONS': 'detect_leaks=0', 'LSAN_OPTIONS': 'exitcode=0',
                   'RUSTFLAGS': '-Ctarget-cpu=native', 'CARGO_BUILD_BUILD_DIR': '/bad/cache'}
        for missing in (None, *populations, 'ignored', 'failed', 'stale_contract_count', 'extra'):
            calls = []
            def run(argv, env):
                self.assertEqual(env['ASAN_OPTIONS'], 'detect_leaks=1:halt_on_error=1:exitcode=1')
                self.assertEqual(env['LSAN_OPTIONS'], 'exitcode=23')
                self.assertEqual(env['RUSTFLAGS'], '-Zsanitizer=address -C target-cpu=generic')
                self.assertNotIn('CARGO_BUILD_BUILD_DIR', env)
                name = argv[argv.index('--test') + 1] if '--test' in argv else argv[-1]
                calls.append(name)
                if missing == 'ignored':
                    return f'test result: ok. {populations[name]} passed; 0 failed; 1 ignored;'
                if missing == 'failed':
                    return f'test result: ok. {populations[name]} passed; 1 failed; 0 ignored;'
                count = populations[name] if missing != name else 0
                if missing == 'stale_contract_count' and name == 'contracts':
                    count = 5
                if missing == 'extra':
                    count += 1
                return f'test result: ok. {count} passed; 0 failed; 0 ignored;'
            with patch.dict(os.environ, hostile), patch.object(asan.sys, 'platform', 'linux'), \
                    patch.object(asan.platform, 'machine', return_value='x86_64'), \
                    patch.object(verifier.cargo_environment, 'private_directory', return_value=nullcontext(ROOT / 'target/test-legacy-env')), \
                    patch.object(verifier.cargo_environment, 'check'), patch.object(verifier, 'run', side_effect=run), \
                    redirect_stdout(io.StringIO()):
                if missing is None:
                    asan.main()
                    self.assertEqual(calls, list(populations))
                else:
                    with self.assertRaisesRegex(ValueError, 'population'):
                        asan.main()

    def test_asan_integration_counts_match_compiler_discovery(self):
        # List, do not execute, the real binaries: no handwritten copy of the
        # expected count can conceal an added/removed test from push diagnostics.
        with verifier.cargo_environment.private_directory(ROOT) as temporary:
            env = verifier.environment(Path(temporary))
            for args, count in asan.cases():
                if '--test' not in args:
                    continue
                output = verifier.run(['cargo', 'test', '--locked', '--offline',
                                       *args, '--', '--list'], env)
                names = re.findall(r'^([^\s:][^\n]*): test$', output, re.M)
                with self.subTest(args=args):
                    self.assertEqual(len(names), len(set(names)))
                    self.assertEqual(len(names), count)
                    if args[-1] == 'contracts':
                        self.assertIn('mismatch_is_error_for_is_ok_and_question_mark', names)

    def test_md5_compiled_mutation_anchors_match_current_source(self):
        mutations = load('test-legacy-hmac-md5-cleanup')
        source = (ROOT / 'crates/brynja-legacy-hmac/src/md5_batch/engine.rs').read_text()
        with patch.object(mutations.driver, 'emit', side_effect=AssertionError('no compilation here')):
            rows = mutations.teardown_mutations(source)
            self.assertEqual(len(rows), 8)
            quarantine = [after for _before, after, kind in rows if kind == 'quarantine']
            self.assertTrue(any('| Error::ExecutionFailed)' in after for after in quarantine))
            self.assertTrue(any('| Error::TagLength)' in after for after in quarantine))
            for before, after, kind in rows:
                self.assertNotEqual(source.replace(before, after, 1), source)
                for replacement in ('', before + before):
                    with self.subTest(before=before, replacement=replacement), self.assertRaises(ValueError):
                        mutations.teardown_mutations(source.replace(before, replacement, 1))

    def test_stream_compiled_mutations_match_current_workers_and_shared_tail(self):
        mutations = load('legacy_hmac_hosted_stream_compiled_tests')
        root = ROOT / 'crates/brynja-legacy-hmac-std/src'
        common = (root / 'common.rs').read_text()
        with patch.object(mutations, 'prepare', side_effect=AssertionError('no compiled fixture here')):
            shared = mutations.tail_mutations(common)
            self.assertEqual(len(shared), 2)
            self.assertEqual(len(set(shared)), 2)
            self.assertTrue(all(item != common for item in shared))
            count = 2 * len(shared)
            for directory in ('strict_execution', 'macos_resident'):
                for file in ('worker.rs', 'sha1_compiled/worker.rs'):
                    original = (root / directory / file).read_text()
                    variants = mutations.worker_mutations(original, file == 'worker.rs')
                    self.assertEqual(len(variants), 12 if file == 'worker.rs' else 5)
                    self.assertEqual(len(set(variants)), len(variants))
                    self.assertTrue(all(item != original for item in variants))
                    self.assertTrue(all(mutations.TAIL_CALL in item for item in variants))
                    count += len(variants)
            self.assertEqual(count, 38)

    def test_stream_mutations_reject_stale_or_ambiguous_anchors(self):
        mutations = load('legacy_hmac_hosted_stream_compiled_tests')
        root = ROOT / 'crates/brynja-legacy-hmac-std/src'
        common = (root / 'common.rs').read_text()
        for anchor in ('$request.tail.valid_bits == 8', '                $request.tail.valid_bits\n'):
            for replacement in ('', anchor + anchor):
                with self.subTest(anchor=anchor), self.assertRaises(ValueError):
                    mutations.tail_mutations(common.replace(anchor, replacement, 1))
        for directory in ('strict_execution', 'macos_resident'):
            for file in ('worker.rs', 'sha1_compiled/worker.rs'):
                source = (root / directory / file).read_text()
                for anchor in (mutations.TAIL_CALL, 'chunk.chunks(4096)',
                               '.chain(core::iter::once(complete))', 'state.update(part).map_err(Error::Mac)?;',
                               '        let secret = state', '.finalize_bits_secret(tail, staging)'):
                    for replacement in ('', anchor + anchor):
                        with self.subTest(directory=directory, file=file, anchor=anchor), self.assertRaises(ValueError):
                            mutations.worker_mutations(source.replace(anchor, replacement, 1), file == 'worker.rs')
                if file == 'worker.rs':
                    for replacement in ('', 'checkpoint(cancel)?;checkpoint(cancel)?;'):
                        with self.assertRaises(ValueError):
                            mutations.worker_mutations(source.replace('checkpoint(cancel)?;', replacement, 1), True)
        with self.assertRaises(ValueError):
            mutations.replace_once('anchor', 'anchor', 'anchor')

    def test_kani_checks_identity_and_each_real_harness(self):
        pin = verifier.tool('kani')
        banner = f'Kani Rust Verifier {pin["version"]} (cargo plugin)\nCBMC 6.11.0'
        success = 'Complete - 1 successfully verified harnesses, 0 failures, 1 total.'
        for outputs, error in ((['wrong'], 'identity'), ([banner, '{}', 'no proof'], 'population'),
                               ([banner, '{}', success, 'no proof'], 'population'),
                               ([banner, '{}', success, success], None)):
            with patch.object(sys, 'argv', ['check-legacy-hmac-kani.py']), \
                    patch.object(verifier.cargo_environment, 'private_directory', return_value=nullcontext(ROOT / 'target/test-legacy-env')), \
                    patch.object(verifier.cargo_environment, 'check'), patch.object(verifier, 'run', side_effect=outputs) as run, \
                    redirect_stdout(io.StringIO()):
                if error:
                    with self.assertRaisesRegex(ValueError, error):
                        kani.main()
                else:
                    kani.main()
                    self.assertEqual([call.args[0][-1] for call in run.call_args_list[2:]], list(kani.HARNESS_NAMES))

    def test_proof_fixture_rejects_dependency_and_population_drift(self):
        paths = ['assurance/legacy-hmac-policy/' + part for part in ('Cargo.toml', 'Cargo.lock', 'src/lib.rs')]
        paths += ['crates/' + name + '/Cargo.toml' for name in
                  ('brynja-core', 'brynja-hash-core', 'brynja-legacy-md5', 'brynja-legacy-sha1', 'brynja-legacy-hmac')]
        originals = {name: (ROOT / name).read_bytes() for name in paths}
        mutations = [(paths[0], b'default-features = false', b'default-features = true'),
                     (paths[1], b'version = "0.1.0"', b'version = "99.0.0"'),
                     (paths[1], b'name = "brynja-core"', b'name = "substitute"'),
                     (paths[2], b'#[kani::proof]', b''),
                     (paths[2], b'Hmac::<Md5>::with_tag_length(', b'copied_policy('),
                     (paths[2], b'kani::assume(!(10..=16).contains(&width));', b'kani::assume(false);')]
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            for name, data in originals.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            kani.policy(root)
            for name, before, after in mutations:
                self.assertIn(before, originals[name])
                (root / name).write_bytes(originals[name].replace(before, after, 1))
                with self.assertRaises(ValueError):
                    kani.policy(root)
                (root / name).write_bytes(originals[name])


if __name__ == '__main__':
    unittest.main()
