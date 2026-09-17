"""Carry-forward selection, proof provenance and real Git delta regressions."""
import json
import subprocess
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

import detached_catalog as catalog
import detached_manifest as records
import verification_carry_forward as carry
import verification_plan as plans


def plan(groups=(), blocked=False):
    return {'fingerprint': 'a' * 64, 'approval_required': blocked, 'head': 'b' * 40,
            'version': '0.24.48', 'stage': 'internal', 'base': 'v0.24.47',
            'groups': list(groups), 'issues': [],
            'verifiers': {kind: list(groups) for kind in ('asan', 'miri', 'kani')}}


def entry(command, phase='repository', stdin=None):
    import shlex
    return {'phase': phase, 'command': command, 'argv': shlex.split(command),
            'environment': {}, 'stdin': stdin}


class CarryForwardTests(unittest.TestCase):
    def context(self, entries, groups=(), blocked=False):
        return {'plan': plan(groups, blocked), 'manifest': {'commands': entries},
                'release_plan': plan(plans.scope.GROUPS), 'public_checkpoint': False}

    def test_baseline_always_runs_and_missing_or_changed_commands_never_reuse(self):
        sha2 = entry('python3 scripts/sha2/check-sha2-execution.py')
        baseline = entry('python3 scripts/release/test-detached-verification.py')
        context = self.context([sha2, baseline])
        self.assertTrue(carry.disposition(sha2, context).startswith('reuse:'))
        self.assertTrue(carry.disposition(baseline, context).startswith('run:'))
        for change in ({'stdin': 'crates/vector.txt'}, {'environment': {'RUSTFLAGS': '-C opt-level=0'}},
                       {'phase': 'asan'}, {'command': sha2['command'] + ' --policy-only'}):
            self.assertTrue(carry.disposition({**sha2, **change}, context).startswith('run:'))
        for groups, blocked in ((('sha2',), False), ((), True)):
            self.assertTrue(carry.disposition(sha2, self.context([sha2], groups, blocked)).startswith('run:'))
        context['public_checkpoint'] = True
        self.assertTrue(carry.disposition(sha2, context).startswith('run:'))
        with self.assertRaises(ValueError):
            carry.required(context, 'command', 'unknown_program')

    def test_family_verifiers_are_partitioned_without_losing_coverage(self):
        for phase, program, flag in (
            ('miri', 'scripts/zeroization/check-zeroization-miri.sh', '--selected'),
            ('kani', 'scripts/assurance/check-kani.sh', '--required-groups'),
        ):
            old = entry(f'{program} {flag} sha2 md5', phase)
            context = self.context([old], ['sha2'])
            for group, reuse in (('sha2', False), ('md5', True), ('sha3', False)):
                current = entry(f'{program} {flag} {group}', phase)
                self.assertEqual(carry.disposition(current, context).startswith('reuse:'), reuse)
            changed = entry(f'{program} {flag} md5', phase)
            changed['environment'] = {'MIRIFLAGS': 'different'}
            self.assertFalse(carry.covered(changed, [old]))
            self.assertFalse(carry.covered(entry(f'{program} {flag} md5', 'repository'), [old]))
        context = self.context([])
        for phase in ('miri', 'kani'):
            required = carry.required(context, phase)
            self.assertEqual(len(required), len(plans.scope.GROUPS))

    def test_matrix_and_emitted_code_reuse_but_changed_test_driver_reruns(self):
        for check in (entry('cargo +1.90.0 check --workspace', 'matrix'),
                      entry('python3 scripts/cryptography/check-secret-owner-compiler.py')):
            self.assertTrue(carry.disposition(check, self.context([check])).startswith('reuse:'))
            self.assertTrue(carry.disposition(check, self.context([check], ['sha2'])).startswith('run:'))
        check = entry('python3 scripts/sha2/check-sha2-execution.py')
        context = self.context([check])
        context['plan']['evidence'] = {'changed_paths': ['scripts/sha2/check-sha2-execution.py']}
        self.assertTrue(carry.disposition(check, context).startswith('run:'))

    def test_only_explanatory_text_is_excluded_from_execution_identity(self):
        original = plan(['sha2'])
        self.assertEqual(plans.execution_identity(original), plans.execution_identity(
            {**original, 'issues': ['different first fallback'], 'reasons': ['different wording']}))
        for key, value in (('fingerprint', 'c' * 64), ('groups', ['md5']), ('head', 'c' * 40),
                           ('verifiers', {}), ('approval_required', True), ('stage', 'public')):
            self.assertNotEqual(plans.execution_identity(original),
                                plans.execution_identity({**original, key: value}))

    def test_receipt_failure_dirty_snapshot_and_nonancestor_block_before_selection(self):
        root = plans.ROOT
        job = Path('/tmp/unused-carry-test')
        manifest = {'sources': {'head': 'b' * 40}, 'plan': plan()}
        with patch.object(carry.jobs, 'collect', side_effect=ValueError('corrupt log')), \
             patch.object(plans, 'build') as build:
            with self.assertRaises(ValueError):
                carry.prepare(job, 'receipt', root, plan())
            build.assert_not_called()
        with patch.object(carry.jobs, 'collect', return_value={'commands': 570}), \
             patch.object(carry.jobs, 'load', return_value=manifest), \
             patch.object(plans, 'changed_paths', return_value=[]), \
             patch.object(plans, 'build', return_value=plan()) as build:
            with patch.object(records, 'git', return_value=b' M crates/changed.rs'):
                with self.assertRaises(ValueError):
                    carry.prepare(job, 'receipt', root, plan())
                build.assert_not_called()
            with patch.object(records, 'git', side_effect=[b'', subprocess.CalledProcessError(1, 'git')]):
                with self.assertRaises(subprocess.CalledProcessError):
                    carry.prepare(job, 'receipt', root, plan())
                build.assert_not_called()
            with patch.object(records, 'git', return_value=b''):
                context = carry.prepare(job, 'receipt', root, plan())
                self.assertEqual(context['plan']['evidence']['source_commit'], 'b' * 40)
                self.assertTrue(build.call_args.kwargs['verified_base'])
                public = {**plan(), 'stage': 'public'}
                self.assertTrue(carry.prepare(job, 'receipt', root, public)['public_checkpoint'])
                manifest['plan'] = public
                self.assertFalse(carry.prepare(job, 'receipt', root, public)['public_checkpoint'])
                self.assertTrue(carry.prepare(job, 'receipt', root,
                    {**public, 'version': '0.25.2'})['public_checkpoint'])

    def test_real_git_delta_classifies_code_dependencies_docs_and_tooling(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            def git(*args):
                return subprocess.check_output(['git', '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid',
                                               '-c', 'commit.gpgsign=false', *args], cwd=root, stderr=subprocess.DEVNULL)
            git('init', '-q')
            originals = {}
            for path in ('Cargo.lock', 'rust-toolchain.toml', 'release-crates.toml', 'assurance/policy.toml'):
                originals[path] = (plans.ROOT / path).read_bytes()
            for path in ('crates/brynja-hash-sha2/src/lib.rs', 'crates/brynja-hash-sha3/src/lib.rs',
                         'crates/brynja-legacy-md5/src/lib.rs', 'crates/brynja-core/src/lib.rs',
                         'scripts/release/verification_plan.py', 'scripts/zeroization/miri_scope.py',
                         'scripts/zeroization/scope_inputs.py', 'scripts/sha2/driver.py', 'README.md'):
                originals[path] = b'baseline\n'
            review = 'scripts/sha3/keccak-batch-reviewed.json'
            originals[review] = json.dumps({'files': {'src': 'a' * 128}, 'version': '0.24.47'}).encode()
            for path, data in originals.items():
                (root / path).parent.mkdir(parents=True, exist_ok=True)
                (root / path).write_bytes(data)
            git('add', '.')
            git('commit', '-qm', 'baseline')
            base = git('rev-parse', 'HEAD').decode().strip()
            def check(path, value, expected, blocked=False):
                (root / path).parent.mkdir(parents=True, exist_ok=True)
                (root / path).write_bytes(value)
                try:
                    result = plans.build(root=root, base=base, verified_base=True)
                    self.assertEqual(result['approval_required'], blocked, result['issues'])
                    self.assertEqual(set(result['groups']), set(expected))
                finally:
                    if path in originals:
                        (root / path).write_bytes(originals[path])
                    else:
                        (root / path).unlink()
            for path in ('README.md', 'scripts/release/verification_plan.py',
                         'scripts/zeroization/miri_scope.py', 'scripts/zeroization/scope_inputs.py'):
                check(path, b'changed\n', ())
            check(review, originals[review].replace(b'a' * 128, b'b' * 128), ())
            check(review, originals[review].replace(b'"src"', b'"other"'),
                  ('sha3', 'kmac', 'tuplehash', 'parallelhash'))
            for path, groups in (
                ('crates/brynja-hash-sha2/src/lib.rs', ('sha2',)),
                ('crates/brynja-legacy-md5/src/lib.rs', ('md5', 'legacy')),
                ('scripts/sha2/driver.py', ('sha2',)),
                ('crates/brynja-hash-sha3/src/lib.rs', ('sha3', 'kmac', 'tuplehash', 'parallelhash')),
            ):
                check(path, b'changed\n', groups)
            check('crates/brynja-core/src/lib.rs', b'changed\n', plans.scope.closure({'core'}))
            check('assurance/unknown/src/lib.rs', b'new\n', plans.scope.GROUPS, True)
            # Deletions are changes too, not absent inputs to be silently reused.
            path = 'crates/brynja-hash-sha2/src/lib.rs'
            (root / path).unlink()
            self.assertEqual(plans.build(root=root, base=base, verified_base=True)['groups'], ['sha2'])
            (root / path).write_bytes(originals[path])
            check('Cargo.lock', originals['Cargo.lock'].replace(b'version = "2.1.0"', b'version = "9.9.9"'), ('sanitization',))
            # Dependency feature changes affect the crate and its consumers.
            check('crates/brynja-hash-sha3/Cargo.toml', b'[features]\ndefault=["new"]\n',
                  ('sha3', 'kmac', 'tuplehash', 'parallelhash'))
            check('rust-toolchain.toml', originals['rust-toolchain.toml'].replace(b'1.98.1', b'1.98.0'), plans.scope.GROUPS, True)
            (root / 'scripts/assurance').mkdir(parents=True)
            driver = root / 'scripts/assurance/check-kani.sh'
            driver.write_text('changed driver\n')
            result = plans.build(root=root, base=base, verified_base=True)
            self.assertEqual(result['verifiers']['kani'], list(plans.scope.GROUPS))
            self.assertEqual(result['verifiers']['miri'], [])
            driver.unlink()
            with patch.dict('os.environ', {'RUSTFLAGS': '-C opt-level=0'}):
                self.assertTrue(plans.build(root=root, base=base, verified_base=True)['approval_required'])
            # Public CLI baselines cannot claim arbitrary commits as tested.
            self.assertTrue(plans.build(root=root, base=base)['approval_required'])

    def test_review_hash_rebinding_is_not_a_policy_or_path_exemption(self):
        compare = plans.inputs.json_hash_binding_only
        before = json.dumps({'files': {'file': 'a' * 128}, 'required': True}).encode()
        self.assertTrue(compare(before, before.replace(b'a' * 128, b'b' * 128)))
        for after in (before.replace(b'"file"', b'"other"'), before.replace(b'true', b'false'),
                      before.replace(b'a' * 128, b'b' * 64), before.replace(b'a' * 128, b'not a hash')):
            self.assertFalse(compare(before, after))
        with self.assertRaises(ValueError):
            compare(before, b'{"files": {}, "files": {}}')

    def test_selection_mutants_fail_the_real_regressions(self):
        source = Path(carry.__file__).read_text()
        for before, after in (
            ("if context['public_checkpoint']:", "if False:"),
            ('if not groups:', 'if False:'),
            ('groups.intersection(affected)', 'False'),
            ("if not covered(entry, context['manifest']['commands']):", 'if False:'),
            ("if driver in changed or entry['stdin'] in changed:", 'if False:'),
        ):
            self.assertEqual(source.count(before), 1)
            mutant = types.ModuleType('carry_mutant')
            exec(compile(source.replace(before, after), carry.__file__, 'exec'), mutant.__dict__)
            result = unittest.TestResult()
            with patch.object(carry, 'disposition', mutant.disposition):
                for name in ('test_baseline_always_runs_and_missing_or_changed_commands_never_reuse',
                             'test_family_verifiers_are_partitioned_without_losing_coverage',
                             'test_matrix_and_emitted_code_reuse_but_changed_test_driver_reruns'):
                    CarryForwardTests(name).run(result)
            self.assertFalse(result.errors, result.errors)
            self.assertTrue(result.failures, 'unsafe reuse mutant escaped: ' + before)
