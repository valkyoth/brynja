#!/usr/bin/env python3
"""Push CI partition, successful ancestry and no-false-success regressions."""
import contextlib
import copy
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import push_ci as ci
import push_ci_baseline as baseline


ROOT = ci.plans.ROOT


class PushTests(unittest.TestCase):
    def test_exact_exhaustive_partition(self):
        inventory = ci.catalog()
        full = ci.commands.repository_commands()
        self.assertEqual(set(sum(inventory.values(), [])), set(full))
        self.assertIn('cargo test --workspace --all-features', inventory['baseline'])
        self.assertIn('cargo fmt --all --check', inventory['baseline'])
        for command in ('python3 scripts/parallelhash/check-parallelhash-execution-package.py',
                        'python3 scripts/kmac/check-kmac-execution-package.py',
                        'python3 scripts/hmac/check-hmac-hosted-cleanup.py',
                        'scripts/kmac/check-kmac-codegen.sh'):
            self.assertIn(command, inventory['qualification'])
        for command in ci.EXTRA:
            self.assertTrue((ROOT / command.split()[1]).is_file())
        for changed in (full + ['python3 scripts/release/unclassified.py'], full[1:]):
            with patch.object(ci.commands, 'repository_commands', return_value=changed):
                with self.assertRaisesRegex(ValueError, 'classify every'):
                    ci.catalog()
        original = ci.tomllib.loads((ROOT / 'scripts/ci/push-catalog.toml').read_text())
        for kind in ('baseline', 'affected', 'qualification'):
            doc = copy.deepcopy(original)
            doc[kind].append(doc['baseline'][0])
            with patch.object(ci.tomllib, 'loads', return_value=doc):
                with self.assertRaisesRegex(ValueError, 'classify every'):
                    ci.catalog()

    def test_no_baseline_means_all_bounded_not_all_release(self):
        with patch.object(baseline, 'find', return_value=(None, 'unavailable')):
            plan = ci.build()
        inventory = ci.catalog()
        self.assertEqual(set(plan['commands']), set(ci.EXTRA + tuple(inventory['baseline'] + inventory['affected'])))
        self.assertFalse(set(plan['qualification']) & set(plan['commands']))
        self.assertEqual(plan['unchanged'], [])
        self.assertEqual(len(plan['commands']), len(set(plan['commands'])))
        self.assertLess(plan['commands'].index('python3 scripts/assurance/check-assurance.py'),
                        plan['commands'].index('cargo fetch --locked'))

    def test_selection_and_dependency_closure(self):
        def plan(paths):
            with (patch.object(baseline, 'find', return_value=('a' * 40, 'success')),
                  patch.object(baseline, 'git', return_value='\0'.join(paths).encode())):
                return ci.build()
        # Full diff from the successful ancestor includes any intervening
        # failures; no HEAD^ optimization is permitted.
        with patch.object(baseline, 'find', return_value=('a' * 40, 'success')), \
             patch.object(baseline, 'git', return_value=b'crates/brynja-mac-hmac/src/engine.rs\0') as git:
            current = ci.build()
            self.assertEqual(git.call_args.args[1:], ('diff', '--name-only', '--no-renames', '-z', 'a' * 40, 'HEAD'))
        self.assertEqual(current['groups'], ['hmac'])
        self.assertIn('python3 scripts/hmac/test-hmac-package.py', current['commands'])
        self.assertNotIn('cargo test --locked --manifest-path assurance/md5-public-api/Cargo.toml', current['commands'])
        self.assertIn('hmac', plan(['crates/brynja-hash-sha2/src/sha256.rs'])['groups'])
        for paths in (['Cargo.lock'], ['assurance/new/Cargo.toml'], ['crates/unknown/src/lib.rs'],
                      ['scripts/release/new_helper.py'], ['../invalid']):
            self.assertEqual(plan(paths)['groups'], list(ci.plans.scope.GROUPS))
        for paths in ([], ['README.md']):
            self.assertEqual(plan(paths)['groups'], [])
            self.assertTrue(set(ci.catalog()['baseline']) <= set(plan(paths)['commands']))

    def test_baseline_must_be_entire_successful_main_push(self):
        good = dict(status='completed', conclusion='success', event='push', head_branch='main',
                    path='.github/workflows/ci.yml', head_repository=dict(full_name='owner/repo'),
                    head_sha='a' * 40)
        self.assertTrue(baseline.successful(good, 'owner/repo'))
        for key, values in dict(status=['queued', 'in_progress'],
                                conclusion=['failure', 'cancelled', 'skipped', 'timed_out', None],
                                event=['pull_request', 'workflow_dispatch'], head_branch=['other'],
                                path=['.github/workflows/other.yml'], head_repository=[{}, None],
                                head_sha=[None]).items():
            for value in values:
                self.assertFalse(baseline.successful(dict(good, **{key: value}), 'owner/repo'))
        self.assertFalse(baseline.successful(good, 'fork/repo'))

    def test_real_ancestor_and_contract_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def git(*args):
                return baseline.git(root, *args).decode().strip()
            git('init', '-q')
            git('config', 'user.name', 'CI test')
            git('config', 'user.email', 'ci@example.invalid')
            for name in baseline.CONTRACTS:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('contract\n')
            git('add', '.')
            git('commit', '-qm', 'successful baseline')
            good = git('rev-parse', 'HEAD')
            (root / 'source.rs').write_text('changed in failed push')
            git('add', '.')
            git('commit', '-qm', 'failed push')
            failed = git('rev-parse', 'HEAD')
            (root / 'README.md').write_text('subsequent docs push')
            git('add', '.')
            git('commit', '-qm', 'current')
            head = git('rev-parse', 'HEAD')
            self.assertTrue(baseline.compatible(root, good, head))
            self.assertFalse(baseline.compatible(root, head, head))
            self.assertFalse(baseline.compatible(root, head, good))
            self.assertFalse(baseline.compatible(root, '0' * 40, head))
            self.assertFalse(baseline.compatible(root, '--all', head))
            def row(sha, conclusion):
                return dict(id=1, status='completed', conclusion=conclusion, event='push', head_branch='main',
                            path='.github/workflows/ci.yml', head_repository=dict(full_name='owner/repo'), head_sha=sha)
            with patch.dict(os.environ, {'GITHUB_ACTIONS': 'true', 'GITHUB_REPOSITORY': 'owner/repo'}), \
                 patch.object(baseline, 'page', return_value=[row(failed, 'failure'), row(good, 'success')]):
                self.assertEqual(baseline.find(root)[0], good)
            self.assertIn('source.rs', git('diff', '--name-only', good, head))
            for name in baseline.CONTRACTS:
                path = root / name
                original = path.read_bytes()
                path.write_bytes(original + b'changed')
                self.assertFalse(baseline.compatible(root, good, head), name)
                path.write_bytes(original)

    def test_unavailable_api_and_local_never_invent_a_baseline(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(baseline, 'page') as page:
            self.assertIsNone(baseline.find(ROOT)[0])
            page.assert_not_called()
        for fault in (OSError('offline'), ValueError('malformed'), subprocess.TimeoutExpired('gh', 20)):
            with patch.dict(os.environ, {'GITHUB_ACTIONS': 'true', 'GITHUB_REPOSITORY': 'owner/repo'}), \
                 patch.object(baseline, 'git', side_effect=[b'a' * 40, b'']), \
                 patch.object(baseline, 'page', side_effect=fault):
                self.assertIsNone(baseline.find(ROOT)[0])

    def test_api_validation_pagination_and_dirty_checkout(self):
        for output in (b'{}', b'{"workflow_runs":{}}', b'{"workflow_runs":[null]}', b'not-json'):
            with patch.object(baseline.subprocess, 'check_output', return_value=output):
                with self.assertRaises((ValueError, KeyError)):
                    baseline.page('owner/repo', 1)
        with patch.object(baseline.subprocess, 'check_output', return_value=b'{"workflow_runs":[]}') as api:
            self.assertEqual(baseline.page('owner/repo', 2), [])
            self.assertIn('status=success', api.call_args.args[0][2])
            self.assertIn('page=2', api.call_args.args[0][2])
            self.assertEqual(api.call_args.kwargs['timeout'], 20)
        with patch.dict(os.environ, {'GITHUB_ACTIONS': 'true', 'GITHUB_REPOSITORY': 'owner/repo'}):
            with patch.object(baseline, 'git', side_effect=[b'a' * 40, b' M source.rs']), \
                 patch.object(baseline, 'page') as api:
                self.assertIsNone(baseline.find(ROOT)[0])
                api.assert_not_called()
            with patch.object(baseline, 'git', side_effect=[b'a' * 40, b'']), \
                 patch.object(baseline, 'page', return_value=[{}] * 100) as api:
                self.assertIsNone(baseline.find(ROOT)[0])
                self.assertEqual(api.call_count, 3)

    @unittest.skipUnless(sys.platform == 'linux', 'Linux pre-push process-group integration')
    def test_real_child_failure_and_timeout_remain_failures(self):
        import shlex
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(subprocess.CalledProcessError) as failed:
                ci.execute(shlex.join([sys.executable, '-c', 'raise SystemExit(23)']))
            self.assertEqual(failed.exception.returncode, 23)
            with patch.object(ci, 'TIMEOUT', 0.2), self.assertRaises(subprocess.TimeoutExpired):
                ci.execute(shlex.join([sys.executable, '-c', 'import time; time.sleep(5)']))

    def test_failure_timeout_and_token_separation(self):
        with patch.object(ci.subprocess, 'Popen') as popen, \
             patch.dict(os.environ, {'GH_TOKEN': 'not-for-tests', 'GITHUB_TOKEN': 'not-for-tests'}), \
             contextlib.redirect_stdout(io.StringIO()):
            process = popen.return_value.__enter__.return_value
            process.wait.return_value = 7
            with self.assertRaises(subprocess.CalledProcessError):
                ci.execute('cargo test')
            self.assertNotIn('GH_TOKEN', popen.call_args.kwargs['env'])
            self.assertNotIn('GITHUB_TOKEN', popen.call_args.kwargs['env'])
            self.assertTrue(popen.call_args.kwargs['start_new_session'])
            process.wait.side_effect = [subprocess.TimeoutExpired('cargo', 300), -9]
            with patch.object(ci.os, 'killpg') as kill, self.assertRaises(subprocess.TimeoutExpired):
                ci.execute('cargo test')
            kill.assert_called_once_with(process.pid, ci.signal.SIGKILL)
        with patch.object(ci, 'build', return_value=dict(base=None, reason='test', groups=[],
                         commands=['first', 'second'], unchanged=[], qualification=['deep'])), \
             patch.object(ci, 'execute', side_effect=ValueError('failed')) as execute, \
             contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(ci.run(check=True), 0)
            execute.assert_not_called()
            with self.assertRaises(ValueError):
                ci.run()
            self.assertEqual(execute.call_count, 1)
            self.assertNotIn('diagnostics: PASS', output.getvalue())

    def test_workflow_retains_independent_checks_and_qualification(self):
        workflow = (ROOT / '.github/workflows/ci.yml').read_text()
        audit = workflow.split('\n  audit:\n')[1].split('\n  hardened-sha1:')[0]
        self.assertNotIn('needs:', audit)
        self.assertNotIn('continue-on-error', audit)
        for command in ('cargo deny check', 'cargo audit --deny warnings', 'generate-sbom.sh --check',
                        'check-github-release-controls.py --public'):
            self.assertIn(command, audit)
        self.assertIn('cargo test --workspace --all-features', workflow)
        for family in ('sha256', 'sha2', 'sha3'):
            self.assertIn(f'cargo run --locked --manifest-path assurance/{family}-public-api/Cargo.toml', workflow)
            self.assertIn(f'python3 scripts/sha2/check-{family}-public-api.py' if family != 'sha3'
                          else 'python3 scripts/sha3/check-sha3-public-api.py', ci.catalog()['qualification'])
        self.assertIn('--stage tests', workflow)
        full = (ROOT / 'scripts/cryptography/check-macos-resident-ci.py').read_text()
        self.assertIn("'all'", full)
        self.assertIn("'codegen'", full)
        self.assertIn("'packages'", full)


def main():
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(PushTests)
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    if not result.wasSuccessful():
        raise AssertionError('push CI regressions failed')


if __name__ == '__main__':
    main()
