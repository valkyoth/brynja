#!/usr/bin/env python3
"""Release redesign regressions: fake commands and records, no crypto campaigns."""
import copy
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import tomllib
import unittest
from unittest.mock import patch

import release_crates as publisher
import scoped_release as scoped


class ScopedRelease(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='brynja-scoped-release-')
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.write('release-crates.toml', '[release]\nversion="0.25.3"\n')
        self.write('security/pentest/v0.25.3.md',
                   'Version: v0.25.3\nStatus: PASS\nRetest: PASS\nOpen-Findings: 0\n'
                   'Date: 2026-10-31\nTester: Fixture\nScope: tooling delta only\n')
        self.write(scoped.PLAN, 'schema=1\nversion="0.25.3"\nscope="fixture"\n'
                   '[[checks]]\nid="first"\ncommand=["fixture-first"]\ntimeout_seconds=1\n'
                   '[[checks]]\nid="second"\ncommand=["fixture-second"]\ntimeout_seconds=1\n')
        self.git('init', '-q')
        self.git('config', 'user.name', 'Fixture')
        self.git('config', 'user.email', 'fixture@example.invalid')
        self.git('config', 'commit.gpgsign', 'false')
        self.git('add', '.')
        self.git('commit', '-qm', 'fixture')
        self.head = 'a' * 40
        self.runs = [dict(id=10, workflow_id=1, head_sha=self.head, head_branch='main',
                         event='push', path='.github/workflows/ci.yml', status='completed',
                         conclusion='success')]
        self.checks = [dict(id=i, name=f'Analyze ({language})', head_sha=self.head,
                           app=dict(id=1, slug='github-actions'), status='completed', conclusion='success')
                       for i, language in enumerate(('python', 'c-cpp', 'rust', 'actions'))]

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def git(self, *args):
        subprocess.run(['git', *args], cwd=self.root, check=True, capture_output=True)

    def test_version_boundary_preserves_historical_flow(self):
        self.assertFalse(scoped.enabled('v0.25.2'))
        for version in ('v0.25.3', '0.26.0', '1.0.0-rc.1'):
            self.assertTrue(scoped.enabled(version))
        with self.assertRaises(ValueError):
            scoped.enabled('garbage')

    def test_aes_candidate_gate_is_finite_and_does_not_publish(self):
        plan = scoped.load('0.27.1')
        commands = {check['id']: check['command'] for check in plan['checks']}
        self.assertEqual(len(commands), 30)
        self.assertEqual(commands['release-plan'], ['scripts/release/test-release-plan.sh'])
        self.assertEqual(commands['crypto-tests'],
            ['cargo', 'test', '--locked', '-p', 'brynja-crypto', '-p',
             'brynja-legacy-hkdf', '--no-default-features', '--features', 'brynja-crypto/hazmat-aes-block,brynja-crypto/external-key-provider'])
        self.assertEqual(commands['aes-provider-api'],
                         ['python3', 'scripts/aes/check-aes-provider-api.py', '1.99.1'])
        self.assertEqual(commands['facade-integration'],
            ['cargo', 'check', '--locked', '-p', 'brynja', '--no-default-features'])
        self.assertEqual(set(plan['ci_checks']), set(commands) -
                         {'sbom', 'dependency-policy', 'advisories',
                          'hkdf-package-runner-tests', 'hkdf-packaged-endpoints',
                          'aes-downstream-endpoints', 'aes-consumer-format',
                          'aes-consumer-lint-direct', 'aes-consumer-lint-facade'})
        self.assertEqual(commands['aes-owner-contract'],
                         ['python3', 'scripts/cryptography/test-aes-owner-contract.py'])
        self.assertEqual(commands['aes-wide-owner-contract'],
                         ['python3', 'scripts/cryptography/test-aes-wide-owner-contract.py'])
        self.assertEqual(commands['aes-wide-api'],
                         ['python3', 'scripts/aes/check-aes-wide-api.py', '1.99.1'])
        self.assertEqual(commands['aes-dataflow-regressions'],
                         ['python3', 'scripts/aes/test-aes-dataflow.py'])
        self.assertEqual(commands['aes-downstream-endpoints'],
                         ['python3', 'scripts/aes/check-aes-consumer.py'])
        consumer_manifest = 'assurance/aes-public-api/Cargo.toml'
        expected_consumer_checks = {
            'aes-consumer-format': ['cargo', '+1.99.1', 'fmt', '--manifest-path',
                                    consumer_manifest, '--check'],
        }
        for route in ('direct', 'facade'):
            expected_consumer_checks['aes-consumer-lint-' + route] = [
                'cargo', '+1.99.1', 'clippy', '--locked', '--offline',
                '--manifest-path', consumer_manifest, '--no-default-features',
                '--features', route, '--all-targets', '--no-deps', '--', '-D', 'warnings']
        workflow = (scoped.ROOT / '.github/workflows/ci.yml').read_text()
        for name, command in expected_consumer_checks.items():
            self.assertEqual(commands[name], command)
            self.assertIn(' '.join(command), workflow)
        self.assertEqual(commands['hkdf-package-runner-tests'],
                         ['python3', 'scripts/hkdf/test-hkdf-public-api.py'])
        self.assertEqual(commands['hkdf-packaged-endpoints'],
                         ['python3', 'scripts/hkdf/check-hkdf-public-api.py', '--family', 'all'])
        for command in commands.values():
            self.assertNotIn('--workspace', command)
            self.assertNotIn('--all', command)
            self.assertNotIn('publish', command)
            self.assertNotIn('miri', command)
            self.assertNotIn('kani', command)
            self.assertNotIn('--matrix', command)
            self.assertFalse(any('run-verification' in arg or 'brynja-verify' in arg
                                 or 'check-hkdf-timing.py' in arg
                                 or 'check-aes-timing.py' in arg
                                 or 'check-aes-wide-timing.py' in arg
                                 or 'check-aes-kani.py' in arg
                                 or 'check-aes-dataflow.py' in arg for arg in command))
        release = tomllib.loads((scoped.ROOT / 'release-crates.toml').read_text())
        self.assertEqual(release['release']['version'], '0.27.1')
        self.assertEqual(release['release']['stage'], 'internal')
        self.assertTrue(release['release']['exceptional'])
        self.assertIn('pentest', release['release']['exception_reason'])
        self.assertFalse(any(row['publish'] for row in release['crates'].values()))
        self.assertIn('brynja-legacy-hkdf', release['crates'])
        order = publisher.PUBLISH_ORDER
        self.assertLess(order.index('brynja-legacy-hmac'), order.index('brynja-legacy-hkdf'))

    def test_aes_ci_endpoints_fetch_before_offline_consumers(self):
        workflow = (scoped.ROOT / '.github/workflows/ci.yml').read_text()
        job = workflow.split('\n  aes-public-api:\n', 1)[1].split('\n  hkdf-public-api:', 1)[0]

        def validate(text):
            fetch = '        run: cargo +1.99.1 fetch --locked\n'
            consumer = '        run: python3 scripts/aes/check-aes-consumer.py\n'
            self.assertEqual(text.count(fetch), 1)
            self.assertEqual(text.count(consumer), 1)
            self.assertLess(text.index(fetch), text.index('cargo +1.99.1 clippy'))
            self.assertLess(text.index(fetch), text.index(consumer))
            self.assertIn('rustup toolchain install 1.90.0 --profile minimal --target thumbv7em-none-eabi', text)
            self.assertIn('rustup toolchain install 1.99.1 --profile minimal --component rustfmt,clippy --target thumbv7em-none-eabi', text)
            self.assertIn('run: python3 scripts/aes/test-aes-consumer.py', text)
            for route in ('direct', 'facade'):
                self.assertIn(f'--no-default-features --features {route} --all-targets --no-deps -- -D warnings', text)
            for token in ('--matrix', 'check-aes-timing.py', 'check-aes-kani.py',
                          'check-aes-dataflow.py', 'brynja-verify', 'continue-on-error'):
                self.assertNotIn(token, text)

        validate(job)
        for before, after in [('fetch --locked', 'fetch --locked --offline'),
                              ('check-aes-consumer.py\n', 'check-aes-consumer.py --matrix\n'),
                              ('--features facade', '--features direct'),
                              ('--target thumbv7em-none-eabi', '')]:
            with self.subTest(before=before), self.assertRaises(AssertionError):
                validate(job.replace(before, after))

    def test_invalid_tag_gate_argument_does_not_enter_historical_campaign(self):
        out = subprocess.run(['bash', 'scripts/tag_gate.sh', 'garbage'], cwd=scoped.ROOT,
                             text=True, capture_output=True)
        self.assertEqual(out.returncode, 2)
        self.assertIn('no verification started', out.stderr)
        self.assertNotIn('RUN', out.stdout)

    def test_selector_errors_stop_without_falling_back_to_historical_work(self):
        self.write('bin/python3', '#!/bin/sh\nprintf "%s\\n" "$*" >> "$TRACE"\nexit 9\n')
        (self.root / 'bin/python3').chmod(0o755)
        env = dict(os.environ, PATH=str(self.root / 'bin') + os.pathsep + os.environ['PATH'],
                   TRACE=str(self.root / 'trace'))
        for name, args in (('scripts/checks.sh', []), ('scripts/tag_gate.sh', ['v0.25.3']),
                           ('scripts/release/validate-release-readiness.sh', ['v0.25.3'])):
            self.write('trace', '')
            result = subprocess.run(['bash', str(scoped.ROOT / name), *args], cwd=self.root,
                                    env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 9, name)
            self.assertEqual(len((self.root / 'trace').read_text().splitlines()), 1, name)

    def test_gate_list_and_unknown_selection_execute_nothing(self):
        with patch.object(scoped, 'execute') as run:
            scoped.gate('0.25.3', listing=True, root=self.root)
            with self.assertRaisesRegex(ValueError, 'unknown'):
                scoped.gate('0.25.3', 'missing', root=self.root)
        run.assert_not_called()

    def test_ci_executes_only_the_agreed_subset_without_review_authorization(self):
        text = (self.root / scoped.PLAN).read_text().replace('scope="fixture"',
            'scope="fixture"\nci_checks=["second"]')
        self.write(scoped.PLAN, text)
        self.write('security/pentest/v0.25.3.md', 'Status: RETEST REQUIRED\n')
        self.git('add', '.')
        self.git('commit', '-qm', 'explicit CI subset with pending review')
        with patch.object(scoped, 'execute') as run:
            scoped.gate('0.25.3', ci=True, root=self.root)
            self.assertEqual([c.args[0]['id'] for c in run.call_args_list], ['second'])
        with patch.object(scoped, 'execute') as run:
            with self.assertRaises(ValueError):
                scoped.gate('0.25.3', root=self.root)
        run.assert_not_called()

    def test_missing_ci_selection_never_expands_to_the_gate(self):
        with patch.object(scoped, 'execute') as run:
            with self.assertRaisesRegex(ValueError, 'CI check selection'):
                scoped.gate('0.25.3', ci=True, root=self.root)
        run.assert_not_called()

    def test_qualification_jobs_remain_explicit_and_commands_preserved(self):
        # The moved job bodies are compared to their frozen GitHub-only tag.
        # This is workflow-text validation, not execution of historical scripts.
        before = scoped.git(scoped.ROOT, 'show', 'v0.25.2:.github/workflows/ci.yml')
        after = (scoped.ROOT / '.github/workflows/qualification.yml').read_text()
        jobs = ('hardened-sha1', 'ordinary-md5', 'macos-resident', 'host', 'rust-version', 'target')
        for index, name in enumerate(jobs):
            def body(text):
                part = text.split(f'  {name}:\n', 1)[1]
                return part.split(f'\n  {jobs[index + 1]}:', 1)[0] if index + 1 < len(jobs) else part
            original = body(before).strip()
            current = body(after).split('\n', 1)[1].strip()  # only new job-level if
            self.assertEqual(original, current, name)
        self.assertNotIn('\n  push:', after)
        self.assertNotIn('\n  pull_request:', after)
        routine = (scoped.ROOT / '.github/workflows/ci.yml').read_text()
        self.assertIn('scoped_release.py --ci', routine)
        self.assertIn('cargo audit --file tools/brynja-verify/Cargo.lock --deny warnings', routine)
        for token in ('check-rust-version-matrix', 'run-verification.py', 'needs:', 'continue-on-error'):
            self.assertNotIn(token, routine)

    def test_routine_ci_fetches_locked_workspace_before_offline_checks(self):
        workflow = (scoped.ROOT / '.github/workflows/ci.yml').read_text()

        def validate(text):
            checks_job = text.split('\n  checks:\n', 1)[1].split('\n  audit:', 1)[0]
            commands = [line.strip().removeprefix('run: ')
                        for line in checks_job.splitlines()
                        if line.strip().startswith('run: ')]
            self.assertEqual(commands.count('cargo fetch --locked'), 1)
            self.assertLess(commands.index('rustup show'),
                            commands.index('cargo fetch --locked'))
            self.assertLess(commands.index('cargo fetch --locked'),
                            commands.index('python3 scripts/release/scoped_release.py --ci'))

        validate(workflow)
        fetch = '        run: cargo fetch --locked\n'
        run = '        run: python3 scripts/release/scoped_release.py --ci\n'
        for replacement in ('', '        # run: cargo fetch --locked\n',
                            '        run: cargo fetch\n',
                            '        run: cargo fetch --locked --offline\n',
                            '        run: cargo fetch --locked --manifest-path assurance/hkdf-timing/Cargo.toml\n'):
            with self.subTest(replacement=replacement), self.assertRaises(AssertionError):
                validate(workflow.replace(fetch, replacement))
        with self.assertRaises(AssertionError):
            validate(workflow.replace(fetch, '').replace(run, run + fetch))
        with self.assertRaises(AssertionError):
            validate(workflow.replace(fetch, '').replace('\n  audit:\n', '\n  audit:\n' + fetch))

    def test_only_explicit_final_checks_run_no_evidence(self):
        # An unrelated tracker failure/missing receipt must not block this gate.
        self.write('verification/results.json', '{"status":"outdated, failed"}')
        self.git('add', '.')
        self.git('commit', '-qm', 'unrelated evidence metadata')
        with patch.object(scoped, 'execute') as run:
            scoped.gate('0.25.3', root=self.root)
            self.assertEqual([c.args[0]['id'] for c in run.call_args_list], ['first', 'second'])
        with patch.object(scoped, 'execute') as run:
            scoped.gate('0.25.3', 'second', root=self.root)
            self.assertEqual([c.args[0]['id'] for c in run.call_args_list], ['second'])

    def test_failure_stops_without_restarting_completed_work(self):
        with patch.object(scoped, 'execute', side_effect=RuntimeError('failed')) as run:
            with self.assertRaisesRegex(RuntimeError, 'failed'):
                scoped.gate('0.25.3', root=self.root)
            self.assertEqual(run.call_count, 1)

    def test_missing_pentest_and_dirty_candidate_block_before_execution(self):
        self.write('security/pentest/v0.25.3.md', 'Version: v0.25.3\nStatus: RETEST REQUIRED\n')
        with patch.object(scoped, 'execute') as run:
            with self.assertRaisesRegex(ValueError, 'clean'):
                scoped.gate('0.25.3', root=self.root)
            self.git('add', '.')
            self.git('commit', '-qm', 'pending review')
            with self.assertRaisesRegex(ValueError, 'Status: PASS'):
                scoped.gate('0.25.3', root=self.root)
        run.assert_not_called()

    def test_version_mismatch_never_falls_back_to_full_campaign(self):
        with self.assertRaisesRegex(ValueError, 'finite'):
            scoped.gate('0.26.0', root=self.root)

    def test_untracked_implementation_blocks_before_execution(self):
        self.write('crates/new-cipher/src/lib.rs', '// uncommitted implementation\n')
        with patch.object(scoped, 'execute') as run:
            with self.assertRaisesRegex(ValueError, 'clean'):
                scoped.gate('0.25.3', root=self.root)
        run.assert_not_called()

    def test_staged_implementation_still_requires_commit(self):
        self.write('crates/new-cipher/src/lib.rs', '// staged implementation\n')
        self.git('add', 'crates/new-cipher/src/lib.rs')
        with patch.object(scoped, 'execute') as run:
            with self.assertRaisesRegex(ValueError, 'clean'):
                scoped.gate('0.25.3', root=self.root)
        run.assert_not_called()

    def test_deleted_tracked_review_blocks_before_execution(self):
        (self.root / 'security/pentest/v0.25.3.md').unlink()
        with patch.object(scoped, 'execute') as run:
            with self.assertRaisesRegex(ValueError, 'clean'):
                scoped.gate('0.25.3', root=self.root)
        run.assert_not_called()

    def test_candidate_change_during_gate_blocks_completion(self):
        with patch.object(scoped, 'execute', side_effect=lambda *a: self.write('changed', 'x')):
            with self.assertRaisesRegex(RuntimeError, 'changed during'):
                scoped.gate('0.25.3', root=self.root)

    def test_publishing_never_runs_gate_tests_or_audit(self):
        with patch.object(publisher, 'run') as run, patch.object(scoped, 'publication') as handoff:
            publisher.run_preflight('0.25.3', dry_run=False, release_tag_at_head=True)
            handoff.assert_called_once_with('0.25.3', dry_run=False, root=publisher.ROOT)
            run.assert_not_called()
            publisher.publish('brynja', dry_run=True, checked_candidate=True)
            run.assert_called_once_with(['cargo', 'publish', '--no-verify', '--locked', '-p', 'brynja'], dry_run=True)

    def test_publication_cli_ignores_legacy_evidence_and_never_runs_checks(self):
        plan = dict(version='0.25.3', stage='public',
                    crates={'brynja': dict(version='0.25.3', change='code')})
        forbidden = AssertionError('publication must not inspect historical evidence or execute checks')
        with patch('sys.argv', ['release_crates.py', '--version', '0.25.3', '--yes',
                               '--detached-receipts', '/missing/old-receipts.json',
                               '--native-review-sha256', 'obsolete']), \
             patch.object(publisher, 'validate_repository', return_value=plan), \
             patch.object(publisher, 'publish_plan', return_value=('brynja',)), \
             patch.object(publisher, 'require_clean_tree') as clean, \
             patch.object(publisher, 'check_release_tag', return_value=True) as tag, \
             patch.object(publisher, 'evidence_environment', side_effect=forbidden), \
             patch.object(publisher, 'check_evidence', side_effect=forbidden), \
             patch.object(publisher, 'gate_path', side_effect=forbidden), \
             patch.object(scoped, 'gate', side_effect=forbidden), \
             patch.object(scoped, 'publication') as handoff, \
             patch.object(publisher, 'run') as run:
            self.assertEqual(publisher.main(), 0)
            clean.assert_called_once_with(dry_run=False)
            tag.assert_called_once_with('0.25.3', dry_run=False)
            handoff.assert_called_once_with('0.25.3', dry_run=False, root=publisher.ROOT)
            run.assert_called_once_with(
                ['cargo', 'publish', '--no-verify', '--locked', '-p', 'brynja'], dry_run=False)

    def test_publication_guards_read_identity_and_ci_not_evidence(self):
        self.write('verification/results.json', '{"status":"unmapped, outdated"}')
        self.git('add', '.')
        self.git('commit', '-qm', 'historical evidence accepted as is')
        self.git('tag', 'v0.25.3')
        head = scoped.git(self.root, 'rev-parse', 'HEAD')
        runs = [{**r, 'head_sha': head} for r in self.runs]
        checks = [{**c, 'head_sha': head} for c in self.checks]
        original_run = subprocess.run
        def guarded_run(command, **kwargs):
            if command == ['git', 'verify-tag', 'v0.25.3']:
                return subprocess.CompletedProcess(command, 0)
            self.assertEqual(command[0], 'git')
            self.assertIn(command[1], ('status', 'show', 'rev-parse'))
            return original_run(command, **kwargs)
        # Real local candidate/report/tag reads; only signature and remote I/O mocked.
        with patch.object(scoped, 'pages', side_effect=[runs, checks]) as pages, \
             patch.object(scoped.subprocess, 'run', side_effect=guarded_run) as run, \
             patch.object(scoped, 'execute', side_effect=AssertionError('no verification')):
            scoped.publication('0.25.3', dry_run=False, root=self.root)
            run.assert_any_call(['git', 'verify-tag', 'v0.25.3'], cwd=self.root, check=True)
            self.assertEqual(pages.call_count, 2)

    def test_publication_pending_review_is_a_clear_error_not_an_upload(self):
        plan = dict(version='0.25.3', stage='public',
                    crates={'brynja': dict(version='0.25.3', change='code')})
        with patch('sys.argv', ['release_crates.py', '--yes']), \
             patch.object(publisher, 'validate_repository', return_value=plan), \
             patch.object(publisher, 'publish_plan', return_value=('brynja',)), \
             patch.object(publisher, 'require_clean_tree'), \
             patch.object(publisher, 'check_release_tag', return_value=True), \
             patch.object(scoped, 'publication', side_effect=ValueError('pentest pending')), \
             patch.object(publisher, 'run') as run:
            self.assertEqual(publisher.main(), 1)
            run.assert_not_called()

    def test_dry_run_wait_never_claims_upload_or_prompts(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), \
             patch('builtins.input', side_effect=AssertionError('no prompt')), \
             patch.object(publisher.time, 'sleep', side_effect=AssertionError('no wait')):
            publisher.wait_for_index('brynja-core', '0.10.0', dry_run=True)
        self.assertIn('nothing uploaded', output.getvalue())
        self.assertNotIn('Published ', output.getvalue())

    def test_github_requires_success_for_the_exact_commit(self):
        scoped.github_green(self.head, self.runs, self.checks)
        for field, value in [('head_sha', 'b' * 40), ('head_branch', 'other'), ('event', 'pull_request'),
                             ('conclusion', 'failure'), ('status', 'in_progress')]:
            runs = copy.deepcopy(self.runs)
            runs[0][field] = value
            with self.assertRaises(ValueError):
                scoped.github_green(self.head, runs, self.checks)

    def test_latest_failed_rerun_not_hidden_by_old_success(self):
        later = {**self.runs[0], 'run_attempt': 2, 'conclusion': 'failure'}
        with self.assertRaises(ValueError):
            scoped.github_green(self.head, [*self.runs, later], self.checks)
        with self.assertRaises(ValueError):
            scoped.github_green(self.head, [later, *self.runs], self.checks)

    def test_codeql_and_optional_started_workflows_cannot_be_silently_ignored(self):
        with self.assertRaises(ValueError):
            scoped.github_green(self.head, self.runs, self.checks[:-1])
        for conclusion in ('failure', 'cancelled', 'timed_out', 'skipped'):
            checks = copy.deepcopy(self.checks)
            checks[-1]['conclusion'] = conclusion
            with self.assertRaises(ValueError):
                scoped.github_green(self.head, self.runs, checks)
        extra = {**self.runs[0], 'id': 11, 'workflow_id': 2, 'conclusion': 'failure'}
        with self.assertRaises(ValueError):
            scoped.github_green(self.head, [*self.runs, extra], self.checks)

    def test_paginated_statuses_are_all_read(self):
        pages = [{'check_runs': self.checks[:2]}, {'check_runs': self.checks[2:]}]
        with patch.object(subprocess, 'check_output', return_value=json.dumps(pages).encode()):
            self.assertEqual(scoped.pages('fixture', 'check_runs', self.root), self.checks)

    def test_real_fake_command_failures_and_timeout(self):
        for command in (['python3', '-c', 'raise SystemExit(3)'],
                        ['python3', '-c', 'import time; time.sleep(30)']):
            with self.assertRaises((RuntimeError, subprocess.TimeoutExpired)):
                scoped.execute(dict(id='fixture', command=command, timeout_seconds=1), self.root)


if __name__ == '__main__':
    unittest.main()
