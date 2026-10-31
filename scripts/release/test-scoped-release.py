#!/usr/bin/env python3
"""Release redesign regressions: fake commands and records, no crypto campaigns."""
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
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
