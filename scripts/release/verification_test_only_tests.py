"""Bounded Git-delta regressions for isolated, reviewed test-only reuse."""
import copy
import hashlib
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import verification_test_only as isolated
import verification_carry_forward as carry
import verification_plan as plans
from verification_carry_forward_tests import entry, plan


class TestOnlyReuseTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.git('init', '-q')
        self.git('config', 'user.email', 'fixture@example.invalid')
        self.git('config', 'user.name', 'fixture')
        self.write(isolated.NORMALIZATION, b'old-normalization')
        self.write(isolated.VERIFICATION, b'old-verification')
        self.git('add', '.')
        self.git('-c', 'commit.gpgsign=false', 'commit', '-qm', 'baseline')
        self.base = self.git('rev-parse', 'HEAD').strip()
        pairs = {path: tuple(hashlib.sha256(raw).hexdigest() for raw in values) for path, values in (
            (isolated.NORMALIZATION, (b'old-normalization', b'new-normalization')),
            (isolated.VERIFICATION, (b'old-verification', b'new-verification')))}
        self.patch = patch.object(isolated, 'REVISIONS', pairs)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.write(isolated.NORMALIZATION, b'new-normalization')

    def git(self, *args):
        return subprocess.check_output(['git', *args], cwd=self.root, stderr=subprocess.PIPE).decode()

    def write(self, name, raw):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)

    def prove(self):
        return isolated.prove(self.root, self.base, plans.changed_paths(self.root, self.base))

    def test_exact_reviewed_test_delta_tracks_unchanged_dependent(self):
        self.assertEqual(self.prove(), {isolated.NORMALIZATION, isolated.VERIFICATION})
        self.write(isolated.VERIFICATION, b'new-verification')
        self.assertEqual(self.prove(), {isolated.NORMALIZATION, isolated.VERIFICATION})
        self.write(isolated.NORMALIZATION, b'old-normalization')
        self.assertEqual(self.prove(), {isolated.VERIFICATION})

    def test_unreviewed_revisions_removals_additions_and_line_endings_reject(self):
        for data in (b'unreviewed', b'new-normalization\r\n', b'', b'old-normalization'):
            with self.subTest(data=data):
                self.write(isolated.NORMALIZATION, data)
                self.assertIsNone(self.prove())
        (self.root / isolated.NORMALIZATION).unlink()
        self.assertIsNone(self.prove())
        self.write(isolated.NORMALIZATION, b'new-normalization')
        with patch.object(plans.inputs, 'snapshot', return_value=(None, b'new-normalization')):
            self.assertIsNone(self.prove())
        self.git('add', '.')
        self.git('-c', 'commit.gpgsign=false', 'commit', '-qm', 'corrected')
        self.base = self.git('rev-parse', 'HEAD').strip()
        self.write(isolated.NORMALIZATION, b'old-normalization')
        self.assertIsNone(self.prove())  # Reverting a correction is not its reviewed direction.

    def test_actual_delta_cannot_omit_tracked_or_untracked_inputs(self):
        self.assertIsNone(isolated.prove(self.root, self.base, []))
        for path in ('crates/brynja-legacy-hmac/src/lib.rs', 'Cargo.toml', 'Cargo.lock',
                     'assurance/legacy-hmac-md5-cleanup/src/lib.rs',
                     'scripts/legacy-hmac/legacy_hmac_md5_normalization.py',
                     'scripts/legacy-hmac/test-unregistered.py',
                     'scripts/hmac/hmac_engine_codegen.py', '.cargo/config.toml',
                     'scripts/zeroization/check-zeroization-miri.sh',
                     'assurance/policy.toml', 'rust-toolchain.toml',
                     'security/native-reuse/evidence-approval.json'):
            with self.subTest(path=path):
                self.write(path, b'new input')
                self.assertIsNone(self.prove())
                self.assertIsNone(isolated.prove(self.root, self.base, [isolated.NORMALIZATION]))
                (self.root / path).unlink()

    def test_metadata_rebinding_must_preserve_structure(self):
        cases = [(name, b'[files]\nsource="' + b'a' * 64 + b'"\n') for name in isolated.TOML_BINDINGS]
        cases += [(name, b'{"source":"' + b'a' * 64 + b'"}') for name in isolated.JSON_BINDINGS]
        for name, before in cases:
            self.write(name, before)
        self.write(isolated.NORMALIZATION, b'old-normalization')
        self.git('add', '.')
        self.git('-c', 'commit.gpgsign=false', 'commit', '-qm', 'metadata')
        self.base = self.git('rev-parse', 'HEAD').strip()
        self.write(isolated.NORMALIZATION, b'new-normalization')
        for name, before in cases:
            with self.subTest(name=name):
                self.write(name, before.replace(b'a' * 64, b'b' * 64))
                self.assertIsNotNone(self.prove())
                self.write(name, before.replace(b'source', b'changed-policy'))
                self.assertIsNone(self.prove())
                self.write(name, b'invalid metadata')
                self.assertIsNone(self.prove())
                self.write(name, before)

    def test_baseline_orchestration_and_docs_do_not_hide_shared_changes(self):
        for name in ('scripts/release/new_policy.py', 'docs/review.md', 'security/pentest/v0.25.1.md'):
            self.write(name, b'current baseline checks required')
        self.assertIsNotNone(self.prove())
        self.write('scripts/legacy-hmac/shared.py', b'changed helper')
        self.assertIsNone(self.prove())

    def test_policy_preserves_drivers_baseline_coverage_tools_and_approval(self):
        unchanged = entry('python3 scripts/legacy-hmac/test-legacy-hmac-hosted-cleanup.py Hosted.test_one')
        dependent = entry('python3 ' + isolated.VERIFICATION)
        corrected = entry('python3 ' + isolated.NORMALIZATION)
        baseline = entry('python3 scripts/release/test-detached-verification.py')
        matrix = entry('cargo +1.90.0 check --workspace', 'matrix')
        kani = entry('python3 scripts/legacy-hmac/check-legacy-hmac-kani.py', 'kani')
        selected = [unchanged, dependent, corrected, baseline, matrix, kani]
        delta = {**plan(['legacy_hmac']), 'full_phases': [],
                 'evidence': {'changed_paths': [isolated.NORMALIZATION]}}
        context = {'plan': delta, 'manifest': {'commands': selected}, 'public_checkpoint': False,
                   'test_only_rerun': self.prove()}
        for task in (unchanged, matrix, kani):
            self.assertTrue(carry.disposition(task, context).startswith('reuse:'))
            missing = {**context, 'manifest': {'commands': []}}
            self.assertTrue(carry.disposition(task, missing).startswith('run:'))
            for extra in ({'public_checkpoint': True}, {'tool_drift': {task['phase']: 'changed'}}):
                self.assertTrue(carry.disposition(task, {**context, **extra}).startswith('run:'))
            full = copy.deepcopy(context)
            full['plan']['full_phases'] = [task['phase']]
            self.assertTrue(carry.disposition(task, full).startswith('run:'))
        for task in (dependent, corrected, baseline):
            self.assertTrue(carry.disposition(task, context).startswith('run:'))
        self.assertTrue(carry.disposition(unchanged, {**context, 'test_only_rerun': None}).startswith('run:'))

