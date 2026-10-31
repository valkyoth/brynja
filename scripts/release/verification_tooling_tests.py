"""Real Git deltas and carry-forward rejection tests for the bounded review."""
import copy
import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import verification_tooling_reuse as tooling
import verification_carry_forward as carry
import verification_plan as plans
from verification_carry_forward_tests import entry, plan


class ToolingReuseTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.driver = 'scripts/sha3/check-sha3-execution.py'
        self.git('init', '-q')
        self.git('config', 'user.email', 'test@example.invalid')
        self.git('config', 'user.name', 'test')
        self.write(self.driver, b'old checker\n')
        self.git('add', '.')
        self.git('-c', 'commit.gpgsign=false', 'commit', '-qm', 'baseline')
        self.base = self.git('rev-parse', 'HEAD').strip()
        self.profile = {'schema': 1, 'bases': {self.base: sorted(tooling.PHASES)},
                        'files': {self.driver: {
                            'before': [hashlib.sha256(b'old checker\n').hexdigest()],
                            'after': hashlib.sha256(b'corrected checker\n').hexdigest(),
                            'mode': '100644'}}}
        mocked = patch.object(tooling, 'review', return_value=self.profile)
        mocked.start()
        self.addCleanup(mocked.stop)
        self.write(self.driver, b'corrected checker\n')

    def git(self, *args):
        return subprocess.check_output(['git', *args], cwd=self.root, stderr=subprocess.PIPE).decode()

    def write(self, name, data):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def prove(self):
        return tooling.prove(self.root, self.base, plans.changed_paths(self.root, self.base))

    def test_exact_complete_delta_only(self):
        self.assertEqual(self.prove(), tooling.PHASES)
        self.assertFalse(tooling.prove(self.root, self.base, []))
        self.assertFalse(tooling.prove(self.root, '0' * 40, [self.driver]))
        self.profile['bases'][self.base] = ['repository']
        self.assertFalse(self.prove())

    def test_followup_is_exact_and_does_not_replace_original_review(self):
        original = copy.deepcopy(self.profile)
        path = self.root / self.driver
        newer = b'follow-up checker correction\n'
        row = {**self.profile['files'][self.driver], 'after': hashlib.sha256(newer).hexdigest()}
        with patch.dict(tooling.FOLLOWUP, {self.driver: row}):
            self.assertFalse(self.prove())
            self.write(self.driver, newer)
            self.assertEqual(self.prove(), tooling.PHASES)
            self.write(self.driver, newer.replace(b'\n', b'\r\n'))
            self.assertFalse(self.prove())
            self.write(self.driver, newer)
            path.chmod(0o755)
            self.assertFalse(self.prove())
        self.assertEqual(self.profile, original)

    def test_readme_followup_is_not_a_general_documentation_exemption(self):
        name = 'crates/example/README.md'
        self.write(name, b'new reviewed prose\n')
        row = {'before': [None], 'after': hashlib.sha256(b'new reviewed prose\n').hexdigest(),
               'mode': '100644'}
        with patch.dict(tooling.FOLLOWUP, {name: row}):
            self.assertEqual(self.prove(), tooling.PHASES)
            self.write(name, b'new reviewed prose\n```rust\nunsafe { change() }\n```\n')
            self.assertFalse(self.prove())
        self.assertFalse(self.prove())
        (self.root / name).unlink()
        for name in ('crates/example/src/lib.rs', 'Cargo.toml',
                     'scripts/zeroization/run-miri-task.py', 'scripts/assurance/check-kani.sh',
                     'security/native-reuse/evidence-approval.json'):
            self.write(name, b'new reviewed prose\n')
            with patch.dict(tooling.FOLLOWUP, {name: row}):
                self.assertFalse(self.prove())
            (self.root / name).unlink()

    def test_no_production_build_driver_or_authority_exemption(self):
        for name in ('crates/brynja-hash-sha3/src/lib.rs', 'Cargo.toml', 'Cargo.lock',
                     'assurance/sha3-execution/src/main.rs', 'assurance/policy.toml',
                     'rust-toolchain.toml', '.cargo/config.toml',
                     'scripts/zeroization/run-miri-task.py',
                     'scripts/zeroization/check-zeroization-sanitizer.sh',
                     'scripts/assurance/check-kani.sh',
                     'scripts/release/unreviewed.py',
                     'security/native-reuse/evidence-approval.json'):
            with self.subTest(name=name):
                self.write(name, b'unreviewed input')
                self.assertFalse(self.prove())
                (self.root / name).unlink()

    def test_scope_classifier_needs_exact_review_not_directory_exemption(self):
        name = 'scripts/zeroization/scope_hmac.py'
        raw = b'# reviewed classification correction\n'
        row = {'before': [None], 'after': hashlib.sha256(raw).hexdigest(), 'mode': '100644'}
        self.write(name, raw)
        self.assertFalse(self.prove())
        with patch.dict(tooling.FOLLOWUP, {name: row}):
            self.assertEqual(self.prove(), tooling.PHASES)
            self.write(name, raw + b'# unreviewed edit\n')
            self.assertFalse(self.prove())
            self.write(name, raw.replace(b'\n', b'\r\n'))
            self.assertFalse(self.prove())
            self.write(name, raw)
            (self.root / name).chmod(0o755)
            self.assertFalse(self.prove())

    def test_bytes_removal_mode_and_symlinks_reject(self):
        path = self.root / self.driver
        for raw in (b'corrected checker\r\n', b'new checker\n', b''):
            self.write(self.driver, raw)
            self.assertFalse(self.prove())
        path.unlink()
        self.assertFalse(self.prove())
        self.write(self.driver, b'corrected checker\n')
        path.chmod(0o755)
        self.assertFalse(self.prove())
        path.unlink()
        self.write('elsewhere', b'corrected checker\n')
        path.symlink_to(self.root / 'elsewhere')
        self.assertFalse(self.prove())

    def test_trusted_orchestration_is_explicit_not_a_glob(self):
        for name in tooling.ORCHESTRATION:
            self.write(name, b'current trusted verifier requires review')
        self.assertEqual(self.prove(), tooling.PHASES)
        self.write('scripts/release/unregistered.py', b'new helper')
        self.assertFalse(self.prove())

    def test_runtime_and_native_approval_cannot_be_exempted_by_profile_rows(self):
        for name in ('crates/brynja-hash-sha3/src/lib.rs', 'Cargo.lock',
                     'security/native-reuse/evidence-approval.json',
                     'scripts/zeroization/run-miri-task.py',
                     'scripts/assurance/check-kani.sh'):
            with self.subTest(name=name):
                self.write(name, b'new input')
                self.profile['files'][name] = {'before': [None],
                    'after': hashlib.sha256(b'new input').hexdigest(), 'mode': '100644'}
                self.assertFalse(self.prove())
                (self.root / name).unlink()
                del self.profile['files'][name]

    def test_generated_metadata_preserves_claims_and_checks_actual_hashes(self):
        old = {'tools': ['unchanged'], 'inputs': {self.driver: self.profile['files'][self.driver]['before'][0]}}
        new = copy.deepcopy(old)
        new['inputs'][self.driver] = self.profile['files'][self.driver]['after']
        def check(value, changed=(self.driver,)):
            return tooling.generated_only(self.root, self.base, json.dumps(old).encode(),
                                          json.dumps(value).encode(), changed)
        self.assertTrue(check(new))
        self.assertFalse(check(new, ()))
        for corrupt in ({**new, 'tools': ['new verifier']},
                        {**new, 'inputs': {}},
                        {**new, 'inputs': {self.driver: '0' * 64}},
                        {**new, 'inputs': {**new['inputs'], 'unregistered': 'a' * 64}}):
            self.assertFalse(check(corrupt))
        added = 'scripts/release/verification_tooling_reuse.py'
        self.write(added, b'new helper')
        new['inputs'][added] = hashlib.sha256(b'new helper').hexdigest()
        self.assertTrue(check(new, (self.driver, added)))

    def test_native_metadata_transition_is_not_general_profile_exemption(self):
        self.write(tooling.NATIVE_REVIEW, b'proposed manifest')
        with patch.object(tooling, 'approved_native_update', return_value=True) as guard:
            self.assertEqual(self.prove(), tooling.PHASES)
            guard.assert_called_once()
        with patch.object(tooling, 'approved_native_update', return_value=False):
            self.assertFalse(self.prove())
        with patch.object(tooling, 'approved_native_update', side_effect=ValueError('unapproved')):
            self.assertFalse(self.prove())

    def test_native_pair_requires_external_pin_and_original_artifacts(self):
        import native_evidence_approval as approval
        import native_review_tests as fixtures
        import native_review_io as io
        root = self.root / 'native-fixture'
        root.mkdir()
        fixtures.init_repository(root)
        fixtures.write(root, 'crates/example/src/lib.rs', 'pub fn original() {}\n')
        capture = fixtures.commit(root)
        artifact = 'assurance/kmac-execution-native/test.json'
        record = {'commit': capture, 'cpu': 'synthetic test CPU', 'results': {'test': 'fixture'}}
        fixtures.write(root, artifact, record)
        index = approval.INDEXES['kmac-execution']
        fixtures.write(root, index, {'lanes': {'test': {'artifact': artifact,
            'sha256': io.sha(io.read(root, artifact))}}})
        anchor = fixtures.commit(root)
        old = {'schema': 1, 'purpose': 'native-observation-integrity', 'status': 'owner-approved',
               'reviewed_commit': anchor, 'families': ['kmac-execution'], 'validation_changes': {}}
        fixtures.write(root, approval.REVIEW, old)
        fixtures.commit(root)
        before = (root / approval.REVIEW).read_bytes()
        new = {**old, 'validation_changes': {'kmac-execution': {
            'scripts/check.py': {'before': 'a' * 64, 'after': 'b' * 64}}}}
        fixtures.write(root, approval.REVIEW, new)
        fixtures.commit(root)
        after = (root / approval.REVIEW).read_bytes()
        pair = (io.sha(before), io.sha(after))
        with patch.object(tooling, 'NATIVE_PAIR', pair), \
             patch.object(approval, 'INDEXES', {'kmac-execution': index}):
            for value in ('', pair[0], '0' * 64):
                with self.subTest(pin=value), patch.dict(os.environ, {approval.ENVIRONMENT: value}):
                    with self.assertRaises(ValueError):
                        tooling.approved_native_update(root, before, after)
            with patch.dict(os.environ, {approval.ENVIRONMENT: pair[1]}):
                self.assertTrue(tooling.approved_native_update(root, before, after))
                self.assertFalse(tooling.approved_native_update(root, before, after + b'\n'))
                self.assertFalse(tooling.approved_native_update(root, after, before))
                self.assertFalse(tooling.approved_native_update(root, None, after))
                fixtures.write(root, artifact, {**record, 'cpu': 'FORGED CPU'})
                fixtures.write(root, index, {'lanes': {'test': {'artifact': artifact,
                    'sha256': io.sha(io.read(root, artifact))}}})
                fixtures.commit(root)
                with self.assertRaisesRegex(ValueError, 'approved native index/artifact changed'):
                    tooling.approved_native_update(root, before, after)

    def test_decisions_keep_tool_driver_checkpoint_and_missing_coverage_gates(self):
        tasks = [entry('cargo +1.90.0 check --workspace', 'matrix'),
                 entry('scripts/assurance/check-kani.sh --required-groups sha3', 'kani'),
                 entry('cargo test -p brynja-hash-sha3', 'asan')]
        miri = entry('python3 scripts/zeroization/run-miri-task.py --group sha3 --task 0 --profile extended', 'miri')
        tasks.append(miri)
        context = {'plan': {**plan(['sha3']), 'full_phases': [],
                           'evidence': {'changed_paths': [self.driver]}},
                   'manifest': {'commands': tasks}, 'public_checkpoint': False,
                   'tooling_only_phases': self.prove()}
        # The real Miri identity resolver remains mandatory. Mock only that
        # independent coverage result here; missing/false coverage must reject.
        for task in tasks:
            with self.subTest(phase=task['phase']), patch.object(carry, 'covered', return_value=True):
                self.assertTrue(carry.disposition(task, context).startswith('reuse:'))
                for extra in ({'tool_drift': {task['phase']: 'different'}},
                              {'public_checkpoint': True}, {'tooling_only_phases': set()}):
                    self.assertTrue(carry.disposition(task, {**context, **extra}).startswith('run:'))
                full = copy.deepcopy(context)
                full['plan']['full_phases'] = [task['phase']]
                self.assertTrue(carry.disposition(task, full).startswith('run:'))
                changed = copy.deepcopy(context)
                driver = task['argv'][1] if task['argv'][0] == 'python3' else task['argv'][0]
                changed['plan']['evidence']['changed_paths'].append(driver)
                self.assertTrue(carry.disposition(task, changed).startswith('run:'))
            with patch.object(carry, 'covered', return_value=False):
                self.assertEqual(carry.disposition(task, context), 'run: no matching successful command evidence')
        for task in (entry('python3 ' + self.driver),
                     entry('python3 scripts/sha3/check-sha3-bit-differential.py'),
                     entry('python3 scripts/release/test-detached-verification.py')):
            with patch.object(carry, 'covered', return_value=True):
                self.assertTrue(carry.disposition(task, context).startswith('run:'))


class ToolingReviewEndpoints(unittest.TestCase):
    def test_real_review_has_only_expected_phases_and_nonruntime_changes(self):
        policy = tooling.review()
        self.assertEqual(sorted(sorted(v) for v in policy['bases'].values()),
                         [['asan', 'kani'], ['matrix'], ['miri']])
        # Fixed review endpoints, not an assertion that future HEAD is exempt.
        # The live planner must reject new implementation work without making
        # this historical regression test fail on the next release.
        endpoint = '41c3287cbf44b661354e47f1d059dc2119a45bbd'
        for name, row in policy['files'].items():
            old_hashes = set()
            for base in policy['bases']:
                before, _ = plans.inputs.snapshot(plans.ROOT, base, name)
                old_hashes.add(hashlib.sha256(before).hexdigest() if before is not None else None)
            self.assertLessEqual(set(row['before']), old_hashes, name)
            after = plans.inputs.git(plans.ROOT, 'show', endpoint + ':' + name)
            if name == 'scripts/assurance/assurance_policy.py':
                needle = b'            "verification_carry_forward.py", "verification_carry_forward_tests.py",\n'
                self.assertEqual(after.count(needle), 1)
                after = after.replace(needle, needle +
                    b'            "verification_tooling_reuse.py", "verification_tooling_review.py", "verification_tooling_tests.py",\n')
            self.assertEqual(hashlib.sha256(after).hexdigest(), row['after'], name)
        for base in policy['bases']:
            raw = plans.inputs.git(plans.ROOT, 'show', base + ':assurance/evidence.json')
            self.assertIn(hashlib.sha256(raw).hexdigest(), policy['generated_before'])
        # Checks on the approved source-bound profile, not trusting a filename.
        self.assertTrue(all(p.startswith(('scripts/', 'docs/', 'security/'))
                            for p in policy['files']))
        self.assertNotIn('security/native-reuse/evidence-approval.json', policy['files'])


if __name__ == '__main__':
    unittest.main()
