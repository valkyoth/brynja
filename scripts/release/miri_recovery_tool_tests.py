"""Cross-host Miri reuse preserves selected tools and historical semantics."""
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import detached_checkpoints as checkpoints
import detached_history as history
import detached_job as jobs
import detached_manifest as records
import detached_recovery as recovery
import miri_coverage_identity as identity
import miri_recovery_tools as policy
import verification_plan as plans
from miri_coverage_tests import entry, task


class MiriRecoveryToolTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.old_root, self.new_root = self.root / 'old/source', self.root / 'new/source'
        for root in (self.old_root, self.new_root):
            (root / 'assurance').mkdir(parents=True)
            (root / 'assurance/policy.toml').write_bytes((plans.ROOT / 'assurance/policy.toml').read_bytes())
        probes = records.verifier_commands(self.old_root, [entry()])
        self.name = probes['verifier:miri'][2]
        self.compiler = 'compiler:' + self.name + '-x86_64-unknown-linux-gnu'
        tools = {'python': 'old Python', 'python3': 'old Python3', 'rustup': 'old rustup',
                 'installed': self.name + '-x86_64-unknown-linux-gnu',
                 'platform': 'linux', 'rustc': 'rustc default', 'cargo': 'cargo default',
                 self.compiler: 'rustc Miri\nhost: x86_64-unknown-linux-gnu',
                 'verifier:miri': 'miri exact revision'}
        self.old = {'schema': 3, 'tools': tools, 'commands': [entry()],
                    'sources': {'head': 'c' * 40}, 'plan': {'stage': 'internal'},
                    'phases': ['miri'], 'approval': None, 'miri_profile': 'extended'}
        self.new = copy.deepcopy(self.old)
        self.new.update(recovery=[{'job': str(self.old_root.parent), 'receipt': 'a' * 64}],
                        recovery_tools=policy.POLICY)
        self.new['tools'].update(python='new Python', python3='new Python3', rustup='new rustup')
        self.new['tools']['installed'] += '\nunrelated-stable'
        self.new['tools']['compiler:unrelated-stable'] = 'other compiler'

    def compatible(self, old=None, new=None):
        return policy.compatible(old or self.old, new or self.new, self.old_root, self.new_root)

    def test_selected_tools_allow_only_unrelated_inventory_without_live_probes(self):
        before = copy.deepcopy((self.old, self.new))
        with patch.object(records.subprocess, 'check_output', side_effect=AssertionError('no live probe')):
            self.assertTrue(self.compatible())
        self.assertEqual((self.old, self.new), before)

    def test_each_selected_identity_missing_empty_or_changed_rejects(self):
        for key in ('platform', 'rustc', 'cargo', self.compiler, 'verifier:miri'):
            for value in (None, '', 'different', 1):
                with self.subTest(key=key, value=value):
                    new = copy.deepcopy(self.new)
                    if value is None:
                        del new['tools'][key]
                    else:
                        new['tools'][key] = value
                    self.assertFalse(self.compatible(new=new))

    def test_changed_policy_toolchain_and_ambiguous_compiler_fail_closed(self):
        path = self.new_root / 'assurance/policy.toml'
        path.write_text(path.read_text().replace(self.name, 'nightly-2099-01-01'))
        self.assertFalse(self.compatible())
        path.write_bytes((self.old_root / 'assurance/policy.toml').read_bytes())
        new = copy.deepcopy(self.new)
        new['tools']['compiler:' + self.name] = new['tools'][self.compiler]
        self.assertFalse(self.compatible(new=new))
        path.write_text('malformed [')
        self.assertFalse(self.compatible())

    def test_old_manifest_without_policy_retains_full_inventory_equality(self):
        legacy = copy.deepcopy(self.new)
        legacy.pop(policy.FIELD)
        self.assertFalse(self.compatible(new=legacy))
        legacy['tools'] = copy.deepcopy(self.old['tools'])
        self.assertTrue(self.compatible(new=legacy))

    def test_empty_mixed_and_opaque_commands_cannot_use_selected_miri_rule(self):
        for commands in ([], [{**entry(), 'phase': 'repository'}],
                         [entry(), {**entry(), 'argv': ['cargo', 'test']}],
                         [{**entry(), 'argv': ['scripts/zeroization/check-zeroization-miri.sh']} ]):
            with self.subTest(commands=commands):
                with self.assertRaises(ValueError):
                    policy.validate({**self.new, 'commands': commands})
                self.assertFalse(self.compatible(old={**self.old, 'commands': commands}))

    def test_unknown_policy_schema_or_missing_recovery_rejected(self):
        for delta in ({policy.FIELD: 'future'}, {policy.FIELD: None}, {'schema': 2}, {'recovery': []}):
            with self.assertRaises(ValueError):
                recovery.references({**self.new, **delta})

    def test_binding_new_jobs_and_resume_does_not_reinterpret_old_jobs(self):
        new = copy.deepcopy(self.new)
        new.pop(policy.FIELD)
        policy.bind(new)
        self.assertEqual(new[policy.FIELD], policy.POLICY)
        for parent in ({}, {policy.FIELD: policy.POLICY}):
            child = copy.deepcopy(self.new)
            child.pop(policy.FIELD)
            policy.bind(child, parent)
            self.assertEqual(child.get(policy.FIELD), parent.get(policy.FIELD))
        plain = copy.deepcopy(self.old)
        policy.bind(plain)
        self.assertNotIn(policy.FIELD, plain)

    def test_manifest_policy_is_sealed_and_validated(self):
        manifest = {**self.new, 'id': 'fixture', 'created': jobs.stamp(), 'seconds': 10,
                    'log_bytes': 4096, 'shards': 1, 'workers': 1, 'resume': None, 'partition': None}
        job = self.new_root.parent
        records.atomic(job / 'manifest.json', manifest)
        receipt = records.digest(manifest)
        self.assertEqual(jobs.load(job, receipt)[policy.FIELD], policy.POLICY)
        manifest.pop(policy.FIELD)
        records.atomic(job / 'manifest.json', manifest)
        with self.assertRaisesRegex(ValueError, 'receipt mismatch'):
            jobs.load(job, receipt)
        manifest[policy.FIELD] = 'unknown'
        records.atomic(job / 'manifest.json', manifest)
        with self.assertRaisesRegex(ValueError, 'tool policy'):
            jobs.load(job, records.digest(manifest))

    def test_start_seals_new_rule_but_resume_preserves_legacy_rule(self):
        plan = {'stage': 'internal', 'verification_mode': 'affected', 'base': 'fixture', 'issues': []}
        parent = {**self.new}
        parent.pop(policy.FIELD)
        def clone(_root, destination, _closure):
            destination.mkdir(parents=True)
        with patch.object(plans, 'build', return_value=plan), \
                patch.object(jobs.catalog, 'selected', return_value=[entry()]), \
                patch.object(records, 'sources', return_value={}), \
                patch.object(records, 'tool_identity', return_value=self.new['tools']), \
                patch.object(jobs, 'clone_inputs', side_effect=clone), \
                patch.object(checkpoints, 'inherited', return_value={}), \
                patch.object(recovery, 'expected', return_value={}), \
                patch.object(jobs.subprocess, 'Popen') as launch:
            launch.return_value.pid = 123
            for resumed in (False, True):
                job = self.root / ('resume-job' if resumed else 'new-job')
                with patch.object(jobs, 'load', return_value=parent):
                    receipt = jobs.start(self.new_root, job, ['miri'], None, None, 10, 4096,
                        resume=self.new['recovery'] if resumed else None,
                        recovery=None if resumed else self.new['recovery'], miri_profile='extended')
                manifest = jobs.load(job, receipt)
                self.assertEqual(manifest.get(policy.FIELD), None if resumed else policy.POLICY)

    def test_both_resume_readers_reject_policy_changes(self):
        parent = copy.deepcopy(self.new)
        child = {**parent, 'resume': [{'job': str(self.old_root.parent), 'receipt': 'a' * 64}]}
        child.pop(policy.FIELD)
        with patch.object(checkpoints, 'completed', return_value=(parent, {})):
            with self.assertRaisesRegex(ValueError, 'tool policy'):
                checkpoints.inherited(child)
        reader = history.History({})
        with patch.object(reader, 'completed', return_value=(parent, {}, {})):
            with self.assertRaisesRegex(ValueError, 'tool policy'):
                reader.parents(child, 1)

    def test_recovery_uses_original_record_without_skipping_source_or_coverage(self):
        old = self.old
        old_job = self.old_root.parent
        previous = {'command': entry(), 'log_bytes': 123, 'log_sha256': 'b' * 64}
        class Reader:
            locations = {'a' * 64: old_job}
            def completed(self, *_args, **_kwargs):
                return old, {'state': 'cancelled'}, {7: previous}
        new = {**self.new, 'commands': [entry(), entry(1)]}
        with patch.object(records, 'git', return_value=b''), \
                patch.object(plans, 'build', return_value={'groups': [], 'verifiers': {'miri': []}, 'full_phases': []}), \
                patch.object(plans, 'changed_paths', return_value=[]), \
                patch.object(identity.miri_tasks, 'task_inventory', return_value=[task(), task('new')]):
            found = recovery.expected(new, self.new_root, Reader())
            self.assertEqual(set(found), {0})
            self.assertEqual(found[0]['origin'], {'receipt': 'a' * 64, 'index': 7})
            self.assertEqual(found[0]['log_sha256'], previous['log_sha256'])
            with patch.object(recovery.carry, 'disposition', return_value='run: changed source'):
                self.assertEqual(recovery.expected(new, self.new_root, Reader()), {})
