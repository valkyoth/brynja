"""Exact reviewed subset coverage; no arbitrary whole-suite success inference."""
import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import miri_cases
import miri_tasks
import miri_split_review as review
import miri_coverage_identity as identity
import detached_recovery as recovery
import verification_carry_forward as carry
import verification_plan as plans
from miri_coverage_tests import entry


class SplitReuseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.old, self.new = (Path(self.temp.name) / name for name in ('old', 'new'))
        self.old.mkdir()
        self.new.mkdir()
        self.current, self.previous = {}, {}
        for group in review.TESTS:
            self.current[group] = miri_tasks.task_inventory(plans.ROOT, group, 'extended')
            self.previous[group] = miri_cases.tasks(group, miri_tasks.inventory(plans.ROOT, group),
                                                    'extended', legacy=True)
        self.pins, tests, support = {}, {}, {}
        for name in review.decomposition.REVISIONS:
            self.pins[name] = self.install_pair(name)
        for group, (name, _, _) in review.TESTS.items():
            tests[group] = (name, *self.install_pair(name))
        for group, (name, _) in review.SUPPORT.items():
            support[group] = (name, self.install_pair(name, same=True)[0])
        for obj, attr, value in ((review.decomposition, 'REVISIONS', self.pins),
                                 (review, 'TESTS', tests), (review, 'SUPPORT', support)):
            patched = patch.object(obj, attr, value)
            patched.start()
            self.addCleanup(patched.stop)
        catalog = patch.object(miri_tasks, 'task_inventory', side_effect=lambda root, group, profile:
                               self.previous[group] if root == self.old else self.current[group])
        catalog.start()
        self.addCleanup(catalog.stop)

    def install_pair(self, name, same=False):
        raw = [(name + ':old\n').encode(), (name + (':old\n' if same else ':new\n')).encode()]
        for root, value in zip((self.old, self.new), raw):
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(value)
        return tuple(hashlib.sha256(value).hexdigest() for value in raw)

    def command(self, group, index):
        return entry(index, group=group)

    def keys(self, group):
        coverage = identity.Coverage(self.old, self.new)
        return coverage, {coverage.old.key(self.command(group, i)): i
                          for i in range(len(self.previous[group]))}

    def test_all_1040_tuple_widths_map_only_to_their_own_208_cases(self):
        coverage, old_keys = self.keys('tuplehash')
        mapped = {}
        for i, task in enumerate(self.current['tuplehash']):
            if 'BRYNJA_MIRI_WIDTH' not in task['environment']:
                continue
            sources = [old_keys[key] for key in coverage.keys_for(self.command('tuplehash', i)) if key in old_keys]
            self.assertEqual(len(sources), 1)
            mapped.setdefault(sources[0], []).append(task['environment']['BRYNJA_MIRI_WIDTH'])
        self.assertEqual(len(mapped), 208)
        self.assertTrue(all(widths == ['0', '1', '2', '3', '4'] for widths in mapped.values()))

    def test_all_setup_cases_and_three_verification_tests_need_the_old_full_success(self):
        coverage, keys = self.keys('kmac')
        mapped = []
        for i, task in enumerate(self.current['kmac']):
            if review.SETUP not in task['argv'] and not any(n in task['argv'] for n in review.VERIFICATION):
                continue
            if task['argv'][-2:] != ['--', '--exact']:
                continue
            indices = [keys[key] for key in coverage.keys_for(self.command('kmac', i)) if key in keys]
            self.assertEqual(indices, [0])
            mapped.append(i)
        self.assertEqual(len(mapped), 103)
        # No earlier passing sub-line of a failed broad command is considered.
        for i in mapped:
            self.assertFalse(carry.covered(self.command('kmac', i), [], roots=(self.old, self.new)))

    def test_unknown_source_catalog_and_support_edits_reject_split_mapping(self):
        i = next(i for i, task in enumerate(self.current['tuplehash']) if 'BRYNJA_MIRI_WIDTH' in task['environment'])
        for root, name in [(self.old, review.TESTS['tuplehash'][0]),
                           (self.new, review.TESTS['tuplehash'][0]),
                           (self.new, review.SUPPORT['tuplehash'][0]),
                           (self.new, next(iter(self.pins)))]:
            with self.subTest(root=root, name=name):
                path = root / name
                original = path.read_bytes()
                path.write_bytes(original + b'changed assertion\n')
                coverage, keys = self.keys('tuplehash')
                self.assertFalse(set(coverage.keys_for(self.command('tuplehash', i))) & keys.keys())
                path.write_bytes(original)

    def test_no_reverse_width_to_full_or_cross_case_strength_and_profile_mapping(self):
        group = 'tuplehash'
        i = next(i for i, task in enumerate(self.current[group]) if 'BRYNJA_MIRI_WIDTH' in task['environment'])
        coverage, keys = self.keys(group)
        origin = next(keys[key] for key in coverage.keys_for(self.command(group, i)) if key in keys)
        self.assertFalse(coverage.covers(self.command(group, origin + 1), self.command(group, i)))
        self.assertFalse(coverage.covers(entry(origin, 'routine', group), self.command(group, i)))
        reverse = identity.Coverage(self.new, self.old)
        self.assertFalse(reverse.covers(self.command(group, i), self.command(group, origin)))

    def test_shape_mutations_and_parallelhash_never_inherit_split_success(self):
        tuple_task = next(t for t in self.current['tuplehash'] if 'BRYNJA_MIRI_WIDTH' in t['environment'])
        for change in ({'coverage': 'unreviewed'}, {'marker': 'different'},
                       {'environment': {**tuple_task['environment'], 'BRYNJA_MIRI_WIDTH': '5'}},
                       {'environment': {**tuple_task['environment'], 'BRYNJA_MIRI_CASE': '999'}},
                       {'argv': [*tuple_task['argv'], '--skip', 'anything']}):
            with self.subTest(change=change):
                self.assertIsNone(review.predecessor({**tuple_task, **change}, 'tuplehash', 'extended', self.previous['tuplehash']))
        self.assertIsNone(review.predecessor(tuple_task, 'parallelhash', 'extended', self.previous['tuplehash']))
        self.assertIsNone(review.predecessor(tuple_task, 'tuplehash', 'routine', self.previous['tuplehash']))
        self.assertFalse(review.reviewed_roots(self.old, self.new, 'parallelhash'))

    def test_kmac_filtered_ignored_and_wrong_feature_suite_does_not_cover_setup(self):
        task = next(t for t in self.current['kmac'] if t['marker'] == 'MIRI_CASE_PASS: kmac-streamed-setup:0')
        old = self.previous['kmac'][0]
        for argv in ([*old['argv'], '--skip', review.SETUP],
                     [*old['argv'], '--skip', 'setup'], [*old['argv'], '--ignored'],
                     ['-p', 'brynja-mac-kmac', '--lib', *old['argv'][3:]],
                     ['-p', 'brynja-mac-kmac', '--features', 'conformance-testing', *old['argv'][2:]]):
            self.assertIsNone(review.predecessor(task, 'kmac', 'extended', [{**old, 'argv': argv}]))

    def test_source_permission_does_not_cover_new_broad_suite_or_bypass_tool_gate(self):
        current = self.command('kmac', 57)
        context = {'plan': {'groups': ['kmac'], 'verifiers': {'miri': ['kmac']},
                           'full_phases': ['miri'], 'evidence': {'changed_paths': list(self.pins)}},
                   'manifest': {'commands': [self.command('kmac', 0)]},
                   'public_checkpoint': False, 'coverage_roots': (self.old, self.new),
                   'miri_split_groups': {'kmac'}}
        self.assertTrue(carry.disposition(current, context).startswith('reuse:'))
        for delta in ({'tool_drift': {'miri': 'changed'}}, {'public_checkpoint': True},
                      {'miri_split_groups': set()}, {'manifest': {'commands': []}}):
            self.assertTrue(carry.disposition(current, {**context, **delta}).startswith('run:'))
        self.assertTrue(carry.disposition(self.command('kmac', 0), context).startswith('run:'))

    def test_recovery_expands_only_completed_covered_cases_with_original_log_identity(self):
        receipt = 'a' * 64
        previous = {'command': self.command('kmac', 0), 'log_bytes': 123,
                    'log_sha256': 'b' * 64}
        plan = {'stage': 'internal', 'verification_mode': 'affected'}
        old = {'tools': {}, 'sources': {'head': 'c' * 40}, 'plan': plan}
        exact = next(i for i, task in enumerate(self.current['kmac'])
                     if task['marker'] == 'MIRI_CASE_PASS: kmac-streamed-setup:0')
        manifest = {'schema': 3, 'tools': {}, 'plan': plan,
                    'recovery': [{'job': str(self.old.parent), 'receipt': receipt}],
                    'commands': [self.command('kmac', 0), self.command('kmac', exact),
                                 self.command('kmac', exact + 1)]}
        # Recovery obtains the historical root as <job>/source.
        historical_root = self.old
        old_job = self.old.parent
        class Reader:
            locations = {receipt: old_job}
            def completed(self, *_args, **_kwargs):
                return old, {'state': 'cancelled'}, {7: previous}
        real_coverage = identity.Coverage
        with patch.object(recovery.records, 'git', return_value=b''), \
                patch.object(recovery.plans, 'build', return_value={
                    'groups': ['kmac'], 'verifiers': {'miri': ['kmac']}, 'full_phases': ['miri']}), \
                patch.object(recovery.plans, 'changed_paths', return_value=list(self.pins)), \
                patch.object(review.decomposition, 'prove', return_value=set()), \
                patch.object(review, 'source_groups', return_value={'kmac'}), \
                patch.object(carry.test_only, 'prove', return_value=set()), \
                patch.object(identity, 'Coverage', side_effect=lambda _old, new: real_coverage(historical_root, new)):
            result = recovery.expected(manifest, self.new, Reader())
            self.assertEqual(set(result), {1, 2})
            for record in result.values():
                self.assertEqual(record['state'], 'reused')
                self.assertEqual(record['origin'], {'receipt': receipt, 'index': 7})
                self.assertEqual(record['log_sha256'], previous['log_sha256'])
                self.assertEqual(record['log_bytes'], previous['log_bytes'])
            with patch.object(Reader, 'completed', return_value=(old, {'state': 'cancelled'}, {})):
                self.assertEqual(recovery.expected(manifest, self.new, Reader()), {})
            with patch.object(review, 'source_groups', return_value=set()):
                self.assertEqual(recovery.expected(manifest, self.new, Reader()), {})

    def test_source_scope_rejects_other_family_edits_and_unknown_upstream(self):
        def git(*args):
            return subprocess.check_output(['git', '-c', 'user.name=Test', '-c',
                'user.email=test@example.invalid', '-c', 'commit.gpgsign=false', *args],
                cwd=self.new, stderr=subprocess.DEVNULL)
        def write(path, raw):
            target = self.new / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
        # Preserve endpoint fixtures while recording the before-tree in Git.
        changed = {str(p.relative_to(self.new)): p.read_bytes() for p in self.new.rglob('*') if p.is_file()}
        for p in self.old.rglob('*'):
            if p.is_file():
                write(str(p.relative_to(self.old)), p.read_bytes())
        for path in ('Cargo.lock', 'rust-toolchain.toml', 'assurance/policy.toml'):
            write(path, (plans.ROOT / path).read_bytes())
        write('release-crates.toml', b'[release]\nversion="0.25.2"\nstage="public"\nverification="full"\n')
        git('init', '-q')
        git('add', '.')
        git('commit', '-qm', 'before')
        base = git('rev-parse', 'HEAD').decode().strip()
        for path, raw in changed.items():
            write(path, raw)
        def eligible():
            return review.source_groups(self.new, base, plans.changed_paths(self.new, base))
        self.assertEqual(eligible(), {'kmac', 'tuplehash'})
        write('crates/brynja-mac-kmac/src/extra.rs', b'new implementation\n')
        self.assertEqual(eligible(), {'tuplehash'})
        write('crates/brynja-hash-sha3/src/extra.rs', b'new dependency code\n')
        self.assertEqual(eligible(), set())


class SplitReviewEndpoints(unittest.TestCase):
    def test_current_source_endpoints_match_review(self):
        for group, (path, _, expected) in review.TESTS.items():
            self.assertEqual(hashlib.sha256((plans.ROOT / path).read_bytes()).hexdigest(), expected)
            path, expected = review.SUPPORT[group]
            self.assertEqual(hashlib.sha256((plans.ROOT / path).read_bytes()).hexdigest(), expected)
