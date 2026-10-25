"""Fast compatibility inventory regressions; no compiler or native rerun."""
import copy
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import api_profile_model as model
import legacy_hmac_owner_contract as contract


class LegacyOwnerTests(unittest.TestCase):
    def setUp(self):
        self.policy = model.read_policy()
        self.owner = next(row for row in self.policy['registered-secret-owner']
                          if row['id'] == 'registered.algorithm.hmac')
        self.profiles = copy.deepcopy(self.owner['compatibility_profiles'])
        self.directory = tempfile.TemporaryDirectory(prefix='brynja-legacy-owner-')
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        paths = {target.split('#')[0] for target in contract.targets()}
        paths.add(contract.LEAF + 'src/algorithms.rs')
        for name in paths:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(model.ROOT / name, path)

    def validate(self):
        contract.validate(self.root, self.profiles, self.policy['registered-secret-owner'])

    def test_legacy_profile_does_not_replace_modern_owner_or_authorize_execution(self):
        self.validate()
        with patch.object(subprocess, 'run', side_effect=AssertionError('inventory must not execute tests')):
            register = model.build_register(self.policy, model.read_surfaces())
        owner = next(row for row in register['registered_secret_owners'] if row['id'] == self.owner['id'])
        self.assertEqual(owner['symbol'], 'crates/brynja-mac-hmac/src/engine.rs#Engine')
        self.assertEqual(owner['compatibility_profiles'], [contract.RECORD])
        self.assertEqual(len(register['capabilities']), 135)
        self.assertEqual(len(register['registered_secret_owners']), 9)
        self.assertEqual({r['id'] for r in self.profiles[0]['routes']},
                         {'portable', 'sha1-execution', 'md5-batch', 'strict_execution', 'macos_resident'})
        self.assertIn('pending', self.profiles[0]['qualification'])
        self.assertIn(b'not an execution receipt', model.render_coverage(register))
        self.assertIn(b'not-dump-exclusion', model.render_coverage(register))

    def test_nested_record_fields_routes_and_claims_are_exact(self):
        baseline = copy.deepcopy(self.profiles)
        mutations = []
        for key in baseline[0]:
            value = copy.deepcopy(baseline)
            del value[0][key]
            mutations.append(value)
        for key, replacement in (('qualification', 'qualified'), ('milestone', '0.25.0'),
                                  ('admission', 'automatic'), ('compiler_checks', []),
                                  ('delegated_owners', []), ('limitations', [])):
            value = copy.deepcopy(baseline)
            value[0][key] = replacement
            mutations.append(value)
        for index in range(len(baseline[0]['routes'])):
            value = copy.deepcopy(baseline)
            del value[0]['routes'][index]
            mutations.append(value)
            value = copy.deepcopy(baseline)
            value[0]['routes'][index]['storage'] = 'all-memory-and-registers-erased'
            mutations.append(value)
        mutations.extend([[], baseline * 2, baseline + [{'id': 'invented'}]])
        for value in mutations:
            with self.subTest(profile=value), self.assertRaisesRegex(ValueError, 'canonical compatibility'):
                contract.validate(self.root, value, self.policy['registered-secret-owner'])
        print(f'Legacy owner registration: {len(mutations)} missing/altered/overclaimed records rejected', flush=True)

    def test_delegate_and_target_population_cannot_disappear(self):
        for identity in contract.RECORD['delegated_owners']:
            rows = [row for row in self.policy['registered-secret-owner'] if row['id'] != identity]
            with self.assertRaisesRegex(ValueError, 'delegated clearing owner'):
                contract.validate(self.root, self.profiles, rows)
        for name in {target.split('#')[0] for target in contract.targets()}:
            path = self.root / name
            saved = path.with_suffix(path.suffix + '.saved')
            path.rename(saved)
            try:
                with self.subTest(name=name), self.assertRaises((ValueError, OSError)):
                    self.validate()
                path.symlink_to(saved)
                with self.assertRaises(ValueError):
                    self.validate()
                path.unlink()
            finally:
                saved.rename(path)

    def test_owned_fields_seal_and_fake_destructor_reject(self):
        for name, before, after in (
            ('engine.rs', 'inner: A::State,', 'inner: core::mem::ManuallyDrop<A::State>,'),
            ('engine.rs', 'outer: A::State,', 'outer: core::mem::ManuallyDrop<A::State>,'),
            ('engine.rs', 'tag_bytes: usize,', 'tag_bytes: u64,'),
            ('engine.rs', 'impl<A: Algorithm> Engine<A> {',
             'impl<A: Algorithm> Drop for Engine<A> {}\nimpl<A: Algorithm> Engine<A> {'),
            ('algorithms.rs', 'pub(crate) mod sealed', 'pub mod sealed'),
            ('algorithms.rs', 'pub trait Algorithm: sealed::Hash', 'pub trait Algorithm: Other'),
        ):
            path = self.root / contract.LEAF / 'src' / name
            original = path.read_text()
            self.assertIn(before, original)
            try:
                path.write_text(original.replace(before, after, 1))
                with self.subTest(name=name, before=before), self.assertRaises((ValueError, contract.rust.RustContractError)):
                    self.validate()
            finally:
                path.write_text(original)

    def test_entire_legacy_source_and_fixture_inventory_is_raw_pinned(self):
        pins = {row['path'] for row in self.policy['reviewed-source']}
        self.assertLessEqual(contract.reviewed_paths(), pins)
        for tree in contract.SOURCE_TREES:
            self.assertTrue((model.ROOT / tree).is_dir(), tree)
            self.assertTrue(any(name.startswith(tree + '/') for name in pins), tree)
        read = Path.read_bytes
        for name in (contract.LEAF + 'src/engine.rs', contract.HOST + 'src/macos_resident/mod.rs',
                     'scripts/legacy-hmac/legacy_hmac_hosted_reconcile.py',
                     'assurance/legacy-hmac-hosted-cleanup/src/verification.rs',
                     'scripts/cryptography/legacy_hmac_owner_tests.py'):
            original = (model.ROOT / name).read_bytes()
            def changed(path, name=name, original=original):
                return original.replace(b'\n', b'\r\n') if path == model.ROOT / name else read(path)
            with self.subTest(name=name), patch.object(Path, 'read_bytes', changed):
                with self.assertRaisesRegex(model.ProfileError, 'reviewed secret-state source changed'):
                    model.build_register(self.policy, model.read_surfaces())

    def test_new_helpers_and_owners_are_not_outside_inventory(self):
        before = contract.reviewed_paths(self.root)
        for name in ('scripts/legacy-hmac/new.py', contract.HOST + 'src/new.rs',
                     contract.LEAF + 'src/new.rs', 'assurance/legacy-hmac-hosted-cleanup/src/new.rs'):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('// inventory probe\n')
            self.assertIn(name, contract.reviewed_paths(self.root) - before)
