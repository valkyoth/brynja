"""Inactive-feature proof mutations; synthetic hashes never qualify hardware."""
import copy
import json
import subprocess
import unittest
from unittest.mock import patch

import native_review_io as io
import native_review_scope as scope
import native_hmac_profile as profile
import native_hmac_reuse as hmac
import native_unchanged as reuse

# Keep regression inputs independent of future native collection and changes to
# the active approval manifest. Updating fixtures is an explicit review action.
POST_HMAC = '5d707623cf6c8d1898bea1f16f62caf4c66a2360'
POST_LEGACY = '542d7268c48d792c9ff784cae6d81a3dfaf5de30'


class InactiveHmacTests(unittest.TestCase):
    revision = POST_HMAC

    @classmethod
    def setUpClass(cls):
        cls.capture = profile.COMMAND_REVIEW
        cls.head = cls.revision
        index = io.document(io.raw_blob(io.ROOT, cls.head, 'security/sha2-hardened-native.json'))
        record = io.document(io.raw_blob(io.ROOT, cls.head, next(iter(index['lanes'].values()))['artifact']))
        if record['capture_commit'] != cls.capture:
            raise AssertionError('update immutable pre-HMAC fixture explicitly')
        cls.names = set(record['sources'])
        population = {name for revision in (cls.capture, cls.head)
                      for name in io.names(io.ROOT, revision) if scope.selected(name, cls.names)}
        population |= {'crates/brynja/Cargo.toml'}
        population |= {'scripts/' + name for names in profile.DRIVERS.values() for name in names}
        population |= {'assurance/' + name + '/Cargo.toml' for name in profile.FIXTURES.values()}
        cls.original = {}
        for revision in (cls.capture, cls.head):
            available = io.names(io.ROOT, revision)
            cls.original[revision] = {name: io.raw_blob(io.ROOT, revision, name)
                                      for name in population & available}

    def setUp(self):
        self.data = copy.deepcopy(self.original)
        self.mode_overrides = {}
        self.captured = {name: io.sha(self.data[self.capture][name]) for name in self.names}
        # Synthetic before/after approval pairs isolate the equivalence proof.
        # The real external-approval suite rejects absent/forged authorization.
        name = 'scripts/sha2/check-sha2-hardened-native-evidence.py'
        self.approved = {name: {'before': io.sha(self.data[self.capture][name]),
                                'after': io.sha(self.data[self.head][name])}}
        for name, replacement in (
            ('raw_blob', lambda root, revision, name: self.data[revision][name]),
            ('historical', lambda root, revision, name: io.normalized(self.data[revision][name])),
            ('tree', self.tree), ('git', lambda *args: b'')):
            mocked = patch.object(io, name, replacement)
            mocked.start()
            self.addCleanup(mocked.stop)

    def tree(self, root, revision):
        return {name: self.mode_overrides.get(name, '100644 blob ' + io.sha(raw))
                for name, raw in self.data[revision].items()}

    def current(self):
        return {name: io.sha(raw) for name, raw in self.data[self.head].items()
                if name in self.names or name in profile.ADDED}

    def validate(self, family='sha2-hardened'):
        return reuse.validate_inputs(io.ROOT, self.capture, self.head, self.current(),
            self.captured, lambda name, raw: io.sha(raw), self.approved, family=family)

    def test_complete_guarded_integration_retains_original_hash_scope_only(self):
        self.assertEqual(self.validate(), 'inactive-hmac')
        with self.assertRaisesRegex(ValueError, 'population'):
            self.validate('hmac')
        for name in profile.ADDED:
            if name in self.data[self.head]:
                # No current HMAC byte is falsely claimed as previously tested.
                self.data[self.head][name] += b'\n// HMAC requires its own qualification\n'
        self.assertEqual(self.validate(), 'inactive-hmac')

    def test_original_hash_and_current_hash_must_both_bind(self):
        self.captured[next(iter(self.captured))] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'original native source'):
            self.validate()

    def test_validation_approval_is_still_required(self):
        self.approved = {}
        with self.assertRaisesRegex(ValueError, 'active native input changed'):
            self.validate()

    def test_every_guard_and_existing_production_prefix_is_load_bearing(self):
        mutations = []
        for name, edits in profile.MODULES.items():
            raw = self.data[self.head][name]
            for _, addition in edits:
                mutations.append((name, raw.replace(addition, b'pub mod unguarded;\n', 1)))
        for name in profile.TEST_SUFFIXES:
            raw = self.data[self.head][name]
            old = self.data[self.capture][name]
            mutations += [(name, b'// changed old prefix\n' + raw),
                          (name, raw.replace(b'#[cfg(feature = ', b'#[cfg(not(feature = ', 1)),
                          (name, old + b'#[test]\nfn unguarded() {}\n')]
        for name, raw in mutations:
            original = self.data[self.head][name]
            self.data[self.head][name] = raw
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.validate()
            self.data[self.head][name] = original

    def test_kernel_orphan_config_and_build_changes_reject(self):
        names = ('crates/brynja-crypto-cpu/src/lib.rs',
                 'crates/brynja-hash-sha2/src/lib.rs',
                 profile.PREFIX + 'src/unregistered_hmac.rs',
                 profile.PREFIX + 'src/strict_hmac/new_unregistered.rs',
                 profile.PREFIX + 'build.rs', '.cargo/config.toml', 'rust-toolchain.toml')
        for name in names:
            original = self.data[self.head].get(name)
            self.data[self.head][name] = b'changed input\n'
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.validate()
            if original is None:
                del self.data[self.head][name]
            else:
                self.data[self.head][name] = original

    def test_manifest_defaults_optional_edges_versions_and_profiles_reject(self):
        name = profile.PREFIX + 'Cargo.toml'
        original = self.data[self.head][name]
        for old, new in ((b'default = []', b'default = ["hmac-execution"]'),
                         (b'optional = true', b'optional = false'),
                         (b'version = "0.1.1"', b'version = "0.1.2"'),
                         (b'"dep:brynja-mac-hmac"', b'"brynja-mac-hmac/default"')):
            self.assertIn(old, original)
            self.data[self.head][name] = original.replace(old, new)
            with self.subTest(new=new), self.assertRaises(ValueError):
                self.validate()
        self.data[self.head][name] = original
        for name in ('Cargo.toml', 'Cargo.lock'):
            original = self.data[self.head][name]
            self.data[self.head][name] = original.replace(b'2.1.1', b'2.1.2')
            self.assertNotEqual(original, self.data[self.head][name])
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.validate()
            self.data[self.head][name] = original

    def test_approved_command_changes_cannot_activate_new_features(self):
        name = 'scripts/sha2/capture-sha2-hardened-native.py'
        before = self.data[self.head][name]
        self.data[self.head][name] = before.replace(b"'brynja-crypto-cpu'", b"'brynja-crypto-cpu-std'")
        self.approved[name] = {'before': io.sha(before), 'after': io.sha(self.data[self.head][name])}
        with self.assertRaisesRegex(ValueError, 'command/feature selection changed'):
            self.validate()

    def test_deleted_and_nonregular_inputs_reject(self):
        name = profile.PREFIX + 'src/lib.rs'
        self.mode_overrides[name] = '120000 blob ' + '0' * 40
        with self.assertRaisesRegex(ValueError, 'nonregular'):
            self.validate()
        self.mode_overrides.clear()
        del self.data[self.head][name]
        with self.assertRaises(ValueError):
            self.validate()

    def test_unchanged_build_script_cannot_observe_projected_metadata(self):
        name = profile.PREFIX + 'build.rs'
        for revision in (self.capture, self.head):
            self.data[revision][name] = b'fn main() { /* can inspect Cargo.toml */ }\n'
        with self.assertRaisesRegex(ValueError, 'custom build script'):
            self.validate()


class LegacyInactiveHmacTests(InactiveHmacTests):
    revision = POST_LEGACY

    def test_resident_additions_require_enclosing_guard_and_exact_declaration(self):
        name = profile.PREFIX + 'src/macos_resident/mod.rs'
        old = self.data[self.head][name]
        for replacement in (b'pub mod memory;\npub mod memory;', b'pub use memory::*;',
                            b'#[cfg(any())]\npub mod memory;'):
            self.data[self.head][name] = old.replace(b'pub mod memory;', replacement)
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                self.validate()
        self.data[self.head][name] = old
        name = profile.PREFIX + 'src/lib.rs'
        self.assertIn(b'#[cfg(feature = "macos-resident")]', self.data[self.head][name])
        self.data[self.head][name] = self.data[self.head][name].replace(
            b'#[cfg(feature = "macos-resident")]', b'#[cfg(any())]')
        with self.assertRaises(ValueError):
            self.validate()

    def test_legacy_dependency_identity_edges_and_resident_activation_reject(self):
        name = 'Cargo.toml'
        old = self.data[self.head][name]
        entry = b'brynja-legacy-sha1 = { path = "crates/brynja-legacy-sha1", version = "=0.1.0", default-features = false }'
        self.assertIn(entry, old)
        for replacement in (entry.replace(b'false', b'true'),
                            entry.replace(b'=0.1.0', b'=0.1.1'),
                            entry.replace(b'crates/brynja-legacy-sha1', b'other'),
                            entry[:-2] + b', features = ["cpu"] }'):
            self.data[self.head][name] = old.replace(entry, replacement)
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                self.validate()
        self.data[self.head][name] = old
        name = 'Cargo.lock'
        old = self.data[self.head][name]
        row = b'name = "brynja-legacy-hmac"\nversion = "0.1.0"\ndependencies = [\n "brynja-core",'
        self.assertIn(row, old)
        for replacement in (row.replace(b'0.1.0', b'0.1.1'), row.replace(b'brynja-core', b'brynja-crypto-cpu'),
                            row.replace(b'dependencies', b'source = "registry+forged"\ndependencies')):
            self.data[self.head][name] = old.replace(row, replacement)
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                self.validate()
        self.data[self.head][name] = old
        name = profile.PREFIX + 'Cargo.toml'
        self.data[self.head][name] = self.data[self.head][name].replace(
            b'default = []', b'default = ["macos-resident"]')
        with self.assertRaises(ValueError):
            self.validate()


class HmacFeatureGraphTests(unittest.TestCase):
    def test_each_real_family_input_delta_with_synthetic_tool_review(self):
        for head in (POST_HMAC, POST_LEGACY):
            with self.subTest(head=head):
                self.check_real_families(head)

    def check_real_families(self, head):
        # Exercise all actual source populations. These are structural tests,
        # not owner approval and not a native execution claim. Gate entry points
        # still require the externally pinned manifest before reaching this.
        manifest = io.document(io.raw_blob(io.ROOT, head, 'security/native-reuse/evidence-approval.json'))
        for family in profile.FIXTURES:
            index = io.document(io.raw_blob(io.ROOT, head, 'security/' + family + '-native.json'))
            record = io.document(io.raw_blob(io.ROOT, head, next(iter(index['lanes'].values()))['artifact']))
            capture = record.get('capture_commit', record.get('commit'))
            captured = {name: io.sha(io.raw_blob(io.ROOT, capture, name)) for name in record['sources']}
            population = set(captured) | (profile.ADDED & io.names(io.ROOT, head))
            current = {name: io.sha(io.raw_blob(io.ROOT, head, name)) for name in population}
            approved = copy.deepcopy(manifest['validation_changes'].get(family, {}))
            if profile.PACKAGE in captured:
                before = io.raw_blob(io.ROOT, capture, profile.PACKAGE)
                after = io.raw_blob(io.ROOT, head, profile.PACKAGE)
                self.assertTrue(profile.replacements(before, after, (profile.ARCHIVES,)))
                approved[profile.PACKAGE] = {'before': io.sha(before), 'after': io.sha(after)}
            with self.subTest(family=family):
                self.assertEqual(reuse.validate_inputs(io.ROOT, capture, head, current, captured,
                    lambda name, raw: io.sha(raw), approved, family=family), 'inactive-hmac')

    def test_resolved_native_fixture_unions_exclude_hmac(self):
        for family, fixture in profile.FIXTURES.items():
            command = ['cargo', '+1.98.1', 'metadata', '--locked', '--offline', '--format-version', '1',
                       '--manifest-path', f'assurance/{fixture}/Cargo.toml']
            if family == 'parallelhash-execution':
                command += ['--features', 'execution']
            result = subprocess.run(command, cwd=io.ROOT, check=True, capture_output=True,
                                    timeout=60)
            graph = json.loads(result.stdout)
            with self.subTest(family=family):
                profile.feature_graph(io.ROOT, graph)
                node = next(n for n in graph['resolve']['nodes'] if any(
                    p['id'] == n['id'] and p['name'] == profile.HOST for p in graph['packages']))
                for feature in ('hmac-execution', 'macos-resident', 'strict-hmac'):
                    mutant = copy.deepcopy(graph)
                    selected = next(n for n in mutant['resolve']['nodes'] if n['id'] == node['id'])
                    selected['features'].append(feature)
                    with self.assertRaises(ValueError):
                        profile.feature_graph(io.ROOT, mutant)
                for package in profile.LEGACY | {profile.LEAF}:
                    mutant = copy.deepcopy(graph)
                    mutant['packages'].append({'id': package, 'name': package})
                    mutant['resolve']['nodes'].append({'id': package, 'features': []})
                    with self.assertRaises(ValueError):
                        profile.feature_graph(io.ROOT, mutant)


if __name__ == '__main__':
    unittest.main()
