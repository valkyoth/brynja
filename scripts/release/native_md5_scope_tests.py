"""Real-Git mutations of the bounded MD5 dependency proof; no native claims."""
import copy
import subprocess
import tempfile
import unittest
from pathlib import Path

import native_dependency_scope as dependencies
import native_md5_dependency_profile as profile
import native_review_io as io
import native_review_tests as fixtures
import native_unchanged as reuse


class Md5DependencyProfileTests(unittest.TestCase):
    def test_real_cargo_feature_union_stays_inside_reviewed_roots(self):
        # Independent cross-check of the profile's feature argument. This
        # resolves metadata only, on all targets, without executing Rust/tests.
        features = ('brynja-legacy-md5/execution,brynja-legacy-md5/hardened-execution,'
                    'brynja-legacy-md5-std/runtime-execution,'
                    'brynja-legacy-md5-std/runtime-hardened-execution')
        result = subprocess.run(['cargo', '+1.98.1', 'tree', '--locked', '--offline',
            '--target', 'all', '-p', 'brynja-legacy-md5', '-p', profile.HOST,
            '--features', features, '--prefix', 'none', '--format', '{p}|{f}'],
            cwd=io.ROOT, capture_output=True, text=True, timeout=60, check=True)
        expected = {
            'brynja-core': ('0.9.0', 'default'),
            'brynja-hash-core': ('0.1.0', 'default'),
            'brynja-legacy-md5': ('0.1.0', 'batch,cpu,default,execution,hardened-execution'),
            profile.HOST: ('0.1.0', 'default,runtime-execution,runtime-hardened-execution'),
        }
        population = set()
        for line in result.stdout.splitlines():
            if not line:
                continue
            identity, enabled = line.removesuffix(' (*)').split('|')
            name = identity.split()[0]
            self.assertIn(name, expected)
            version, actual_features = expected[name]
            self.assertEqual(identity, f'{name} v{version} ({io.ROOT}/crates/{name})')
            self.assertEqual(enabled, actual_features)
            population.add(name)
        self.assertEqual(population, set(expected))

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='brynja-md5-dependency-profile-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        fixtures.init_repository(self.root)
        # Real reviewed command/manifests, not mocked digest acceptance.
        for name in ('Cargo.toml', 'Cargo.lock', *profile.REVIEWED):
            fixtures.write(self.root, name, io.read(io.ROOT, name).decode())
        for path in (io.ROOT / 'crates').glob('*/Cargo.toml'):
            name = path.relative_to(io.ROOT).as_posix()
            fixtures.write(self.root, name, io.read(io.ROOT, name).decode())
        self.closure = set(profile.REVIEWED)
        for base in profile.ROOTS:
            name = base + '/src/lib.rs'
            fixtures.write(self.root, name, 'pub fn implementation() {}\n')
            self.closure.add(name)
        self.capture = fixtures.commit(self.root)
        self.captured = self.sources()

    def sources(self):
        return {name: io.sha(io.read(self.root, name)) for name in self.closure}

    def validate(self, selected=profile.PROFILE):
        head = fixtures.commit(self.root)
        reuse.validate_inputs(self.root, self.capture, head, self.sources(),
                              self.captured, lambda name, raw: io.sha(raw),
                              dependency_profile=selected)

    def unrelated_pin(self):
        for name in ('Cargo.toml', 'Cargo.lock'):
            text = io.read(self.root, name).decode()
            self.assertIn('2.1.1', text)
            fixtures.write(self.root, name, text.replace('2.1.1', '2.1.2'))

    def test_bounded_profile_reuses_unused_pin_change_but_default_stays_conservative(self):
        self.unrelated_pin()
        with self.assertRaisesRegex(ValueError, 'absent from capture closure'):
            self.validate(None)
        self.validate()
        with self.assertRaisesRegex(ValueError, 'unknown native dependency'):
            self.validate('guess-the-features')

    def test_profile_does_not_mutate_original_lock_rows_or_omit_other_edges(self):
        rows = dependencies.graph(io.historical(self.root, self.capture, 'Cargo.lock'))
        original = copy.deepcopy(rows)
        result = profile.reachability_rows(self.root, self.capture, self.closure, rows)
        self.assertEqual(rows, original)
        self.assertEqual(set(rows[profile.HOST]['dependencies']) -
                         set(result[profile.HOST]['dependencies']), {profile.INACTIVE})
        result[profile.HOST]['dependencies'] = rows[profile.HOST]['dependencies']
        self.assertEqual(result, rows)
        projection = dependencies.projection(self.root, self.capture, self.closure, profile.PROFILE)
        self.assertIn(profile.INACTIVE, projection['lock'][profile.HOST]['dependencies'])
        self.assertEqual(set(projection['lock']), {p.split('/')[-1] for p in profile.ROOTS})

    def test_each_reviewed_command_and_manifest_rejects_drift_in_either_snapshot(self):
        for name in profile.REVIEWED:
            original = io.read(self.root, name)
            fixtures.write(self.root, name, original.decode() + '\n# changed profile\n')
            changed = fixtures.commit(self.root)
            for before, after in ((self.capture, changed), (changed, self.capture)):
                with self.subTest(name=name, before=before), self.assertRaisesRegex(
                        ValueError, 'command/manifest review changed'):
                    dependencies.equivalent(self.root, before, after, self.closure, profile.PROFILE)
            fixtures.write(self.root, name, original.decode())
            fixtures.commit(self.root)

    def test_activating_strict_defaults_or_collecting_all_features_rejects(self):
        host = 'crates/brynja-legacy-md5-std/Cargo.toml'
        collector = 'scripts/md5/capture-md5-execution-native.py'
        for name, old, new in (
            (host, 'default = []', 'default = ["strict-execution"]'),
            (host, 'optional = true', 'optional = false'),
            (collector, "'--features','execution'", "'--all-features'"),
            (collector, "'runtime-execution'", "'strict-execution'"),
        ):
            original = io.read(self.root, name).decode()
            self.assertIn(old, original)
            fixtures.write(self.root, name, original.replace(old, new))
            changed = fixtures.commit(self.root)
            with self.subTest(name=name, new=new), self.assertRaisesRegex(
                    ValueError, 'command/manifest review changed'):
                dependencies.equivalent(self.root, self.capture, changed, self.closure, profile.PROFILE)
            fixtures.write(self.root, name, original)
            fixtures.commit(self.root)

    def test_missing_or_extra_capture_roots_are_not_feature_exemptions(self):
        for closure in (self.closure - {'crates/brynja-core/Cargo.toml',
                                       'crates/brynja-core/src/lib.rs'},
                        self.closure | {'crates/brynja-hash-sha3/src/lib.rs'}):
            with self.assertRaisesRegex(ValueError, 'exact capture roots'):
                dependencies.projection(self.root, self.capture, closure, profile.PROFILE)

    def test_profiles_still_reject_runtime_build_config_and_active_dependency_changes(self):
        self.unrelated_pin()
        mutations = {
            'crates/brynja-legacy-md5/src/lib.rs': 'pub fn changed_kernel() {}\n',
            'crates/brynja-core/build.rs': 'fn main() {}\n',
            '.cargo/config.toml': '[build]\nrustflags=["--cfg", "changed"]\n',
            'crates/brynja-legacy-md5/src/orphan.rs': 'pub fn omitted_kernel() {}\n',
            'Cargo.toml': io.read(self.root, 'Cargo.toml').decode().replace(
                'resolver = "3"', 'resolver = "2"'),
            'Cargo.lock': io.read(self.root, 'Cargo.lock').decode().replace(
                'name = "brynja-core"\nversion = "0.9.0"',
                'name = "brynja-core"\nversion = "0.9.1"'),
        }
        for name, changed in mutations.items():
            path = self.root / name
            original = path.read_text() if path.exists() else None
            self.assertNotEqual(original, changed)
            fixtures.write(self.root, name, changed)
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.validate()
            if original is None:
                path.unlink()
            else:
                fixtures.write(self.root, name, original)
            fixtures.commit(self.root)

    def test_changed_lock_edge_is_not_removed_by_profile(self):
        raw = io.read(self.root, 'Cargo.lock').decode()
        start = raw.index('name = "brynja-legacy-md5-std"')
        end = raw.index('[[package]]', start)
        row = raw[start:end]
        changed = row.replace(' "brynja-legacy-md5",', ' "brynja-hash-sha3",')
        self.assertNotEqual(row, changed)
        fixtures.write(self.root, 'Cargo.lock', raw[:start] + changed + raw[end:])
        with self.assertRaisesRegex(ValueError, 'absent from capture closure'):
            self.validate()

