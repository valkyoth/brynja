"""Real-Git mutations of the bounded MD5 dependency proof; no native claims."""
import copy
import os
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path

import native_dependency_scope as dependencies
import native_md5_dependency_profile as profile
import native_review_io as io
import native_review_tests as fixtures
import native_unchanged as reuse

# Immutable v0.24.55 fixture input, not approval of a current capture. The
# historical command profile remains pinned independently in profile.REVIEWED.
FIXTURE_COMMIT = 'c0c2e069a988f41cfed010dd81c66f14b9a6578f'


class Md5DependencyProfileTests(unittest.TestCase):
    def test_real_cargo_feature_union_stays_inside_reviewed_roots(self):
        # Independent cross-check of the profile's feature argument. This
        # resolves metadata only, on all targets, without executing Rust/tests.
        features = ('brynja-legacy-md5/execution,brynja-legacy-md5/hardened-execution,'
                    'brynja-legacy-md5-std/runtime-execution,'
                    'brynja-legacy-md5-std/runtime-hardened-execution')
        # CI forces colour globally. Keep machine-readable output independent
        # of that setting; do not weaken the exact identity/feature comparisons.
        for colour in ('auto', 'always', 'never'):
            with self.subTest(ambient_colour=colour):
                result = subprocess.run(['cargo', '+1.98.1', 'tree', '--locked', '--offline',
                    '--color', 'never', '--target', 'all', '-p', 'brynja-legacy-md5',
                    '-p', profile.HOST, '--features', features, '--prefix', 'none',
                    '--format', '{p}|{f}'], cwd=io.ROOT, capture_output=True, text=True,
                    timeout=60, check=True, env=dict(os.environ, CARGO_TERM_COLOR=colour))
                self.assertNotIn('\x1b', result.stdout)
                self.assert_feature_union(result.stdout)

    def assert_feature_union(self, output, root=io.ROOT):
        # This cross-check executes Cargo in the current checkout, not the
        # frozen evidence fixture. Compare versions with that checkout's
        # manifests while keeping the allowed roots and feature sets exact.
        # This is not permission to update profile.REVIEWED or reuse evidence.
        expected = {
            'brynja-core': 'default',
            'brynja-hash-core': 'default',
            'brynja-legacy-md5': 'batch,cpu,default,execution,hardened-execution',
            profile.HOST: 'default,runtime-execution,runtime-hardened-execution',
        }
        population = set()
        for line in output.splitlines():
            if not line:
                continue
            identity, enabled = line.removesuffix(' (*)').split('|')
            name = identity.split()[0]
            self.assertIn(name, expected)
            manifest = root / 'crates' / name / 'Cargo.toml'
            package = tomllib.loads(manifest.read_text())['package']
            self.assertEqual(package['name'], name)
            self.assertIsInstance(package['version'], str)
            self.assertEqual(identity,
                f'{name} v{package["version"]} ({root}/crates/{name})')
            self.assertEqual(enabled, expected[name])
            population.add(name)
        self.assertEqual(population, set(expected))

    def feature_union_fixture(self, core_version):
        root = self.root / 'current-checkout'
        rows = (
            ('brynja-core', core_version, 'default'),
            ('brynja-hash-core', '0.1.0', 'default'),
            ('brynja-legacy-md5', '0.1.0', 'batch,cpu,default,execution,hardened-execution'),
            (profile.HOST, '0.1.0', 'default,runtime-execution,runtime-hardened-execution'),
        )
        output = []
        for name, version, features in rows:
            fixtures.write(root, f'crates/{name}/Cargo.toml',
                f'[package]\nname="{name}"\nversion="{version}"\n')
            output.append(f'{name} v{version} ({root}/crates/{name})|{features}')
        return root, '\n'.join(output) + '\n'

    def test_live_feature_union_tracks_manifest_version_bumps_not_old_literals(self):
        root, old = self.feature_union_fixture('0.9.0')
        self.assert_feature_union(old, root)
        for version in ('0.10.0', '0.11.0'):
            root, current = self.feature_union_fixture(version)
            self.assert_feature_union(current, root)
            with self.subTest(version=version), self.assertRaises(AssertionError):
                self.assert_feature_union(old, root)
            old = current

    def test_live_feature_union_still_rejects_identity_feature_and_population_drift(self):
        root, output = self.feature_union_fixture('0.10.0')
        self.assert_feature_union(output, root)
        for name in ('brynja-core', 'brynja-hash-core', 'brynja-legacy-md5', profile.HOST):
            line = next(line for line in output.splitlines() if line.startswith(name + ' '))
            version = line.split(' v', 1)[1].split(' ', 1)[0]
            for changed in (
                output.replace(f'{name} v{version}', f'{name} v9.9.9'),
                output.replace(f'({root}/crates/{name})', f'(/unreviewed/{name})'),
                output.replace(line, line + ',strict-execution'),
                output.replace(line + '\n', ''),
            ):
                with self.subTest(name=name, changed=changed), self.assertRaises(AssertionError):
                    self.assert_feature_union(changed, root)
        with self.assertRaises(AssertionError):
            self.assert_feature_union(output + 'unreviewed v1.0.0 (/unreviewed)|default\n', root)
        fixtures.write(root, 'crates/brynja-core/Cargo.toml',
            '[package]\nname="substituted-core"\nversion="0.10.0"\n')
        with self.assertRaises(AssertionError):
            self.assert_feature_union(output, root)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='brynja-md5-dependency-profile-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        fixtures.init_repository(self.root)
        io.git(self.root, 'config', 'core.autocrlf', 'false')
        # Keep the reviewed commands and their dependency graph from the same
        # immutable snapshot. Current helpers may legitimately change without
        # reapproving this historical profile. CI already fetches full history.
        names = {'Cargo.toml', 'Cargo.lock', *profile.REVIEWED}
        names.update(name for name in io.names(io.ROOT, FIXTURE_COMMIT)
                     if name.startswith('crates/') and name.count('/') == 2
                     and name.endswith('/Cargo.toml'))
        for name in sorted(names):
            raw = io.raw_blob(io.ROOT, FIXTURE_COMMIT, name)
            if name in profile.REVIEWED:
                self.assertEqual(io.sha(raw), profile.REVIEWED[name], name)
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        self.closure = set(profile.REVIEWED)
        for base in profile.ROOTS:
            name = base + '/src/lib.rs'
            fixtures.write(self.root, name, 'pub fn implementation() {}\n')
            self.closure.add(name)
        self.capture = fixtures.commit(self.root)
        self.captured = self.sources()

    def sources(self):
        return {name: io.sha(io.read(self.root, name)) for name in self.closure}

    def test_fixture_preserves_raw_historical_profile_and_dependency_graph(self):
        names = {'Cargo.toml', 'Cargo.lock', *profile.REVIEWED}
        names.update(name for name in io.names(io.ROOT, FIXTURE_COMMIT)
                     if name.startswith('crates/') and name.count('/') == 2
                     and name.endswith('/Cargo.toml'))
        self.assertEqual(io.names(self.root, self.capture),
                         names | {base + '/src/lib.rs' for base in profile.ROOTS})
        for name in sorted(names):
            with self.subTest(name=name):
                raw = io.raw_blob(self.root, self.capture, name)
                self.assertEqual(raw, io.raw_blob(io.ROOT, FIXTURE_COMMIT, name))
                if name in profile.REVIEWED:
                    self.assertEqual(io.sha(raw), profile.REVIEWED[name])

    def test_added_hmac_archive_preserves_profile_but_requires_external_review(self):
        # Replay the packaging edit that exposed this fixture bug. The current
        # helper is legitimate, but it is not the historically approved command.
        name = 'scripts/md5/check-md5-package.py'
        original = io.raw_blob(self.root, self.capture, name)
        needle = b"'brynja-mac-kmac', 'brynja-hash-tuple')"
        self.assertEqual(original.count(needle), 1)
        changed = original.replace(needle,
            b"'brynja-mac-kmac', 'brynja-hash-tuple', 'brynja-mac-hmac')")
        self.assertNotEqual(io.sha(changed), profile.REVIEWED[name])
        (self.root / name).write_bytes(changed)
        head = fixtures.commit(self.root)
        for before, after in ((self.capture, head), (head, self.capture), (head, head)):
            with self.subTest(before=before, after=after):
                self.assertTrue(dependencies.equivalent(
                    self.root, before, after, self.closure, profile.PROFILE))
        # Structural inactivity is not permission to change captured tooling.
        # The real gate supplies these pairs only after external digest approval.
        def check(changes=None):
            reuse.validate_inputs(self.root, self.capture, head, self.sources(),
                self.captured, lambda name, raw: io.sha(raw), changes, profile.PROFILE)
        with self.assertRaisesRegex(ValueError, 'native implementation/fixture/tool changed'):
            check()
        pairs = {name: {'before': io.sha(original), 'after': io.sha(changed)}}
        check(pairs)
        for field in ('before', 'after'):
            forged = copy.deepcopy(pairs)
            forged[name][field] = '0' * 64
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'reviewed validation bytes'):
                check(forged)

    def test_hmac_archive_normalization_never_changes_commands_features_or_other_bytes(self):
        original = io.raw_blob(self.root, self.capture, profile.PACKAGE)
        changed = original.replace(profile.OLD_ARCHIVES, profile.HMAC_ARCHIVES)
        self.assertEqual(profile.reviewed_bytes(profile.PACKAGE, changed), original)
        self.assertEqual(profile.reviewed_bytes('scripts/other.py', changed), changed)
        for mutant in (changed + b'\n', changed.replace(b'\n', b'\r\n'),
                       changed.replace(b"'--no-verify'", b"'--all-features'"),
                       changed.replace(b'features=["runtime-execution"]',
                                       b'features=["strict-execution"]'),
                       changed + profile.HMAC_ARCHIVES,
                       changed + profile.OLD_ARCHIVES):
            self.assertNotEqual(mutant, changed)
            self.assertNotEqual(io.sha(profile.reviewed_bytes(profile.PACKAGE, mutant)),
                                profile.REVIEWED[profile.PACKAGE])

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

    def test_all_reviewed_pins_reject_crlf_in_either_snapshot(self):
        io.git(self.root, 'config', 'core.autocrlf', 'false')
        for name, expected in profile.REVIEWED.items():
            path = self.root / name
            original = path.read_bytes()
            self.assertEqual(io.sha(original), expected)
            changed_bytes = original.replace(b'\n', b'\r\n')
            self.assertNotEqual(original, changed_bytes)
            path.write_bytes(changed_bytes)
            changed = fixtures.commit(self.root)
            self.assertEqual(io.raw_blob(self.root, changed, name), changed_bytes)
            for before, after in ((self.capture, changed), (changed, self.capture)):
                with self.subTest(name=name, before=before), self.assertRaisesRegex(
                        ValueError, 'command/manifest review changed'):
                    dependencies.equivalent(self.root, before, after, self.closure, profile.PROFILE)
            path.write_bytes(original)
            restored = fixtures.commit(self.root)
            self.assertTrue(dependencies.equivalent(
                self.root, self.capture, restored, self.closure, profile.PROFILE))

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

