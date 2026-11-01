"""Validate existing-task translations using metadata and fake scope mutations."""
import copy
import json
import tomllib
import unittest
from pathlib import Path
from unittest.mock import patch
import verification_miri_bindings as bindings

ROOT = Path(__file__).resolve().parents[2]


class MiriBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = json.loads((ROOT / 'verification/catalog.json').read_text())['entries']
        with patch('subprocess.Popen', side_effect=AssertionError('binding generation executed a process')):
            cls.document = bindings.build(cls.rows)

    def test_all_tasks_keep_exact_selectors_and_markers(self):
        expected = {r['id']: r for r in self.rows if r['phase'] == 'miri'}
        self.assertEqual(len(expected), 4933)
        self.assertEqual({c['id'] for c in self.document['checks']}, set(expected))
        self.assertEqual(self.document, json.loads((ROOT / 'verification/miri-checks.json').read_text()))
        for check in self.document['checks']:
            row = expected[check['id']]
            task = row['definition']['task']
            command = check['command']
            self.assertEqual(command[:8], ['cargo', '+' + bindings.NIGHTLY, 'miri', 'test', '--locked', '--offline', '--target', bindings.TARGET])
            tail = task['argv'] + ([] if '--' in task['argv'] else ['--']) + ['--nocapture']
            self.assertEqual(command[8:], tail)
            self.assertEqual(check['category'], 'miri-' + row['definition']['profile'])
            flags = check['environment']['MIRIFLAGS'].split()
            self.assertEqual(flags, ['-Zmiri-report-progress=10000000'] + ['-Zmiri-env-set=' + k + '=' + v for k, v in task['environment'].items()])
            self.assertEqual(check['success']['minimum_tests'], 1)
            if task['marker']:
                self.assertEqual(check['success']['exact_tests'], 1)
                self.assertEqual(check['success']['unique_lines'], [task['marker']])
            else:
                self.assertNotIn('exact_tests', check['success'])

    def test_explicit_build_closures_and_harnesses_are_present(self):
        checked = set()
        for check in self.document['checks']:
            if '--manifest-path' in check['command']:
                continue  # Separate workspace closures checked below.
            identity = tuple(check['inputs'])
            if identity in checked:
                continue
            checked.add(identity)
            groups = [self.document['groups'][g] for g in check['inputs']]
            paths = {p for g in groups for p in g.get('paths', [])}
            packages = {p for g in groups for lock in g.get('locks', []) for p in lock['packages']}
            for path in paths:
                self.assertTrue((ROOT / path).exists(), path)
            for package in packages - {'sanitization'}:
                self.assertIn('crates/' + package + '/src', paths)
                doc = tomllib.loads((ROOT / 'crates' / package / 'Cargo.toml').read_text())
                # No external resolver: direct nonoptional edges must remain
                # in the explicit closure; new edges force a binding review.
                sections = ['dependencies', 'build-dependencies']
                if package == check['command'][check['command'].index('-p') + 1]:
                    sections.append('dev-dependencies')
                for section in sections:
                    for name, value in doc.get(section, {}).items():
                        if not value.get('optional', False):
                            self.assertIn(name, packages, check['id'])
            self.assertTrue(all('docs/VERIFICATION_RESULTS.md' not in g.get('paths', []) for g in groups))

    def test_fixture_workspaces_use_their_own_locks_and_shared_sources(self):
        fixtures = [c for c in self.document['checks'] if '--manifest-path' in c['command']]
        self.assertEqual(len(fixtures), 18)
        for check in fixtures:
            manifest = check['command'][check['command'].index('--manifest-path') + 1]
            base = str(Path(manifest).parent)
            groups = [self.document['groups'][g] for g in check['inputs']]
            paths = {p for g in groups for p in g.get('paths', [])}
            locks = [lock for g in groups for lock in g.get('locks', [])]
            self.assertEqual({lock['path'] for lock in locks}, {base + '/Cargo.lock'})
            packages = {p for lock in locks for p in lock['packages']}
            rows = tomllib.loads((ROOT / base / 'Cargo.lock').read_text())['package']
            self.assertTrue(packages <= {r['name'] for r in rows})
            for path in paths:
                self.assertTrue((ROOT / path).exists(), path)
            manifests = {p for g in groups for p in g.get('toml', {}) if p != 'Cargo.toml'}
            for path in manifests:
                doc = tomllib.loads((ROOT / path).read_text())
                self.assertIn(doc['package']['name'], packages)
                for section in ['dependencies', 'build-dependencies']:
                    for name, value in doc.get(section, {}).items():
                        if not value.get('optional', False):
                            self.assertIn(name, packages)
            if 'legacy-hash' in manifest:
                self.assertIn('assurance/legacy-hash-public-api/src', paths)
                self.assertIn('assurance/legacy-hash-public-api/fixtures', paths)
                self.assertNotIn('brynja-legacy-md5-std', packages)
                self.assertNotIn('brynja-legacy-sha1-std', packages)
            self.assertNotIn('miri-workspace', check['inputs'])
        for argv in [
            ['--manifest-path', 'assurance/unknown/Cargo.toml', '--lib'],
            ['--manifest-path', 'assurance/legacy-hash-final/Cargo.toml', '--lib', 'dynamic_'],
            ['--manifest-path', 'assurance/static-cpu-execution/Cargo.toml', '--all-features', '--lib'],
        ]:
            with self.assertRaisesRegex(ValueError, 'unreviewed Miri fixture'):
                bindings.fixture_inputs(argv, {})

    def test_unreviewed_scope_or_identity_never_broadens(self):
        with self.assertRaises(ValueError):
            bindings.closure('unknown-crate', set())
        with self.assertRaises(ValueError):
            bindings.closure('brynja-legacy-md5', {'new-feature'})
        row = copy.deepcopy(next(r for r in self.rows if r['phase'] == 'miri'))
        row['definition']['task']['argv'] += ['--all-features']
        with self.assertRaisesRegex(ValueError, 'identity'):
            bindings.build([row])

    def test_component_closures_do_not_reopen_unrelated_algorithms(self):
        self.assertEqual(bindings.closure('brynja-legacy-md5', {'cpu'}), bindings.BASE | {'brynja-legacy-md5'})
        self.assertNotIn('brynja-legacy-md5', bindings.closure('brynja-mac-hmac', {'hardened-execution'}))
        self.assertNotIn('brynja-mac-hmac', bindings.closure(bindings.HOST, {'runtime-execution'}))
        self.assertIn('brynja-mac-hmac', bindings.closure(bindings.HOST, {'hmac-execution'}))
        self.assertIn('sanitization', bindings.closure('brynja-sanitization', set()))
