#!/usr/bin/env python3
"""Check explicit portable registrations and fixture versions without running crypto."""
import copy
from pathlib import Path
import re
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[2]

# Reviewed, explicit build closures for these portable harness commands only.
# This is not automatic feature/dependency analysis or a release-family planner.
CLOSURES = {
    'brynja-legacy-md5': {'brynja-core', 'brynja-hash-core'},
    'brynja-legacy-sha1': {'brynja-core', 'brynja-hash-core'},
    'brynja-hash-sha2': {'brynja-core', 'brynja-hash-core'},
    'brynja-hash-sha3': {'brynja-core', 'brynja-hash-core'},
    'brynja-mac-kmac': {'brynja-core', 'brynja-hash-core', 'brynja-hash-sha3'},
    'brynja-hash-tuple': {'brynja-core', 'brynja-hash-core', 'brynja-hash-sha3'},
    'brynja-mac-hmac': {'brynja-core', 'brynja-hash-core', 'brynja-hash-sha2', 'brynja-hash-sha3'},
    'brynja-legacy-hmac': {'brynja-core', 'brynja-hash-core', 'brynja-legacy-md5', 'brynja-legacy-sha1'},
    # Cargo builds these dev dependencies even though the portable vector
    # harness does not request native execution. Their inputs are not omitted.
    'brynja-hash-parallel': {'brynja-core', 'brynja-hash-core', 'brynja-hash-sha3',
                           'brynja-hash-sha2', 'brynja-crypto-cpu', 'brynja-crypto-cpu-std'},
}


def validate(registry):
    seen = set()
    for check in registry['checks']:
        key = (check['component'], check['id'])
        assert key not in seen, 'duplicate check'
        seen.add(key)
        argv = check['command']
        assert argv[:3] == ['cargo', '+1.99.1', 'test'], 'unexpected executable'
        assert all(flag in argv for flag in ('--offline', '--locked', '--no-default-features'))
        assert '--workspace' not in argv and '--all-features' not in argv
        package = argv[argv.index('-p') + 1]
        harness = argv[argv.index('--test') + 1]
        assert package in CLOSURES
        groups = [registry['groups'][name] for name in check['inputs']]
        paths = {path for group in groups for path in group.get('paths', [])}
        manifests = {path for group in groups for path in group.get('toml', {})}
        locks = {name for group in groups for lock in group.get('locks', []) for name in lock['packages']}
        for name in CLOSURES[package] | {package}:
            assert f'crates/{name}/src' in paths, f'missing source: {name}'
            assert f'crates/{name}/Cargo.toml' in manifests, f'missing manifest: {name}'
            assert name in locks, f'missing lock row: {name}'
        test = f'crates/{package}/tests/{harness}.rs'
        assert test in paths, 'missing harness input'
        source = (ROOT / test).read_text()
        assert check['success']['minimum_tests'] >= 1
        for marker in check['success']['contains']:
            if marker.startswith('test ') and marker.endswith(' ... ok'):
                name = marker.removeprefix('test ').removesuffix(' ... ok')
                assert re.search(r'#\[test\]\s*fn ' + re.escape(name) + r'\(', source), marker
        for path in paths:
            assert (ROOT / path).exists(), f'missing input: {path}'
        assert not any(path in ('verification/results.json', 'docs/VERIFICATION_RESULTS.md') for path in paths)
    assert {c['command'][c['command'].index('-p') + 1] for c in registry['checks']} == set(CLOSURES)


class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.registry = tomllib.loads((ROOT / 'verification/checks.toml').read_text())

    def test_registered_harnesses_and_explicit_closures(self):
        validate(self.registry)

    def test_missing_transitive_source_and_harness_are_rejected(self):
        for group in ('hash-core', 'md5-api'):
            changed = copy.deepcopy(self.registry)
            changed['groups'][group]['paths'] = []
            with self.assertRaises(AssertionError):
                validate(changed)

    def test_zero_population_or_wrong_marker_is_rejected(self):
        for field, value in (('minimum_tests', 0), ('contains', ['test not_a_test ... ok'])):
            changed = copy.deepcopy(self.registry)
            changed['checks'][0]['success'][field] = value
            with self.assertRaises(AssertionError):
                validate(changed)

    def test_facade_fixture_versions_follow_actual_local_package(self):
        version = tomllib.loads((ROOT / 'crates/brynja/Cargo.toml').read_text())['package']['version']
        for path in (ROOT / 'assurance').glob('*/Cargo.toml'):
            doc = tomllib.loads(path.read_text())
            dependency = doc.get('dependencies', {}).get('brynja', {})
            if isinstance(dependency, dict) and dependency.get('path'):
                assert dependency.get('version', '=' + version) == '=' + version, str(path)


if __name__ == '__main__':
    unittest.main()
