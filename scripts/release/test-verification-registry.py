#!/usr/bin/env python3
"""Check explicit portable registrations and fixture versions without running crypto."""
import copy
from pathlib import Path
import re
import tomllib
import unittest
import verification_hkdf_dynamic_tests as hkdf_dynamic
from verification_sanitizer_tests import SanitizerRegistryTests
from verification_miri_tests import MiriBindingTests
from verification_kani_tests import KaniBindingTests
from verification_additional_tests import AdditionalBindingTests
from verification_script_tests import ScriptBindingTests
from verification_assessment_tests import AssessmentBindingTests
from verification_engine_tests import EngineBindingTests
from verification_md5_checker_tests import Md5CheckerBindingTests
from verification_hosted_tests import HostedBindingTests
from verification_compiler_tests import CompilerBindingTests
from verification_codegen_tests import CodegenBindingTests
from verification_shell_tests import ShellBindingTests
from verification_checker_tests import CheckerBindingTests
from verification_source_policy_tests import PolicyBindingTests
from verification_legacy_policy_tests import LegacyPolicyBindingTests
from verification_hardened_tests import HardenedBindingTests
from verification_inventory_tests import InventoryBindingTests
from verification_control_tests import ControlBindingTests
from verification_record_policy_tests import RecordPolicyBindingTests
from verification_package_tests import PackageBindingTests
from verification_execution_tests import ExecutionBindingTests
from verification_owner_tests import OwnerBindingTests
from verification_acceptance_tests import AcceptanceBindingTests
from verification_final_tests import FinalBindingTests

ROOT = Path(__file__).resolve().parents[2]

# Reviewed, explicit build closures for these portable harness commands only.
# This is not automatic feature/dependency analysis or a release-family planner.
CLOSURES = {
    'brynja-legacy-hkdf': {'brynja-core', 'brynja-hash-core', 'brynja-legacy-hmac',
                          'brynja-legacy-sha1', 'brynja-legacy-md5'},
    # HKDF metadata is tested through the composition crate, so its default
    # compiled dependencies remain declared even though no hash is exercised.
    'brynja-crypto': {'brynja-core', 'brynja-hash-core', 'brynja-hash-sha2',
                      'brynja-hash-sha3', 'brynja-hash-tuple', 'brynja-hash-parallel',
                      'brynja-mac-kmac', 'brynja-mac-hmac'},
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
        if check.get('category', 'portable') != 'portable':
            continue
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
    assert {c['command'][c['command'].index('-p') + 1] for c in registry['checks'] if c.get('category', 'portable') == 'portable'} == set(CLOSURES)


class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.registry = tomllib.loads((ROOT / 'verification/checks.toml').read_text())

    def test_registered_harnesses_and_explicit_closures(self):
        validate(self.registry)

    def test_hkdf_optimized_checks_reuse_exact_existing_suites(self):
        selected = [c for c in self.registry['checks']
                    if c['component'] in ('hkdf', 'legacy_hkdf') and c.get('category') == 'optimized']
        self.assertEqual(len(selected), 4)
        self.assertEqual(self.registry['groups']['hkdf-optimized']['toml'],
                         {'Cargo.toml': ['profile.release']})
        for check in selected:
            original = next(c for c in self.registry['checks']
                            if c['component'] == check['component']
                            and c['id'] == check['id'].removeprefix('optimized-'))
            self.assertEqual([arg for arg in check['command'] if arg != '--release'], original['command'])
            self.assertEqual(check['command'].count('--release'), 1)
            self.assertEqual(set(check['inputs']), set(original['inputs']) | {'hkdf-optimized'})
            self.assertEqual(check['success'], original['success'])
            self.assertIn('CARGO_PROFILE_RELEASE_OPT_LEVEL', check['reject_environment'])
            self.assertIn('CARGO_PROFILE_RELEASE_LTO', check['reject_environment'])
            self.assertNotIn('--workspace', check['command'])
            self.assertNotIn('--all-features', check['command'])

    def test_hkdf_owner_compiler_checks_are_separate_and_scoped(self):
        for component, family, package in (
                ('hkdf', 'modern', 'brynja-crypto'),
                ('legacy_hkdf', 'legacy', 'brynja-legacy-hkdf')):
            check, = [c for c in self.registry['checks']
                      if c['component'] == component and c['id'] == 'owner-dispatch']
            self.assertEqual(check['command'],
                             ['python3', 'scripts/hkdf/check-hkdf-owner-cleanup.py', family])
            self.assertEqual(check['category'], 'compiler')
            self.assertTrue({'compiler', 'hkdf-msrv', 'hkdf-owner-codegen'} <= set(check['inputs']))
            paths = {p for group in check['inputs'] for p in self.registry['groups'][group].get('paths', [])}
            for dependency in CLOSURES[package] | {package}:
                self.assertIn(f'crates/{dependency}/src', paths)
            self.assertIn('assurance/hkdf-owner-cleanup/Cargo.lock', paths)
            self.assertEqual(len(check['success']['contains']), 5)
            for compiler in ('1.90.0', '1.99.1'):
                for panic in ('abort', 'unwind'):
                    self.assertTrue(any(f'Rust {compiler}; x86_64; panic={panic};' in signal
                                        for signal in check['success']['contains']))

    def test_hkdf_operation_compiler_checks_are_separate_and_scoped(self):
        for component, family, package, consumers, mutations in (
                ('hkdf', 'modern', 'brynja-crypto', 18, 120),
                ('legacy_hkdf', 'legacy', 'brynja-legacy-hkdf', 2, 15)):
            check, = [c for c in self.registry['checks']
                      if c['component'] == component and c['id'] == 'operation-scratch']
            self.assertEqual(check['command'],
                             ['python3', 'scripts/hkdf/check-hkdf-operation-cleanup.py', family])
            self.assertEqual(check['category'], 'compiler')
            self.assertTrue({'compiler', 'hkdf-msrv', 'hkdf-operation-codegen'} <= set(check['inputs']))
            paths = {p for group in check['inputs'] for p in self.registry['groups'][group].get('paths', [])}
            for dependency in CLOSURES[package] | {package}:
                self.assertIn(f'crates/{dependency}/src', paths)
            self.assertIn('scripts/hmac/hmac_engine_scratch.py', paths)
            if family == 'modern':
                self.assertIn('assurance/hkdf-operation-cleanup/Cargo.lock', paths)
                self.assertIn('assurance/hkdf-operation-cleanup/src', paths)
            else:
                self.assertIn('hkdf-optimized', check['inputs'])
            signals = check['success']['contains']
            self.assertEqual(len(signals), 5)
            for compiler in ('1.90.0', '1.99.1'):
                for panic in ('abort', 'unwind'):
                    self.assertIn(f'HKDF {family} operation scratch: PASS; Rust {compiler}; x86_64; '
                                  f'panic={panic}; {consumers} consumers; {mutations} rejected mutations', signals)

    def test_hkdf_timing_screens_are_diagnostics_with_exact_populations(self):
        for component, family, package, count in (
                ('hkdf', 'modern', 'brynja-crypto', 36),
                ('legacy_hkdf', 'legacy', 'brynja-legacy-hkdf', 5)):
            check, = [c for c in self.registry['checks']
                      if c['component'] == component and c['id'] == 'timing-screen']
            self.assertEqual(check['command'], ['python3', 'scripts/hkdf/check-hkdf-timing.py', family])
            self.assertEqual(check['category'], 'timing')
            self.assertEqual(check['platform'], 'linux-x86_64')
            paths = {p for group in check['inputs'] for p in self.registry['groups'][group].get('paths', [])}
            for dependency in CLOSURES[package] | {package}:
                self.assertIn(f'crates/{dependency}/src', paths)
            self.assertIn('assurance/hkdf-timing/Cargo.lock', paths)
            self.assertIn('scripts/hmac/hmac_timing.py', paths)
            self.assertIn('Independent HKDF timing preflight: PASS', check['success']['unique_lines'])
            self.assertIn(f'HKDF {family} timing screen: {count} campaigns; 512 pairs; 4 repetitions; zero alarms',
                          check['success']['unique_lines'])
            self.assertIn('not constant-time', check['establishes'])
            self.assertIn('No automatic retry', check['establishes'])

    def test_hkdf_dynamic_bindings_and_negative_controls(self):
        hkdf_dynamic.validate(self.registry, CLOSURES)
        hkdf_dynamic.negative_controls(self.registry, CLOSURES)

    def test_missing_transitive_source_and_harness_are_rejected(self):
        for group in ('hash-core', 'md5-api'):
            changed = copy.deepcopy(self.registry)
            changed['groups'][group]['paths'] = []
            with self.assertRaises(AssertionError):
                validate(changed)

    def test_zero_population_or_wrong_marker_is_rejected(self):
        for field, value in (('minimum_tests', 0), ('contains', ['test not_a_test ... ok'])):
            changed = copy.deepcopy(self.registry)
            check = next(c for c in changed['checks'] if c.get('category', 'portable') == 'portable')
            check['success'][field] = value
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
