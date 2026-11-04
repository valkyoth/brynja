#!/usr/bin/env python3
"""Check explicit portable registrations and fixture versions without running crypto."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
import tomllib
import unittest
import verification_hkdf_dynamic_tests as hkdf_dynamic
import verification_hkdf_public_dynamic_tests as hkdf_public_dynamic
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

# Include fail-closed runner tests in the normal registry regression suite.
aes_spec = importlib.util.spec_from_file_location('aes_runner_tests', ROOT / 'scripts/aes/test-aes-runners.py')
aes_runner_tests = importlib.util.module_from_spec(aes_spec)
aes_spec.loader.exec_module(aes_runner_tests)
AesApiRunnerTests = aes_runner_tests.ApiTests
AesKaniRunnerTests = aes_runner_tests.KaniTests
AesMutationTests = aes_runner_tests.MutationTests
AesOwnerCodegenTests = aes_runner_tests.OwnerCodegenTests
AesOperationCodegenTests = aes_runner_tests.OperationCodegenTests

aes_consumer_spec = importlib.util.spec_from_file_location('aes_consumer_tests', ROOT / 'scripts/aes/test-aes-consumer.py')
aes_consumer_tests = importlib.util.module_from_spec(aes_consumer_spec)
aes_consumer_spec.loader.exec_module(aes_consumer_tests)
AesConsumerTests = aes_consumer_tests.ConsumerTests

aes_timing_spec = importlib.util.spec_from_file_location('aes_timing_tests', ROOT / 'scripts/aes/test-aes-timing.py')
aes_timing_tests = importlib.util.module_from_spec(aes_timing_spec)
aes_timing_spec.loader.exec_module(aes_timing_tests)
AesTimingTests = aes_timing_tests.TimingTests
aes_dataflow_spec = importlib.util.spec_from_file_location('aes_dataflow_tests', ROOT / 'scripts/aes/test-aes-dataflow.py')
aes_dataflow_tests = importlib.util.module_from_spec(aes_dataflow_spec)
aes_dataflow_spec.loader.exec_module(aes_dataflow_tests)
AesDataflowTests = aes_dataflow_tests.DataflowTests
sys.path.insert(0, str(ROOT / 'scripts/cryptography'))
aes_contract_spec = importlib.util.spec_from_file_location('aes_contract_tests', ROOT / 'scripts/cryptography/test-aes-owner-contract.py')
aes_contract_tests = importlib.util.module_from_spec(aes_contract_spec)
aes_contract_spec.loader.exec_module(aes_contract_tests)
AesDevelopmentOwnerTests = aes_contract_tests.OwnerContractTests

provider_spec = importlib.util.spec_from_file_location('aes_provider_tests', ROOT / 'scripts/aes/test-aes-provider-runner.py')
provider_tests = importlib.util.module_from_spec(provider_spec)
provider_spec.loader.exec_module(provider_tests)
AesProviderRunnerTests = provider_tests.ProviderRunnerTests

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
        if '--lib' in argv:
            assert key == ('hkdf', 'parameters'), 'unexpected library test selection'
            assert argv[-2:] == ['--lib', 'hkdf::parameters::tests::']
            test = 'crates/brynja-crypto/src/hkdf/parameter_tests.rs'
        else:
            assert '--test' in argv, 'missing test harness selection'
            harness = argv[argv.index('--test') + 1]
            test = f'crates/{package}/tests/{harness}.rs'
        assert package in CLOSURES
        groups = [registry['groups'][name] for name in check['inputs']]
        paths = {path for group in groups for path in group.get('paths', [])}
        manifests = {path for group in groups for path in group.get('toml', {})}
        locks = {name for group in groups for lock in group.get('locks', []) for name in lock['packages']}
        for name in CLOSURES[package] | {package}:
            assert f'crates/{name}/src' in paths, f'missing source: {name}'
            assert f'crates/{name}/Cargo.toml' in manifests, f'missing manifest: {name}'
            assert name in locks, f'missing lock row: {name}'
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

    def test_aes_initial_checks_pin_harnesses_and_counts(self):
        checks = {c['id']: c for c in self.registry['checks'] if c['component'] == 'aes'}
        expected = {'vectors': 6, 'rounds-and-faults': 7, 'msrv-vectors': 6,
                    'ownership': 11, 'optimized-vectors': 6, 'no-std-thumb': 0,
                    'asan-vectors': 6, 'miri-ownership': 1, 'asan-faults': 7,
                    'miri-public': 1, 'differential': 1, 'field-layout-proof': 0,
                    'api-msrv': 0, 'api-current': 0, 'mutation-controls': 0,
                    'owner-dispatch': 0, 'operation-cleanup': 0, 'owner-contract': 0,
                    'downstream': 0, 'downstream-matrix': 0, 'timing-screen': 0,
                    'dataflow-review': 0, 'provider-native': 12, 'provider-msrv': 12,
                    'provider-asan': 12, 'provider-miri': 12, 'provider-api-current': 0,
                    'provider-api-msrv': 0, 'provider-no-std': 0, 'provider-docs': 1}
        self.assertEqual(set(checks), set(expected))
        for name, count in expected.items():
            check = checks[name]
            for field in ('component', 'id', 'category'):
                self.assertRegex(check[field], r'^[a-z0-9_-]+$')
            self.assertIn('aes-build', check['inputs'])
            self.assertNotIn('--workspace', check['command'])
            if check['command'][0] == 'cargo':
                command = check['command']
                self.assertIn('--features', command)
                features = 'hazmat-aes-block,external-key-provider' if name.startswith('provider-') else 'hazmat-aes-block'
                self.assertEqual(command[command.index('--features') + 1], features)
            if count:
                self.assertEqual(check['success']['exact_tests'], count)
                self.assertEqual(check['success']['minimum_tests'], count)
            self.assertIn('RUSTC_WRAPPER', check['reject_environment'])
        self.assertEqual(checks['rounds-and-faults']['command'][-2:], ['--lib', 'aes::'])
        self.assertEqual(checks['ownership']['command'][-2:], ['--doc', 'aes::'])
        self.assertEqual(checks['miri-ownership']['command'][-3:],
                         ['output_outlives_key_and_explicit_clear_preserves_canaries', '--', '--exact'])
        for name in ('vectors','msrv-vectors','optimized-vectors','asan-vectors'):
            command = checks[name]['command']
            self.assertEqual(command[command.index('--test') + 1], 'aes128')
        sanitizer = checks['asan-vectors']
        self.assertEqual(sanitizer['command'][:3], ['cargo', '+nightly-2026-09-11', 'test'])
        self.assertEqual(sanitizer['environment']['RUSTFLAGS'], '-Zsanitizer=address')
        self.assertEqual(sanitizer['environment']['ASAN_OPTIONS'], 'detect_leaks=1:halt_on_error=1:exitcode=1')
        self.assertEqual(sanitizer['environment']['LSAN_OPTIONS'], 'exitcode=23')
        self.assertEqual(sanitizer['environment']['CARGO_ENCODED_RUSTFLAGS'], '')
        self.assertIn('asan-tools', sanitizer['inputs'])
        miri = checks['miri-ownership']
        self.assertEqual(miri['command'][:4], ['cargo', '+nightly-2026-09-11', 'miri', 'test'])
        self.assertEqual(miri['environment']['MIRIFLAGS'], '-Zmiri-report-progress=10000000')
        self.assertIn('miri-tools', miri['inputs'])
        for check in (sanitizer, miri):
            self.assertEqual(check['platform'], 'linux-x86_64')
            self.assertEqual(check['environment']['RUSTUP_AUTO_INSTALL'], '0')

        self.assertEqual(checks['asan-faults']['environment'], sanitizer['environment'])
        self.assertEqual(checks['asan-faults']['command'][-4:],
                         ['--lib', '--target', 'x86_64-unknown-linux-gnu', 'aes::'])
        self.assertEqual(checks['miri-public']['environment'], miri['environment'])
        self.assertEqual(checks['miri-public']['command'][-3:],
                         ['public_ciphertext_commit_preserves_inputs_and_canaries', '--', '--exact'])
        oracle = checks['differential']
        self.assertEqual(oracle['command'][-5:],
                         ['openssl_independent_encrypt_and_decrypt_corpus', '--', '--ignored', '--exact', '--nocapture'])
        self.assertEqual(oracle['success']['unique_lines'], ['AES_OPENSSL_COMPARISONS: 4096', 'AES_CACHED_OPENSSL_COMPARISONS: 4096'])
        self.assertIn('aes-oracle', oracle['inputs'])
        self.assertEqual(self.registry['groups']['aes-oracle']['tools'], [{'program': 'openssl'}])

    def test_aes_downstream_binding_and_dependency_closure(self):
        check = next(c for c in self.registry['checks'] if c['component'] == 'aes' and c['id'] == 'downstream')
        consumer = aes_consumer_tests.consumer
        self.assertEqual(check['command'], ['python3', 'scripts/aes/check-aes-consumer.py'])
        self.assertEqual(check['success']['contains'], ['AES downstream: PASS;'])
        self.assertEqual(check['success']['unique_lines'], [consumer.MARKER] + [
            f'AES_DOWNSTREAM_HOST: {compiler} {route} {profile} 6 exact tests'
            for compiler in consumer.TOOLCHAINS for route in consumer.ROUTES for profile in ('debug', 'release')
        ] + [f'AES_DOWNSTREAM_TARGET: {compiler} {route} thumbv7em-none-eabi compile-only'
             for compiler in consumer.TOOLCHAINS for route in consumer.ROUTES] + consumer.FEATURE_MARKERS)
        self.assertTrue({'aes-build', 'aes-consumer', 'compiler', 'hkdf-msrv'} <= set(check['inputs']))
        paths = self.registry['groups']['aes-consumer']['paths']
        for name in consumer.FACADE:
            self.assertIn('crates/' + name, paths)
        for name in consumer.FILES:
            self.assertIn('assurance/aes-public-api/' + name, paths)
        for name in ('scripts/aes/check-aes-consumer.py', 'scripts/aes/test-aes-consumer.py',
                     'scripts/hmac/hmac_verifiers.py', 'scripts/repository/facade_cargo_environment.py'):
            self.assertIn(name, paths)

    def test_aes_consumer_matrix_exact_compilers_and_population(self):
        consumer = aes_consumer_tests.consumer
        check = next(c for c in self.registry['checks'] if c['component'] == 'aes' and c['id'] == 'downstream-matrix')
        self.assertEqual(check['command'], ['python3', 'scripts/aes/check-aes-consumer.py', '--matrix'])
        self.assertIn('hkdf-public-api-matrix', check['inputs'])
        tools = self.registry['groups']['hkdf-public-api-matrix']['tools']
        self.assertEqual({(t['program'], t['toolchain']) for t in tools},
                         {(program, compiler) for compiler in consumer.MATRIX for program in ('cargo', 'rustc')})
        self.assertEqual(check['success']['unique_lines'], [consumer.MATRIX_MARKER] + [
            f'AES_DOWNSTREAM_HOST: {compiler} {route} {profile} 6 exact tests'
            for compiler in consumer.MATRIX for route in consumer.ROUTES for profile in ('debug', 'release')
        ] + [f'AES_DOWNSTREAM_TARGET: {compiler} {route} thumbv7em-none-eabi compile-only'
             for compiler in consumer.TOOLCHAINS for route in consumer.ROUTES] + consumer.FEATURE_MARKERS)

    def test_aes_timing_scope_and_full_input_closure(self):
        check = next(c for c in self.registry['checks'] if c['component'] == 'aes' and c['id'] == 'timing-screen')
        self.assertEqual(check['command'], ['python3', 'scripts/aes/check-aes-timing.py'])
        self.assertEqual(check['platform'], 'linux-x86_64')
        self.assertIn(aes_timing_tests.timing.MARKER, check['success']['unique_lines'])
        self.assertTrue({'aes-build', 'aes-timing', 'aes-oracle', 'compiler', 'hash-core'} <= set(check['inputs']))
        paths = self.registry['groups']['aes-timing']['paths']
        for path in ('assurance/aes-timing/Cargo.toml', 'assurance/aes-timing/Cargo.lock',
                     'assurance/aes-timing/src', 'scripts/aes/check-aes-timing.py',
                     'scripts/aes/test-aes-timing.py', 'scripts/hmac/hmac_timing.py',
                     'scripts/hmac/hmac_verifiers.py', 'scripts/repository/facade_cargo_environment.py'):
            self.assertIn(path, paths)

    def test_aes_proof_and_diagnostic_bindings(self):
        checks = {c['id']: c for c in self.registry['checks'] if c['component'] == 'aes'}
        proof = checks['field-layout-proof']
        self.assertEqual(proof['command'], ['python3', 'scripts/aes/check-aes-kani.py'])
        self.assertEqual(proof['success']['unique_lines'], [aes_runner_tests.kani.MARKER])
        self.assertTrue({'kani-tools', 'kani-setup', 'aes-proof'} <= set(proof['inputs']))
        for name, version, tool in [('api-msrv', '1.90.0', 'hkdf-msrv'), ('api-current', '1.99.1', 'compiler')]:
            check = checks[name]
            self.assertEqual(check['command'], ['python3', 'scripts/aes/check-aes-api.py', version])
            self.assertEqual(check['success']['unique_lines'], [f'AES_API_PASS: {version} 58 paired probes'])
            self.assertTrue({tool, 'aes-build', 'aes-runner'} <= set(check['inputs']))
        for group in ('aes-proof', 'aes-runner'):
            paths = self.registry['groups'][group]['paths']
            for path in ('scripts/aes/test-aes-runners.py', 'scripts/hmac/hmac_verifiers.py',
                         'scripts/repository/facade_cargo_environment.py'):
                self.assertIn(path, paths)
            self.assertTrue(all((ROOT / path).exists() for path in paths))

    def test_aes_nist_fixture_integrity_and_package_inclusion(self):
        directory = ROOT / 'crates/brynja-crypto/tests/fixtures/aes128'
        expected = {
            'ECBGFSbox128.rsp': '8fd29513660c25497cd7a491792b8d16bb209d1a176fa5294ec65d1e71db9b20',
            'ECBKeySbox128.rsp': '4e1f2d023fd7f1c23e9296c0ced224021c0dc83d6259099869e578daa54bbdec',
            'ECBVarKey128.rsp': 'f2af24115a5e5e3b1e050b9652ca49d8027632f0c663fb1db89ba22bd3878b1f',
            'ECBVarTxt128.rsp': '0f293b0d0b5958e67403b838f771f9bb78ed413bbce1ec62229331ca0a19b244',
        }
        self.assertEqual({p.name for p in directory.glob('*.rsp')}, set(expected))
        for name, digest in expected.items():
            self.assertEqual(hashlib.sha256((directory / name).read_bytes()).hexdigest(), digest)
        manifest = tomllib.loads((ROOT / 'crates/brynja-crypto/Cargo.toml').read_text())
        self.assertIn('tests/fixtures/aes128/*', manifest['package']['include'])
        self.assertIn('crates/brynja-crypto/tests/fixtures/aes128',
                      self.registry['groups']['aes-build']['paths'])

    def test_aes_mutation_and_codegen_scope(self):
        checks = {c['id']: c for c in self.registry['checks'] if c['component'] == 'aes'}
        mutation = checks['mutation-controls']
        self.assertEqual(mutation['command'], ['python3', 'scripts/aes/check-aes-mutations.py'])
        self.assertEqual(mutation['success']['unique_lines'], [aes_runner_tests.mutation.MARKER] +
                         ['AES_MUTATION_REJECTED: ' + m[0] for m in aes_runner_tests.mutation.MUTATIONS] +
                         [aes_runner_tests.mutation.SCRATCH_MARKER])
        self.assertTrue({'aes-mutations', 'compiler', 'hash-core'} <= set(mutation['inputs']))
        owner = checks['owner-dispatch']
        self.assertEqual(owner['command'], ['python3', 'scripts/aes/check-aes-owner-cleanup.py'])
        self.assertEqual(owner['platform'], 'linux-x86_64')
        self.assertTrue({'aes-owner-codegen', 'compiler', 'hkdf-msrv'} <= set(owner['inputs']))
        self.assertEqual(owner['success']['unique_lines'], [aes_runner_tests.owner.MARKER] +
                         [f'AES owner dispatch: PASS; Rust {compiler}; x86_64; panic={panic}; 3 probes; 12 rejected IR mutations'
                          for compiler in ('1.90.0', '1.99.1') for panic in ('abort', 'unwind')])
        paths = self.registry['groups']['aes-owner-codegen']['paths']
        for helper in ('scripts/hkdf/hkdf_owner_codegen.py', 'scripts/hmac/hmac_engine_codegen.py',
                       'scripts/hmac/hmac_verifiers.py', 'scripts/repository/facade_cargo_environment.py'):
            self.assertIn(helper, paths)

    def test_aes_dataflow_review_scope(self):
        check = next(c for c in self.registry['checks'] if c['component'] == 'aes' and c['id'] == 'dataflow-review')
        self.assertEqual(check['command'], ['python3', 'scripts/aes/check-aes-dataflow.py'])
        self.assertEqual(check['platform'], 'linux-x86_64')
        self.assertTrue({'aes-build', 'aes-dataflow', 'compiler', 'hkdf-msrv', 'hash-core'} <= set(check['inputs']))
        self.assertEqual(check['success']['unique_lines'], [aes_dataflow_tests.flow.MARKER] +
                         [f'AES dataflow: PASS; Rust {compiler}; panic={panic}; 6 helpers; {count} inverse machine instructions'
                          for compiler, count in (('1.90.0', 740), ('1.99.1', 749)) for panic in ('abort', 'unwind')] +
                         [f'AES machine review: PASS; Rust {compiler}; panic={panic}; 6 reviewed instruction streams'
                          for compiler in ('1.90.0', '1.99.1') for panic in ('abort', 'unwind')])
        self.assertEqual(set(self.registry['groups']['aes-dataflow']['paths']), {
            'scripts/aes/check-aes-dataflow.py', 'scripts/aes/test-aes-dataflow.py',
            'scripts/aes/aes_machine_review.py', 'scripts/aes/machine-review.json',
            'docs/assurance/aes128-development.md',
            'scripts/hmac/hmac_engine_codegen.py', 'scripts/hmac/hmac_verifiers.py',
            'scripts/repository/facade_cargo_environment.py'})
        self.assertIn('PYTHONOPTIMIZE', check['reject_environment'])

    def test_aes_operation_cleanup_scope(self):
        checks = [c for c in self.registry['checks'] if c['component'] == 'aes' and c['id'] == 'operation-cleanup']
        self.assertEqual(len(checks), 1)
        check = checks[0]
        self.assertEqual(check['command'], ['python3', 'scripts/aes/check-aes-operation-cleanup.py'])
        self.assertEqual(check['platform'], 'linux-x86_64')
        self.assertTrue({'aes-operation-codegen', 'aes-build', 'compiler', 'hkdf-msrv', 'hash-core'} <= set(check['inputs']))
        self.assertEqual(check['success']['unique_lines'], [aes_runner_tests.operation.MARKER] +
                         [f'AES operation cleanup: PASS; Rust {compiler}; x86_64; panic={panic}; 7 scratch bodies; 3 explicit clears; 75 rejected IR mutations'
                          for compiler in ('1.90.0', '1.99.1') for panic in ('abort', 'unwind')])
        paths = self.registry['groups']['aes-operation-codegen']['paths']
        for helper in ('scripts/aes/check-aes-operation-cleanup.py', 'scripts/aes/test-aes-runners.py',
                       'scripts/hmac/hmac_engine_codegen.py', 'scripts/hmac/hmac_engine_scratch.py',
                       'scripts/hmac/hmac_verifiers.py', 'scripts/repository/facade_cargo_environment.py'):
            self.assertIn(helper, paths)

    def test_aes_development_owner_scope(self):
        selected = [c for c in self.registry['checks'] if c['component'] == 'aes' and c['id'] == 'owner-contract']
        self.assertEqual(len(selected), 1)
        check = selected[0]
        self.assertEqual(check['command'], ['python3', 'scripts/cryptography/test-aes-owner-contract.py'])
        self.assertEqual(check['success'], {'contains': ['Ran 24 tests in '], 'unique_lines': ['OK']})
        paths = self.registry['groups']['aes-owner-contract']['paths']
        for path in ('security/cryptographic-api-profile-policy.toml', 'verification/checks.toml',
                     'scripts/cryptography/aes_owner_contract.py', 'scripts/cryptography/rust_source_contract.py',
                     'scripts/cryptography/test-aes-owner-contract.py'):
            self.assertIn(path, paths)

    def test_hkdf_downstream_dynamic_checks_and_negative_controls(self):
        registry = copy.deepcopy(self.registry)
        for include in registry['includes']:
            registry['groups'].update(json.loads((ROOT / include).read_text())['groups'])
        hkdf_public_dynamic.validate(registry)
        hkdf_public_dynamic.negative_controls(registry)
        dynamic = [c for c in self.registry['checks']
                   if c['component'] in ('hkdf', 'legacy_hkdf') and c.get('category') in ('asan', 'miri')]
        self.assertEqual(len(dynamic), 13)

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
                ('hkdf', 'modern', 'brynja-crypto', 24, 180),
                ('legacy_hkdf', 'legacy', 'brynja-legacy-hkdf', 3, 25)):
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

    def test_hkdf_private_encoder_keeps_wire_and_public_boundary_coverage(self):
        checks = {c['id']: c for c in self.registry['checks'] if c['component'] == 'hkdf'}
        prefix = ['cargo', '+1.99.1', 'test', '--locked', '--offline', '-p',
                  'brynja-crypto', '--no-default-features']
        for name, selector, count in (
                ('parameters', ['--lib', 'hkdf::parameters::tests::'], 6),
                ('label-aliasing', ['--doc', 'hkdf::parameters::Tls13Label'], 2)):
            check = checks[name]
            self.assertEqual(check['command'], prefix + selector)
            self.assertEqual(check['success']['minimum_tests'], count)
            self.assertEqual(check['success']['exact_tests'], count)
            self.assertIn(f'test result: ok. {count} passed; 0 failed; 0 ignored;',
                          check['success']['contains'])
            self.assertIn('hkdf-composition', check['inputs'])
        self.assertEqual(self.registry['groups']['hkdf-parameters']['paths'],
                         ['crates/brynja-crypto/src/hkdf/parameter_tests.rs'])

    def test_removed_hkdf_integration_harness_does_not_return(self):
        # Inspect the filesystem, not git's index: ignored/untracked leftovers
        # are also auto-discovered by Cargo and can break tests and Clippy.
        obsolete = ROOT / 'crates/brynja-crypto/tests/hkdf_parameters.rs'
        self.assertFalse(obsolete.exists() or obsolete.is_symlink(),
                         'Remove the obsolete external encoder harness; its six tests live in src/hkdf/parameter_tests.rs')

    def test_label_doctests_do_not_claim_diagnostic_specific_evidence(self):
        check = next(c for c in self.registry['checks']
                     if (c['component'], c['id']) == ('hkdf', 'label-aliasing'))
        self.assertIn('assert only', check['establishes'])
        self.assertIn('Stable rustdoc does not verify', check['establishes'])
        self.assertIn('unrelated compile errors', check['establishes'])

    def test_missing_transitive_source_and_harness_are_rejected(self):
        for group in ('hash-core', 'md5-api', 'hkdf-parameters'):
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
