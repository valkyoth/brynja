"""Synthetic checker regressions, deliberately not native/crypto qualification."""
from verification_assessment_bindings import ENV
from verification_miri_bindings import REJECT

OWNER_HELPERS = [
    'scripts/cryptography/' + name + '.py' for name in (
        'secret_owner_compiler', 'mir_cleanup_flow', 'api_profile_contracts',
        'api_profile_operations', 'legacy_md5_owner_contract', 'legacy_sha1_owner_contract',
        'hmac_owner_contract', 'legacy_hmac_owner_contract', 'rust_source_contract')]

RESIDENT_PACKAGES = ('brynja-core', 'brynja-hash-core', 'brynja-crypto-cpu', 'brynja-crypto-cpu-std',
    'brynja-hash-sha2', 'brynja-hash-sha3', 'brynja-mac-kmac', 'brynja-hash-tuple', 'brynja-mac-hmac',
    'brynja-legacy-sha1', 'brynja-legacy-sha1-std', 'brynja-legacy-md5', 'brynja-legacy-md5-std')
RESIDENT_DEPENDENCIES = tuple(p for p in RESIDENT_PACKAGES if p not in ('brynja-legacy-md5-std', 'brynja-legacy-sha1-std'))

# Imports shared by the facade checker. These are executable checker inputs,
# not a request to requalify the implementations mentioned by their fixtures.
FACADE_HELPERS = ['scripts/repository/' + name + '.py' for name in (
    'check-facade-package', 'facade_adversarial_cases', 'facade_archive_catalog',
    'facade_batch_cases', 'facade_cargo_environment', 'facade_conformance_cases',
    'facade_cshake_cases', 'facade_family_cases', 'facade_hardened_sha3',
    'facade_hardened_sha3_scoped', 'facade_hardened_sha3_sources', 'facade_hardened_sha3_regressions',
    'facade_keccak_acceptance', 'facade_keccak_cases', 'facade_keccak_routes',
    'facade_kmac_acceptance', 'facade_kmac_corpus', 'facade_kmac_probes',
    'facade_kmac_sources', 'facade_package_cases', 'facade_parallelhash_acceptance',
    'facade_parallelhash_cases', 'facade_parallelhash_driver',
    'facade_parallelhash_execution', 'facade_parallelhash_probes',
    'facade_parallelhash_references', 'facade_scoped_sha2',
    'facade_scoped_sha2_lifecycle', 'facade_scoped_sha2_sources', 'facade_scoped_sha2_regressions',
    'facade_sha2_acceptance', 'facade_sha2_execution',
    'facade_sha2_execution_regressions', 'facade_sha2_execution_sources',
    'facade_sha2_routes', 'facade_sha3_execution', 'facade_sha3_negatives',
    'facade_tuplehash_acceptance', 'facade_tuplehash_probes',
    'facade_workspace_policy', 'legacy_execution_cases', 'legacy_execution_package',
    'legacy_hardened_cases', 'legacy_hardened_package')]
FACADE_HELPERS += ['scripts/sha2/sha2_public_api.py']
FACADE_PACKAGES = (
    'brynja-core', 'brynja-mac-hmac', 'brynja-crypto-cpu', 'brynja-hash-core',
    'brynja-hash-sha2', 'brynja-hash-sha3', 'brynja-mac-kmac', 'brynja-hash-tuple',
    'brynja-hash-parallel', 'brynja-crypto', 'brynja-pki', 'brynja-protocol',
    'brynja-tls13-handshake', 'brynja-tls12', 'brynja-tls13', 'brynja-tls',
    'brynja-dtls', 'brynja-platform', 'brynja-quic-tls', 'brynja', 'brynja-crypto-cpu-std')


def definitions():
    result = {}

    def add(path, helpers, count=None, marker=None, extra=()):
        result[('python3', path)] = dict(paths=[path, *helpers, *extra],
            success=({'contains': [f'\nRan {count} tests in '], 'unique_lines': ['OK']} if count else
                     {'contains': [marker], 'unique_lines': [marker]}), count=count)

    legacy = ['scripts/legacy-hmac/' + name + '.py' for name in ('legacy_hmac_bits', 'legacy_hmac_acceptance')]
    legacy += ['scripts/md5/check-md5-differential.py', 'scripts/sha1/check-sha1-differential.py']
    add('scripts/legacy-hmac/test-legacy-hmac-native.py',
        [*legacy, 'scripts/legacy-hmac/legacy_hmac_native.py'], count=4)
    add('scripts/legacy-hmac/test-legacy-hmac-md5-native.py',
        [*legacy, 'scripts/legacy-hmac/legacy_hmac_md5_native.py', 'scripts/legacy-hmac/legacy_hmac_md5_lanes.py'], count=5)
    add('scripts/sha3/test-keccak-batch-codegen.py', ['scripts/sha3/keccak_batch_codegen.py'], count=3)
    add('scripts/hmac/test-hmac-x86-sha512.py',
        ['scripts/hmac/check-hmac-x86-sha512.py', 'scripts/hmac/hmac_verifiers.py',
         'scripts/repository/facade_cargo_environment.py'], count=6)
    add('scripts/hmac/test-hmac-acceptance.py',
        ['scripts/hmac/' + name + '.py' for name in (
            'hmac_acceptance', 'hmac_faults', 'hmac_adapter_native',
            'hmac_execution_fault_tests', 'hmac_execution_faults',
            'check-hmac-hosted-native', 'check-hmac-launch', 'hmac_verifiers')] +
        ['scripts/cpu/check-hosted-execution.py', 'scripts/cpu/cpu_boundary_backends.py',
         'scripts/repository/facade_cargo_environment.py'], count=12)
    acceptance = result[('python3', 'scripts/hmac/test-hmac-acceptance.py')]
    acceptance['test_modules'] = ['scripts/hmac/hmac_execution_fault_tests.py']
    acceptance['source_paths'] = [
        'crates/brynja-mac-hmac/src',
        'crates/brynja-crypto-cpu-std/src/execution/hmac.rs',
        'crates/brynja-crypto-cpu-std/src/strict_hmac/compiled.rs',
        'crates/brynja-crypto-cpu-std/src/macos_resident/hmac/compiled.rs',
        *['assurance/hmac-faults/' + name for name in (
            'adapter_tests.rs', 'native_adapter_tests.rs', 'execution_model.rs', 'execution_cases.rs')]]
    add('scripts/hmac/test-hmac-protected.py',
        ['scripts/hmac/' + name + '.py' for name in (
            'check-hmac-protected', 'hmac_protected_compiled', 'hmac_owner_profile',
            'hmac_verifiers', 'hmac_acceptance', 'hmac_faults')] +
        ['scripts/cpu/check-hosted-execution.py', 'scripts/cpu/cpu_boundary_backends.py',
         'scripts/repository/facade_cargo_environment.py'], count=10)
    protected = result[('python3', 'scripts/hmac/test-hmac-protected.py')]
    protected['source_paths'] = [
        'crates/brynja-crypto-cpu-std/src/strict_hmac',
        'crates/brynja-crypto-cpu-std/src/macos_resident/hmac',
        'crates/brynja-crypto-cpu-std/tests/hmac.rs',
        'assurance/hmac-protected/acceptance.rs', 'assurance/hmac-protected/compiled.rs']
    protected['toml'] = {'crates/brynja-mac-hmac/Cargo.toml': ['package.version']}
    hmac_helpers = ['scripts/hmac/' + name + '.py' for name in (
        'hmac_acceptance', 'hmac_faults', 'hmac_package')]
    add('scripts/hmac/test-hmac-package.py', [*hmac_helpers,
        *['scripts/hmac/' + name + '.py' for name in (
            'check-hmac-package', 'hmac_combined_tests', 'hmac_combined_acceptance',
            'hmac_execution_acceptance', 'hmac_execution_faults', 'hmac_adapter_native')],
        'scripts/repository/facade_cargo_environment.py', 'scripts/sha2/sha2_public_api.py'], count=12)
    package = result[('python3', 'scripts/hmac/test-hmac-package.py')]
    package['test_modules'] = ['scripts/hmac/hmac_combined_tests.py']
    package['source_paths'] = ['crates/brynja-mac-hmac/tests/general.rs', 'crates/brynja-mac-hmac/README.md']
    add('scripts/hmac/test-hmac-facade.py', [*FACADE_HELPERS, *hmac_helpers,
        'scripts/hmac/check-hmac-facade.py', 'scripts/hmac/hmac_combined_acceptance.py'], count=5)
    add('scripts/hmac/test-hmac-strict.py', [*FACADE_HELPERS, *hmac_helpers,
        *['scripts/hmac/' + name + '.py' for name in (
            'check-hmac-strict', 'hmac_strict_cases', 'hmac_timing', 'hmac_timing_routes',
            'hmac_verifiers', 'hmac_adapter_native')],
        *['scripts/repository/' + name + '.py' for name in (
            'legacy_strict_package', 'legacy_strict_sources', 'strict_accelerated_consumer',
            'strict_accelerated_mutants', 'strict_accelerated_sources', 'strict_consumer_bits',
            'strict_consumer_sources', 'strict_public_consumer', 'test_strict_public_consumer',
            'test_facade_keccak')]], count=9)
    for script in ('test-hmac-facade.py', 'test-hmac-strict.py'):
        # These tests inspect package identity itself. Keep its version, without
        # pulling unrelated workspace/dependency metadata into their fingerprint.
        result[('python3', 'scripts/hmac/' + script)]['toml'] = {
            f'crates/{p}/Cargo.toml': ['package.name', 'package.version'] for p in FACADE_PACKAGES}
    result[('python3', 'scripts/hmac/test-hmac-strict.py')]['source_paths'] = [
        'crates/brynja-strict/src/hmac_tests.rs', 'crates/brynja-strict/README.md']
    add('scripts/cryptography/test-mir-cleanup-flow.py', OWNER_HELPERS,
        marker='strict MIR cleanup flow accepts five valid place/provenance paths and rejects twenty-nine projected-write, alias-escape, return-escape, may-flow, unwind, CFG, assembly, and post-cleanup regressions')
    add('scripts/cryptography/test-secret-owner-compiler.py', OWNER_HELPERS,
        marker='secret-owner MIR evidence rejects nineteen identity, target, data-flow, and dominance regressions plus twenty-two registered identity, namespace, and coverage bypasses',
        extra=('crates/brynja-hash-sha2/src/hardened/owner.rs', 'crates/brynja-mac-kmac/src/core_state.rs'))
    add('scripts/legacy-hmac/test-legacy-hmac-timing.py',
        ['scripts/legacy-hmac/' + n + '.py' for n in ('legacy_hmac_timing', 'legacy_hmac_timing_runner',
         'legacy_hmac_timing_review', 'legacy_hmac_timing_review_tests', 'review-legacy-hmac-timing')] +
        ['scripts/repository/facade_cargo_environment.py'], count=14)
    result[('python3', 'scripts/legacy-hmac/test-legacy-hmac-timing.py')]['test_modules'] = [
        'scripts/legacy-hmac/legacy_hmac_timing_review_tests.py']
    add('scripts/cryptography/test-macos-legacy-resident-package.py',
        ['scripts/cryptography/' + n + '.py' for n in ('check-macos-legacy-resident-package',
         'check-macos-resident-package', 'macos_legacy_resident_oracle', 'macos_resident_oracle',
         'macos_resident_keyed_oracle')] +
        ['scripts/md5/check-md5-differential.py', 'scripts/sha1/check-sha1-differential.py'], count=5)
    resident = result[('python3', 'scripts/cryptography/test-macos-legacy-resident-package.py')]
    resident['toml'] = {f'crates/{p}/Cargo.toml': ['dependencies', 'dev-dependencies', 'build-dependencies', 'target']
                        for p in RESIDENT_PACKAGES}
    resident['toml']['Cargo.toml'] = ['workspace.dependencies.' + p for p in RESIDENT_DEPENDENCIES]
    return result


def build(rows):
    known = definitions()
    paths = {argv[1] for argv in known}
    groups = {'checker-python': {'tools': [{'program': 'python3'}]}}
    checks = []
    for row in rows:
        argv = tuple(row['command'])
        if row['phase'] != 'repository' or len(argv) < 2 or argv[0] != 'python3' or argv[1] not in paths:
            continue
        if argv not in known or row.get('environment') or row.get('stdin'):
            raise ValueError('unreviewed synthetic checker command: ' + row['id'])
        spec = known[argv]
        key = 'checker-' + row['id']
        groups[key] = {'paths': [*spec['paths'], *spec.get('source_paths', [])]}
        if 'toml' in spec:
            groups[key].update(toml=spec['toml'], normalize_local_versions=True)
        checks.append(dict(component=row['families'][0], id=row['id'], name=row['label'], category='repository',
            command=list(argv), cwd='.', inputs=['checker-python', key], environment=ENV, reject_environment=REJECT,
            success=spec['success'], timeout_seconds=300, log_bytes=16777216,
            establishes='Existing synthetic/mock checker regressions only. Native drivers, SDE execution and compiler invocations are mocked; '
                        'no native, emulated, timing or emitted-code qualification is claimed.'))
    return dict(schema=1, groups=groups, checks=checks)
