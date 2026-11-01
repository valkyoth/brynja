"""Remaining existing package consumers and general SHA-512/t assessments.

Explicit declarations only; exporting never imports or executes a verifier.
The four formerly ambient package compilers are now selected through an opt-in
argument. Original catalog commands/history remain untouched and unmapped.
"""
from pathlib import Path
import tomllib
from verification_assessment_bindings import ENV
from verification_cargo_bindings import BASE, CPU, HOST, SHA2, SHA3, source_inputs, fixture_inputs
from verification_checker_bindings import FACADE_PACKAGES, definitions as checker_definitions
from verification_owner_bindings import LEGACY_HELPERS
from verification_miri_bindings import REJECT

ROOT = Path(__file__).resolve().parents[2]
LEAF = BASE | {CPU, SHA2, SHA3, 'brynja-mac-hmac'}
HOSTED = LEAF | {HOST, 'brynja-mac-kmac', 'brynja-hash-tuple'}
LEGACY = BASE | {'brynja-legacy-sha1', 'brynja-legacy-md5', 'brynja-legacy-hmac'}
STRICT = HOSTED | {'brynja-hash-parallel', 'brynja-hash-parallel-std', 'brynja-strict'}
PACKAGING = ['scripts/repository/facade_cargo_environment.py', 'scripts/sha2/sha2_public_api.py']
GENERAL_HELPERS = ['scripts/sha2/' + name + '.py' for name in (
    'general_sha512_t_policy', 'sha512_t_contract', 'sha512_t_iv_oracle', 'sha512_t_digest_oracle',
    'general_sha512_t_cleanup', 'general_sha512_t_lifecycle', 'general_sha512_t_acceptance',
    'general_sha512_t_final', 'general_sha512_t_work', 'sha2_public_api')]
GENERAL_HELPERS += ['scripts/cryptography/rust_source_contract.py', 'scripts/cryptography/mir_cleanup_flow.py']
GENERAL_REVIEW = 'scripts/sha2/general-sha512-t-reviewed.toml'
GENERAL_GATES = ['scripts/checks.sh', 'scripts/zeroization/check-zeroization-miri.sh',
    'scripts/zeroization/check-zeroization-sanitizer.sh', 'scripts/ci/check-rust-version-matrix.sh',
    'scripts/assurance/check-bare-metal.sh']


def definitions():
    specs = {}
    checker = checker_definitions()

    def helpers(stem):
        return checker[('python3', 'scripts/hmac/test-hmac-' + stem + '.py')]['paths'][1:]

    def add(script, packages, paths, markers, *, pin=False, contains=(), compilers=('1.99.1',)):
        specs[('python3', script)] = dict(packages=packages, paths=paths, markers=markers,
            contains=list(contains), pin=pin, compilers=compilers)

    add('scripts/hmac/check-hmac-package.py', LEAF,
        [*PACKAGING, 'assurance/hmac-faults', *['scripts/hmac/' + n + '.py' for n in (
            'hmac_package', 'hmac_acceptance', 'hmac_faults', 'hmac_execution_acceptance',
            'hmac_execution_faults', 'hmac_adapter_native')]], [
            'HMAC extracted archive: debug/release vectors, lifecycle, bounded, bits, general, tag policy and README PASS',
            'HMAC packaged API/ownership negatives: 118 rejected',
            'HMAC packaged algorithm/comparison compiled mutants: 8 rejected',
            'HMAC packaged bit-rounding adapter mutant: 1 rejected',
            'HMAC packaged general exact-bit/policy mutants: 2 rejected',
            'HMAC packaged shared tag policy: 6 compiled caller/algorithm/width mutants rejected',
            'HMAC adapter faults: 6 debug/release tests; 328 synthetic faults; 144 real handoffs; 12 compiled mutants rejected',
            'HMAC packaged hardened-execution API: 12 positive identities; 66 rejected probes',
            'HMAC packaged runtime-execution API: 12 positive identities; 68 rejected probes',
            'HMAC retained execution: 4 debug/release lifecycle tests; 4 compiled mutants rejected',
            'HMAC execution composition: 6 debug/release tests; 2784 synthetic faults; 11 compiled mutants rejected; not native/erasure evidence'], pin=True)
    add('scripts/hmac/check-hmac-protected.py', HOSTED,
        [*helpers('protected'), 'assurance/hmac-protected', 'assurance/hosted-cpu-execution'], [
            'Protected HMAC packaged ownership/API: 25 rejected probes',
            'Protected compiled HMAC package: 12 positive identities, 15 rejected probes',
            'Protected HMAC: 5 compiled behavioral mutants rejected',
            'Protected scalar HMAC packaged acceptance: PASS; author tests, qualification pending'], pin=True)
    add('scripts/hmac/check-hmac-facade.py', set(FACADE_PACKAGES) | LEGACY | {'brynja-hash-parallel-std'},
        [*helpers('facade'), 'assurance/hmac-facade'], [
            *[f'{p}: 118 facade HMAC ownership/API negatives rejected' for p in ('brynja-crypto', 'brynja')],
            *[f'{p}: portable no_std build, opt-in no_std check/native build, feature isolation PASS'
              for p in ('brynja-crypto', 'brynja')],
            *[f'{p}: co-installed modern/legacy runtime (383 general parameters), no_std and 12 separation negatives PASS'
              for p in ('brynja-crypto', 'brynja')],
            'PASS: six isolated protocol closures and six real feature-activation mutants',
            'Focused HMAC facade acceptance: PASS; no native or independent qualification claim'])
    add('scripts/hmac/check-hmac-strict.py', STRICT,
        [*helpers('strict'), 'assurance/hmac-strict', 'assurance/hmac-faults/host_probe.rs'], [
            'Strict HMAC: 140 ownership/lifetime/export negatives; compiled=False',
            'Strict HMAC: 138 ownership/lifetime/export negatives; compiled=True',
            'Strict HMAC: three compiling export/feature-broadening mutants detected',
            'Strict HMAC packaged acceptance: PASS; no independent or release qualification claim'],
        contains=['Strict HMAC scalar debug/release: protected execution',
                  *[f'Strict HMAC compiled debug/release: {family}; ' for family in ('sha256', 'sha512', 'keccak')]])
    add('scripts/legacy-hmac/check-legacy-hmac-package.py', LEGACY, LEGACY_HELPERS, [
        'Legacy verification: 2 compiled mismatch-acceptance mutants rejected',
        'Legacy HMAC: extracted debug/release RFC vectors, contracts, README, 140 byte / 176 bit differentials per profile and normal-edge isolation PASS'], pin=True)
    add('scripts/legacy-hmac/check-legacy-hmac-hosted-package.py', HOSTED | LEGACY | {'brynja-legacy-hmac-std'},
        [*LEGACY_HELPERS, *['scripts/legacy-hmac/' + n + '.py' for n in (
            'legacy_hmac_hosted_acceptance', 'legacy_hmac_hosted_sha1', 'legacy_hmac_hosted_md5')]], [
            'Hosted legacy HMAC ownership/classification negatives: 28 rejected',
            'Hosted legacy HMAC compiled cleanup mutants: 10 rejected',
            'Legacy HMAC strict-execution extracted-package acceptance: PASS; author checks, qualification pending'], pin=True)
    general = [*GENERAL_HELPERS, GENERAL_REVIEW, *GENERAL_GATES,
        *tomllib.loads((ROOT / GENERAL_REVIEW).read_text())['files'], 'assurance/general-sha512-t']
    acceptance = 'General SHA-512/t extracted-package acceptance: PASS (4590 independent cases, all 510 t)'
    work = 'General SHA-512/t Rust fallback-model work counts: PASS; 12240 cases per profile, ordinary and hardened; debug/release; not native assembly evidence'
    add('scripts/sha2/check-general-sha512-t.py', set(FACADE_PACKAGES), general, [
        *[f'general SHA-512/t: {compiler} {profile} unwind MIR/LLVM/assembly cleanup PASS'
          for compiler in ('1.90.0', '1.98.1') for profile in ('dev', 'release')],
        'General SHA-512/t destructor probe: debug/release PASS', acceptance, work,
        'General SHA-512/t final scalar work/resource/profile evidence: PASS; 50 performance rows',
        'Local exact-source artifact: target/general-sha512-t-final.json; no native/timing/FIPS approval',
        'General SHA-512/t public descriptors and all-510 IV oracle: PASS',
        'Ordinary/hardened byte/bit hashing: PASS; no CPU admission or FIPS validation'],
        compilers=('1.99.1', '1.90.0', '1.98.1'))
    add('scripts/sha2/test-general-sha512-t.py', set(FACADE_PACKAGES), general, [
        'General SHA-512/t destructor probe: debug/release PASS; 20 compiled clearing/ownership mutants rejected',
        acceptance, work, 'General SHA-512/t algorithm mutants: 15 compiled and rejected by runtime tests', 'OK'],
        contains=['\nRan 15 tests in '])
    return specs


def build(rows):
    known = definitions()
    scripts = {argv[1] for argv in known}
    groups = {'final-component-python': {'tools': [{'program': 'python3'}]}}
    checks = []
    for row in rows:
        argv = tuple(row['command'])
        if row['phase'] != 'repository' or len(argv) < 2 or argv[0] != 'python3' or argv[1] not in scripts:
            continue
        if argv not in known or row.get('environment') or row.get('stdin'):
            raise ValueError('unreviewed final component selector: ' + row['id'])
        spec = known[argv]
        key = 'final-component-' + row['id']
        group = groups[key] = dict(paths=sorted(set([argv[1], 'rust-toolchain.toml', *spec['paths'],
            *['crates/' + p for p in sorted(spec['packages'])]])),
            tools=[{'program': p, 'toolchain': c} for c in spec['compilers'] for p in ('cargo', 'rustc', 'rustdoc')],
            toml={'Cargo.toml': ['workspace.package', 'workspace.resolver', 'workspace.lints',
                               'workspace.members', 'workspace.exclude', 'profile', 'patch', 'replace']})
        if argv[1].endswith('/check-legacy-hmac-package.py'):
            # This command inspects the normal-edge workspace metadata graph,
            # not every crate's Rust implementation.
            group['patterns'] = ['crates/*/Cargo.toml']
            group['toml']['Cargo.toml'] += ['workspace.dependencies']
        inputs = ['final-component-python', key]
        inputs += source_inputs(groups, key + '-dependencies', spec['packages'], 'Cargo.lock')
        if '/sha2/' in argv[1]:
            inputs += fixture_inputs(groups, 'general-sha512-t', key + '-fixture')
        command = [*argv, *(['--toolchain', '1.99.1'] if spec['pin'] else [])]
        checks.append(dict(component=row['families'][0], id=row['id'], name=row['label'], category='repository',
            command=command, cwd='.', inputs=inputs, environment=dict(ENV, RUSTUP_TOOLCHAIN='1.99.1'),
            reject_environment=REJECT, platform='linux-x86_64', timeout_seconds=3600, log_bytes=16777216,
            success=dict(contains=[*spec['markers'], *spec['contains']], unique_lines=spec['markers']),
            establishes='Existing package/consumer or general SHA-512/t scalar assessment, including its '
                'original compiled mutations and completion checks. No optional native-kernel, resident, '
                'Miri, sanitizer or proof campaign is selected. Protected consumers require GNU/Linux; '
                'the facade also requires the installed x86_64-unknown-none standard library. Missing '
                'prerequisites fail rather than fall back. Archive inputs affect this assessment only, '
                'not separate algorithm evidence. Historical policy pins may reject drift; that is not '
                'a release blocker or a reason to rerun unrelated checks. '
                + ('The explicit --toolchain 1.99.1 option replaces ambient selection; historical command '
                   'and provenance are retained, not promoted to this configuration.' if spec['pin'] else
                   'Historical observations remain unmapped until their exact configuration can be established.')))
    return dict(schema=1, groups=groups, checks=checks)
