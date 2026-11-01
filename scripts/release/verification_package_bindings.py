"""Explicit existing archive/consumer checks; no publication or native campaign.

Package bytes, copied fixtures and the selected dependency rows are inputs here.
Historical policy inputs belong only to wrappers that actually read them. They
never invalidate separate runtime/proof records through this registration.
"""
from verification_assessment_bindings import ENV
from verification_cargo_bindings import BASE, CPU, HOST, SHA2, SHA3, source_inputs
from verification_miri_bindings import REJECT
from verification_record_policy_bindings import definitions as record_definitions
from verification_checker_bindings import FACADE_PACKAGES

PACKAGES = BASE | {CPU, HOST, SHA2, SHA3, 'brynja-mac-kmac', 'brynja-hash-tuple', 'brynja-mac-hmac'}
SHA2_HELPERS = ['scripts/sha2/check-sha2-execution.py', 'scripts/sha2/sha2_execution_faults.py']
SHA3_HELPERS = ['scripts/sha3/check-sha3-execution.py', 'scripts/sha3/cshake_execution_regressions.py']
ORACLES = ['scripts/sha3/check-cshake-differential.py', 'scripts/sha3/check-sha3-bit-differential.py']


def definitions():
    result = {}

    def add(script, *, packages=PACKAGES, fixtures=(), helpers=(), markers=(), compiler='1.99.1',
            args=(), prefixes=(), policy=None):
        result[('python3', script, *args)] = dict(packages=packages, fixtures=list(fixtures),
            paths=list(helpers), markers=list(markers), prefixes=list(prefixes), compiler=compiler,
            policy=policy)

    for family, title in [('md5', 'MD5'), ('sha1', 'SHA-1')]:
        suffix = 'cpu=False; strict=False' if family == 'md5' else 'cpu=False; execution=False; hardened=False; strict=False'
        add(f'scripts/{family}/check-{family}-package.py', packages=BASE | {'brynja-legacy-' + family},
            helpers=[f'assurance/{family}-public-api/src/lib.rs'], markers=[
                f'Scoped {title} packaged negatives: 13; compiled regressions: 18 rejected',
                f'{title} packaged closure and external consumer: PASS; {suffix}; no upload'])
    add('scripts/kmac/check-kmac-execution-package.py',
        fixtures=['sha3-execution', 'kmac-execution', 'kmac-differential', 'kmac-conformance-rejected'],
        helpers=[*SHA3_HELPERS, *ORACLES, 'docs/kmac-accelerated-execution.md',
            'scripts/kmac/check-kmac-differential.py', 'scripts/kmac/check-kmac-conformance-enabled.py',
            'scripts/kmac/kmac_production_mutants.py', 'scripts/kmac/kmac_admission_mutants.py',
            'scripts/repository/facade_kmac_sources.py'], markers=[
                'Packaged KMAC mismatch/exact-width mutants: PASS; rejected=6',
                'Packaged KMAC algorithm/verification mutants: PASS; rejected=8',
                'Compiled conformance separation: two verifier leaks and unclassified policy rejected',
                'Production KMAC admission: 14 policy downgrades rejected; 2 pristine profiles restored',
                'Packaged KMAC hardened execution public API: PASS',
                'Packaged KMAC execution ownership: PASS; rejected=156',
                'Packaged KMAC compiled cleanup/overflow mutants: PASS; rejected=86',
                'Production-only KMAC oracle mutants: 15 rejected; pristine sources restored'])
    add('scripts/tuplehash/check-tuplehash-execution-package.py',
        fixtures=['sha3-execution', 'tuplehash-execution'],
        helpers=[*SHA3_HELPERS, 'docs/tuplehash-accelerated-execution.md'], markers=[
            'Packaged TupleHash algorithm/verification mutants: PASS; rejected=8',
            'Packaged TupleHash borrowed encoding mutants: PASS; rejected=10',
            'Packaged TupleHash hardened execution public API: PASS',
            'Packaged TupleHash execution ownership: PASS; rejected=230',
            'Packaged TupleHash compiled cleanup/overflow mutants: PASS; rejected=34',
            'Packaged scoped TupleHash mutants: PASS; rejected=54'])
    add('scripts/parallelhash/check-parallelhash-execution-package.py',
        packages=PACKAGES | {'brynja-hash-parallel', 'brynja-hash-parallel-std'},
        fixtures=['sha3-execution'], helpers=[*SHA3_HELPERS,
            'scripts/parallelhash/parallelhash_package_fixtures.py',
            'assurance/parallelhash-differential/tests/scoped.rs'], markers=[
            'Packaged protected ParallelHash lifecycle and ownership tests: PASS',
            'Streaming/scoped ownership rejects 436 compiled probes',
            'ParallelHash package execution: PASS; compiled regressions=132'])
    add('scripts/sha2/check-sha2-execution.py', fixtures=['sha2-execution', 'general-sha512-t'],
        helpers=[*SHA2_HELPERS, 'scripts/sha2/sha2-execution-reviewed.toml',
            'scripts/checks.sh', 'scripts/zeroization/check-zeroization-miri.sh',
            'scripts/zeroization/check-zeroization-sanitizer.sh', 'docs/sha2-ordinary-execution.md',
            'docs/x86-sha512-execution.md', 'scripts/sha2/check-x86-sha512.py',
            'scripts/sha2/x86_sha512_package.py', 'scripts/sha2/x86_sha512_regressions.py',
            'scripts/sha2/x86_sha512_faults.py', 'scripts/sha2/x86_sha512_ci.py',
            'scripts/ci/install-sde.sh', '.github/workflows/dedicated-sha512.yml'], markers=[
            'Seven packaged identity, ownership and secret-route negatives rejected',
            'Twelve compiled no-op, partial-bit, wrong-IV and false-work mutants rejected',
            'Complete ordinary SHA-2 packaged execution: PASS'])
    add('scripts/sha3/check-sha3-execution.py', fixtures=['sha3-execution'],
        helpers=[*SHA3_HELPERS, 'scripts/sha3/sha3-execution-reviewed.toml',
            'scripts/sha3/cshake_execution_vectors.py', 'scripts/checks.sh',
            'scripts/zeroization/check-zeroization-miri.sh', 'scripts/zeroization/check-zeroization-sanitizer.sh'], markers=[
            '24 raw-input rejections with 24 explicit-marker controls and four marker bypass rejections: PASS',
            'Four compiled bit-preflight/output-admission regressions: PASS',
            'Six packaged ownership negatives and fourteen compiled output/padding/work mutations: PASS',
            'cSHAKE: 24 raw input rejections, 24 controls and six ownership negatives passed',
            'cSHAKE/hosted: eighteen debug/release algorithm, route and error mutants rejected'])
    for stem, count in [('sha256', 6), ('sha512', 8)]:
        add(f'scripts/sha2/check-{stem}-batch.py', args=['--package'], compiler='1.98.1',
            fixtures=[stem + '-batch', 'general-sha512-t'], helpers=SHA2_HELPERS,
            policy=f'scripts/sha2/test-{stem}-batch.py', markers=[
                '24 packaged batch ownership/classification/authority negatives rejected',
                f'{count} compiled batch algorithm/output mutants rejected'])
    add('scripts/sha3/test-keccak-batch-package.py', compiler='1.98.1',
        fixtures=['keccak-batch', 'general-sha512-t'], helpers=[*SHA2_HELPERS, *ORACLES,
            'scripts/sha3/check-keccak-batch.py', 'scripts/sha3/keccak_batch_policy.py'], markers=[
            "Packaged Keccak batch: 23 negatives, 9 compiled mutants rejected; modes=('portable',)"])
    add('scripts/sha3/check-keccak-batch.py', packages=BASE | {CPU, HOST, SHA2, SHA3},
        fixtures=['keccak-batch'], compiler='1.98.1', helpers=ORACLES,
        policy='scripts/sha3/test-keccak-batch-policy.py', markers=[
            'Keccak batch source/public-data and assurance policy: PASS',
            'Keccak batch: 1024 independent outputs and six malformed requests PASS; mode=portable; vector_calls=0'])
    for family, stem, title, regression in [
        ('sha2', 'sha256', 'SHA-256',
         'SHA-256 public acceptance rejects corrupted digests, missing exports, backend misreporting, exhaustion bypass, unadmitted features, and altered packages'),
        ('sha2', 'sha2', 'Complete SHA-2',
         'complete SHA-2 acceptance rejects seven corrupted byte/bit results plus byte/bit API, claim, documentation, backend, identity, width, feature, and package regressions'),
        ('sha3', 'sha3', 'Complete SHA-3/SHAKE',
         'complete SHA-3 acceptance rejects six corrupted outputs plus API, rate, zero-output, exhaustion, domain, path, feature, phase, private-module, and package regressions')]:
        helpers = [f'scripts/{family}/{stem}_public_api.py',
            f'scripts/{family}/check-{stem}-public-api.py', f'scripts/{family}/test-{stem}-public-api.py',
            'scripts/checks.sh', 'scripts/ci/check-rust-version-matrix.sh',
            'scripts/assurance/check-bare-metal.sh', '.github/workflows/ci.yml']
        fixtures = [stem + '-public-api']
        if stem == 'sha2':
            helpers += ['scripts/sha2/check-sha2-bit-differential.py']
            fixtures += ['sha2-bit-differential']
        for mode in ('check', 'test'):
            selected = (PACKAGES | {'brynja-crypto', 'brynja-hash-parallel'} if stem == 'sha256'
                        else set(FACADE_PACKAGES))
            extra = []
            markers = [f'{title} package-content acceptance: PASS'] if mode == 'check' else [regression]
            if stem == 'sha256' and mode == 'test':
                # This regression really builds the three distinct isolated
                # manifest closures, not only SHA-256's smaller consumer.
                selected = set(FACADE_PACKAGES)
                extra = ['scripts/sha2/sha2_public_api.py', 'scripts/sha3/sha3_public_api.py']
                markers += ['Three isolated packagers reject missing inherited CPU-std development edges']
            add(f'scripts/{family}/{mode}-{stem}-public-api.py', packages=selected,
                fixtures=fixtures, helpers=[*helpers, *extra], markers=markers)
    return result


def build(rows):
    known = definitions()
    scripts = {argv[1] for argv in known}
    policies = record_definitions()
    groups = {'package-python': {'tools': [{'program': 'python3'}]}}
    checks = []
    for row in rows:
        argv = tuple(row['command'])
        if row['phase'] != 'repository' or len(argv) < 2 or argv[0] != 'python3' or argv[1] not in scripts:
            continue
        if argv not in known or row.get('environment') or row.get('stdin'):
            raise ValueError('unreviewed package selector: ' + row['id'])
        spec = known[argv]
        key = 'package-' + row['id']
        # These wrappers copy/package entire selected crate trees. That scope is
        # intentional for archive tests, not an excuse to hash other crates.
        paths = [argv[1], 'rust-toolchain.toml', *spec['paths']]
        paths += ['crates/' + p for p in sorted(spec['packages'])]
        paths += ['assurance/' + p for p in spec['fixtures']]
        patterns = []
        if spec['policy']:
            policy = policies[('python3', spec['policy'])]
            paths += policy['paths']
            patterns += policy['patterns']
        groups[key] = dict(paths=sorted(set(paths)), patterns=patterns,
            tools=[{'program': p, 'toolchain': spec['compiler']} for p in ('cargo', 'rustc', 'rustdoc')],
            toml={'Cargo.toml': ['workspace.package', 'workspace.resolver', 'workspace.lints',
                'workspace.members', 'workspace.exclude', 'profile', 'patch', 'replace']})
        if argv[1] == 'scripts/sha2/check-sha2-execution.py':
            groups[key]['tools'] += [{'program': 'clippy-driver', 'toolchain': spec['compiler']}]
        inputs = ['package-python', key]
        inputs += source_inputs(groups, key + '-dependencies', spec['packages'], 'Cargo.lock')
        checks.append(dict(component=row['families'][0], id=row['id'], name=row['label'], category='repository',
            command=list(argv), cwd='.', inputs=inputs,
            environment=dict(ENV, RUSTUP_TOOLCHAIN=spec['compiler']), reject_environment=REJECT,
            platform='linux-x86_64', timeout_seconds=3600, log_bytes=16777216,
            success=dict(contains=spec['markers'], unique_lines=spec['markers'], unique_prefixes=spec['prefixes']),
            establishes='Existing default package/consumer or portable batch check, including its compiled negative/mutation '
                        'controls where present. No --native, QEMU, sanitizer or proof campaign is selected. '
                        'Preferred/hosted routes are not required-native qualification. Original historical policy '
                        'inputs, if inspected by this wrapper, affect only this row. Packaging identity changes '
                        'can invalidate this archive check without reopening separate implementation evidence.'))
    return dict(schema=1, groups=groups, checks=checks)
