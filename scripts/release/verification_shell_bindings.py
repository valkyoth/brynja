"""Finite bindings for existing shell checks; never execute them on import/scan.

Preserve each original command and compiler/target selection. Additional local
tool lookup and offline execution do not turn historical results into passes.
"""
from verification_assessment_bindings import ENV
from verification_cargo_bindings import BASE, CPU, SHA2, SHA3, fixture_inputs, source_inputs
from verification_miri_bindings import REJECT

TARGET = 'x86_64-unknown-linux-gnu'


def definitions():
    result = {}

    def add(path, packages, versions, markers, *, fixtures=(), helpers=(), utilities=(),
            args=(), tests=False, rust_tools=(), extra=()):
        result[(path, *args)] = dict(packages=packages, versions=versions, markers=markers,
            fixtures=fixtures, helpers=helpers, utilities=utilities, tests=tests,
            rust_tools=rust_tools, extra=extra)

    for family, label, regions in [('md5', 'MD5', 'five'), ('sha1', 'SHA-1', 'six')]:
        packages = BASE | {'brynja-legacy-' + family}
        add(f'scripts/{family}/check-{family}-codegen.sh', packages, ('1.98.1',),
            [f'{label} owner Drop/wipe and {regions} clearing regions survive MIR/LLVM/assembly',
             f'Scoped {label} guard/handle cleanup survives MIR/LLVM/assembly; four mutations rejected'],
            helpers=('scripts/cryptography/mir_cleanup_flow.py',), utilities=('mktemp', 'rm', 'python3'))
        message = ('MD5 vector arithmetic and shift instructions' if family == 'md5'
                   else 'SHA-1 schedule and round instructions')
        add(f'scripts/{family}/check-{family}-cpu-codegen.sh', packages, ('1.90.0', '1.98.1'),
            [message + ' present at both compiler endpoints; no admission or cleanup qualification'],
            utilities=('mktemp', 'rm', 'find', 'grep'))
    for family, script, marker in [
        ('sha2', 'sha256', 'SHA-2 CPU codegen contains x86 SHA-256, AArch64 SHA2/SHA512, and RISC-V Zknh instructions'),
        ('sha3', 'sha3', 'SHA-3 CPU codegen contains AVX2 and AArch64 SHA3 instructions under Rust 1.90.0 and 1.98.1')]:
        add(f'scripts/{family}/check-{script}-cpu-codegen.sh', {CPU}, ('1.90.0', '1.98.1'), [marker],
            utilities=('dirname', 'mktemp', 'rm', 'find', 'grep'))
    for family, package, marker in [
        ('sha2', SHA2, f'hardened SHA-2 owner cleanup survives MIR, LLVM IR, and {TARGET} assembly under 1.98.1'),
        ('sha3', SHA3, f'hardened FIPS 202 cleanup and no-local-byte-array boundary survive development/release MIR, LLVM IR, and {TARGET} assembly under 1.98.1')]:
        add(f'scripts/{family}/check-{family}-hardened-codegen.sh', BASE | {package}, ('1.98.1',), [marker],
            utilities=('mktemp', 'rm', 'find', 'grep', 'awk'))
    add('scripts/kmac/check-kmac-codegen.sh', BASE | {SHA3, 'brynja-mac-kmac'}, ('1.90.0', '1.98.1'),
        [f'KMAC source-owned state transitions and cleanup survive Rust 1.90.0 1.98.1 development/release MIR, LLVM IR, and {TARGET} assembly'],
        utilities=('mktemp', 'rm', 'find', 'grep', 'awk', 'head', 'cut'))
    add('scripts/tuplehash/check-tuplehash-codegen.sh', BASE | {SHA3, 'brynja-hash-tuple'}, ('1.90.0', '1.98.1'),
        [f'TupleHash exact source and reader cleanup survives Rust 1.90.0 1.98.1 development/release MIR, LLVM IR, and {TARGET} assembly'],
        fixtures=('tuplehash-public-api',), utilities=('mktemp', 'rm', 'find', 'grep', 'awk', 'head', 'sed', 'basename'))
    add('scripts/constant-time/check-constant-time-codegen.sh', set(), ('1.99.1',),
        [f'constant-time evidence roots preserve fixed work in LLVM and {TARGET} assembly under 1.99.1'],
        args=('1.99.1', TARGET), fixtures=('constant-time-codegen',),
        helpers=('scripts/constant-time/constant_time_codegen.py',), utilities=('mktemp', 'rm', 'find', 'python3'))
    add('scripts/zeroization/check-zeroization-codegen.sh', {'brynja-core'}, ('1.99.1',),
        [f'zeroization stores survive MIR, LLVM IR, and {TARGET} assembly under 1.99.1'],
        args=('1.99.1', TARGET), utilities=('mktemp', 'rm', 'find', 'grep', 'awk'))
    add('scripts/sanitization/check-sanitization-adapter-codegen.sh', {'brynja-core', 'brynja-sanitization', 'sanitization'}, ('1.99.1',),
        [f'adapter explicit-clear path preserves volatile stores in MIR, LLVM IR, and {TARGET} assembly under 1.99.1'],
        args=('1.99.1', TARGET), utilities=('mktemp', 'rm', 'find', 'grep'),
        extra=('crates/brynja-sanitization/tests/behavior.rs',))
    add('scripts/sanitization/check-sanitization-candidate.sh', set(), ('1.99.1',), [],
        fixtures=('sanitization-admission',), tests=True, rust_tools=('rustfmt', 'clippy-driver'))
    add('scripts/cpu/check-cpu-admission-fixture.sh', set(), ('1.99.1',),
        ['CPU admission scalar/mock fixtures pass on std, no_std, and no-atomics targets'],
        fixtures=('cpu-admission-fixture',), utilities=('grep',), tests=True)
    add('scripts/cryptography/check-api-profile-contract.sh', set(), ('1.99.1',),
        ['sealed hardened capability and typed public/secret output contract: PASS'],
        fixtures=('api-profile-contract',), utilities=('sh',), tests=True)
    add('scripts/kmac/check-kmac-conformance-gate.sh', set(), ('1.99.1',),
        ['default KMAC builds reject conformance constructors; explicit assurance feature compiles'],
        fixtures=('kmac-conformance-rejected', 'kmac-differential'), utilities=('mktemp', 'rm', 'grep', 'python3'),
        helpers=('scripts/kmac/check-kmac-conformance-enabled.py', 'scripts/kmac/kmac_conformance_inventory.py',
                 'scripts/cryptography/rust_source_contract.py', 'scripts/repository/facade_conformance_cases.py'))
    return result


def build(rows):
    known = definitions()
    paths = {argv[0] for argv in known}
    groups = {'shell-tools': {'tools': [{'program': 'bash'}]},
        'shell-workspace': {'toml': {'Cargo.toml': ['workspace.package.edition', 'workspace.package.rust-version',
            'workspace.lints', 'workspace.resolver', 'profile.dev', 'profile.test', 'profile.release']}}}
    checks = []
    for row in rows:
        argv = tuple(row['command'])
        if row['phase'] != 'repository' or not argv or argv[0] not in paths:
            continue
        if argv not in known or row.get('environment') or row.get('stdin'):
            raise ValueError('unreviewed shell command: ' + row['id'])
        spec = known[argv]
        key = 'shell-' + row['id']
        groups[key] = {'paths': [argv[0], *spec['helpers'], *spec['extra']],
            'tools': [{'program': p, 'toolchain': c} for c in spec['versions']
                      for p in ('cargo', 'rustc', *spec['rust_tools'])] +
                     [{'program': p} for p in spec['utilities']]}
        inputs = ['shell-tools', 'shell-workspace', key]
        inputs += source_inputs(groups, key + '-source', spec['packages'], 'Cargo.lock')
        for fixture in spec['fixtures']:
            inputs += fixture_inputs(groups, fixture, key + '-' + fixture)
        markers = spec['markers']
        success = {'contains': markers or ['test result: ok.'], 'unique_lines': markers}
        if spec['tests']:
            success['minimum_tests'] = 1
        checks.append(dict(component=row['families'][0], id=row['id'], name=row['label'], category='repository',
            command=list(argv), cwd='.', inputs=inputs,
            environment={**ENV, 'RUSTUP_TOOLCHAIN': '1.99.1'}, reject_environment=REJECT,
            platform='linux-x86_64', success=success, timeout_seconds=1800, log_bytes=16777216,
            establishes='Existing shell check with its original compiler/target and assertion boundaries. '
                        'Emitted-artifact checks are not native execution or whole-API erasure qualification; '
                        'the sanitizer candidate command does not select its optional broad matrix.'))
    return dict(schema=1, groups=groups, checks=checks)
