"""Explicit bindings for existing bounded proofs, not new proof obligations."""
import json
from verification_miri_bindings import BASE, CPU, SHA2, SHA3, HOST, source_group, REJECT

VERSION = '0.68.0'
TOOLCHAIN = '1.90.0'
INVENTORY_ONLY = {'core', 'sanitization', 'legacy', 'acceleration', 'static_cpu'}
# Original proof commands/populations from check-kani.sh, without its unrelated
# repository-wide inventory preflight. SHA-2/3 retain their separate batch step.
PROOFS = {
    'md5': [(['-p', 'brynja-legacy-md5', '--features', 'batch'], 3)],
    'sha1': [(['-p', 'brynja-legacy-sha1'], 1)],
    'sha2': [(['-p', SHA2, '--features', 'batch-execution'], 11),
             (['-p', SHA2, '--features', 'batch512-execution', '--harness', 'batch512::control::proofs::batch_budget_is_atomic_and_never_wraps'], 1)],
    'sha3': [(['-p', SHA3], 10),
             (['-p', SHA3, '--features', 'batch-execution', '--harness', 'batch::control::proofs::batch_budget_is_atomic_and_never_wraps'], 1)],
    'kmac': [(['-p', 'brynja-mac-kmac'], 2)],
    'tuplehash': [(['-p', 'brynja-hash-tuple'], 2)],
    'parallelhash': [(['-p', 'brynja-hash-parallel'], 1)],
}
PACKAGES = {
    'md5': BASE | {'brynja-legacy-md5'}, 'sha1': BASE | {'brynja-legacy-sha1'},
    'sha2': BASE | {SHA2, CPU}, 'sha3': BASE | {SHA3, CPU},
    'kmac': BASE | {'brynja-mac-kmac', SHA3},
    'tuplehash': BASE | {'brynja-hash-tuple', SHA3},
    'parallelhash': BASE | {'brynja-hash-parallel', SHA3, SHA2, CPU, HOST},
    'legacy_hmac': BASE | {'brynja-legacy-hmac', 'brynja-legacy-sha1', 'brynja-legacy-md5'},
    'hmac': set(),  # dependency-free fixture includes the actual runtime policy
}
SHARED = ['scripts/hmac/hmac_verifiers.py', 'scripts/repository/facade_cargo_environment.py']


def marker(component):
    return f'Scoped Kani {component}: PASS; {sum(n for _, n in PROOFS[component])} existing bounded proofs'


def build(rows):
    groups = {
        'kani-tools': {'tools': [{'program': p, 'toolchain': TOOLCHAIN} for p in ('cargo', 'rustc')]
            + [{'program': 'python3'}, {'program': 'cargo-kani'}, {'program': 'kani-bundle', 'toolchain': VERSION}]},
        'kani-workspace': {'toml': {'Cargo.toml': ['workspace.package.edition', 'workspace.package.rust-version',
            'workspace.lints', 'workspace.resolver', 'profile.dev', 'profile.test']}},
        'kani-setup': {'paths': SHARED},
        'kani-adapter': {'paths': ['scripts/release/run-kani-component.py'],
            'toml': {'assurance/policy.toml': ['toolchains.kani']}},
        'kani-inherited-workspace': {'toml': {'Cargo.toml': ['workspace.package.edition',
            'workspace.package.rust-version', 'workspace.lints']}},
    }
    checks = []
    for row in rows:
        if row['phase'] not in ('kani', 'inventory-only'):
            continue
        if len(row['families']) != 1:
            raise ValueError('ambiguous Kani component')
        component = row['families'][0]
        if component in INVENTORY_ONLY:
            continue
        if component not in PACKAGES:
            raise ValueError('unreviewed Kani component')
        inputs = ['kani-tools', 'kani-setup']
        lock = 'Cargo.lock'
        if component in ('hmac', 'legacy_hmac'):
            prefix = 'legacy-hmac' if component == 'legacy_hmac' else 'hmac'
            base = 'assurance/' + prefix + '-policy'
            lock = base + '/Cargo.lock'
            script = 'scripts/' + prefix + '/check-' + prefix + '-kani.py'
            command = ['python3', script]
            completion = ('Legacy HMAC invalid-tag-width Kani: PASS; 2 proofs; no cryptographic proof claim'
                if component == 'legacy_hmac' else 'HMAC public-length Kani proofs: PASS; 2 proofs, no cryptographic proof claim')
            key = 'kani-' + prefix + '-fixture'
            paths = [base + '/src', script]
            paths += (['scripts/legacy-hmac/legacy_hmac_verifiers.py'] if component == 'legacy_hmac'
                      else ['crates/brynja-mac-hmac/src/policy.rs'])
            # Existing wrappers enforce these exact fixture/policy manifests.
            groups[key] = {'paths': paths + [base + '/Cargo.toml', 'assurance/policy.toml'],
                'optional_paths': [base + '/build.rs'],
                'locks': [{'path': lock, 'packages': ['brynja-' + prefix + '-policy-fixture']}]}
            inputs.append(key)
            if component == 'legacy_hmac':
                inputs.append('kani-inherited-workspace')
        else:
            command = ['python3', 'scripts/release/run-kani-component.py', component,
                       '--steps-json', json.dumps(PROOFS[component], separators=(',', ':'))]
            completion = marker(component)
            inputs += ['kani-workspace', 'kani-adapter']
        expected_old = (command if component in ('hmac', 'legacy_hmac') else
            ['scripts/assurance/check-kani.sh', '--required-groups', component])
        if row['command'] != expected_old:
            raise ValueError('Kani catalog command changed; review the binding')
        for package in sorted(PACKAGES[component]):
            key = 'kani-' + component.replace('_', '-') + '-' + package.removeprefix('brynja-')
            groups[key] = source_group(package, lock)
            inputs.append(key)
        checks.append(dict(component=component, id=row['id'], name=f'{component} bounded Kani proofs', category='kani',
            establishes='Existing public-length/control predicates only; not a cryptographic construction proof.',
            command=command, cwd='.', inputs=inputs, platform='linux-x86_64',
            environment={'RUSTUP_AUTO_INSTALL': '0', 'CARGO_NET_OFFLINE': 'true'},
            reject_environment=REJECT + ['KANI_HOME', 'KANIFLAGS', 'KANI_ARGS'],
            success={'contains': [completion], 'unique_lines': [completion]},
            timeout_seconds=1200, log_bytes=16777216))
    return dict(schema=1, groups=groups, checks=checks)
