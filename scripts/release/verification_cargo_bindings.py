"""Reviewed Cargo build closures shared by explicit matrix/fixture bindings.

No Cargo discovery, automatic dependency resolver or reverse-family expansion.
"""
from pathlib import Path
import tomllib
from verification_miri_bindings import BASE, CPU, HOST, SHA2, SHA3, source_group, MANIFEST_FIELDS

ROOT = Path(__file__).resolve().parents[2]
MODERN = BASE | {SHA2, SHA3, 'brynja-mac-hmac', 'brynja-mac-kmac', 'brynja-hash-tuple', 'brynja-hash-parallel'}
CRYPTO = MODERN | {'brynja-crypto'}
FACADE = CRYPTO | {'brynja', 'brynja-pki', 'brynja-protocol', 'brynja-tls', 'brynja-tls12', 'brynja-tls13', 'brynja-tls13-handshake'}
LEGACY = BASE | {'brynja-legacy-md5', 'brynja-legacy-sha1'}
FIXTURES = {
    'sha2-hardened-api': (BASE | {SHA2}, []),
    'sha3-hardened-api': (BASE | {SHA3}, []),
    'sha256-public-api': (CRYPTO | {CPU}, []),
    'sha2-public-api': (FACADE | {CPU}, []),
    'sha3-public-api': (FACADE, []),
    'cshake-public-api': (FACADE, []),
    'sp800185-public-api': (FACADE, []),
    'sp800185-final': (FACADE | {CPU, 'brynja-hash-parallel-std'}, ['sp800185-public-api']),
    'hash-final-acceptance': (FACADE | {CPU}, ['sha2-public-api', 'sha3-public-api', 'sha3-hardened-api']),
    'general-sha512-t': (BASE | {SHA2}, []),
    'general-sha512-t-cpu': (BASE | {SHA2, CPU}, ['general-sha512-t']),
    'cpu-admission-fixture': (set(), []),
    'api-profile-contract': ({'brynja-core'}, []),
    'constant-time-codegen': ({'brynja-core'}, []),
    'sanitization-admission': ({'sanitization'}, []),
    'kmac-conformance-rejected': (BASE | {CPU, SHA3, 'brynja-mac-kmac'}, []),
    'hosted-cpu-execution': (BASE | {CPU, HOST, SHA2}, []),
    'legacy-hash-public-api/current': (LEGACY, []),
    'legacy-hash-final': (LEGACY | {'brynja-legacy-md5-std', 'brynja-legacy-sha1-std'}, ['legacy-hash-public-api']),
    'md5-public-api': (BASE | {'brynja-legacy-md5'}, []),
    'sha1-public-api': (BASE | {'brynja-legacy-sha1'}, []),
    'acceleration-contract': (set(), []),
    'hmac-policy': (set(), []),
    'legacy-hmac-policy': (LEGACY | {'brynja-legacy-hmac'}, []),
    'hmac-timing': (BASE | {CPU, HOST, SHA2, SHA3, 'brynja-mac-hmac'}, []),
    'keccak-batch': (BASE | {CPU, HOST, SHA2, SHA3}, []),
    'sha256-batch': (BASE | {CPU, HOST, SHA2}, []),
    'sha512-batch': (BASE | {CPU, HOST, SHA2}, []),
    'sha3-execution': (BASE | {CPU, HOST, SHA2, SHA3}, []),
    'kmac-public-api': (FACADE, []),
    'tuplehash-public-api': (FACADE, []),
    'parallelhash-public-api': (FACADE, []),
    'parallelhash-std-public-api': (BASE | {SHA3, 'brynja-hash-parallel', 'brynja-hash-parallel-std'}, []),
    'parallelhash-differential': (BASE | {CPU, HOST, SHA2, SHA3, 'brynja-hash-parallel', 'brynja-hash-parallel-std'}, []),
    'kmac-execution': (BASE | {CPU, HOST, SHA2, SHA3, 'brynja-mac-kmac'}, []),
    'tuplehash-execution': (BASE | {CPU, HOST, SHA2, SHA3, 'brynja-hash-tuple'}, []),
    'sha2-bit-differential': (BASE | {SHA2}, []),
    'sha3-bit-differential': (BASE | {SHA3}, []),
    'sha3-differential': (BASE | {SHA3}, []),
    'cshake-differential': (BASE | {SHA3}, []),
    'kmac-differential': (BASE | {SHA3, 'brynja-mac-kmac'}, []),
    'tuplehash-differential': (BASE | {SHA3, 'brynja-hash-tuple'}, []),
    'hmac-cleanup': (BASE | {SHA2, SHA3, 'brynja-mac-hmac'}, []),
    'legacy-hmac-cleanup': (LEGACY | {'brynja-legacy-hmac'}, []),
    'hmac-engine-cleanup': (BASE | {SHA2, SHA3, 'brynja-mac-hmac'}, []),
    'legacy-hmac-engine-cleanup': (LEGACY | {'brynja-legacy-hmac'}, []),
    'legacy-hmac-md5-cleanup': (LEGACY | {'brynja-legacy-hmac'}, []),
    'hmac-hosted-cleanup': (BASE | {CPU, HOST, SHA2, SHA3, 'brynja-mac-hmac'}, []),
    'hmac-execution-cleanup': (BASE | {CPU, SHA2, SHA3, 'brynja-mac-hmac'}, []),
    'legacy-hmac-execution-cleanup': (LEGACY | {'brynja-legacy-hmac'}, []),
    'legacy-hmac-hosted-cleanup': (LEGACY | {CPU, HOST, SHA2, SHA3, 'brynja-legacy-hmac', 'brynja-legacy-hmac-std'}, []),
}


def packages(argv):
    name = argv[argv.index('-p') + 1]
    if argv.count('-p') != 1:
        raise ValueError('multiple package selection needs explicit binding')
    if name in ('brynja-legacy-md5', 'brynja-legacy-sha1'):
        result = BASE | {name}
    elif name in ('brynja-legacy-md5-std', 'brynja-legacy-sha1-std'):
        result = BASE | {name, name.removesuffix('-std')}
    elif name == 'brynja-mac-hmac':
        result = BASE | {name, SHA2, SHA3, CPU}
    elif name == 'brynja-legacy-hmac':
        result = LEGACY | {name}
    elif name == 'brynja-legacy-hmac-std':
        result = LEGACY | {name, 'brynja-legacy-hmac', HOST, CPU, SHA2, SHA3}
    elif name == HOST:
        result = BASE | {name, CPU, SHA2, SHA3, 'brynja-mac-hmac'}
    else:
        raise ValueError('unreviewed package command: ' + name)
    return name, result


def source_inputs(groups, prefix, selected, lock):
    inputs = []
    for package in sorted(selected):
        key = prefix + '-' + package.removeprefix('brynja-')
        groups[key] = source_group(package, lock)
        # include_str! documentation is also a compiler input in these crates.
        if package.startswith('brynja-'):
            groups[key]['optional_paths'].append('crates/' + package + '/README.md')
        inputs.append(key)
    return inputs


def fixture_inputs(groups, name, prefix, selected_override=None):
    if name not in FIXTURES:
        raise ValueError('unreviewed fixture: ' + name)
    selected, children = FIXTURES[name]
    if selected_override is not None:
        selected = selected_override
    base = 'assurance/' + name
    inputs = source_inputs(groups, prefix, selected, base + '/Cargo.lock')
    for fixture in [name, *children]:
        directory = 'assurance/' + fixture
        manifest = directory + '/Cargo.toml'
        package = tomllib.loads((ROOT / manifest).read_text())['package']['name']
        key = prefix + '-fixture-' + fixture.replace('/', '-')
        source = directory.removesuffix('/current') if fixture.endswith('/current') else directory
        groups[key] = {'normalize_local_versions': True, 'paths': [source + '/src'],
            'optional_paths': [directory + '/build.rs', source + '/fixtures', source + '/tests', source + '/README.md'],
            'toml': {manifest: MANIFEST_FIELDS + ['bin', 'workspace.resolver', 'profile.dev', 'profile.test', 'profile.release']},
            'locks': [{'path': base + '/Cargo.lock', 'packages': [package]}]}
        if name == 'legacy-hash-final':
            groups[key]['optional_paths'] += ['assurance/legacy-hash-public-api/fixtures']
        if fixture == 'general-sha512-t':
            groups[key]['paths'].append(directory + '/profile.rs')
        if fixture == 'general-sha512-t-cpu':
            groups[key]['paths'].append('crates/brynja-hash-sha2/tests/vectors/general-sha512-t-digest.txt')
        if name == 'hmac-policy':
            groups[key]['paths'].append('crates/brynja-mac-hmac/src/policy.rs')
        if name in ('hmac-cleanup', 'legacy-hmac-cleanup'):
            package = 'brynja-mac-hmac' if name == 'hmac-cleanup' else 'brynja-legacy-hmac'
            groups[key]['paths'].append('crates/' + package + '/src/scratch.rs')
        if name == 'sha3-execution':
            groups[key]['paths'] += ['crates/brynja-hash-sha3/tests/execution_cases',
                                    'crates/brynja-hash-sha3/tests/cshake_execution_cases']
        inputs.append(key)
    return inputs


def cargo_inputs(groups, argv, prefix):
    inherited = prefix + '-inherited-workspace'
    groups.setdefault(inherited, {'toml': {'Cargo.toml': [
        'workspace.package.edition', 'workspace.package.rust-version', 'workspace.lints']}})
    inputs = [inherited]
    if '--manifest-path' in argv:
        manifest = argv[argv.index('--manifest-path') + 1]
        name = manifest.removeprefix('assurance/').removesuffix('/Cargo.toml')
        if manifest != 'assurance/' + name + '/Cargo.toml':
            raise ValueError('unreviewed manifest path')
        return inputs + fixture_inputs(groups, name, prefix)
    name, selected = packages(argv)
    inputs += source_inputs(groups, prefix, selected, 'Cargo.lock')
    key = prefix + '-tests'
    groups[key] = {'optional_paths': ['crates/' + name + '/tests'],
        'toml': {'Cargo.toml': ['profile.dev', 'profile.test', 'profile.release', 'workspace.resolver']}}
    return inputs + [key]
