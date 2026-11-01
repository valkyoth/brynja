"""Explicit scoped bindings for existing Miri selections.

Not a dependency resolver or test generator: use the recorded task argv/case
and small reviewed package/fixture closure tables.
"""
import hashlib
import json

NIGHTLY = 'nightly-2026-09-11'
TARGET = 'x86_64-unknown-linux-gnu'
PROFILES = {'routine', 'extended', 'existing-full'}
BASE = {'brynja-core', 'brynja-hash-core'}
CPU = 'brynja-crypto-cpu'
SHA2 = 'brynja-hash-sha2'
SHA3 = 'brynja-hash-sha3'
HOST = 'brynja-crypto-cpu-std'
FEATURES = {
    'brynja-core': set(), 'brynja-sanitization': set(),
    'brynja-legacy-md5': {'cpu', 'execution', 'hardened-execution'},
    'brynja-legacy-sha1': {'cpu', 'execution', 'hardened-execution'},
    SHA2: {'batch-execution', 'batch512-execution', 'general-sha512-t', 'runtime-execution', 'hardened-execution'},
    SHA3: {'static-execution', 'batch-execution', 'hardened-execution'},
    'brynja-mac-kmac': {'hardened-execution'},
    'brynja-hash-tuple': {'hardened-execution'},
    'brynja-hash-parallel': {'hardened-execution'},
    'brynja-hash-parallel-std': {'runtime-execution'},
    CPU: {'static-execution', 'runtime-execution', 'sha256-batch', 'sha512-batch', 'hardened-execution'},
    HOST: {'sponge-execution', 'runtime-execution', 'hmac-execution', 'strict-hmac-acceleration', 'macos-resident-hmac-acceleration'},
    'brynja-mac-hmac': {'hardened-execution'},
    'brynja-legacy-hmac': {'sha1-execution'},
    'brynja-legacy-hmac-std': {'ALL'},
}
REJECT = ['MIRIFLAGS', 'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS',
          'CARGO_BUILD_TARGET', 'MIRI_SYSROOT', 'MIRI_BE_RUSTC', 'MIRI_REPLACE_LIBRS_IF_NOT_TEST',
          'RUSTC', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER',
          'BRYNJA_MIRI_CASE', 'BRYNJA_MIRI_PROFILE', 'BRYNJA_MIRI_WIDTH']
MANIFEST_FIELDS = ['package.name', 'package.edition', 'package.rust-version',
    'package.build', 'package.links', 'package.autotests', 'lib', 'test', 'features',
    'dependencies', 'dev-dependencies', 'build-dependencies', 'target', 'lints']
# Each separate workspace has its own lock and an explicitly reviewed command.
# In particular legacy-final must NOT enable its default hosted dependencies.
FIXTURES = {
    'acceleration-contract': ('brynja-acceleration-contract-fixture', [], set()),
    'general-sha512-t': ('brynja-general-sha512-t-consumer', [], BASE | {SHA2}),
    'legacy-hash-final': ('brynja-legacy-hash-final-fixture', ['--no-default-features'],
        BASE | {'brynja-legacy-md5', 'brynja-legacy-sha1'}),
    'legacy-hash-public-api/current': ('brynja-legacy-hash-public-api-fixture', [],
        BASE | {'brynja-legacy-md5', 'brynja-legacy-sha1'}),
    'static-cpu-execution': ('brynja-static-cpu-execution-fixture', [], {CPU}),
    'hosted-cpu-execution': ('brynja-hosted-cpu-execution-fixture', [], BASE | {CPU, HOST, SHA2}),
}


def closure(package, features):
    if package not in FEATURES or not features <= FEATURES[package]:
        raise ValueError('unreviewed package/feature scope: ' + package + str(sorted(features)))
    result = BASE | {package}
    if package == 'brynja-core':
        return {package}
    if package == 'brynja-sanitization':
        return {package, 'brynja-core', 'sanitization'}
    if package == CPU:
        return {CPU} | ({'brynja-core'} if 'hardened-execution' in features else set())
    if package in (SHA2, SHA3) and features - {'general-sha512-t'}:
        result.add(CPU)
    if package in ('brynja-mac-kmac', 'brynja-hash-tuple'):
        result.add(SHA3)
        if features:
            result.add(CPU)
    if package == 'brynja-mac-hmac':
        result |= {SHA2, SHA3}
        if features:
            result.add(CPU)
    if package == HOST:
        result |= {CPU, SHA2}
        if features & {'sponge-execution', 'hmac-execution', 'strict-hmac-acceleration', 'macos-resident-hmac-acceleration'}:
            result.add(SHA3)
        if any('hmac' in feature for feature in features):
            result.add('brynja-mac-hmac')
    if package in ('brynja-hash-parallel', 'brynja-hash-parallel-std'):
        # ParallelHash's test target has hosted dev dependencies even without
        # native execution. Keep that explicit build closure in its own scope.
        result |= {'brynja-hash-parallel', CPU, HOST, SHA2, SHA3}
    if package in ('brynja-legacy-hmac', 'brynja-legacy-hmac-std'):
        result |= {'brynja-legacy-md5', 'brynja-legacy-sha1'}
    if package == 'brynja-legacy-hmac-std':
        result |= {'brynja-legacy-hmac', CPU, HOST, SHA2, SHA3}
    return result


def source_group(package, lock='Cargo.lock'):
    if package == 'sanitization':
        return {'toml': {'Cargo.toml': ['workspace.dependencies.sanitization']},
                'locks': [{'path': lock, 'packages': [package]}]}
    base = 'crates/' + package
    return {'paths': [base + '/src'], 'optional_paths': [base + '/build.rs'],
            'normalize_local_versions': True,
            'toml': {
                base + '/Cargo.toml': MANIFEST_FIELDS,
                'Cargo.toml': ['workspace.dependencies.' + package]},
            'locks': [{'path': lock, 'packages': [package]}]}


def fixture_inputs(argv, groups):
    manifest = argv[argv.index('--manifest-path') + 1]
    name = manifest.removeprefix('assurance/').removesuffix('/Cargo.toml')
    if name not in FIXTURES:
        raise ValueError('unreviewed Miri fixture workspace: ' + manifest)
    package, options, packages = FIXTURES[name]
    base = 'assurance/' + name
    expected = ['--manifest-path', base + '/Cargo.toml', *options, '--lib']
    if name.startswith('legacy-hash'):
        expected.append('dynamic_')
    if argv != expected:
        raise ValueError('unreviewed Miri fixture configuration: ' + name)
    key = 'miri-fixture-' + name.replace('/', '-')
    group = {'normalize_local_versions': True,
        'paths': [base + '/src'], 'optional_paths': [base + '/build.rs'],
        'toml': {manifest: MANIFEST_FIELDS + ['workspace.resolver', 'profile.dev', 'profile.test'],
                 'Cargo.toml': ['workspace.package.edition', 'workspace.package.rust-version', 'workspace.lints']},
        'locks': [{'path': base + '/Cargo.lock', 'packages': [package]}]}
    if name.startswith('legacy-hash'):
        shared = 'assurance/legacy-hash-public-api'
        group['paths'] += [shared + '/src', shared + '/fixtures']
        if name.endswith('/current'):
            group['paths'].remove(base + '/src')
        else:
            group['toml'][shared + '/Cargo.toml'] = MANIFEST_FIELDS
            group['optional_paths'].append(shared + '/build.rs')
            group['locks'][0]['packages'].append('brynja-legacy-hash-public-api-fixture')
    groups[key] = group
    inputs = ['miri-tools', key]
    for dependency in sorted(packages):
        dependency_key = key + '-' + dependency.removeprefix('brynja-')
        groups[dependency_key] = source_group(dependency, base + '/Cargo.lock')
        inputs.append(dependency_key)
    return inputs


def package_inputs(argv, groups):
    if argv.count('-p') != 1 or '--workspace' in argv:
        raise ValueError('unreviewed task package selector')
    package = argv[argv.index('-p') + 1]
    features = set(argv[argv.index('--features') + 1].split(',')) if '--features' in argv else set()
    if '--all-features' in argv:
        features.add('ALL')
    packages = closure(package, features)
    inputs = ['miri-tools', 'miri-workspace']
    for dependency in sorted(packages):
        key = 'miri-source-' + dependency.removeprefix('brynja-')
        groups[key] = source_group(dependency)
        inputs.append(key)
    if '--test' in argv or '--tests' in argv:
        key = 'miri-tests-' + package.removeprefix('brynja-')
        # Includes helper modules and fixtures, not just the top-level .rs.
        groups[key] = {'paths': ['crates/' + package + '/tests']}
        inputs.append(key)
    return inputs


def build(rows):
    groups = {
        'miri-tools': {'tools': [{'program': p, 'toolchain': NIGHTLY} for p in ('cargo', 'rustc', 'cargo-miri', 'miri')]},
        'miri-workspace': {'toml': {'Cargo.toml': ['workspace.package.edition',
            'workspace.package.rust-version', 'workspace.lints', 'workspace.resolver', 'profile.dev', 'profile.test']}},
    }
    checks = []
    for row in rows:
        if row['phase'] != 'miri':
            continue
        definition = row['definition']
        identity = hashlib.sha256((json.dumps(definition, sort_keys=True, separators=(',', ':')) + '\n').encode()).hexdigest()
        if row['id'] != 'miri-' + identity[:16]:
            raise ValueError('Miri task identity does not match its meaning')
        task = definition['task']
        argv = task['argv']
        inputs = fixture_inputs(argv, groups) if '--manifest-path' in argv else package_inputs(argv, groups)
        profile = definition['profile']
        if profile not in PROFILES or row['families'] != [definition['group']]:
            raise ValueError('invalid Miri profile/component binding')
        flags = '-Zmiri-report-progress=10000000'
        for key, value in task['environment'].items():
            if key not in {'BRYNJA_MIRI_CASE', 'BRYNJA_MIRI_PROFILE', 'BRYNJA_MIRI_WIDTH'} or not value or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789-' for c in value):
                raise ValueError('unreviewed runtime selector')
            flags += ' -Zmiri-env-set=' + key + '=' + value
        command = ['cargo', '+' + NIGHTLY, 'miri', 'test', '--locked', '--offline', '--target', TARGET, *argv]
        if '--' not in command:
            command.append('--')
        command.append('--nocapture')
        success = {'contains': ['test result: ok.'], 'minimum_tests': 1}
        if task['marker']:
            success.update(exact_tests=1, unique_lines=[task['marker']])
        checks.append(dict(component=definition['group'], id=row['id'],
            name=row['label'], category='miri-' + profile, platform='linux-x86_64',
            establishes='Existing Miri task selection, profile ' + profile + '; ' + task.get('coverage', 'registered')
                + '. No native execution or exhaustive coverage beyond this task is claimed.',
            command=command, cwd='.', inputs=inputs,
            environment={'MIRIFLAGS': flags, 'RUSTUP_AUTO_INSTALL': '0', 'CARGO_TARGET_DIR': 'target/miri-tasks'},
            reject_environment=REJECT, timeout_seconds=3600, log_bytes=16777216,
            success=success))
    return dict(schema=1, groups=groups, checks=checks)
