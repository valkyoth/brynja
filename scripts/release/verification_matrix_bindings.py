"""Finite compiler compatibility registrations; no compiler or test execution."""
import shlex
from verification_cargo_bindings import cargo_inputs
from verification_miri_bindings import REJECT

VERSIONS = {'1.90.0', '1.91.0', '1.92.0', '1.93.0', '1.94.0', '1.95.0', '1.96.0', '1.96.1',
            '1.97.0', '1.97.1', '1.98.0', '1.98.1', '1.99.0', '1.99.1'}
PACKAGE_ARGS = [
    'test --locked --offline -p brynja-crypto-cpu-std --features strict-hmac-acceleration --lib strict_hmac',
    'test --locked --offline -p brynja-crypto-cpu-std --features macos-resident-hmac-acceleration --lib macos_resident::hmac',
    'test --locked --offline -p brynja-crypto-cpu-std --features hmac-execution --test hmac',
    'test --locked --offline -p brynja-mac-hmac --all-features',
    'test --locked --offline -p brynja-legacy-hmac --all-features',
    'test --locked --offline -p brynja-legacy-hmac-std --all-features',
    'test --locked -p brynja-legacy-md5-std', 'test --locked -p brynja-legacy-sha1-std',
    'test --locked -p brynja-legacy-sha1', 'test --locked -p brynja-legacy-md5 --all-features',
    'test --locked -p brynja-legacy-sha1 --features cpu --test cpu',
]
FIXTURE_ARGS = {
    'sha256-public-api': ('run --quiet --locked', '', 'SHA-256 public API acceptance: PASS'),
    'sha2-public-api': ('run --quiet --locked', '', 'Complete SHA-2 public API acceptance: PASS'),
    'sha3-public-api': ('run --quiet --locked', '', 'Complete SHA-3/SHAKE portable public API acceptance: PASS'),
    'cshake-public-api': ('test --quiet --locked', '', None),
    'sp800185-public-api': ('run --quiet --locked', '', 'SP 800-185 portable public API acceptance: PASS'),
    'sp800185-final': ('run --quiet --locked', '', 'SP 800-185 execution acceptance: PASS'),
    'hash-final-acceptance': ('run --quiet --locked', '', 'Combined SHA-2 and SHA-3/SHAKE final acceptance: PASS'),
    'general-sha512-t': ('run --locked --offline', '', 'General SHA-512/t portable public acceptance: PASS'),
    'cpu-admission-fixture': ('check', '', None),
    'hosted-cpu-execution': ('test --locked --offline', '', None),
    'legacy-hash-public-api/current': ('test --locked', '--lib', None),
    'legacy-hash-final': ('run --locked', '', 'Legacy SHA-1/MD5 final public API acceptance: PASS'),
    'md5-public-api': ('test --locked', '--lib', None),
    'sha1-public-api': ('test --locked', '--lib', None),
}


def build(rows):
    groups, checks = {}, []
    allowed = {tuple(shlex.split(args)): None for args in PACKAGE_ARGS}
    for name, (mode, tail, marker) in FIXTURE_ARGS.items():
        allowed[tuple(shlex.split(mode) + ['--manifest-path', 'assurance/' + name + '/Cargo.toml'] + shlex.split(tail))] = marker
    for row in rows:
        if row['phase'] != 'matrix':
            continue
        original = row['command']
        if original[0] != 'cargo' or original[1].removeprefix('+') not in VERSIONS:
            raise ValueError('unreviewed compiler identity')
        args = tuple(original[2:])
        if args == ('check', '--workspace', '--all-features'):
            continue  # Explicit broad diagnostic, not a component obligation.
        if args not in allowed:
            raise ValueError('unreviewed matrix command: ' + str(args))
        version = original[1][1:]
        key = 'matrix-tools-' + version.replace('.', '-')
        groups[key] = {'tools': [{'program': tool, 'toolchain': version} for tool in ('cargo', 'rustc', 'rustdoc')]}
        # Source scopes are shared between compiler versions, not duplicated.
        import hashlib
        prefix = 'matrix-source-' + hashlib.sha256(repr(args).encode()).hexdigest()[:16]
        inputs = [key] + cargo_inputs(groups, list(args), prefix)
        command = original.copy()
        for flag in ['--locked', '--offline']:
            if flag not in command:
                command.insert(3, flag)
        marker = allowed[args]
        if args[0] == 'test':
            success = dict(contains=['test result: ok.'], minimum_tests=1, allow_ignored=True)
        elif marker:
            success = dict(contains=[marker], unique_lines=[marker])
        else:
            success = dict(contains=['Finished', 'target(s)'])
        stdin = row.get('stdin')
        expected = 'crates/brynja-hash-sha2/tests/vectors/general-sha512-t-digest.txt' if '--manifest-path' in args and 'assurance/general-sha512-t/Cargo.toml' in args else None
        if stdin != expected:
            raise ValueError('compiler fixture stdin changed')
        component = 'static_cpu' if 'static_cpu' in row['families'] else row['families'][0]
        checks.append(dict(component=component, id=row['id'], name=f'{version}: ' + ' '.join(args),
            category='matrix', command=command, stdin=stdin, cwd='.', inputs=inputs,
            platform='macos-aarch64' if 'macos_resident::hmac' in args else 'linux-x86_64',
            environment={'RUSTUP_AUTO_INSTALL': '0', 'CARGO_NET_OFFLINE': 'true'}, reject_environment=REJECT,
            success=success, timeout_seconds=1200, log_bytes=16777216,
            establishes='Existing compiler compatibility selection. Nonzero ordinary tests or the named acceptance program; ignored tests are NOT native qualification.'))
    return dict(schema=1, groups=groups, checks=checks)
