#!/usr/bin/env python3
"""Focused real-archive strict HMAC API checks; no unrelated-family sweep."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import sys
from unittest.mock import patch

import hmac_acceptance
import hmac_package
import hmac_strict_cases as cases
import hmac_timing_routes as routes

ROOT = Path(__file__).resolve().parents[2]
sys.path.append(str(ROOT / 'scripts/repository'))
spec = importlib.util.spec_from_file_location('hmac_strict_api', ROOT / 'scripts/repository/check-facade-package.py')
api = importlib.util.module_from_spec(spec)
spec.loader.exec_module(api)
import strict_public_consumer as scalar
import strict_accelerated_consumer as accelerated


def supported():
    return sys.platform == 'linux' and platform.machine() in ('x86_64', 'aarch64') and platform.libc_ver()[0] == 'glibc'


def population(result, count):
    rows = re.findall(r'^test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored; '
                      r'(\d+) measured; (\d+) filtered out;', result.stdout, re.M)
    api.require(result.returncode == 0 and rows == [('ok', str(count), '0', '0', '0', '0')],
                'strict HMAC runtime test population changed')


def graph(document, roots, consumer, *, compiled=False, unified=False):
    expected = accelerated.expected_features() if compiled else scalar.expected_features()
    if unified:
        expected['brynja-crypto-cpu-std'].add('strict-hmac-acceleration')
        expected['brynja-mac-hmac'].add('hardened-execution')
        for name in ('brynja-crypto-cpu', 'brynja-hash-sha2', 'brynja-hash-sha3'):
            expected[name].update(('static-execution', 'hardened-execution'))
    with patch.object(accelerated, 'expected_features', return_value=expected):
        accelerated.graph(api, document, roots, consumer)


def manifest(consumer, roots, *, compiled=False, unified=False):
    extra = ('host={package="brynja-crypto-cpu-std", version="=0.2.0", default-features=false, '
             'features=["strict-hmac-acceleration"]}\n') if unified else ''
    api.manifest(consumer, roots, 'brynja-strict', ['acceleration'] if compiled else [], extra=extra)


def check_graph(cargo, consumer, env, roots, **mode):
    result = api.run(cargo + ['metadata', '--offline', '--format-version=1'], consumer, env)
    graph(json.loads(result.stdout), roots, consumer, **mode)


def negatives(cargo, consumer, env, compiled):
    source = consumer / 'src/lib.rs'
    original = source.read_text()
    command = cargo + ['check', '--locked', '--offline', '--lib', '--message-format=json']
    try:
        source.write_text(cases.positive(compiled))
        api.run(command, consumer, env)
        count = 0
        for body, code in cases.negatives(compiled):
            source.write_text(cases.PREFIX + body)
            hmac_acceptance.diagnostic_rejection(api.run(command, consumer, env, success=False), code)
            count += 1
    finally:
        source.write_text(original)
    api.require(count == (138 if compiled else 140), 'strict HMAC negative probe population')
    print(f'Strict HMAC: {count} ownership/lifetime/export negatives; compiled={compiled}', flush=True)


def campaign(cargo, consumer, env):
    for profile in ([], ['--release']):
        result = api.run(cargo + ['test', '--locked', '--offline', '--test', 'hmac', *profile], consumer, env)
        population(result, 4 if supported() else 2)
    print('Strict HMAC scalar debug/release: ' + ('protected execution' if supported()
          else 'unsupported-platform rejection only'), flush=True)


def compiled_campaign(cargo, consumer, env, family, expected):
    mode = dict(env, BRYNJA_STRICT_HMAC_ROUTE=family, BRYNJA_STRICT_HMAC_EXPECT=expected)
    identities = {'sha256': 2, 'sha512': 6, 'keccak': 4}[family]
    for profile in ([], ['--release']):
        result = api.run(cargo + ['test', '--locked', '--offline', '--test', 'compiled', *profile,
                                  '--', '--nocapture'], consumer, mode)
        population(result, 1)
        markers = [line for line in result.stdout.splitlines() if line.startswith('HMAC_STRICT_')]
        api.require(markers == [f'HMAC_STRICT_COMPILED: {family}; {expected}; {identities} identities'],
                    'strict HMAC compiled route/identity changed')
    print(f'Strict HMAC compiled debug/release: {family}; {expected}', flush=True)


def generic_modes(cargo, consumer, env, directory):
    # Apple targets may enable SHA bundles by default. Inspect the actual
    # compiler configuration, not the presence/absence of RUSTFLAGS alone.
    cfg = api.run(['rustc', cargo[1], '--print', 'cfg'], consumer, env).stdout
    arch, ready = accelerated.compiled(cfg)
    result = {}
    for family, route in (('sha256', 'narrow'), ('sha512', 'wide'), ('keccak', 'keccak')):
        if ready[route]:
            routes.prepare('static', family, directory, env)  # Generic CPU/OS preflight.
        result[family] = ('native' if supported() else 'unsupported-platform') if ready[route] else 'missing-features'
    disabled = '-sha,-sha512,-avx2' if arch == 'x86_64' else '-sha2,-sha3'
    negative = dict(env, RUSTFLAGS='-C target-feature=' + disabled,
                    CARGO_TARGET_DIR=str(directory / 'target-negative-features'))
    return result, negative


def exposure_mutants(cargo, consumer, env, roots):
    """Compile actual facade broadening, then prove its negative probe detects it."""
    path = roots['brynja-strict'] / 'src/hmac.rs'
    original = path.read_text()
    source = consumer / 'src/lib.rs'
    saved = source.read_text()
    command = cargo + ['check', '--locked', '--offline', '--lib', '--message-format=json']
    probes = (
        (original + '\npub use brynja_crypto_cpu_std::strict_hmac::Algorithm;\n', 'Algorithm'),
        (original.replace('#[cfg(feature = "acceleration")]\n', ''), 'CompiledSession'),
        ('//! Deliberately broadened fixture facade.\npub use brynja_crypto_cpu_std::strict_hmac::*;\n', 'Kernel'),
    )
    api.require(original.count('#[cfg(feature = "acceleration")]\n') == 1,
                'strict HMAC feature guard anchor changed')
    try:
        for mutant, name in probes:
            source.write_text('pub use facade::hmac::' + name + ';\n')
            hmac_acceptance.diagnostic_rejection(api.run(command, consumer, env, success=False), 'E0432')
            path.write_text(mutant)
            # This MUST compile. A broken mutant is not counted as coverage.
            result = api.run(command, consumer, env)
            try:
                hmac_acceptance.diagnostic_rejection(result, 'E0432')
            except ValueError:
                pass
            else:
                raise ValueError('strict export negative accepted a successful compilation')
            path.write_text(original)
            hmac_acceptance.diagnostic_rejection(api.run(command, consumer, env, success=False), 'E0432')
    finally:
        path.write_text(original)
        source.write_text(saved)
    print('Strict HMAC: three compiling export/feature-broadening mutants detected', flush=True)


def execute(directory, toolchain, native):
    env = api.clean_environment(directory)
    env['RUSTUP_TOOLCHAIN'] = toolchain
    api.cargo_environment.check(directory / 'package-workspace', env)
    with patch.dict(os.environ, env, clear=True), \
            patch.object(api.packaging, 'PACKAGING_PACKAGES', scalar.specifications(api)):
        roots = api.packaging.package_roots(directory)
    leaf = roots['brynja-mac-hmac']
    hmac_package.validate_members(str(path.relative_to(leaf)) for path in leaf.rglob('*') if path.is_file())
    consumer = directory / 'strict-hmac-consumer'
    (consumer / 'src').mkdir(parents=True)
    (consumer / 'tests').mkdir()
    (consumer / 'tests/hmac.rs').write_text(cases.scalar_fixture(ROOT))
    cargo = ['cargo', '+' + toolchain]
    for compiled in (False, True):
        manifest(consumer, roots, compiled=compiled)
        (consumer / 'src/lib.rs').write_text(cases.positive(compiled) + cases.documentation(ROOT))
        check_graph(cargo, consumer, env, roots, compiled=compiled)
        campaign(cargo, consumer, env)
        negatives(cargo, consumer, env, compiled)
    (consumer / 'tests/compiled.rs').write_text((ROOT / 'assurance/hmac-strict/compiled.rs').read_text())
    generic, negative_env = generic_modes(cargo, consumer, env, directory)
    for family, expected in generic.items():
        compiled_campaign(cargo, consumer, env, family, expected)
        if expected != 'missing-features':
            compiled_campaign(cargo, consumer, negative_env, family, 'missing-features')
    for family in native:
        native_env, _ = routes.prepare('static', family, directory, env)
        # A different build directory prevents a generic/native cache mix-up.
        native_env['CARGO_TARGET_DIR'] = str(directory / ('target-native-' + family))
        campaign(cargo, consumer, native_env)
        compiled_campaign(cargo, consumer, native_env, family,
                          'native' if supported() else 'unsupported-platform')
    manifest(consumer, roots, unified=True)
    (consumer / 'src/lib.rs').write_text('pub use host::strict_hmac::CompiledSession;\n')
    check_graph(cargo, consumer, env, roots, unified=True)
    api.run(cargo + ['check', '--locked', '--offline', '--lib'], consumer, env)
    for name in ('CompiledSession', 'Kernel'):
        (consumer / 'src/lib.rs').write_text('pub use facade::hmac::' + name + ';\n')
        hmac_acceptance.diagnostic_rejection(api.run(cargo + ['check', '--locked', '--offline', '--lib',
            '--message-format=json'], consumer, env, success=False), 'E0432')
    exposure_mutants(cargo, consumer, env, roots)
    (consumer / 'src/lib.rs').write_text(cases.positive())
    campaign(cargo, consumer, env)
    print('Strict HMAC packaged acceptance: PASS; no independent or release qualification claim', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--toolchain', default='1.99.1')
    parser.add_argument('--native-kernel', choices=('sha256', 'sha512', 'keccak'), action='append', default=[])
    args = parser.parse_args()
    api.require(len(args.native_kernel) == len(set(args.native_kernel)), 'duplicate native route')
    with api.cargo_environment.private_directory(ROOT) as directory:
        execute(Path(directory), args.toolchain, args.native_kernel)


if __name__ == '__main__':
    main()
