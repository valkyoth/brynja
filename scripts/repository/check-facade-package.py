#!/usr/bin/env python3
"""Compile opt-ins in isolated downstream consumers of real package archives.

No workspace roots, hosted features, evidence cfgs or registry downloads can
make a missing forwarding edge pass. This is focused facade acceptance, not
new cryptographic or native qualification.
"""
import argparse
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import tomllib
from unittest.mock import patch

import facade_package_cases as cases
import facade_family_cases as families
import facade_batch_cases as batches
import facade_workspace_policy as policy
import facade_cargo_environment as cargo_environment
import facade_adversarial_cases as adversarial
import facade_keccak_cases as keccak
import facade_sha2_acceptance as sha2_batches
import facade_keccak_acceptance as keccak_routes
import facade_tuplehash_acceptance as tuplehash
import facade_parallelhash_acceptance as parallelhash

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/sha2'))
import sha2_public_api as packaging


def require(condition, message):
    if not condition:
        raise ValueError('facade package acceptance: ' + message)


def clean_environment(root):
    env = os.environ.copy()
    for key in tuple(env):
        if key.startswith(('CARGO_', 'RUST', 'BRYNJA_')):
            del env[key]
    env['CARGO_HOME'] = str(root / 'cargo-home')
    env['CARGO_TARGET_DIR'] = str(root / 'target-consumer')
    return env


def run(command, consumer, env, *, success=True, data=None):
    cargo_environment.check(consumer, env)
    result = subprocess.run(command, cwd=consumer, env=env, text=True,
                            capture_output=True, timeout=240, input=data)
    require((result.returncode == 0) == success,
            f'{command}: {result.stdout[-6000:]}\n{result.stderr[-6000:]}')
    return result


def manifest(consumer, roots, package, features, defaults=False, extra=''):
    version = tomllib.loads((roots[package] / 'Cargo.toml').read_text())['package']['version']
    text = ('[workspace]\n[package]\nname="facade-consumer"\nversion="0.0.0"\n'
            'edition="2024"\n[dependencies]\n'
            f'facade = {{ package="{package}", version="={version}", '
            f'default-features={str(defaults).lower()}, features={json.dumps(features)} }}\n'
            + extra + '[patch.crates-io]\n')
    text += ''.join(f'{name} = {{ path={json.dumps(str(path))} }}\n'
                    for name, path in roots.items())
    (consumer / 'Cargo.toml').write_text(text)


def test_run(cargo, consumer, env, count, profile=()):
    result = run(cargo + ['test', '--offline', *profile], consumer, env)
    require(f'test result: ok. {count} passed; 0 failed; 0 ignored;' in result.stdout,
            'runtime test population changed: ' + result.stdout[-4000:])


def documentation():
    blocks = re.findall(r'```rust\n(.*?)```',
                        (ROOT / 'docs/facade-features.md').read_text(), re.S)
    require(len(blocks) == 2, 'documentation example population changed')
    return ''.join(f'#[test]\nfn documentation_{index}() {{\n' +
                   block.replace('brynja::crypto', 'api').replace(
                       'brynja_crypto_cpu_std', 'host') + '\n}\n'
                   for index, block in enumerate(blocks))


def source(consumer, package, body):
    alias = 'facade::crypto' if package == 'brynja' else 'facade'
    # Generated Rust type/test source only; never captures secret runtime data.
    (consumer / 'src/lib.rs').write_text(
        '#![no_std]\n#![forbid(unsafe_code)]\n'
        f'#[allow(unused_imports)]\nuse {alias} as api;\n' + body)


def graph(document, features, *, hosted=False, threaded=False):
    packages = {p['id']: p for p in document['packages']}
    active = {packages[node['id']]['name']: node['features']
              for node in document['resolve']['nodes']}
    require(all(p['source'] is None for p in packages.values()), 'registry/git dependency')
    require(not threaded or (hosted and 'parallelhash-hardened-batch' in features),
            'threaded adapter requires explicit ParallelHash batch opt-in')
    hosts = ({'brynja-crypto-cpu-std'} if hosted else set())
    if threaded:
        hosts.add('brynja-hash-parallel-std')
        require('runtime-batch-execution' in active.get('brynja-hash-parallel-std', []),
                'threaded batch feature missing')
    require({name for name in active if name.endswith('-std')} == hosts and
            not any(name.startswith('brynja-legacy') for name in active),
            'host or legacy package reachable')
    require(not any('conformance-testing' in values for values in active.values()),
            'evidence-only conformance feature reachable')
    expected_cpu = any(f != 'general-sha512-t' for f in features)
    require(('brynja-crypto-cpu' in active) == expected_cpu, 'CPU opt-in/default isolation')
    for feature in features:
        if feature in policy.LEAVES:
            owner, leaf = policy.LEAVES[feature]
            require(leaf in active[owner], 'missing resolved leaf feature: ' + feature)


def archive_graph(document, roots, consumer):
    """Bind resolved identities and source targets to the actual extracted archives."""
    versions = {name: version for name, version, _ in packaging.PACKAGING_PACKAGES}
    versions[parallelhash.ARCHIVE[0]] = parallelhash.ARCHIVE[1]
    versions['facade-consumer'] = '0.0.0'
    paths = {**roots, 'facade-consumer': consumer}
    packages = document['packages']
    identities = [package['id'] for package in packages]
    names = [package['name'] for package in packages]
    nodes = [node['id'] for node in document['resolve']['nodes']]
    require(len(set(names)) == len(names) and len(set(identities)) == len(identities),
            'duplicate packaged identity')
    require(len(nodes) == len(set(nodes)) and set(nodes) == set(identities),
            'resolved package population mismatch')
    require(document['resolve']['root'] in identities and
            packages[identities.index(document['resolve']['root'])]['name'] == 'facade-consumer',
            'unexpected downstream root')
    for package in packages:
        name = package['name']
        require(name in paths and name in versions, 'unregistered archive: ' + name)
        root = paths[name].resolve()
        require(package['version'] == versions[name] and package['source'] is None,
                'archive version/source drift: ' + name)
        require(Path(package['manifest_path']).resolve() == root / 'Cargo.toml',
                'dependency escaped extracted archive: ' + name)
        require(not package.get('links') and package['targets'], 'native/absent targets: ' + name)
        for target in package['targets']:
            require(not {'custom-build', 'proc-macro'}.intersection(target['kind']),
                    'build script/proc macro in archive: ' + name)
            require(Path(target['src_path']).resolve().is_relative_to(root),
                    'source target escaped extracted archive: ' + name)


def resolved_metadata(cargo, consumer, env, roots):
    result = run(cargo + ['metadata', '--offline', '--format-version=1'], consumer, env)
    archive_graph(json.loads(result.stdout), roots, consumer)
    return result


def ownership(consumer, package, cargo, env):
    for owner in ('sha2::hardened_execution::Sha256', 'kmac::execution::Kmac128',
                  'tuplehash::execution::TupleHash128'):
        # First ensure the exact type/lifetime exists independently of the
        # intentionally unsatisfied bound, avoiding false-negative acceptance.
        source(consumer, package, f'pub type Owner = api::{owner}<\'static>;\n')
        run(cargo + ['check', '--offline'], consumer, env)
        for bound in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug'):
            source(consumer, package, f'fn require<T: {bound}>() {{}}\n'
                   f'pub fn probe() {{ require::<api::{owner}<\'static>>(); }}\n')
            result = run(cargo + ['check', '--offline', '--message-format=json'],
                         consumer, env, success=False)
            messages = [json.loads(line) for line in result.stdout.splitlines()]
            require(any(item.get('reason') == 'compiler-message' and
                        (item['message'].get('code') or {}).get('code') == 'E0277'
                        for item in messages), 'ownership probe failed for wrong reason')
    print(f'PASS: {package}: 15 compiled ownership rejections', flush=True)


def execute(root, toolchain, bare_target, native_simd=False):
    require(set(cases.PROBES) == set(policy.CRYPTO), 'incomplete feature probe inventory')
    env = clean_environment(root)
    cargo_environment.check(root / 'package-workspace', env)
    # The shared package helper copies the environment; sanitize packaging too,
    # not only the later extracted consumer compilation.
    with patch.dict(os.environ, env, clear=True):
        roots = parallelhash.package_roots(packaging, root)
    consumer = root / 'consumer'
    (consumer / 'src').mkdir(parents=True)
    cargo = ['cargo', '+' + toolchain]
    keccak.install(consumer, keccak.corpus())
    for package in policy.FEATURES:
        for defaults in (False, True):
            manifest(consumer, roots, package, [], defaults)
            source(consumer, package, cases.PORTABLE)
            test_run(cargo, consumer, env, 1)
            metadata = resolved_metadata(cargo, consumer, env, roots)
            graph(json.loads(metadata.stdout), [])
        # Each absent opt-in must fail for an unresolved public API, not a
        # linker, dependency-resolution or unrelated syntax failure.
        for feature, path in cases.PROBES.items():
            manifest(consumer, roots, package, [])
            source(consumer, package, f'pub use api::{path} as Probe;\n')
            rejected = run(cargo + ['check', '--offline', '--message-format=json'],
                           consumer, env, success=False)
            errors = [json.loads(line) for line in rejected.stdout.splitlines()]
            require(any(item.get('reason') == 'compiler-message' and
                        (item['message'].get('code') or {}).get('code') in ('E0432', 'E0433')
                        for item in errors), 'negative failed for wrong reason: ' + feature)
            manifest(consumer, roots, package, [feature])
            run(cargo + ['check', '--offline', '--target', bare_target], consumer, env)
            metadata = resolved_metadata(cargo, consumer, env, roots)
            graph(json.loads(metadata.stdout), [feature])
            print(f'PASS: {package}/{feature}: absent rejected, packaged no_std opt-in compiled', flush=True)
        features = list(cases.PROBES)
        manifest(consumer, roots, package, features)
        probes = ''.join(f'pub use api::{path} as Probe{index};\n'
                         for index, path in enumerate(cases.PROBES.values()))
        source(consumer, package, probes + cases.PORTABLE + cases.EXECUTION + families.RUST + batches.RUST)
        for profile in ([], ['--release']):
            test_run(cargo, consumer, env, 10, profile)
        run(cargo + ['check', '--offline', '--target', bare_target], consumer, env)
        metadata = resolved_metadata(cargo, consumer, env, roots)
        graph(json.loads(metadata.stdout), features)
        source(consumer, package, keccak.RUST)
        for profile in ([], ['--release']):
            test_run(cargo, consumer, env, 3, profile)
        keccak.mutants(sys.modules[__name__], consumer, roots, cargo, env)
        print(f'PASS: {package}: 1024 independent Keccak outputs, ordinary/secret profiles', flush=True)
        ownership(consumer, package, cargo, env)
        # An independent leaf opt-in unifies the leaf build, but must not
        # expose exports gated on the facade's own feature selection.
        extra = ('leaf = { package="brynja-hash-sha2", version="=0.1.0", '
                 'default-features=false, features=["general-sha512-t"] }\n')
        manifest(consumer, roots, package, [], extra=extra)
        source(consumer, package, 'pub use leaf::Sha512TBits;\n')
        run(cargo + ['check', '--offline', '--target', bare_target], consumer, env)
        metadata = resolved_metadata(cargo, consumer, env, roots)
        graph(json.loads(metadata.stdout), ['general-sha512-t'])
        source(consumer, package, 'pub use api::sha2::Sha512TBits;\n')
        rejected = run(cargo + ['check', '--offline', '--message-format=json'],
                       consumer, env, success=False)
        require('E0432' in rejected.stdout, 'leaf opt-in leaked through curated facade')
        # Additive features must not rewrite the facade's actual feature set.
        identities = {p['id'] for p in json.loads(metadata.stdout)['packages']
                      if p['name'] == package}
        require(all(not n['features'] for n in json.loads(metadata.stdout)['resolve']['nodes']
                    if n['id'] in identities), 'leaf unification enabled facade features')
        extra = ('host = { package="brynja-crypto-cpu-std", version="=0.1.1", '
                 'default-features=false, features=["runtime-execution"] }\n')
        hosted_features = ['sha2-runtime-execution', 'sha2-hardened-execution']
        manifest(consumer, roots, package, hosted_features, extra=extra)
        source(consumer, package, cases.HOSTED + documentation())
        for profile in ([], ['--release']):
            test_run(cargo, consumer, env, 3, profile)
        metadata = resolved_metadata(cargo, consumer, env, roots)
        graph(json.loads(metadata.stdout), hosted_features, hosted=True)
        print(f'PASS: {package}: additive leaf features and separate hosted fallback/require', flush=True)
        adversarial.namespace_negatives(sys.modules[__name__], consumer, roots, package, cargo, env)
    adversarial.protocols(sys.modules[__name__], consumer, roots, cargo, env, bare_target)
    sha2_batches.execute(sys.modules[__name__], root, roots, cargo, env, native_simd)
    keccak_routes.execute(sys.modules[__name__], root, roots, cargo, env, native_simd)
    tuplehash.execute(sys.modules[__name__], root, roots, cargo, env, native_simd)
    parallelhash.execute(sys.modules[__name__], root, roots, cargo, env, native_simd)
    print('Facade package opt-in, default isolation, no_std, runtime and cleanup acceptance: PASS')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--toolchain', default='1.99.1')
    parser.add_argument('--bare-target', default='x86_64-unknown-none')
    parser.add_argument('--native-simd', action='store_true',
                        help='also run local SHA-2/Keccak/TupleHash/ParallelHash accelerated checks; not native qualification')
    args = parser.parse_args()
    with cargo_environment.private_directory(ROOT) as directory:
        execute(Path(directory), args.toolchain, args.bare_target, args.native_simd)


if __name__ == '__main__':
    main()
