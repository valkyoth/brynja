#!/usr/bin/env python3
"""Compile opt-ins in isolated downstream consumers of real package archives.

No workspace roots, hosted features, evidence cfgs or registry downloads can
make a missing forwarding edge pass. This is focused facade acceptance, not
new cryptographic or native qualification.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib

import facade_package_cases as cases
import facade_workspace_policy as policy

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


def run(command, consumer, env, *, success=True):
    result = subprocess.run(command, cwd=consumer, env=env, text=True,
                            capture_output=True, timeout=240)
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


def source(consumer, package, body):
    alias = 'facade::crypto' if package == 'brynja' else 'facade'
    # Generated Rust type/test source only; never captures secret runtime data.
    (consumer / 'src/lib.rs').write_text(
        '#![no_std]\n#![forbid(unsafe_code)]\n'
        f'#[allow(unused_imports)]\nuse {alias} as api;\n' + body)


def graph(document, features, *, hosted=False):
    packages = {p['id']: p for p in document['packages']}
    active = {packages[node['id']]['name']: node['features']
              for node in document['resolve']['nodes']}
    require(all(p['source'] is None for p in packages.values()), 'registry/git dependency')
    require({name for name in active if name.endswith('-std')} ==
            ({'brynja-crypto-cpu-std'} if hosted else set()) and
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


def execute(root, toolchain, bare_target):
    require(set(cases.PROBES) == set(policy.CRYPTO), 'incomplete feature probe inventory')
    roots = packaging.package_roots(root)
    consumer = root / 'consumer'
    (consumer / 'src').mkdir(parents=True)
    env = clean_environment(root)
    cargo = ['cargo', '+' + toolchain]
    for package in policy.FEATURES:
        for defaults in (False, True):
            manifest(consumer, roots, package, [], defaults)
            source(consumer, package, cases.PORTABLE)
            run(cargo + ['test', '--offline'], consumer, env)
            metadata = run(cargo + ['metadata', '--offline', '--format-version=1'], consumer, env)
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
            metadata = run(cargo + ['metadata', '--offline', '--format-version=1'], consumer, env)
            graph(json.loads(metadata.stdout), [feature])
            print(f'PASS: {package}/{feature}: absent rejected, packaged no_std opt-in compiled', flush=True)
        features = list(cases.PROBES)
        manifest(consumer, roots, package, features)
        probes = ''.join(f'pub use api::{path} as Probe{index};\n'
                         for index, path in enumerate(cases.PROBES.values()))
        source(consumer, package, probes + cases.PORTABLE + cases.EXECUTION)
        for profile in ([], ['--release']):
            run(cargo + ['test', '--offline', *profile], consumer, env)
        run(cargo + ['check', '--offline', '--target', bare_target], consumer, env)
        metadata = run(cargo + ['metadata', '--offline', '--format-version=1'], consumer, env)
        graph(json.loads(metadata.stdout), features)
        ownership(consumer, package, cargo, env)
        # Explicit downstream leaf opt-in unifies through the reexport. It is
        # not evidence that the facade enabled that feature by default.
        extra = ('leaf = { package="brynja-hash-sha2", version="=0.1.0", '
                 'default-features=false, features=["general-sha512-t"] }\n')
        manifest(consumer, roots, package, [], extra=extra)
        source(consumer, package, 'pub use api::sha2::Sha512TBits;\n')
        run(cargo + ['check', '--offline', '--target', bare_target], consumer, env)
        metadata = run(cargo + ['metadata', '--offline', '--format-version=1'], consumer, env)
        graph(json.loads(metadata.stdout), ['general-sha512-t'])
        # Additive features must not rewrite the facade's actual feature set.
        identities = {p['id'] for p in json.loads(metadata.stdout)['packages']
                      if p['name'] == package}
        require(all(not n['features'] for n in json.loads(metadata.stdout)['resolve']['nodes']
                    if n['id'] in identities), 'leaf unification enabled facade features')
        extra = ('host = { package="brynja-crypto-cpu-std", version="=0.1.1", '
                 'default-features=false, features=["runtime-execution"] }\n')
        manifest(consumer, roots, package, ['sha2-runtime-execution'], extra=extra)
        source(consumer, package, cases.HOSTED)
        for profile in ([], ['--release']):
            run(cargo + ['test', '--offline', *profile], consumer, env)
        metadata = run(cargo + ['metadata', '--offline', '--format-version=1'], consumer, env)
        graph(json.loads(metadata.stdout), ['sha2-runtime-execution'], hosted=True)
        print(f'PASS: {package}: additive leaf features and separate hosted fallback/require', flush=True)
    print('Facade package opt-in, default isolation, no_std, runtime and cleanup acceptance: PASS')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--toolchain', default='1.99.1')
    parser.add_argument('--bare-target', default='x86_64-unknown-none')
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='brynja-facade-package-') as directory:
        execute(Path(directory), args.toolchain, args.bare_target)


if __name__ == '__main__':
    main()
