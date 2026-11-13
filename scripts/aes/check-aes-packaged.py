#!/usr/bin/env python3
"""Bounded portable AES acceptance against Cargo archives; no upload or installs."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tomllib


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


HERE = Path(__file__).resolve().parent
consumer = module('aes_consumer', HERE / 'check-aes-consumer.py')
archives = module('aes_archive_helpers', HERE.parent / 'hkdf/check-hkdf-public-api.py')
api = module('aes_packaged_api', HERE / 'check-aes-api.py')
wide = module('aes_packaged_wide_api', HERE / 'check-aes-wide-api.py')
ROOT = consumer.ROOT
TARGET = 'thumbv7em-none-eabi'
MARKER = 'AES packaged portable: PASS; 8 host configurations; 4 Cortex-M compile checks; 536 paired API probes; 4 README runs; 4 feature gates; no upload'


def require(condition, message):
    if not condition:
        raise ValueError('AES packaged: ' + message)


def prepare(directory, versions):
    consumer.policy(tomllib.loads((consumer.FIXTURE / 'Cargo.toml').read_text()))
    for name in consumer.FILES:
        source = consumer.FIXTURE / name
        require(source.is_file() and not source.is_symlink()
                and not any(p.is_symlink() for p in source.parents),
                'missing or symlinked fixture: ' + name)
        if name in ('Cargo.toml', 'Cargo.lock'):
            continue
        target = directory / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    # Cargo normalizes dependency declarations when packaging. Resolve those
    # declarations using only unpacked archives, not checkout path dependencies.
    manifest = (f'[workspace]\n[package]\nname="{consumer.NAME}"\nversion="0.0.0"\n'
                'edition="2024"\nrust-version="1.90"\npublish=false\n'
                '[features]\ndefault=[]\ndirect=["dep:brynja-crypto"]\nfacade=["dep:brynja"]\n'
                '[dependencies]\n')
    for name in ('brynja', 'brynja-crypto'):
        manifest += (f'{name}={{version="={versions[name]}",optional=true,'
                     'default-features=false,features=["hazmat-aes-block"]}\n')
    manifest += '[patch.crates-io]\n'
    manifest += ''.join(f'{name}={{path="../../unpacked/{name}-{version}"}}\n'
                        for name, version in versions.items())
    manifest += ('[[test]]\nname="consumer"\npath="tests/consumer.rs"\n'
                 '[profile.release]\noverflow-checks=true\n')
    (directory / 'Cargo.toml').write_text(manifest)


def graph(metadata, route, directory, unpacked, versions, *, provider=False):
    require(route in consumer.ROUTES, 'unknown route')
    packages = {row['id']: row for row in metadata['packages']}
    nodes = metadata['resolve']['nodes']
    require(len(packages) == len(metadata['packages']), 'duplicate packages')
    require(len({node['id'] for node in nodes}) == len(nodes), 'duplicate nodes')
    require(all(node['id'] in packages for node in nodes), 'unresolved node')
    expected = (consumer.DIRECT if route == 'direct' else consumer.FACADE) | {consumer.NAME}
    require({packages[node['id']]['name'] for node in nodes} == expected
            and len(nodes) == len(expected), 'unexpected active dependency population')
    root_id = metadata['resolve']['root']
    require(root_id in packages and packages[root_id]['name'] == consumer.NAME, 'wrong root')
    require(Path(metadata['workspace_root']).resolve() == directory.resolve()
            and metadata['workspace_members'] == [root_id], 'non-isolated workspace')
    for package in packages.values():
        name = package['name']
        require(name in versions or name == consumer.NAME, 'unexpected package: ' + name)
        version = '0.0.0' if name == consumer.NAME else versions[name]
        manifest = (directory if name == consumer.NAME else unpacked / f'{name}-{version}') / 'Cargo.toml'
        require(package['version'] == version and package.get('source') is None
                and Path(package['manifest_path']).resolve() == manifest.resolve(),
                'dependency is not the intended archive: ' + name)
    for node in nodes:
        name = packages[node['id']]['name']
        features = {route} if name == consumer.NAME else {'default'}
        if name == 'brynja' or (name == 'brynja-crypto' and route == 'direct'):
            features = set()
        if name in ('brynja', 'brynja-crypto'):
            features.add('hazmat-aes-block')
            if provider:
                features.add('external-key-provider')
        if name == 'brynja-hash-sha2':
            features.add('general-sha512-t')
        require(set(node['features']) == features, 'unexpected features: ' + name)


def probes(route):
    require(route in consumer.ROUTES, 'unknown route')
    cases = api.probes() + wide.probes()
    require(len(cases) == 134 and len({case[0] for case in cases}) == 134,
            'API probe population changed')
    if route == 'facade':
        cases = [(name, negative.replace('brynja_crypto::aes', 'brynja::crypto::aes'),
                  positive.replace('brynja_crypto::aes', 'brynja::crypto::aes'), code)
                 for name, negative, positive, code in cases]
    return cases


def public_negatives(directory, cargo, selection, env, route):
    probe = directory / 'src/bin/probe.rs'
    probe.parent.mkdir(parents=True, exist_ok=True)
    command = cargo + ['check', *selection, '--bin', 'probe', '--message-format=json']
    try:
        for name, negative, positive, code in probes(route):
            probe.write_text(positive)
            archives.run(command, directory, env)
            probe.write_text(negative)
            archives.cargo_environment.check(directory, env)
            result = subprocess.run(command, cwd=directory, env=env, text=True,
                                    capture_output=True, timeout=120)
            require(result.returncode == 101 and archives.diagnostic_matches(result, code),
                    f'wrong diagnostic for {route}/{name}: {result.stdout[-2000:]} {result.stderr[-1000:]}')
    finally:
        probe.unlink(missing_ok=True)


def readme_source(readme, route):
    require(route in consumer.ROUTES, 'unknown route')
    begin, end = '<!-- AES-PACKAGED-EXAMPLE-BEGIN -->', '<!-- AES-PACKAGED-EXAMPLE-END -->'
    require(readme.count(begin) == readme.count(end) == 1, 'missing/duplicate README example markers')
    example = readme.split(begin)[1].split(end)[0].strip()
    require(example.startswith('```rust\n') and example.endswith('\n```')
            and example.count('```') == 2, 'README example must be one executable Rust block')
    source = example.removeprefix('```rust\n').removesuffix('\n```')
    require('fn main()' in source and all(owner in source for owner in consumer.OWNERS),
            'README example omits owners or executable entry point')
    return source if route == 'direct' else source.replace('brynja_crypto::aes', 'brynja::crypto::aes')


def readme_example(directory, root, versions, cargo, selection, env, route):
    readme = root / 'unpacked' / f'brynja-crypto-{versions["brynja-crypto"]}' / 'README.md'
    example = directory / 'src/bin/readme.rs'
    example.parent.mkdir(parents=True, exist_ok=True)
    try:
        example.write_text(readme_source(readme.read_text(), route))
        archives.run(cargo + ['run', *selection, '--bin', 'readme'], directory, env)
    finally:
        example.unlink(missing_ok=True)


def feature_probe(root, versions, compiler, route, env):
    require(route in consumer.ROUTES, 'unknown route')
    directory = root / 'consumers' / f'feature-{compiler}-{route}'
    (directory / 'src').mkdir(parents=True)
    dependency = 'brynja-crypto' if route == 'direct' else 'brynja'
    namespace = 'brynja_crypto' if route == 'direct' else 'brynja::crypto'
    cargo = ['cargo', '+' + compiler]
    source, manifest = directory / 'src/lib.rs', directory / 'Cargo.toml'
    aes = f'#![no_std]\npub use {namespace}::aes::{{' + ', '.join(consumer.OWNERS) + '};\n'
    patches = '[patch.crates-io]\n' + ''.join(
        f'{name}={{path="../../unpacked/{name}-{version}"}}\n' for name, version in versions.items())
    for defaults in ('true', 'false'):
        text = ('[workspace]\n[package]\nname="aes-packaged-feature-probe"\nversion="0.0.0"\n'
                'edition="2024"\npublish=false\n[dependencies]\n'
                f'{dependency}={{version="={versions[dependency]}",default-features={defaults},features=[]}}\n' + patches)
        manifest.write_text(text)
        source.write_text(aes)
        archives.run(cargo + ['generate-lockfile', '--offline'], directory, env)
        command = cargo + ['check', '--locked', '--offline', '--lib', '--message-format=json']
        archives.cargo_environment.check(directory, env)
        result = subprocess.run(command, cwd=directory, env=env, text=True,
                                capture_output=True, timeout=120)
        consumer.missing_aes(result)
        source.write_text(f'#![no_std]\npub use {namespace}::hkdf;\n')
        archives.run(command, directory, env)
        manifest.write_text(text.replace('features=[]', 'features=["hazmat-aes-block"]'))
        source.write_text(aes)
        archives.run(command, directory, env)
    print(f'AES_PACKAGED_FEATURE: {compiler} {route} absent with defaults on/off; explicit opt-in works', flush=True)


def configuration(directory, root, versions, compiler, route, env):
    cargo = ['cargo', '+' + compiler]
    selection = ['--locked', '--offline', '--no-default-features', '--features', route]
    for target in (None, TARGET):
        command = cargo + ['metadata', '--format-version=1', *selection]
        if target:
            command += ['--filter-platform', target]
        graph(json.loads(archives.run(command, directory, env).stdout), route,
              directory, root / 'unpacked', versions)
    for profile in ('debug', 'release'):
        command = cargo + ['test', *selection, '--test', 'consumer']
        if profile == 'release':
            command.append('--release')
        consumer.check_tests(archives.run(command, directory, env).stdout)
        print(f'AES_PACKAGED_HOST: {compiler} {route} {profile} 21 exact tests', flush=True)
    public_negatives(directory, cargo, selection, env, route)
    print(f'AES_PACKAGED_API: {compiler} {route} 134 paired probes', flush=True)
    readme_example(directory, root, versions, cargo, selection, env, route)
    print(f'AES_PACKAGED_README: {compiler} {route} six owners; executed', flush=True)
    archives.run(cargo + ['check', *selection, '--lib', '--target', TARGET], directory, env)
    print(f'AES_PACKAGED_TARGET: {compiler} {route} {TARGET} compile-only', flush=True)
    feature_probe(root, versions, compiler, route, env)


def package_sources(root, env):
    """Build and byte-check the same archive closure for each AES consumer."""
    versions = {name: tomllib.loads((ROOT / 'crates' / name / 'Cargo.toml').read_text())['package']['version']
                for name in archives.MODERN}
    workspace = archives.package_workspace(root, archives.MODERN)
    cargo = ['cargo', '+' + consumer.TOOLCHAINS[-1]]
    archives.run(cargo + ['generate-lockfile', '--offline'], workspace, env)
    command = cargo + ['package', '--locked', '--offline', '--allow-dirty', '--no-verify']
    for name in archives.MODERN:
        command += ['-p', name]
    archives.run(command, workspace, env)
    for name, version in versions.items():
        prefix = f'{name}-{version}'
        archive = root / f'target/package/{prefix}.crate'
        archives.unpack(archive, root / 'unpacked', prefix)
        archives.check_packaged_inputs(ROOT / 'crates' / name, root / 'unpacked' / prefix)
        print(f'AES_PACKAGE: {prefix} sha256={hashlib.sha256(archive.read_bytes()).hexdigest()}', flush=True)
    return versions


def check():
    for name in (*archives.REJECT_ENV, 'PYTHONOPTIMIZE', 'PYTHONPATH'):
        require(name not in os.environ, 'remove ambient ' + name)
    with archives.cargo_environment.private_directory(ROOT) as temporary:
        root = Path(temporary)
        env = archives.isolated_env(root)
        versions = package_sources(root, env)
        directory = root / 'consumers/aes'
        prepare(directory, versions)
        archives.run(['cargo', '+' + consumer.TOOLCHAINS[0], 'generate-lockfile', '--offline'], directory, env)
        for compiler in consumer.TOOLCHAINS:
            for route in consumer.ROUTES:
                configuration(directory, root, versions, compiler, route, env)
    print(MARKER, flush=True)


if __name__ == '__main__':
    check()
