#!/usr/bin/env python3
"""Isolated checkout consumers; no packaging, installs, upload or qualification."""
import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tomllib

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'hmac'))
import hmac_verifiers as verifier

ROOT = verifier.ROOT
FIXTURE = ROOT / 'assurance/aes-public-api'
NAME = 'brynja-aes-public-api-fixture'
TOOLCHAINS = ('1.90.0', '1.99.1')
MATRIX = ('1.90.0', '1.91.0', '1.92.0', '1.93.0', '1.94.0', '1.95.0',
          '1.96.0', '1.96.1', '1.97.0', '1.97.1', '1.98.0', '1.98.1', '1.99.0', '1.99.1')
ROUTES = ('direct', 'facade')
BASE_TESTS = {'known_answer_both_directions', 'drop_clears_only_owned_regions',
         'explicit_clear_and_reuse', 'output_outlives_key',
         'public_ciphertext_persists_after_key_clear', 'consumer_unwind_clears_key_and_output'}
TESTS = BASE_TESTS | {f'wide::aes{bits}::{name}' for bits in (192, 256) for name in BASE_TESTS}
OWNERS = ('Aes128Key', 'Aes128ExpandedKey', 'Aes192Key', 'Aes192ExpandedKey', 'Aes256Key', 'Aes256ExpandedKey')
DIRECT = {'brynja-core', 'brynja-crypto', 'brynja-hash-core', 'brynja-hash-parallel',
          'brynja-hash-sha2', 'brynja-hash-sha3', 'brynja-hash-tuple',
          'brynja-mac-hmac', 'brynja-mac-kmac'}
FACADE = DIRECT | {'brynja', 'brynja-pki', 'brynja-protocol', 'brynja-tls',
                   'brynja-tls12', 'brynja-tls13', 'brynja-tls13-handshake'}
FILES = ('Cargo.toml', 'Cargo.lock', 'src/lib.rs', 'src/wide.rs', 'tests/consumer.rs', 'tests/wide/mod.rs')
MARKER = 'AES downstream: PASS; 8 host configurations; 4 Cortex-M compile checks; checkout sources only'
MATRIX_MARKER = 'AES downstream matrix: PASS; 14 compilers; 56 host configurations; 4 Cortex-M compile checks; checkout sources only'
FEATURE_MARKERS = [f'AES_FEATURE_GATE: {compiler} {route} absent with defaults on/off; explicit opt-in works'
                   for compiler in TOOLCHAINS for route in ROUTES]


def require(condition, message):
    if not condition:
        raise ValueError('AES downstream: ' + message)


def policy(manifest):
    require(manifest == {
        'workspace': {},
        'package': {'name': NAME, 'version': '0.0.0', 'edition': '2024',
                    'rust-version': '1.90', 'publish': False},
        'features': {'default': [], 'direct': ['dep:brynja-crypto'], 'facade': ['dep:brynja']},
        'dependencies': {name: {'path': '../../crates/' + name, 'default-features': False,
                                'optional': True, 'features': ['hazmat-aes-block']}
                         for name in ('brynja', 'brynja-crypto')},
        'test': [{'name': 'consumer', 'path': 'tests/consumer.rs'}],
        'profile': {'release': {'overflow-checks': True}},
    }, 'fixture build policy changed')


def prepare(directory):
    policy(tomllib.loads((FIXTURE / 'Cargo.toml').read_text()))
    for name in FILES:
        source = FIXTURE / name
        require(source.is_file() and not source.is_symlink(), 'missing/nonregular fixture: ' + name)
        target = directory / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    # Relocate only the two public path dependencies, never include production
    # modules in the consumer or substitute a verification implementation.
    text = (directory / 'Cargo.toml').read_text()
    for name in ('brynja', 'brynja-crypto'):
        text = text.replace('"../../crates/' + name + '"', json.dumps(str(ROOT / 'crates' / name)))
    (directory / 'Cargo.toml').write_text(text)


def graph(metadata, route, directory):
    require(route in ROUTES, 'unknown route')
    packages = {row['id']: row for row in metadata['packages']}
    nodes = metadata['resolve']['nodes']
    require(len(packages) == len(metadata['packages']), 'duplicate packages')
    require(len({row['id'] for row in nodes}) == len(nodes), 'duplicate resolved nodes')
    expected = (DIRECT if route == 'direct' else FACADE) | {NAME}
    require({packages[node['id']]['name'] for node in nodes} == expected and len(nodes) == len(expected),
            'unexpected active dependency population')
    root_id = metadata['resolve']['root']
    require(root_id in packages and packages[root_id]['name'] == NAME, 'wrong consumer root')
    require(Path(metadata['workspace_root']).resolve() == directory.resolve() and
            metadata['workspace_members'] == [root_id], 'consumer is not an isolated workspace')
    for node in nodes:
        package = packages[node['id']]
        name = package['name']
        manifest = directory / 'Cargo.toml' if name == NAME else ROOT / 'crates' / name / 'Cargo.toml'
        require(Path(package['manifest_path']).resolve() == manifest.resolve() and
                package.get('source') is None, 'dependency is not the intended checkout source: ' + name)
        features = {route} if name == NAME else {'default'}
        if name == 'brynja' or (name == 'brynja-crypto' and route == 'direct'):
            features = set()
        if name in ('brynja', 'brynja-crypto'):
            features.add('hazmat-aes-block')
        if name == 'brynja-hash-sha2':
            features.add('general-sha512-t')  # Existing composition dependency, not AES acceleration.
        require(set(node['features']) == features, 'unexpected features: ' + name)


def check_tests(output):
    rows = re.findall(r'^test (\S+) \.\.\. (\S+)\s*$', output, re.M)
    require(len(rows) == len(TESTS) and {name for name, _ in rows} == TESTS and
            all(status == 'ok' for _, status in rows), 'missing, duplicated, ignored or failed consumer test')
    summaries = re.findall(r'^test result: .*$', output, re.M)
    require(len(summaries) == 1 and summaries[0].startswith(
        'test result: ok. 18 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;'),
        'consumer test population summary changed')


def configuration(compiler, route, directory, compile_target=True):
    prepare(directory)
    env = verifier.environment(directory)
    env.update(CARGO_NET_OFFLINE='true', RUSTUP_AUTO_INSTALL='0', CARGO_TERM_COLOR='never')
    cargo = ['cargo', '+' + compiler]
    selection = ['--locked', '--offline', '--no-default-features', '--features', route]
    # run() combines stdout/stderr; metadata diagnostics must not enter its JSON.
    raw = verifier.run(cargo + ['metadata', '--format-version=1'] + selection, env, directory)
    graph(json.loads(raw), route, directory)
    for profile in ('debug', 'release'):
        command = cargo + ['test'] + selection + ['--test', 'consumer']
        if profile == 'release':
            command.append('--release')
        output = verifier.run(command, env, directory)
        check_tests(output)
        print(f'AES_DOWNSTREAM_HOST: {compiler} {route} {profile} 18 exact tests', flush=True)
    if compile_target:
        verifier.run(cargo + ['check'] + selection + ['--lib', '--target', 'thumbv7em-none-eabi'], env, directory)
        print(f'AES_DOWNSTREAM_TARGET: {compiler} {route} thumbv7em-none-eabi compile-only', flush=True)


def missing_aes(result):
    require(result.returncode == 101, 'disabled AES must fail compilation')
    messages = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    errors = [row['message'] for row in messages
              if row.get('reason') == 'compiler-message' and row['message']['level'] == 'error']
    require(len(errors) == 1 and errors[0].get('code', {}).get('code') == 'E0432' and
            any(span['is_primary'] and span['file_name'] == 'src/lib.rs' for span in errors[0]['spans']) and
            'aes' in errors[0]['message'], 'wrong disabled-AES compiler failure')


def feature_probe(compiler, route, directory):
    require(route in ROUTES, 'unknown route')
    directory.mkdir()
    (directory / 'src').mkdir()
    dependency = 'brynja-crypto' if route == 'direct' else 'brynja'
    module = 'brynja_crypto' if route == 'direct' else 'brynja::crypto'
    env = verifier.environment(directory)
    env.update(CARGO_NET_OFFLINE='true', RUSTUP_AUTO_INSTALL='0', CARGO_TERM_COLOR='never')
    cargo = ['cargo', '+' + compiler]
    source = directory / 'src/lib.rs'
    manifest = directory / 'Cargo.toml'
    aes_import = f'#![no_std]\npub use {module}::aes::{{' + ', '.join(OWNERS) + '};\n'
    for defaults in ('true', 'false'):
        text = ('[workspace]\n[package]\nname="aes-feature-probe"\nversion="0.0.0"\n'
                'edition="2024"\npublish=false\n[dependencies]\n' + dependency + '={path=' +
                json.dumps(str(ROOT / 'crates' / dependency)) + ',default-features=' + defaults + ',features=[]}\n')
        manifest.write_text(text)
        source.write_text(aes_import)
        verifier.run(cargo + ['generate-lockfile', '--offline'], env, directory)
        command = cargo + ['check', '--locked', '--offline', '--lib', '--message-format=json']
        result = subprocess.run(command, cwd=directory, env=env, text=True, capture_output=True, timeout=120)
        missing_aes(result)
        # A nearby usable API and then the exact AES import must both compile.
        source.write_text(f'#![no_std]\npub use {module}::hkdf;\n')
        verifier.run(command, env, directory)
        manifest.write_text(text.replace('features=[]', 'features=["hazmat-aes-block"]'))
        source.write_text(aes_import)
        verifier.run(command, env, directory)
    print(f'AES_FEATURE_GATE: {compiler} {route} absent with defaults on/off; explicit opt-in works', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--matrix', action='store_true')
    args = parser.parse_args()
    for compiler in MATRIX if args.matrix else TOOLCHAINS:
        for route in ROUTES:
            with verifier.cargo_environment.private_directory(ROOT) as temporary:
                if compiler in TOOLCHAINS:
                    feature_probe(compiler, route, Path(temporary) / 'feature-probe')
                configuration(compiler, route, Path(temporary), compiler in TOOLCHAINS)
    print(MATRIX_MARKER if args.matrix else MARKER)


if __name__ == '__main__':
    main()
