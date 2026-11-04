#!/usr/bin/env python3
"""Isolated checkout consumers; no packaging, installs, upload or qualification."""
import argparse
import json
from pathlib import Path
import re
import shutil
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
TESTS = {'known_answer_both_directions', 'drop_clears_only_owned_regions',
         'explicit_clear_and_reuse', 'output_outlives_key',
         'public_ciphertext_persists_after_key_clear', 'consumer_unwind_clears_key_and_output'}
DIRECT = {'brynja-core', 'brynja-crypto', 'brynja-hash-core', 'brynja-hash-parallel',
          'brynja-hash-sha2', 'brynja-hash-sha3', 'brynja-hash-tuple',
          'brynja-mac-hmac', 'brynja-mac-kmac'}
FACADE = DIRECT | {'brynja', 'brynja-pki', 'brynja-protocol', 'brynja-tls',
                   'brynja-tls12', 'brynja-tls13', 'brynja-tls13-handshake'}
FILES = ('Cargo.toml', 'Cargo.lock', 'src/lib.rs', 'tests/consumer.rs')
MARKER = 'AES downstream: PASS; 8 host configurations; 4 Cortex-M compile checks; checkout sources only'
MATRIX_MARKER = 'AES downstream matrix: PASS; 14 compilers; 56 host configurations; 4 Cortex-M compile checks; checkout sources only'


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
                                'optional': True} for name in ('brynja', 'brynja-crypto')},
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
        if name == 'brynja-hash-sha2':
            features.add('general-sha512-t')  # Existing composition dependency, not AES acceleration.
        require(set(node['features']) == features, 'unexpected features: ' + name)


def check_tests(output):
    rows = re.findall(r'^test (\S+) \.\.\. (\S+)\s*$', output, re.M)
    require(len(rows) == len(TESTS) and {name for name, _ in rows} == TESTS and
            all(status == 'ok' for _, status in rows), 'missing, duplicated, ignored or failed consumer test')
    summaries = re.findall(r'^test result: .*$', output, re.M)
    require(len(summaries) == 1 and summaries[0].startswith(
        'test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;'),
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
        print(f'AES_DOWNSTREAM_HOST: {compiler} {route} {profile} 6 exact tests', flush=True)
    if compile_target:
        verifier.run(cargo + ['check'] + selection + ['--lib', '--target', 'thumbv7em-none-eabi'], env, directory)
        print(f'AES_DOWNSTREAM_TARGET: {compiler} {route} thumbv7em-none-eabi compile-only', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--matrix', action='store_true')
    args = parser.parse_args()
    for compiler in MATRIX if args.matrix else TOOLCHAINS:
        for route in ROUTES:
            with verifier.cargo_environment.private_directory(ROOT) as temporary:
                configuration(compiler, route, Path(temporary), compiler in TOOLCHAINS)
    print(MATRIX_MARKER if args.matrix else MARKER)


if __name__ == '__main__':
    main()
