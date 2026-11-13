#!/usr/bin/env python3
"""Archive-only no_std AES builds and paired API/feature diagnostics; no execution."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('no_std_campaign', HERE / 'check-aes-accelerated-campaigns.py')
campaign = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(campaign)
packaged, ROOT, NAME = campaign.packaged, campaign.ROOT, campaign.NAME
api = packaged.module('no_std_api', HERE / 'check-aes-execution-api.py')
require = packaged.require
TARGETS = {'thumbv7em-none-eabi': '', 'x86_64-unknown-linux-gnu': '-Ctarget-feature=+aes,+sse2',
           'aarch64-unknown-linux-musl': '-Ctarget-feature=+aes,+neon'}
RISCV_TARGET = 'riscv64imac-unknown-none-elf'
RISCV_BUILDS = [('rv64-ordinary', RISCV_TARGET, ''),
                ('rv64-evidence', RISCV_TARGET, '--cfg brynja_cpu_evidence -Ctarget-feature=+zkne,+zknd')]
FEATURES = {'none': [], 'portable': ['hazmat-aes-block'],
            'static': ['aes-static-execution'], 'runtime': ['aes-runtime-execution']}
REJECT = (*packaged.archives.REJECT_ENV, 'PYTHONOPTIMIZE', 'PYTHONPATH')
RISCV_REJECT = (*REJECT, 'CARGO_BUILD_RUSTFLAGS',
                'CARGO_TARGET_RISCV64IMAC_UNKNOWN_NONE_ELF_RUSTFLAGS',
                'CARGO_TARGET_RISCV64IMAC_UNKNOWN_NONE_ELF_LINKER',
                'CARGO_TARGET_RISCV64IMAC_UNKNOWN_NONE_ELF_RUNNER')


def manifest(versions, route, mode, defaults=False):
    require(route in ('direct', 'facade') and mode in FEATURES and type(defaults) is bool,
            'unknown no_std configuration')
    dependency = 'brynja-crypto' if route == 'direct' else 'brynja'
    return (f'[workspace]\n[package]\nname="{NAME}"\nversion="0.0.0"\nedition="2024"\npublish=false\n'
            '[features]\ndefault=[]\ndirect=[]\nfacade=[]\n[dependencies]\n'
            f'{dependency}={{version="={versions[dependency]}",default-features={str(defaults).lower()},'
            f'features={json.dumps(FEATURES[mode])}}}\n[patch.crates-io]\n'
            + ''.join(f'{name}={{path="../../unpacked/{name}-{version}"}}\n' for name, version in versions.items())
            + '[profile.release]\noverflow-checks=true\n')


def expected_graph(route, mode, defaults):
    require(route in ('direct', 'facade') and mode in FEATURES and type(defaults) is bool,
            'unknown no_std graph configuration')
    names = (packaged.consumer.DIRECT if route == 'direct' else packaged.consumer.FACADE) | {NAME}
    if mode in ('static', 'runtime'):
        names |= {'brynja-crypto-cpu'}
    features = {name: {'default'} for name in names}
    features[NAME] = {route}
    features['brynja-crypto'] = {'default'} if route == 'facade' or defaults else set()
    if route == 'facade':
        features['brynja'] = set(FEATURES[mode]) | ({'default'} if defaults else set())
    features['brynja-crypto'].update(FEATURES[mode])
    if mode in ('static', 'runtime'):
        features['brynja-crypto'].update({'cpu', 'hazmat-aes-block', 'aes-static-execution'})
        features['brynja-crypto-cpu'].add('aes-static-execution')
        if mode == 'runtime':
            features['brynja-crypto-cpu'].add('aes-runtime-execution')
    features['brynja-hash-sha2'].add('general-sha512-t')
    return features


def graph(metadata, versions, directory, route, mode, defaults=False):
    expected = expected_graph(route, mode, defaults)
    packages = {p['id']: p for p in metadata['packages']}
    nodes = metadata['resolve']['nodes']
    require(len(packages) == len(metadata['packages']) and len(nodes) == len(expected)
            and len({n['id'] for n in nodes}) == len(nodes)
            and all(n['id'] in packages for n in nodes)
            and {packages[n['id']]['name'] for n in nodes} == set(expected),
            'unexpected no_std dependency population')
    root_id = metadata['resolve']['root']
    require(root_id in packages and packages[root_id]['name'] == NAME
            and metadata['workspace_members'] == [root_id]
            and Path(metadata['workspace_root']).resolve() == directory.resolve(), 'non-isolated no_std consumer')
    for p in packages.values():
        name = p['name']
        require(name == NAME or name in versions, 'unknown archive dependency')
        version = '0.0.0' if name == NAME else versions[name]
        path = directory if name == NAME else directory.parent.parent / 'unpacked' / f'{name}-{version}'
        require(p['version'] == version and p.get('source') is None
                and Path(p['manifest_path']).resolve() == (path / 'Cargo.toml').resolve(),
                'no_std dependency is not intended archive: ' + name)
    for node in nodes:
        name = packages[node['id']]['name']
        require(set(node['features']) == expected[name], 'unexpected no_std features: ' + name)
    return root_id


def diagnostics(result, expected):
    code, count = expected if isinstance(expected, tuple) else (expected, 1)
    try:
        errors = [row['message'] for line in result.stdout.splitlines()
                  if (row := json.loads(line)).get('reason') == 'compiler-message'
                  and row['message'].get('level') == 'error']
        return result.returncode == 101 and len(errors) == count and all(
            (error.get('code') or {}).get('code') == code and any(
                span.get('is_primary') and span.get('file_name') == 'src/lib.rs'
                for span in error.get('spans', [])) for error in errors)
    except (ValueError, KeyError, TypeError, AttributeError):
        return False


def feature_probes(route):
    require(route in ('direct', 'facade'), 'unknown feature probe route')
    path = 'brynja_crypto' if route == 'direct' else 'brynja::crypto'
    absent = f'pub use {path}::aes::execution::Authority;'
    present = f'pub use {path}::hkdf;'
    yield 'none-defaults-off', 'none', False, absent, present, 'E0433'
    yield 'none-defaults-on', 'none', True, absent, present, 'E0433'
    yield 'portable-only', 'portable', False, absent, f'pub use {path}::aes::Aes128Key;', 'E0432'
    prefix = f'use {path}::aes::execution::{{Authority,Kernel}}; '
    yield 'static-no-platform', 'static', False, prefix + 'pub fn probe(){unsafe{let _=Authority::from_platform(Kernel::ArmAes);}}', prefix + 'pub fn probe(){let _=Authority::new(Kernel::ArmAes);}', 'E0599'


def execute(command, directory, env, artifacts, label):
    packaged.archives.cargo_environment.check(directory, env)
    result = subprocess.run(command, cwd=directory, env=env, text=True, capture_output=True, timeout=300)
    (artifacts / (label + '.json')).write_text(json.dumps({'command': command, 'returncode': result.returncode,
        'stdout': result.stdout, 'stderr': result.stderr}, indent=2) + '\n')
    return result


def pair(command, directory, env, artifacts, label, negative, positive, code):
    source = directory / 'src/lib.rs'
    source.write_text('#![no_std]\n' + positive)
    result = execute(command, directory, env, artifacts, label + '-positive')
    require(result.returncode == 0, 'no_std positive control failed: ' + label + '\n' + result.stderr[-2000:])
    source.write_text('#![no_std]\n' + negative)
    result = execute(command, directory, env, artifacts, label + '-negative')
    require(diagnostics(result, code), 'no_std diagnostic mismatch: ' + label + '\n' + result.stdout[-3000:])


def artifact(result, root_id, target_dir):
    require(result.returncode == 0, 'no_std build failed: ' + result.stderr[:1000] + result.stderr[-2000:])
    rows = [row for line in result.stdout.splitlines() if (row := json.loads(line)).get('reason') == 'compiler-artifact'
            and row.get('package_id') == root_id]
    require(len(rows) == 1 and rows[0]['target']['kind'] == ['lib'], 'missing/ambiguous no_std library artifact')
    paths = [Path(p) for p in rows[0]['filenames'] if p.endswith('.rlib')]
    require(len(paths) == 1 and paths[0].is_file() and not paths[0].is_symlink()
            and paths[0].resolve().is_relative_to(target_dir.resolve()) and paths[0].stat().st_size > 0,
            'invalid no_std rlib artifact')
    return {'path': str(paths[0]), 'sha256': hashlib.sha256(paths[0].read_bytes()).hexdigest()}


def check(compiler, route, riscv=False):
    require(compiler in ('1.90.0', '1.99.1') and route in ('direct', 'facade')
            and type(riscv) is bool, 'unreviewed no_std configuration')
    for name in RISCV_REJECT if riscv else REJECT:
        require(name not in os.environ, 'remove ambient ' + name)
    base = ROOT / 'target/aes-accelerated-no-std'
    base.mkdir(parents=True, exist_ok=True)
    artifacts = Path(tempfile.mkdtemp(prefix=f'{compiler}-{route}-', dir=base))
    print(f'Artifacts: {artifacts}', flush=True)
    with packaged.archives.cargo_environment.private_directory(ROOT) as temporary:
        root = Path(temporary)
        env = packaged.archives.isolated_env(root)
        versions = packaged.package_sources(root, env)
        directory = root / 'consumers/aes'
        (directory / 'src').mkdir(parents=True)
        source, cargo = directory / 'src/lib.rs', ['cargo', '+' + compiler]
        selection = ['--locked', '--offline', '--no-default-features', '--features', route]
        fixture = ROOT / 'assurance/aes-accelerated-campaigns/no-std.rs'
        require(fixture.is_file() and not any(p.is_symlink() for p in (fixture, *fixture.parents)), 'missing/symlinked no_std fixture')
        original = fixture.read_text()

        probe_target = RISCV_TARGET if riscv else 'thumbv7em-none-eabi'
        def configure(mode, defaults=False, target=probe_target):
            (directory / 'Cargo.toml').write_text(manifest(versions, route, mode, defaults))
            packaged.archives.run(cargo + ['generate-lockfile', '--offline'], directory, env)
            metadata = packaged.archives.run(cargo + ['metadata', '--format-version=1', '--filter-platform', target, *selection], directory, env)
            root_id = graph(json.loads(metadata.stdout), versions, directory, route, mode, defaults)
            (artifacts / f'metadata-{mode}-{defaults}-{target}.json').write_text(metadata.stdout)
            return root_id

        source.write_text(original)
        builds = []
        targets = RISCV_BUILDS if riscv else [(target, target, flags) for target, flags in TARGETS.items()]
        for mode in ('static', 'runtime'):
            for name, target, flags in targets:
                env['RUSTFLAGS'] = flags
                root_id = configure(mode, target=target)
                for profile in ('debug', 'release'):
                    label = f'{mode}-{name}-{profile}'
                    command = cargo + ['build', *selection, '--lib', '--target', target, '--message-format=json']
                    if profile == 'release':
                        command += ['--release']
                    result = execute(command, directory, env, artifacts, label)
                    builds.append({'mode': mode, 'target': target, 'profile': profile, 'rustflags': flags,
                                   **artifact(result, root_id, root / 'target')})
                    print(f'AES_NO_STD_BUILD_PASS: {compiler} {route} {label}', flush=True)
        env['RUSTFLAGS'] = ''
        command = cargo + ['check', *selection, '--lib', '--target', probe_target, '--message-format=json']
        count = 0
        for name, mode, defaults, negative, positive, code in feature_probes(route):
            configure(mode, defaults)
            pair(command, directory, env, artifacts, name, negative, positive, code)
            count += 1
        configure('runtime')
        for name, negative, positive, code in api.probes():
            if route == 'facade':
                negative, positive = (s.replace('brynja_crypto', 'brynja::crypto') for s in (negative, positive))
            pair(command, directory, env, artifacts, name, negative, positive, code)
            count += 1
        require(len(builds) == (8 if riscv else 12) and count == 62, 'no_std campaign population changed')
        (artifacts / 'builds.json').write_text(json.dumps(builds, indent=2) + '\n')
    if riscv:
        print(f'AES_RISCV_NO_STD_PASS: {compiler} {route}; 8 bare-metal library builds; 62 paired probes; compile only', flush=True)
    else:
        print(f'AES_ACCELERATED_NO_STD_PASS: {compiler} {route}; 12 library builds; 62 paired probes; compile only', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--toolchain', choices=('1.90.0', '1.99.1'), required=True)
    parser.add_argument('--route', choices=('direct', 'facade'), required=True)
    parser.add_argument('--riscv', action='store_true', help='RV64 bare-metal ordinary/evidence builds and API probes')
    args = parser.parse_args()
    try:
        check(args.toolchain, args.route, args.riscv)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f'AES accelerated no_std FAIL: {error}')
        raise SystemExit(2) from error
