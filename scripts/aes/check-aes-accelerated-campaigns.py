#!/usr/bin/env python3
"""Forced accelerated AESAVS/OpenSSL campaigns against byte-checked Cargo archives."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import importlib.util

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('accelerated_avs', HERE / 'check-aes-avs.py')
avs = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(avs)
packaged = avs.packaged
diff = packaged.module('accelerated_diff', HERE / 'check-aes-packaged-differential.py')
ROOT = packaged.ROOT
NAME = 'brynja-aes-accelerated-fixture'


def replace_exact(source, old, new, count):
    packaged.require(source.count(old) == count, 'campaign adapter anchor changed: ' + old)
    return source.replace(old, new)


def adapt(source, suite):
    """Change only the API import and authority arguments, never the campaign."""
    packaged.require(suite in ('avs', 'differential'), 'unknown campaign')
    source = replace_exact(source, 'use brynja_aes_public_api_fixture::aes::*;',
                           'use brynja_aes_accelerated_fixture::{aes::*, forced_authority};', 1)
    starts = ('fn monte_carlo() -> Check<()> {', 'fn multiblock() -> Check<()> {') if suite == 'avs' else (
        'fn $test() -> TestResult<()> {',)
    for start in starts:
        source = replace_exact(source, start, start + '\n    let authority = forced_authority()?;', 1)
    for owner in ('$key', '$cached'):
        source = replace_exact(source, owner + '::new(', owner + '::new(authority.get()?, ',
                               2 if suite == 'avs' else 1)
    return source


def manifest(versions, route, admission):
    packaged.require(route in ('direct', 'facade') and admission in ('static', 'hosted'),
                     'unknown API/admission route')
    dependency = 'brynja-crypto' if route == 'direct' else 'brynja'
    feature = 'aes-runtime-execution' if admission == 'hosted' else 'aes-static-execution'
    text = (f'[workspace]\n[package]\nname="{NAME}"\nversion="0.0.0"\n'
            'edition="2024"\nrust-version="1.90"\npublish=false\n'
            '[features]\ndefault=[]\ndirect=[]\nfacade=[]\nhosted=[]\n[dependencies]\n'
            f'{dependency}={{version="={versions[dependency]}",default-features=false,features=["{feature}"]}}\n')
    if admission == 'hosted':
        text += (f'brynja-crypto-cpu-std={{version="={versions["brynja-crypto-cpu-std"]}",'
                 'default-features=false,features=["aes-runtime-execution"]}\n')
    text += '[patch.crates-io]\n' + ''.join(
        f'{name}={{path="../../unpacked/{name}-{version}"}}\n' for name, version in versions.items())
    return text + '[profile.release]\noverflow-checks=true\n'


def graph(metadata, versions, directory, route, admission):
    packages = {p['id']: p for p in metadata['packages']}
    nodes = metadata['resolve']['nodes']
    expected = (packaged.consumer.DIRECT if route == 'direct' else packaged.consumer.FACADE) | {
        NAME, 'brynja-crypto-cpu'}
    if admission == 'hosted':
        expected |= {'brynja-crypto-cpu-std'}
    packaged.require(len(packages) == len(metadata['packages']) and len(nodes) == len(expected)
                     and len({n['id'] for n in nodes}) == len(nodes)
                     and all(n['id'] in packages for n in nodes)
                     and {packages[n['id']]['name'] for n in nodes} == expected,
                     'unexpected active accelerated dependency population')
    root_id = metadata['resolve']['root']
    packaged.require(root_id in packages and packages[root_id]['name'] == NAME
                     and metadata['workspace_members'] == [root_id]
                     and Path(metadata['workspace_root']).resolve() == directory.resolve(),
                     'non-isolated accelerated consumer')
    for p in packages.values():
        name = p['name']
        packaged.require(name == NAME or name in versions, 'unknown package')
        version = '0.0.0' if name == NAME else versions[name]
        path = directory if name == NAME else directory.parent.parent / 'unpacked' / f'{name}-{version}'
        packaged.require(p['version'] == version and p.get('source') is None
                         and Path(p['manifest_path']).resolve() == (path / 'Cargo.toml').resolve(),
                         'dependency is not the intended archive: ' + name)
    for node in nodes:
        name = packages[node['id']]['name']
        features = {'default'}
        if name == NAME:
            features = {route} | ({'hosted'} if admission == 'hosted' else set())
        elif name == 'brynja':
            features = {'aes-runtime-execution' if admission == 'hosted' else 'aes-static-execution'}
        elif name == 'brynja-crypto':
            features = {'aes-static-execution', 'hazmat-aes-block'}
            features.add('cpu')
            if route == 'facade':
                features.add('default')
            if admission == 'hosted':
                features.add('aes-runtime-execution')
        elif name == 'brynja-crypto-cpu':
            features |= {'aes-static-execution'}
            if admission == 'hosted':
                features.add('aes-runtime-execution')
        elif name == 'brynja-crypto-cpu-std':
            features = {'aes-runtime-execution'}
        elif name == 'brynja-hash-sha2':
            features.add('general-sha512-t')
            if admission == 'hosted':
                features.add('cpu')
        packaged.require(set(node['features']) == features,
                         f'unexpected features: {name}: {node["features"]} != {sorted(features)}')


def marker(compiler, route, admission, mode, suite):
    return f'AES_ACCELERATED_CAMPAIGN_PASS: {compiler} {route} {admission} {mode} {suite}'


def validate(output, suite, arm):
    (avs if suite == 'avs' else diff).check_output(output)
    expected = 'AES_FORCED_AUTHORITY: ' + ('ArmAes' if arm else 'X86AesNi')
    rows = [line for line in output.splitlines() if line.startswith('AES_FORCED_AUTHORITY:')]
    packaged.require(rows == [expected] * (6 if suite == 'avs' else 3),
                     'wrong/missing accelerated authority population')


def test_executable(output, suite, package_id, target_directory):
    """Select exactly the requested Cargo test artifact, never a guessed filename."""
    rows = [json.loads(line) for line in output.splitlines()]
    finished = [row for row in rows if row.get('reason') == 'build-finished']
    packaged.require(len(finished) == 1 and finished[0].get('success') is True,
                     'missing successful build completion')
    executables = [row for row in rows if row.get('reason') == 'compiler-artifact'
                   and row.get('executable') is not None]
    packaged.require(len(executables) == 1, 'unexpected executable population')
    row = executables[0]
    packaged.require(row.get('package_id') == package_id
                     and row.get('target', {}).get('name') == suite
                     and row.get('target', {}).get('kind') == ['test']
                     and row.get('profile', {}).get('test') is True,
                     'wrong campaign executable')
    path = Path(row['executable'])
    packaged.require(path.is_absolute() and path.is_file()
                     and not any(p.is_symlink() for p in (path, *path.parents))
                     and path.resolve().is_relative_to(target_directory.resolve())
                     and os.access(path, os.X_OK), 'invalid campaign executable path')
    return path


def check(compiler, route, admission, mode, suite):
    packaged.require(compiler in packaged.consumer.TOOLCHAINS and route in ('direct', 'facade')
                     and admission in ('static', 'hosted') and mode in ('native', 'arm-qemu')
                     and suite in ('avs', 'differential'), 'unsupported campaign configuration')
    packaged.require(not (mode == 'arm-qemu' and suite == 'differential'),
                     'OpenSSL subprocess comparison requires a native host')
    for name in (*packaged.archives.REJECT_ENV, 'PYTHONOPTIMIZE', 'PYTHONPATH'):
        packaged.require(name not in os.environ, 'remove ambient ' + name)
    machine = platform.machine().lower()
    packaged.require(machine in ('x86_64', 'amd64', 'aarch64', 'arm64'), 'unsupported host')
    oracle = diff.oracle.select(os.environ) if suite == 'differential' else None
    before = diff.oracle.digest(oracle) if oracle else None
    base = ROOT / 'target/aes-accelerated-campaigns'
    base.mkdir(parents=True, exist_ok=True)
    artifacts = Path(tempfile.mkdtemp(prefix=f'{compiler}-{route}-{admission}-{mode}-{suite}-', dir=base))
    print(f'Artifacts: {artifacts}', flush=True)
    with packaged.archives.cargo_environment.private_directory(ROOT) as temporary:
        root = Path(temporary)
        env = packaged.archives.isolated_env(root)
        versions = packaged.package_sources(root, env)
        directory = root / 'consumers/aes'
        (directory / 'src').mkdir(parents=True)
        fixture = ROOT / 'assurance/aes-accelerated-campaigns/lib.rs'
        packaged.require(fixture.is_file() and not any(p.is_symlink() for p in (fixture, *fixture.parents)),
                         'missing/symlinked accelerated adapter')
        shutil.copyfile(fixture, directory / 'src/lib.rs')
        (directory / 'Cargo.toml').write_text(manifest(versions, route, admission))
        harness = avs if suite == 'avs' else diff
        harness.prepare(directory)
        source = directory / f'tests/{suite}.rs'
        source.write_text(adapt(source.read_text(), suite))
        cargo = ['cargo', '+' + compiler]
        selection = ['--locked', '--offline', '--no-default-features', '--features',
                     route + (',hosted' if admission == 'hosted' else '')]
        packaged.archives.run(cargo + ['generate-lockfile', '--offline'], directory, env)
        metadata = packaged.archives.run(cargo + ['metadata', '--format-version=1', *selection], directory, env)
        graph(json.loads(metadata.stdout), versions, directory, route, admission)
        (artifacts / 'metadata.json').write_text(metadata.stdout)
        target = ['--target', 'aarch64-unknown-linux-musl'] if mode == 'arm-qemu' else []
        if target:
            env['CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER'] = 'rust-lld'
            env['CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUNNER'] = 'qemu-aarch64 -cpu max'
        if admission == 'static':
            # Probe with a baseline binary BEFORE compiling globally specialized tests.
            probe = root / 'probe'
            packaged.archives.run(['rustc', '+' + compiler, '--edition=2024',
                str(ROOT / 'assurance/aes-kernel-candidate/probe.rs'), '-o', str(probe), *target,
                *(['-C', 'linker=rust-lld'] if target else [])], directory, env)
            observed = packaged.archives.run([*(['qemu-aarch64', '-cpu', 'max'] if target else []),
                                             str(probe)], directory, env)
            packaged.require(observed.stdout.splitlines() == ['AES_STATIC_HOST_BUNDLE_PASS'], 'ISA probe failed')
            env['RUSTFLAGS'] = ('-Ctarget-feature=+aes,+neon' if target or machine in ('aarch64', 'arm64')
                                else '-Ctarget-feature=+aes,+sse2')
        else:
            env['RUSTFLAGS'] = '-Ctarget-feature=-aes'
        if oracle:
            env.update(BRYNJA_OPENSSL=str(oracle), OPENSSL_CONF='/dev/null')
            diff.oracle.preflight(oracle, env)
            print(f'Independent oracle: {oracle}; executable SHA-256: {before}', flush=True)
        compiler_identity = packaged.archives.run(['rustc', '+' + compiler, '-vV'], directory, env).stdout
        observations = []
        for profile in (('release',) if suite == 'avs' else ('debug', 'release')):
            print(f'Running forced {admission} {mode} {suite} {profile}', flush=True)
            command = cargo + ['test', *selection, *target, '--test', suite]
            if profile == 'release':
                command += ['--release']
            command += ['--no-run', '--message-format=json']
            built = packaged.archives.run(command, directory, env)
            (artifacts / f'{profile}-build.jsonl').write_text(built.stdout)
            (artifacts / f'{profile}-build.stderr').write_text(built.stderr)
            executable = test_executable(built.stdout, suite,
                json.loads(metadata.stdout)['resolve']['root'], root / 'target')
            retained = artifacts / f'{profile}-tests'
            shutil.copy2(executable, retained)
            digest = hashlib.sha256(retained.read_bytes()).hexdigest()
            packaged.require(hashlib.sha256(executable.read_bytes()).hexdigest() == digest,
                             'retained executable differs from build')
            execution = [*(['qemu-aarch64', '-cpu', 'max'] if target else []),
                         str(retained), '--include-ignored', '--show-output', '--test-threads=1']
            packaged.archives.cargo_environment.check(directory, env)
            result = subprocess.run(execution, cwd=directory, env=env, text=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=1800)
            (artifacts / f'{profile}.log').write_text(result.stdout)
            print(result.stdout, end='', flush=True)
            result.check_returncode()
            validate(result.stdout, suite, bool(target) or machine in ('aarch64', 'arm64'))
            packaged.require(hashlib.sha256(retained.read_bytes()).hexdigest() == digest,
                             'retained executable changed during execution')
            observations.append({'profile': profile, 'build': command, 'execution': execution,
                                 'binary': retained.name, 'sha256': digest})
        if oracle:
            packaged.require(diff.oracle.digest(oracle) == before, 'OpenSSL executable changed')
            print(diff.oracle.SUCCESS, flush=True)
        (artifacts / 'execution.json').write_text(json.dumps({
            'kind': 'unauthenticated-development-observation',
            'toolchain': compiler_identity, 'host': platform.platform(), 'machine': machine,
            'mode': mode, 'admission': admission, 'route': route, 'suite': suite,
            'rustflags': env['RUSTFLAGS'], 'oracle_sha256': before, 'profiles': observations,
            'scope': 'Correctness only; no timing, emitted-code or physical qualification.'
        }, indent=2) + '\n')
    print(marker(compiler, route, admission, mode, suite), flush=True)
    print('Correctness only; emulation is not native qualification. No timing or spill-erasure claim.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--toolchain', choices=packaged.consumer.TOOLCHAINS, required=True)
    parser.add_argument('--route', choices=('direct', 'facade'), required=True)
    parser.add_argument('--admission', choices=('static', 'hosted'), required=True)
    parser.add_argument('--mode', choices=('native', 'arm-qemu'), default='native')
    parser.add_argument('--suite', choices=('avs', 'differential'), required=True)
    args = parser.parse_args()
    try:
        check(args.toolchain, args.route, args.admission, args.mode, args.suite)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f'AES accelerated campaign FAIL: {error}', flush=True)
        raise SystemExit(2) from error
