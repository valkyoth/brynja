#!/usr/bin/env python3
"""Independent OpenSSL comparisons through packaged portable AES APIs."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('aes_packaged_differential_helpers', HERE / 'check-aes-packaged.py')
packaged = importlib.util.module_from_spec(spec)
spec.loader.exec_module(packaged)
oracle = packaged.module('aes_packaged_oracle', HERE / 'check-aes-differential.py')
ROOT = packaged.ROOT
FIXTURE = ROOT / 'assurance/aes-differential/differential.rs'
TESTS = {'oracle_path_admission'} | {f'aes{bits}_openssl_independent_corpus' for bits in (128, 192, 256)}
MARKERS = [f'AES{bits}_{kind}OPENSSL_COMPARISONS: 4096'
           for bits in (128, 192, 256) for kind in ('', 'CACHED_')] + [
    f'AES{bits}_PUBLIC_OPENSSL_COMPARISONS: 2048 per owner' for bits in (128, 192, 256)]


def prepare(directory):
    packaged.require(FIXTURE.is_file() and not FIXTURE.is_symlink()
                     and not any(p.is_symlink() for p in FIXTURE.parents),
                     'missing or symlinked differential fixture')
    target = directory / 'tests/differential.rs'
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(FIXTURE, target)


def check_output(output):
    rows = re.findall(r'^test (\S+) \.\.\. (\S+)\s*$', output, re.M)
    packaged.require(len(rows) == 4 and {name for name, _ in rows} == TESTS
                     and all(status == 'ok' for _, status in rows),
                     'missing, duplicated, ignored or failed packaged differential test')
    summaries = re.findall(r'^test result: .*$', output, re.M)
    packaged.require(len(summaries) == 1 and summaries[0].startswith(
        'test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;'),
        'wrong packaged differential summary')
    for marker in MARKERS:
        packaged.require(output.splitlines().count(marker) == 1,
                         'missing/duplicate differential population marker')


def profile_marker(compiler, route, profile):
    return f'AES_PACKAGED_DIFFERENTIAL_PROFILE: {compiler} {route} {profile}; 12288 cases; both owners; public encryption checked'


def marker(compiler, route):
    return f'AES packaged differential: PASS; {compiler} {route}; debug/release; all three widths; no upload'


def configuration(directory, root, versions, compiler, route, env):
    cargo = ['cargo', '+' + compiler]
    selection = ['--locked', '--offline', '--no-default-features', '--features', route]
    metadata = packaged.archives.run(cargo + ['metadata', '--format-version=1', *selection], directory, env)
    packaged.graph(json.loads(metadata.stdout), route, directory, root / 'unpacked', versions)
    for profile in ('debug', 'release'):
        command = cargo + ['test', *selection, '--test', 'differential']
        if profile == 'release':
            command.append('--release')
        command += ['--', '--include-ignored', '--show-output', '--test-threads=1']
        result = packaged.archives.run(command, directory, env)
        print(result.stdout, end='', flush=True)
        check_output(result.stdout)
        print(profile_marker(compiler, route, profile), flush=True)


def check(compiler, route):
    packaged.require(compiler in packaged.consumer.TOOLCHAINS and route in packaged.consumer.ROUTES,
                     'unsupported packaged differential configuration')
    for name in (*packaged.archives.REJECT_ENV, 'PYTHONOPTIMIZE', 'PYTHONPATH'):
        packaged.require(name not in os.environ, 'remove ambient ' + name)
    # Select once before constructing the isolated environment; ambient oracle
    # overrides must be rejected, not silently stripped into a passing run.
    executable = oracle.select(os.environ)
    before = oracle.digest(executable)
    print(f'Independent oracle executable: {executable}', flush=True)
    print(f'Independent oracle SHA-256: {before}', flush=True)
    with packaged.archives.cargo_environment.private_directory(ROOT) as temporary:
        root = Path(temporary)
        env = packaged.archives.isolated_env(root)
        env.update(BRYNJA_OPENSSL=str(executable), OPENSSL_CONF='/dev/null')
        oracle.preflight(executable, env)
        versions = packaged.package_sources(root, env)
        directory = root / 'consumers/aes'
        packaged.prepare(directory, versions)
        prepare(directory)
        packaged.archives.run(['cargo', '+' + compiler, 'generate-lockfile', '--offline'], directory, env)
        configuration(directory, root, versions, compiler, route, env)
        packaged.require(oracle.digest(executable) == before, 'OpenSSL executable changed during comparison')
    print(oracle.SUCCESS, flush=True)
    print(marker(compiler, route), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--toolchain', choices=packaged.consumer.TOOLCHAINS, required=True)
    parser.add_argument('--route', choices=packaged.consumer.ROUTES, required=True)
    args = parser.parse_args()
    check(args.toolchain, args.route)
