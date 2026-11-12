#!/usr/bin/env python3
"""Packaged static x86 AES ASan/LSan lifecycle with mandatory failing controls."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('sanitizer_campaign', HERE / 'check-aes-accelerated-campaigns.py')
campaign = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(campaign)
packaged, ROOT = campaign.packaged, campaign.ROOT
require = packaged.require
TOOLCHAIN = 'nightly-2026-09-11'
TARGET = 'x86_64-unknown-linux-gnu'
FLAGS = '-Zsanitizer=address -Ctarget-feature=+aes,+sse2'
# Both runtimes share the exitcode setting; keep it identical and nonzero.
ASAN = 'detect_leaks=1:halt_on_error=1:exitcode=23'
LSAN = 'exitcode=23'
REJECT = (*packaged.archives.REJECT_ENV, 'PYTHONOPTIMIZE', 'PYTHONPATH',
          'ASAN_OPTIONS', 'LSAN_OPTIONS', 'LD_PRELOAD', 'LD_AUDIT', 'LD_LIBRARY_PATH')
TESTS = {'unavailable_static_routes_reject_before_key_admission'} | {
    f'native::aes{bits}::{name}' for bits in (128, 192, 256) for name in (
        'nist_corpus_both_owners', 'quarantine_clears_secret_preserves_public_and_never_falls_back',
        'failed_constructor_clears_admitted_storage', 'caller_unwind_clears_both_key_owners')}
MARKERS = {f'AES_EXECUTION_KAT_PASS: {bits}:{count}' for bits, count in ((128, 568), (192, 700), (256, 810))}


def validate_tests(output):
    rows = re.findall(r'^test (\S+) \.\.\. (\S+)$', output, re.M)
    require(len(rows) == len(TESTS) and {name for name, _ in rows} == TESTS
            and all(status == 'ok' for _, status in rows), 'incorrect accelerated lifecycle test population')
    summaries = re.findall(r'^test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;', output, re.M)
    require(summaries == [('ok', '13', '0', '0', '0', '0')], 'incorrect accelerated lifecycle summary')
    markers = [line for line in output.splitlines() if line.startswith('AES_EXECUTION_KAT_PASS:')]
    require(len(markers) == 3 and set(markers) == MARKERS, 'incorrect accelerated KAT markers')
    require(not re.search(r'(?:ERROR|WARNING|SUMMARY): (?:Address|Leak)Sanitizer', output),
            'sanitizer diagnostic in successful test output')


def validate_control(mode, result):
    require(mode in ('bounds', 'leak'), 'unknown sanitizer control')
    expected = ('AddressSanitizer: heap-buffer-overflow', 23) if mode == 'bounds' else (
        'LeakSanitizer: detected memory leaks', 23)
    require(result.returncode == expected[1] and 'ERROR: ' + expected[0] in result.stdout,
            f'sanitizer control did not fail with the intended diagnosis: {mode}; exit={result.returncode}')
    if mode == 'bounds':
        require('READ of size 1' in result.stdout, 'wrong bounds-control access')
    else:
        require('64 byte(s) leaked in 1 allocation(s)' in result.stdout, 'wrong leak-control extent')


def manifest(versions, route):
    text = campaign.manifest(versions, route, 'static')
    # The archived integration test names the typed CPU error as well as the
    # selected public API. It does not construct a second authority or fallback.
    dependency = f'brynja-crypto-cpu={{version="={versions["brynja-crypto-cpu"]}"}}\n'
    return campaign.replace_exact(text, '[patch.crates-io]', dependency + '[patch.crates-io]', 1)


def adapt(source, route):
    require(route in ('direct', 'facade'), 'unknown sanitizer API route')
    require(source.count('brynja_crypto::aes') == 2, 'archived lifecycle imports changed')
    return source if route == 'direct' else source.replace('brynja_crypto::aes', 'brynja::crypto::aes')


def copy_file(source, target):
    require(source.is_file() and not any(p.is_symlink() for p in (source, *source.parents)),
            'missing/symlinked sanitizer fixture')
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)


def execute(command, directory, env, artifacts, label):
    packaged.archives.cargo_environment.check(directory, env)
    result = subprocess.run(command, cwd=directory, env=env, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=600)
    (artifacts / (label + '.log')).write_text(result.stdout)
    (artifacts / (label + '.json')).write_text(json.dumps(
        {'command': command, 'returncode': result.returncode}, indent=2) + '\n')
    print(result.stdout, end='', flush=True)
    return result


def run_profile(cargo, selection, directory, env, artifacts, root, route, profile):
    require(profile in ('debug', 'release'), 'unknown sanitizer profile')
    options = ['--release'] if profile == 'release' else []
    command = cargo + ['build', *selection, '--target', TARGET, *options, '--bin', 'sanitizer-control']
    execute(command, directory, env, artifacts, profile + '-control-build').check_returncode()
    binary = root / 'target' / TARGET / profile / 'sanitizer-control'
    for mode in ('bounds', 'leak'):
        result = execute([str(binary), mode], directory, env, artifacts, profile + '-' + mode)
        validate_control(mode, result)
        print(f'AES_SANITIZER_CONTROL_PASS: {route} {profile} {mode}', flush=True)
    command = cargo + ['test', *selection, '--target', TARGET, *options,
                       '--test', 'lifecycle', '--', '--show-output', '--test-threads=1']
    result = execute(command, directory, env, artifacts, profile + '-lifecycle')
    result.check_returncode()
    validate_tests(result.stdout)
    print(f'AES_ACCELERATED_SANITIZER_PROFILE_PASS: {route} {profile}; 13 tests', flush=True)


def check(route):
    require(route in ('direct', 'facade'), 'unknown sanitizer route')
    require(platform.system() == 'Linux' and platform.machine() == 'x86_64',
            'accelerated sanitizer run requires Linux x86_64')
    for name in REJECT:
        require(name not in os.environ, 'remove ambient ' + name)
    base = ROOT / 'target/aes-accelerated-sanitizers'
    base.mkdir(parents=True, exist_ok=True)
    artifacts = Path(tempfile.mkdtemp(prefix=route + '-', dir=base))
    print(f'Artifacts: {artifacts}', flush=True)
    with packaged.archives.cargo_environment.private_directory(ROOT) as temporary:
        root = Path(temporary)
        env = packaged.archives.isolated_env(root)
        versions = packaged.package_sources(root, env)
        directory = root / 'consumers/aes'
        (directory / 'src').mkdir(parents=True)
        (directory / 'src/lib.rs').write_text('#![no_std]\n')
        (directory / 'Cargo.toml').write_text(manifest(versions, route))
        archive = root / 'unpacked' / ('brynja-crypto-' + versions['brynja-crypto'])
        source = archive / 'tests/aes_execution.rs'
        copy_file(source, directory / 'tests/lifecycle.rs')
        (directory / 'tests/lifecycle.rs').write_text(adapt(source.read_text(), route))
        for bits in (128, 192, 256):
            for kind in ('ECBGFSbox', 'ECBKeySbox', 'ECBVarKey', 'ECBVarTxt'):
                relative = f'tests/fixtures/aes{bits}/{kind}{bits}.rsp'
                copy_file(archive / relative, directory / relative)
        copy_file(ROOT / 'assurance/aes-accelerated-campaigns/sanitizer-control.rs',
                  directory / 'src/bin/sanitizer-control.rs')
        cargo = ['cargo', '+' + TOOLCHAIN]
        selection = ['--locked', '--offline', '--no-default-features', '--features', route]
        packaged.archives.run(cargo + ['generate-lockfile', '--offline'], directory, env)
        metadata = packaged.archives.run(cargo + ['metadata', '--format-version=1', *selection], directory, env)
        campaign.graph(json.loads(metadata.stdout), versions, directory, route, 'static')
        (artifacts / 'metadata.json').write_text(metadata.stdout)
        version = packaged.archives.run(['rustc', '+' + TOOLCHAIN, '-Vv'], directory, env)
        (artifacts / 'rustc.txt').write_text(version.stdout)
        # Probe baseline code before compiling or executing target specialization.
        probe = root / 'probe'
        packaged.archives.run(['rustc', '+' + TOOLCHAIN, '--edition=2024',
            str(ROOT / 'assurance/aes-kernel-candidate/probe.rs'), '-o', str(probe)], directory, env)
        observed = packaged.archives.run([str(probe)], directory, env)
        require(observed.stdout.splitlines() == ['AES_STATIC_HOST_BUNDLE_PASS'], 'ISA probe failed')
        env.update(RUSTFLAGS=FLAGS, ASAN_OPTIONS=ASAN, LSAN_OPTIONS=LSAN)
        for profile in ('debug', 'release'):
            run_profile(cargo, selection, directory, env, artifacts, root, route, profile)
    print(f'AES_ACCELERATED_SANITIZERS_PASS: {route}; 2 profiles; 26 tests; 4 failing sanitizer controls', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--route', choices=('direct', 'facade'), required=True)
    try:
        check(parser.parse_args().route)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f'AES accelerated sanitizers FAIL: {error}')
        raise SystemExit(2) from error
