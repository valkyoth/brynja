#!/usr/bin/env python3
"""Internal AES expansion correctness and no_std domain controls; not public admission."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('expansion_packages', HERE / 'check-aes-packaged.py')
packaged = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(packaged)
ROOT, require = packaged.ROOT, packaged.require
FIXTURE = ROOT / 'assurance/aes-kernel-candidate'
REJECT = (*packaged.archives.REJECT_ENV, 'PYTHONOPTIMIZE', 'PYTHONPATH', 'LD_PRELOAD', 'LD_AUDIT', 'LD_LIBRARY_PATH')
INVALID = ('invalid_zero_key', 'invalid_short_schedule', 'invalid_mismatched_schedule', 'invalid_wide_key', 'invalid_long_schedule')
MARKERS = ('AES_KERNEL_KAT_PASS: 128:568', 'AES_KERNEL_KAT_PASS: 192:700', 'AES_KERNEL_KAT_PASS: 256:810',
           'AES_KERNEL_ALIGNMENT_PASS: 768', 'AES_EXPANSION_KAT_PASS: 128:568', 'AES_EXPANSION_KAT_PASS: 192:700',
           'AES_EXPANSION_KAT_PASS: 256:810', 'AES_EXPANSION_ALIGNMENT_PASS: 768', 'AES_EXPANSION_GENERATED_PASS: 774')
TESTS = {'aes128_kat', 'aes192_kat', 'aes256_kat', 'every_byte_alignment_and_canaries',
         'parser_rejects_incomplete_or_substituted_vectors', 'expansion::aes128_schedule_and_vectors',
         'expansion::aes192_schedule_and_vectors', 'expansion::aes256_schedule_and_vectors',
         'expansion::every_key_and_schedule_byte_alignment', 'expansion::generated_keys_match_every_schedule_byte'}


def validate(output):
    names = re.findall(r'^test (\S+) \.\.\. ok$', output, re.MULTILINE)
    summaries = re.findall(r'^test result:.*$', output, re.MULTILINE)
    require(len(names) == 10 and set(names) == TESTS and len(summaries) == 1 and re.fullmatch(
        r'test result: ok\. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in [0-9.]+s', summaries[0]),
        'incomplete expansion test population')
    for marker in MARKERS:
        require(output.splitlines().count(marker) == 1, 'missing/duplicate expansion marker: ' + marker)


def rejected_domain(result, target):
    source = 'aarch64_expand.rs' if target.startswith('aarch64') else 'x86_expand.rs'
    try:
        errors = []
        for line in result.stderr.splitlines():
            row = json.loads(line)
            if row.get('level') != 'error':
                continue
            if row.get('code') is None and not row.get('spans') and row.get('message', '').startswith('aborting due to '):
                continue
            errors.append(row)
        return result.returncode == 1 and len(errors) == 1 and (errors[0].get('code') or {}).get('code') == 'E0080' and any(
            span.get('is_primary') and Path(span.get('file_name', '')).name == source for span in errors[0].get('spans', []))
    except (ValueError, AttributeError, TypeError):
        return False


def execute(command, directory, env, artifacts, label):
    packaged.archives.cargo_environment.check(directory, env)
    try:
        result = subprocess.run(command, cwd=directory, env=env, capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired as error:
        def decode(value):
            return value.decode(errors='replace') if isinstance(value, bytes) else value or ''
        (artifacts / (label + '.json')).write_text(json.dumps({'command': command, 'timeout': True,
            'stdout': decode(error.stdout), 'stderr': decode(error.stderr)}, indent=2) + '\n')
        raise
    (artifacts / (label + '.json')).write_text(json.dumps({'command': command, 'returncode': result.returncode,
        'stdout': result.stdout, 'stderr': result.stderr}, indent=2) + '\n')
    return result


def successful(result, label):
    require(result.returncode == 0, label + ' failed: ' + result.stdout[-2000:] + result.stderr[-2000:])


def check(compiler, mode):
    require(compiler in ('1.90.0', '1.99.1') and mode in ('x86', 'arm-qemu'), 'unreviewed expansion configuration')
    require(platform.system() == 'Linux' and platform.machine() == 'x86_64', 'requires Linux x86_64 test host')
    for name in REJECT:
        require(name not in os.environ, 'remove ambient ' + name)
    base = ROOT / 'target/aes-expansion-candidate'
    base.mkdir(parents=True, exist_ok=True)
    artifacts = Path(tempfile.mkdtemp(prefix=f'{compiler}-{mode}-', dir=base))
    print(f'Artifacts: {artifacts}', flush=True)
    target = 'x86_64-unknown-linux-gnu' if mode == 'x86' else 'aarch64-unknown-linux-musl'
    runner = [] if mode == 'x86' else ['qemu-aarch64', '-cpu', 'max']
    with packaged.archives.cargo_environment.private_directory(ROOT) as temporary:
        directory = Path(temporary)
        env = packaged.archives.isolated_env(directory)
        rustc = ['rustc', '+' + compiler, '--edition=2024', '--target', target]
        obj = rustc + ['--crate-type=lib', '--emit=obj', '--error-format=json', str(FIXTURE / 'expansion-compile.rs')]
        result = execute(obj + ['-o', str(artifacts / 'valid.o')], directory, env, artifacts, 'valid')
        successful(result, 'valid no_std expansion domain')
        for case in INVALID:
            result = execute(obj + ['--cfg', case, '-o', str(artifacts / (case + '.o'))], directory, env, artifacts, case)
            require(rejected_domain(result, target), 'wrong/missing constant-domain rejection: ' + case)
        print('AES_EXPANSION_DOMAIN_PASS: 3 valid shapes; 5 rejected shapes; no_std', flush=True)
        binary = artifacts / 'expansion-tests'
        command = rustc + ['--test', '--cfg', 'aes_expansion_candidate', str(FIXTURE / 'main.rs'),
                           '-C', 'opt-level=2', '-C', 'overflow-checks=yes', '-o', str(binary)]
        if mode == 'arm-qemu':
            command += ['-C', 'linker=rust-lld']
        successful(execute(command, directory, env, artifacts, 'build'), 'expansion build')
        result = execute([*runner, str(binary), '--show-output', '--test-threads=1'], directory, env, artifacts, 'tests')
        print(result.stdout, end='', flush=True)
        successful(result, 'expansion execution')
        validate(result.stdout)
    print(f'AES_EXPANSION_CANDIDATE_PASS: {compiler} {mode}; correctness only; not public admission', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--toolchain', choices=('1.90.0', '1.99.1'), required=True)
    parser.add_argument('--mode', choices=('x86', 'arm-qemu'), required=True)
    args = parser.parse_args()
    try:
        check(args.toolchain, args.mode)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f'AES expansion candidate FAIL: {error}', flush=True)
        raise SystemExit(2) from error
