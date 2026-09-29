#!/usr/bin/env python3
"""Isolated retained SHA-256 owner build; never native/platform qualification."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

import windows_enclave_borrowed_build as base

ROOT, SOURCE = base.ROOT, base.SOURCE
VARIANTS = {'normal': None, 'missing-clear': 'probe_persistent_skip_clear',
            'generation': 'probe_persistent_reuse_generation',
            'token': 'probe_persistent_ignore_token',
            'public': 'probe_persistent_implicit_public'}
SOURCES = tuple(base.base.source_files()) + (
    'assurance/windows-enclave-probe/persistent_result.rs',
    'assurance/windows-enclave-probe/persistent_result_tests.rs',
    'assurance/windows-enclave-probe/retained_digest.rs',
    'assurance/windows-enclave-probe/retained_digest_tests.rs',
    'scripts/cryptography/windows_enclave_retained_build.py',
    'scripts/cryptography/test-windows-enclave-retained-digest.py',
    'scripts/cryptography/windows_enclave_borrowed_build.py',
    'scripts/cryptography/windows_enclave_sha256_build.py')


def build(directory, target, testing=False, level='2'):
    directory = directory.resolve()
    commands = base.prepare(directory, target)
    for name in ('retained_digest.rs', 'retained_digest_tests.rs'):
        shutil.copyfile(SOURCE / name, directory / name)
    tests = directory / 'retained_digest_tests.rs'
    oracle = ['#[test]', 'fn independent_twenty_vector_oracle_retains_digest_after_worker_exit() {']
    for message in base.base.vectors():
        oracle.append('oracle(&[' + ','.join(map(str, message)) + '], &[' +
                      ','.join(map(str, hashlib.sha256(message).digest())) + ']);')
    tests.write_text(tests.read_text() + '\n' + '\n'.join(oracle + ['}', '']))
    common = ['rustc', '+1.98.1', '--edition=2024', '--target', target, '-D', 'warnings',
              '-C', 'opt-level=' + level, '-C', 'overflow-checks=yes',
              '-C', 'panic=' + ('unwind' if testing else 'abort'),
              '-L', 'dependency=' + str(directory)]
    for dep in ('brynja_core', 'brynja_hash_sha2'):
        common += ['--extern', dep + '=' + str(directory / ('lib' + dep + '.rlib'))]
    def run(arguments):
        command = common + arguments
        commands.append(command)
        result = subprocess.run(command, capture_output=True, text=True, timeout=90)
        if result.returncode:
            raise RuntimeError(result.stderr)
    for variant, cfg in VARIANTS.items():
        library = directory / ('libpersistent_result_' + variant.replace('-', '_') + '.rlib')
        run(['--crate-name', 'persistent_result', '--crate-type', 'rlib', str(SOURCE / 'persistent_result.rs'),
             '-o', str(library)] + (['--cfg', cfg] if cfg else []))
        args = ['--crate-name', 'retained_digest', str(directory / 'retained_digest.rs'),
                '--extern', 'persistent_result=' + str(library)]
        if testing:
            suffix = '.exe' if 'windows' in target else ''
            run(args + ['--test', '-o', str(directory / (variant + suffix))])
        else:
            run(args + ['--crate-type', 'rlib', '-o', str(directory / ('libretained_' + variant + '.rlib'))])
    return commands


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    target = 'x86_64-pc-windows-msvc'
    commands = build(args.directory, target)
    record = {'native_executed': False, 'strict_qualified': False, 'target': target,
              'commands': commands, 'rustc': subprocess.check_output(['rustc', '+1.98.1', '-vV'], text=True),
              'source_sha256': {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in SOURCES},
              'archives_sha256': {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                  for p in sorted(args.directory.glob('*.rlib'))}}
    (args.directory / 'retained-build.json').write_text(json.dumps(record, indent=2) + '\n')
    print('Retained digest Windows cross-build: PASS; native execution/strict qualification: NO')
