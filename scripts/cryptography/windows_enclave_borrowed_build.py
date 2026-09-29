#!/usr/bin/env python3
"""Build the isolated direct-borrow input model with first-party dependencies."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

import windows_enclave_sha256_build as base

ROOT = base.ROOT
SOURCE = ROOT / 'assurance/windows-enclave-probe'


def prepare(directory, target):
    directory.mkdir(parents=True, exist_ok=True)
    base.check_graph()
    commands = []
    for crate in base.CRATES:
        name = crate.replace('-', '_')
        command = ['rustc', '+1.98.1', '--edition=2024', '--target', target, '-C', 'opt-level=2',
                   '--crate-type', 'rlib', '--crate-name', name, str(ROOT / 'crates' / crate / 'src/lib.rs'),
                   '-o', str(directory / ('lib' + name + '.rlib'))]
        if crate == 'brynja-hash-sha2':
            command += ['-L', 'dependency=' + str(directory)]
            for dep in ('brynja_core', 'brynja_hash_core'):
                command += ['--extern', dep + '=' + str(directory / ('lib' + dep + '.rlib'))]
        subprocess.run(command, check=True, capture_output=True, timeout=90)
        commands.append(command)
    for name in ('borrowed_input.rs', 'borrowed_input_tests.rs'):
        shutil.copyfile(SOURCE / name, directory / name)
    tests = (directory / 'borrowed_input_tests.rs').read_text()
    rows = ['#[test]', 'fn independent_twenty_vector_oracle_and_secret_output_cleanup() {']
    for message in base.vectors():
        rows.append('oracle(&[' + ','.join(map(str, message)) + '], &[' +
                    ','.join(map(str, hashlib.sha256(message).digest())) + ']);')
    (directory / 'borrowed_input_tests.rs').write_text(tests + '\n' + '\n'.join(rows + ['}', '']))
    return commands


def arguments(directory, target):
    return ['rustc', '+1.98.1', '--edition=2024', '--target', target,
            '--crate-name', 'enclave_borrowed', '-C', 'overflow-checks=yes',
            '-L', 'dependency=' + str(directory),
            '--extern', 'brynja_core=' + str(directory / 'libbrynja_core.rlib'),
            '--extern', 'brynja_hash_sha2=' + str(directory / 'libbrynja_hash_sha2.rlib')]


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    directory = args.directory.resolve()
    target = 'x86_64-pc-windows-msvc'
    commands = prepare(directory, target)
    command = arguments(directory, target) + ['-C', 'opt-level=2', '-D', 'warnings', '--crate-type', 'rlib',
        str(directory / 'borrowed_input.rs'), '-o', str(directory / 'libenclave_borrowed.rlib')]
    subprocess.run(command, check=True, timeout=90)
    paths = base.source_files() + [
        'assurance/windows-enclave-probe/borrowed_input.rs',
        'assurance/windows-enclave-probe/borrowed_input_tests.rs',
        'scripts/cryptography/windows_enclave_borrowed_build.py',
        'scripts/cryptography/test-windows-enclave-borrowed-input.py',
        'scripts/cryptography/windows_enclave_sha256_build.py']
    record = {'native_executed': False, 'strict_qualified': False, 'target': target,
              'commands': commands + [command],
              'source_sha256': {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in paths},
              'rustc': subprocess.check_output(['rustc', '+1.98.1', '-vV'], text=True),
              'archive_sha256': hashlib.sha256((directory / 'libenclave_borrowed.rlib').read_bytes()).hexdigest()}
    (directory / 'borrowed-build.json').write_text(json.dumps(record, indent=2) + '\n')
    print('Borrowed input Windows cross-build: PASS; native execution/strict qualification: NO')
