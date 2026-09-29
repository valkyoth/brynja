#!/usr/bin/env python3
"""Direct-copy worker research build, isolated from shipping crates and gates."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

import windows_enclave_borrowed_build as model
import windows_enclave_wire_build as wire

ROOT = model.ROOT
VARIANTS = {'normal': None, 'missing-clear': 'probe_borrowed_skip_clear',
            'ignore-copy': 'probe_borrowed_ignore_copy', 'reread': 'probe_borrowed_reread',
            'full-capacity': 'probe_borrowed_full_capacity'}
SOURCES = tuple(dict.fromkeys(wire.SOURCES + (
    'assurance/windows-enclave-probe/borrowed_input.rs',
    'assurance/windows-enclave-probe/borrowed_input_tests.rs',
    'assurance/windows-enclave-probe/window_borrowed.rs',
    'assurance/windows-enclave-probe/window_borrowed_tests.rs',
    'assurance/windows-enclave-probe/window_borrowed.c',
    'scripts/cryptography/windows_enclave_borrowed_build.py',
    'scripts/cryptography/windows_enclave_borrowed_worker_build.py',
    'scripts/cryptography/test-windows-enclave-borrowed-worker.py')))


def build(directory, target, testing=False, optimization='2'):
    directory = directory.resolve()
    wire.layout_check()
    commands = model.prepare(directory, target)
    for name in ('window_borrowed.rs', 'window_borrowed_tests.rs', 'wire_protocol.rs'):
        shutil.copyfile(model.SOURCE / name, directory / name)
    tests = directory / 'window_borrowed_tests.rs'
    oracle = ['#[test]', 'fn independent_twenty_vector_oracle() {']
    for message in model.base.vectors():
        oracle.append('oracle(&[' + ','.join(map(str, message)) + '], &[' +
                      ','.join(map(str, hashlib.sha256(message).digest())) + ']);')
    tests.write_text(tests.read_text() + '\n' + '\n'.join(oracle + ['}', '']))
    common = ['rustc', '+1.98.1', '--edition=2024', '--target', target, '-C',
              'opt-level=' + optimization, '-C', 'overflow-checks=yes',
              '-C', 'panic=' + ('unwind' if testing else 'abort'),
              '-L', 'dependency=' + str(directory)]
    for dep in ('brynja_core', 'brynja_hash_sha2'):
        common += ['--extern', dep + '=' + str(directory / ('lib' + dep + '.rlib'))]
    def run(args):
        commands.append(common + args)
        subprocess.run(common + args, check=True, capture_output=True, text=True, timeout=120)
    result = directory / 'libenclave_result.rlib'
    run(['--crate-name', 'enclave_result', '--crate-type', 'rlib',
         str(model.SOURCE / 'result_scope.rs'), '-o', str(result)])
    for name, cfg in VARIANTS.items():
        borrowed = directory / ('libborrowed_' + name.replace('-', '_') + '.rlib')
        args = ['--crate-name', 'enclave_borrowed', '--crate-type', 'rlib',
                str(directory / 'borrowed_input.rs'), '-o', str(borrowed)]
        run(args + (['--cfg', cfg] if cfg else []))
        args = ['--crate-name', 'enclave_borrowed_worker', str(directory / 'window_borrowed.rs'),
                '--extern', 'enclave_borrowed=' + str(borrowed),
                '--extern', 'enclave_result=' + str(result)]
        if testing:
            suffix = '.exe' if 'windows' in target else ''
            run(args + ['--test', '-o', str(directory / (name + '-worker' + suffix))])
        else:
            run(args + ['--crate-type', 'staticlib', '-C', 'lto=fat', '--emit=' +
                ','.join(kind + '=' + str(directory / (name + '_rust.' + ext))
                         for kind, ext in [('link', 'lib'), ('asm', 's'), ('llvm-ir', 'll')])])
    return commands


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    target = 'x86_64-pc-windows-msvc'
    commands = build(args.directory, target)
    record = {'native_executed': False, 'strict_qualified': False, 'target': target,
              'commands': commands,
              'source_sha256': {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in SOURCES},
              'rustc': subprocess.check_output(['rustc', '+1.98.1', '-vV'], text=True),
              'archives': {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                           for p in args.directory.glob('*_rust.lib')}}
    (args.directory / 'borrowed-worker-build.json').write_text(json.dumps(record, indent=2) + '\n')
    (args.directory / 'rustc-info.txt').write_text(record['rustc'])
    print('Direct-copy Windows worker cross-build: PASS; native execution/qualification: NO')
