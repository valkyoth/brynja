#!/usr/bin/env python3
"""Build only the scoped result research model; no native enclave qualification."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

import windows_enclave_sha256_build as base
from windows_enclave_hardened_build import layout_check

ROOT = base.ROOT
VARIANTS = {'normal': None, 'reusable': 'probe_reusable_result',
            'forgotten': 'probe_forget_result', 'wrong-token': 'probe_ignore_result_token',
            'implicit-public': 'probe_implicit_result_public'}
SOURCES = tuple(base.source_files()) + (
    'assurance/windows-enclave-probe/result_scope.rs',
    'assurance/windows-enclave-probe/result_scope_tests.rs',
    'assurance/windows-enclave-probe/window_result.rs',
    'assurance/windows-enclave-probe/sha256_vectors.rs',
    'scripts/cryptography/windows_enclave_hardened_build.py',
    'scripts/cryptography/windows_enclave_result_build.py',
    'scripts/cryptography/test-windows-enclave-result.py',
    'scripts/cryptography/windows_enclave_sha256_build.py')


def build(directory, target, testing=False):
    base.check_graph()
    layout_check()
    if (ROOT / 'assurance/windows-enclave-probe/sha256_vectors.rs').read_text() != base.vector_source():
        raise ValueError('independent public vectors changed')
    directory = directory.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    libs = directory / 'dependencies'
    libs.mkdir(exist_ok=True)
    commands = []
    def run(args):
        command = ['rustc', '+1.98.1', '--edition=2024', '--target', target,
                   '-C', 'opt-level=2', '-C', 'overflow-checks=yes',
                   '-C', 'panic=' + ('unwind' if testing else 'abort'), *args]
        commands.append(command)
        subprocess.run(command, cwd=ROOT, check=True, timeout=120)
    for crate in base.CRATES:
        name = crate.replace('-', '_')
        args = ['--crate-type', 'rlib', '--crate-name', name,
                str(ROOT / 'crates' / crate / 'src/lib.rs'), '-o', str(libs / ('lib' + name + '.rlib'))]
        if crate == 'brynja-hash-sha2':
            args += ['-L', 'dependency=' + str(libs)]
            for dep in ('brynja_core', 'brynja_hash_core'):
                args += ['--extern', dep + '=' + str(libs / ('lib' + dep + '.rlib'))]
        run(args)
    for variant, cfg in VARIANTS.items():
        args = ['assurance/windows-enclave-probe/result_scope.rs', '--crate-name', 'enclave_result',
                '-L', 'dependency=' + str(libs)]
        for dep in ('brynja_core', 'brynja_hash_sha2'):
            args += ['--extern', dep + '=' + str(libs / ('lib' + dep + '.rlib'))]
        if cfg:
            args += ['--cfg', cfg]
        run(args + ['--crate-type', 'rlib', '-o', str(directory / ('lib' + variant + '.rlib'))])
        if testing:
            suffix = '.exe' if 'windows' in target else ''
            run(args + ['--test', '-o', str(directory / (variant + suffix))])
        worker = ['assurance/windows-enclave-probe/window_result.rs', '--crate-name', 'enclave_result_worker',
                  '-L', 'dependency=' + str(libs), '--extern',
                  'enclave_result=' + str(directory / ('lib' + variant + '.rlib'))]
        for dep in ('brynja_core', 'brynja_hash_sha2'):
            worker += ['--extern', dep + '=' + str(libs / ('lib' + dep + '.rlib'))]
        if testing:
            run(worker + ['--test', '-o', str(directory / (variant + '-worker' + suffix))])
        else:
            run(worker + ['--crate-type', 'staticlib', '-C', 'lto=fat', '--emit=' +
                ','.join(kind + '=' + str(directory / (variant + '_rust.' + ext))
                         for kind, ext in [('link', 'lib'), ('asm', 's'), ('llvm-ir', 'll')])])
    return commands


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('--target', default='x86_64-pc-windows-msvc')
    args = parser.parse_args()
    commands = build(args.output, args.target)
    record = {'kind': 'scoped-result-model-cross-build', 'native_executed': False,
              'strict_qualified': False, 'target': args.target, 'commands': commands,
              'rustc': subprocess.check_output(['rustc', '+1.98.1', '-vV'], text=True),
              'source_sha256': {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in SOURCES},
              'archives': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in args.output.glob('*_rust.lib')}}
    (args.output / 'result-build.json').write_text(json.dumps(record, indent=2) + '\n')
    print('Scoped result model cross-build: PASS; native execution/strict qualification: NO')
