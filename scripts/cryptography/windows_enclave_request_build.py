#!/usr/bin/env python3
"""Source-bound public request experiment; not a release gate."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

import windows_enclave_sha256_build as base
from windows_enclave_hardened_build import layout_check

ROOT = base.ROOT
VARIANTS = {'normal': None, 'reread': 'probe_reread_snapshot',
            'missing-clear': 'probe_skip_request_clear', 'implicit-public': 'probe_implicit_public'}


def build(directory, target, testing=False):
    base.check_graph()
    layout_check()
    if (ROOT / 'assurance/windows-enclave-probe/sha256_vectors.rs').read_text() != base.vector_source():
        raise ValueError('independent vectors changed')
    directory = directory.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    commands = []
    mutations = {}
    def run(args):
        command = ['rustc', '+1.98.1', '--edition=2024', '-C', 'opt-level=2',
                   '-C', 'overflow-checks=yes', '-C', 'codegen-units=1',
                   '-C', 'force-unwind-tables=yes', '-C', 'embed-bitcode=yes',
                   '-C', 'panic=' + ('unwind' if testing else 'abort'), '--target', target, *args]
        commands.append(command)
        subprocess.run(command, cwd=ROOT, check=True, timeout=120)
    for variant, cfg in VARIANTS.items():
        libs = directory / (variant + '-libs')
        libs.mkdir(exist_ok=True)
        for crate in base.CRATES:
            source = ROOT / 'crates' / crate / 'src/lib.rs'
            name = crate.replace('-', '_')
            args = ['--crate-type', 'rlib', '--crate-name', name, str(source),
                    '-o', str(libs / ('lib' + name + '.rlib'))]
            if crate == 'brynja-hash-sha2':
                args += ['-L', 'dependency=' + str(libs)]
                for dep in ('brynja_core', 'brynja_hash_core'):
                    args += ['--extern', dep + '=' + str(libs / ('lib' + dep + '.rlib'))]
            run(args)
        args = ['assurance/windows-enclave-probe/window_request.rs', '--crate-name', 'enclave_request',
                '-L', 'dependency=' + str(libs)]
        for dep in ('brynja_core', 'brynja_hash_sha2'):
            args += ['--extern', dep + '=' + str(libs / ('lib' + dep + '.rlib'))]
        if cfg:
            args += ['--cfg', cfg]
        if testing:
            suffix = '.exe' if 'windows' in target else ''
            run(args + ['--test', '-o', str(directory / (variant + suffix))])
        else:
            run(args + ['--crate-type', 'staticlib', '-C', 'lto=fat',
                        '--emit=' + ','.join(kind + '=' + str(directory / (variant + '_rust.' + suffix))
                                             for kind, suffix in [('link', 'lib'), ('asm', 's'), ('llvm-ir', 'll')])])
    return commands, mutations


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    commands, mutations = build(args.output, 'x86_64-pc-windows-msvc')
    identity = subprocess.check_output(['rustc', '+1.98.1', '-vV'], text=True)
    (args.output / 'rustc-info.txt').write_text(identity)
    record = {'commands': commands, 'mutations': mutations, 'rustc': identity, 'features': [],
              'source_sha256': {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in base.source_files()},
              'archives': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in args.output.glob('*_rust.lib')}}
    (args.output / 'rust-build.json').write_text(json.dumps(record, indent=2) + '\n')
    print('Request-boundary experiment archives built; not native or strict qualification')
