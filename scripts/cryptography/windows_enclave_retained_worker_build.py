#!/usr/bin/env python3
"""Build independent PUBLIC-vector retained-worker images; no release admission."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

import windows_enclave_placement_build as placement
import windows_enclave_hardened_build as hardened
import windows_enclave_persistent as native

base = placement.base
VARIANTS = {'normal': None, 'forget': 'probe_retained_forget',
            'no-export': 'probe_retained_no_export', 'discard': 'probe_retained_discard'}
SOURCES = tuple(sorted(set(base.SOURCES) | set(native.SOURCES) | {
    'assurance/windows-enclave-probe/retained_placement.rs',
    'assurance/windows-enclave-probe/retained_placement_tests.rs',
    'assurance/windows-enclave-probe/window_retained.rs',
    'assurance/windows-enclave-probe/window_retained.c',
    'scripts/cryptography/windows_enclave_placement_build.py',
    'scripts/cryptography/windows_enclave_hardened_build.py',
    'scripts/cryptography/windows_enclave_retained_worker_build.py',
    'scripts/cryptography/windows_enclave_retained_native.py',
    'scripts/cryptography/test-windows-enclave-retained-worker.py',
    'scripts/cryptography/test-windows-enclave-retained-native.py'}))


def build(directory):
    directory = directory.resolve()
    hardened.layout_check()
    target = 'x86_64-pc-windows-msvc'
    commands = base.build(directory, target)
    shutil.copyfile(base.SOURCE / 'retained_placement.rs', directory / 'retained_placement.rs')
    invocation = placement.command(directory, target, '2', False)
    result = placement.run(invocation)
    if result.returncode:
        raise RuntimeError(result.stderr)
    commands.append(invocation)
    for name, cfg in VARIANTS.items():
        invocation = ['rustc', '+1.98.1', '--edition=2024', '--target', target,
                      '--crate-name', 'retained_worker', '--crate-type', 'staticlib', '-D', 'warnings',
                      '-C', 'opt-level=2', '-C', 'overflow-checks=yes', '-C', 'panic=abort', '-C', 'lto=fat',
                      '-L', 'dependency=' + str(directory)]
        for dep, archive in [('brynja_core', 'libbrynja_core.rlib'),
                             ('brynja_hash_sha2', 'libbrynja_hash_sha2.rlib'),
                             ('persistent_result', 'libpersistent_result_normal.rlib'),
                             ('retained_placement', 'libretained_placement.rlib')]:
            invocation += ['--extern', dep + '=' + str(directory / archive)]
        invocation += [str(base.SOURCE / 'window_retained.rs'), '--emit=' +
                       ','.join(kind + '=' + str(directory / (name + '_rust.' + ext))
                                for kind, ext in [('link', 'lib'), ('asm', 's'), ('llvm-ir', 'll')])]
        if cfg:
            invocation += ['--cfg', cfg]
        result = placement.run(invocation)
        if result.returncode:
            raise RuntimeError(result.stderr)
        commands.append(invocation)
    record = {'native_executed': False, 'strict_qualified': False, 'target': target, 'commands': commands,
              'rustc': subprocess.check_output(['rustc', '+1.98.1', '-vV'], text=True),
              'source_sha256': {p: hashlib.sha256((base.ROOT / p).read_bytes()).hexdigest() for p in SOURCES},
              'archives_sha256': {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                  for p in sorted(directory.glob('*_rust.lib'))}}
    (directory / 'retained-worker-build.json').write_text(json.dumps(record, indent=2) + '\n')
    print('Retained worker Windows cross-build: PASS; native execution/qualification: NO')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    build(parser.parse_args().directory)
