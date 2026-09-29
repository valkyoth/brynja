#!/usr/bin/env python3
"""Concrete retained-output facade candidate, not a production constructor."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import windows_enclave_retained_lifetime_build as base

ROOT, SOURCE, replace = base.ROOT, base.SOURCE, base.replace
VARIANTS = base.VARIANTS
SOURCES = tuple(sorted(set(base.SOURCES) | {
    'assurance/windows-enclave-probe/retained_facade.rs',
    'assurance/windows-enclave-probe/retained_facade_campaign.rs',
    'assurance/windows-enclave-probe/retained_facade_tests.rs',
    'scripts/cryptography/windows_enclave_retained_facade_build.py',
    'scripts/cryptography/windows_enclave_retained_facade_run.py',
    'scripts/cryptography/test-windows-enclave-retained-facade.py'}))


def prepare(directory):
    base.prepare(directory)
    for name in ('retained_facade.rs', 'retained_facade_campaign.rs'):
        shutil.copyfile(SOURCE/name, directory/name)
    path = directory/'retained_native_host.rs'
    source = replace(path.read_text(), 'mod retained_model;',
        'mod retained_model;\npub mod retained_facade;\nmod retained_facade_campaign;')
    source = replace(source, '    retained_native_campaign::run(image)',
        '    let result = retained_native_campaign::run(image);\n'
        '    if result != 0 { return result; }\n    retained_facade_campaign::run(image)')
    path.write_text(source)
    path = directory/'retained_native_main.c'
    path.write_text(replace(path.read_text(),
        'HostCounter(0) == 12 && HostCounter(1) == 12 && HostCounter(2) == 265',
        'HostCounter(0) == 14 && HostCounter(1) == 14 && HostCounter(2) == 281'))


def build(directory):
    directory = directory.resolve(); prepare(directory); commands = []
    for name, cfg in VARIANTS.items():
        command = ['rustc', '+1.98.1', '--edition=2024', '--target', 'x86_64-pc-windows-msvc',
            '--crate-type', 'staticlib', '--crate-name', 'retained_facade_host', '-D', 'warnings',
            '-C', 'opt-level=2', '-C', 'panic=abort', '-C', 'overflow-checks=yes',
            str(directory/'retained_native_host.rs'), '-o', str(directory/(name+'.lib'))]
        if cfg: command += ['--cfg', cfg]
        subprocess.run(command, check=True, capture_output=True, timeout=120); commands.append(command)
    record = {'native_executed': False, 'strict_qualified': False, 'public_vectors_only': True,
        'commands': commands, 'rustc': subprocess.check_output(['rustc', '+1.98.1', '-vV'], text=True),
        'source_sha256': {p: hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in SOURCES},
        'generated_sha256': {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(directory.iterdir()) if p.suffix in ('.rs', '.c', '.h')},
        'archives': {n+'.lib': hashlib.sha256((directory/(n+'.lib')).read_bytes()).hexdigest() for n in VARIANTS}}
    (directory/'retained-facade-build.json').write_text(json.dumps(record, indent=2)+'\n')
    print('Concrete retained-output facade cross-build: PASS; production qualification: NO')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('directory', type=Path)
    build(parser.parse_args().directory)
