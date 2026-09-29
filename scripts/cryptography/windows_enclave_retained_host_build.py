#!/usr/bin/env python3
"""Isolated ownership model build with explicitly synthetic test transport."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'assurance/windows-enclave-probe'
SOURCES = ('assurance/windows-enclave-probe/retained_host.rs',
           'assurance/windows-enclave-probe/retained_host_tests.rs',
           'assurance/windows-enclave-probe/retained_host_fixture.rs',
           'scripts/cryptography/windows_enclave_retained_host_build.py',
           'scripts/cryptography/test-windows-enclave-retained-host.py')
VARIANTS = {'normal': None, 'early': 'probe_retained_host_early_commit',
            'reopen': 'probe_retained_host_reopen_abandoned', 'receipt': 'probe_retained_host_ignore_receipt',
            'release': 'probe_retained_host_false_close'}


def prepare(directory, fixture=False):
    directory.mkdir(parents=True, exist_ok=True)
    for name in ('retained_host.rs', 'retained_host_tests.rs', 'retained_host_fixture.rs'):
        shutil.copyfile(SOURCE / name, directory / name)
    if fixture:
        source = directory / 'retained_host.rs'
        source.write_text(source.read_text() + '\n#[path="retained_host_fixture.rs"] mod fixture;\n'
                          'pub use fixture::fixture;\n')


def command(directory, target, level='2', testing=False, cfg=None):
    args = ['rustc', '+1.98.1', '--edition=2024', '--target', target, '--crate-name', 'retained_host',
            '-D', 'warnings', '-C', 'opt-level=' + level, '-C', 'overflow-checks=yes',
            '-C', 'panic=' + ('unwind' if testing else 'abort'), str(directory / 'retained_host.rs')]
    if cfg:
        args += ['--cfg', cfg]
    return args + (['--test', '-o', str(directory / ('test.exe' if 'windows' in target else 'test'))]
                   if testing else ['--crate-type', 'rlib', '-o', str(directory / 'libretained_host.rlib')])


def run(args):
    return subprocess.run(args, capture_output=True, text=True, timeout=60)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    directory = args.directory.resolve()
    prepare(directory, fixture=True)
    invocation = command(directory, 'x86_64-pc-windows-msvc')
    result = run(invocation)
    if result.returncode:
        raise RuntimeError(result.stderr)
    record = {'native_executed': False, 'strict_qualified': False, 'synthetic_transport': True,
              'commands': [invocation], 'rustc': subprocess.check_output(['rustc', '+1.98.1', '-vV'], text=True),
              'source_sha256': {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in SOURCES},
              'generated_source_sha256': hashlib.sha256((directory / 'retained_host.rs').read_bytes()).hexdigest(),
              'archive_sha256': hashlib.sha256((directory / 'libretained_host.rlib').read_bytes()).hexdigest()}
    (directory / 'retained-host-build.json').write_text(json.dumps(record, sort_keys=True, indent=2) + '\n')
    print('Retained host model Windows cross-build: PASS; synthetic transport only; native qualification: NO')
