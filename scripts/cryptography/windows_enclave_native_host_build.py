#!/usr/bin/env python3
"""Cross-build isolated Rust-owned Windows host; not native qualification."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

import windows_enclave_sha256_build as oracle

ROOT = oracle.ROOT
SOURCE = ROOT / 'assurance/windows-enclave-probe'
FILES = ('host_session.rs', 'host_session_wire.rs', 'host_native_bridge.rs', 'host_native_bridge_tests.rs',
         'native_host.rs', 'native_host_campaign.rs', 'native_host.h',
         'native_host_resource.c', 'native_host_transport.c', 'native_host_main.c')


def build(directory):
    directory = directory.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    for name in FILES:
        shutil.copyfile(SOURCE / name, directory / name)
    model = (SOURCE / 'host_session.rs').read_text()
    assert model.count('#![no_std]\n') == 1
    (directory / 'native_model.rs').write_text(model.replace('#![no_std]\n', '') + '\n' +
                                             (SOURCE / 'host_native_bridge.rs').read_text())
    shutil.copyfile(SOURCE / 'native_host_campaign.rs', directory / 'campaign.rs')
    rows = ['const VECTORS: &[(&[u8], &[u8; 32])] = &[']
    for message in oracle.vectors():
        rows.append('(&[' + ','.join(map(str, message)) + '], &[' +
                    ','.join(map(str, hashlib.sha256(message).digest())) + ']),')
    (directory / 'native_vectors.rs').write_text('\n'.join(rows + ['];', '']))
    command = ['rustc', '+1.98.1', '--edition=2024', '--target', 'x86_64-pc-windows-msvc',
               '--crate-type', 'staticlib', '--crate-name', 'native_host', '-C', 'opt-level=2',
               '-C', 'panic=abort', '-C', 'overflow-checks=yes', '-D', 'warnings',
               str(directory / 'native_host.rs'), '-o', str(directory / 'native_host.lib')]
    subprocess.run(command, check=True, timeout=120)
    commands = [command]
    for name, cfg in (('early', 'probe_host_commit_early'), ('cleanup', 'probe_host_ignore_cleanup')):
        mutant = command[:-1] + [str(directory / (name + '.lib')), '--cfg', cfg]
        subprocess.run(mutant, check=True, timeout=120)
        commands.append(mutant)
    paths = ['assurance/windows-enclave-probe/' + name for name in FILES] + [
        'scripts/cryptography/windows_enclave_native_host_build.py',
        'scripts/cryptography/windows_enclave_native_host_run.py',
        'scripts/cryptography/test-windows-enclave-native-host.py',
        'scripts/cryptography/windows_enclave_sha256_build.py']
    record = {'native_executed': False, 'strict_qualified': False, 'commands': commands,
              'rustc': subprocess.check_output(['rustc', '+1.98.1', '-vV'], text=True),
              'source_sha256': {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in paths},
              'archives': {name: hashlib.sha256((directory / name).read_bytes()).hexdigest()
                           for name in ('native_host.lib', 'early.lib', 'cleanup.lib')}}
    (directory / 'host-build.json').write_text(json.dumps(record, indent=2) + '\n')
    print('Rust native host cross-build: PASS; native execution/strict qualification: NO')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    build(parser.parse_args().output)
