#!/usr/bin/env python3
"""Isolated metadata-only host build. Original public wire fixtures stay unchanged."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

import windows_enclave_native_host_build as previous
import windows_enclave_borrowed_build as borrowed

ROOT, SOURCE = previous.ROOT, previous.SOURCE
FILES = tuple(n for n in previous.FILES if n not in ('native_host_transport.c', 'host_native_bridge.rs')) + (
    'borrowed_input.rs', 'host_borrowed_bridge.rs', 'host_borrowed_bridge_tests.rs',
    'native_borrowed_transport.c')
SOURCES = tuple(dict.fromkeys(tuple(borrowed.base.source_files()) +
    tuple('assurance/windows-enclave-probe/' + n for n in FILES) + (
    'scripts/cryptography/windows_enclave_borrowed_host_build.py',
    'scripts/cryptography/windows_enclave_borrowed_host_run.py',
    'scripts/cryptography/test-windows-enclave-borrowed-host.py',
    'scripts/cryptography/windows_enclave_borrowed_build.py',
    'scripts/cryptography/windows_enclave_native_host_build.py',
    'scripts/cryptography/windows_enclave_native_host_run.py',
    'scripts/cryptography/windows_enclave_sha256_build.py')))


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('borrowed-host source anchor absent or ambiguous: ' + old[:60])
    return text.replace(old, new, 1)


def prepare(directory, target):
    directory = directory.resolve()
    commands = borrowed.prepare(directory, target)
    for name in FILES:
        shutil.copyfile(SOURCE / name, directory / name)
    # Keep the earlier byte-serializing model and its evidence unchanged. This
    # generated private model omits that entry routine completely, not just its call.
    wire = (SOURCE / 'host_session_wire.rs').read_text()
    begin = wire.index('    /// Called only by the eventual fixed native bridge')
    end = wire.index('    /// Each offer is a copied value', begin)
    if wire[begin:end].count('pub(super) fn enter(') != 1:
        raise ValueError('unexpected original host entry routine')
    (directory / 'host_session_wire.rs').write_text(wire[:begin] + wire[end:])
    model = (SOURCE / 'host_session.rs').read_text()
    model = replace_once(model, '#![no_std]\n', '')
    model = replace_once(model, '#[cfg(test)]\n#[path = "host_session_tests.rs"]\nmod tests;', '')
    model += '\n' + (SOURCE / 'host_borrowed_bridge.rs').read_text()
    model += '\n#[cfg(test)]\n#[path="host_native_bridge_tests.rs"] mod bridge_tests;\n'
    model += '#[cfg(test)]\n#[path="host_borrowed_bridge_tests.rs"] mod borrowed_tests;\n'
    (directory / 'native_model.rs').write_text(model)
    host = replace_once((SOURCE / 'native_host.rs').read_text(),
                        'request.as_ptr(),', 'request.metadata().as_ptr(),')
    (directory / 'native_host.rs').write_text(host)
    campaign = replace_once((SOURCE / 'native_host_campaign.rs').read_text(),
                            'for fault in 1..=3 {', 'for fault in [1, 2, 3, 5] {')
    (directory / 'campaign.rs').write_text(campaign)
    main = replace_once((SOURCE / 'native_host_main.c').read_text(),
        'result == 0 && HostCounter(0) == 5 && HostCounter(1) == 5\n'
        '        && HostCounter(2) == 63',
        'result == 0 && HostCounter(0) == 6 && HostCounter(1) == 6\n'
        '        && HostCounter(2) == 64')
    (directory / 'native_host_main.c').write_text(main)
    shutil.copyfile(SOURCE / 'native_borrowed_transport.c', directory / 'native_host_transport.c')
    rows = ['const VECTORS: &[(&[u8], &[u8; 32])] = &[']
    for message in previous.oracle.vectors():
        rows.append('(&[' + ','.join(map(str, message)) + '], &[' +
                    ','.join(map(str, hashlib.sha256(message).digest())) + ']),')
    (directory / 'native_vectors.rs').write_text('\n'.join(rows + ['];', '']))
    command = ['rustc', '+1.98.1', '--edition=2024', '--target', target,
               '--crate-name', 'enclave_borrowed', '--crate-type', 'rlib',
               '-C', 'opt-level=2', '-L', 'dependency=' + str(directory),
               '--extern', 'brynja_core=' + str(directory / 'libbrynja_core.rlib'),
               str(directory / 'borrowed_input.rs'), '-o', str(directory / 'libenclave_borrowed.rlib')]
    subprocess.run(command, check=True, capture_output=True, timeout=60)
    return commands + [command]


def build(directory):
    directory = directory.resolve()
    commands = prepare(directory, 'x86_64-pc-windows-msvc')
    command = ['rustc', '+1.98.1', '--edition=2024', '--target', 'x86_64-pc-windows-msvc',
               '--crate-type', 'staticlib', '--crate-name', 'borrowed_host', '-C', 'opt-level=2',
               '-C', 'panic=abort', '-C', 'overflow-checks=yes', '-D', 'warnings',
               '-L', 'dependency=' + str(directory), '--extern',
               'enclave_borrowed=' + str(directory / 'libenclave_borrowed.rlib'),
               str(directory / 'native_host.rs'), '-o', str(directory / 'native_host.lib')]
    subprocess.run(command, check=True, timeout=120)
    commands.append(command)
    for name, cfg in (('early', 'probe_host_commit_early'), ('cleanup', 'probe_host_ignore_cleanup')):
        mutant = command[:-1] + [str(directory / (name + '.lib')), '--cfg', cfg]
        subprocess.run(mutant, check=True, timeout=120)
        commands.append(mutant)
    generated = ('native_model.rs', 'host_session_wire.rs', 'native_host.rs',
                 'campaign.rs', 'native_vectors.rs', 'native_host_transport.c', 'native_host_main.c')
    record = {'native_executed': False, 'strict_qualified': False, 'commands': commands,
              'rustc': subprocess.check_output(['rustc', '+1.98.1', '-vV'], text=True),
              'source_sha256': {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in SOURCES},
              'generated_sha256': {p: hashlib.sha256((directory / p).read_bytes()).hexdigest() for p in generated},
              'archives': {name: hashlib.sha256((directory / name).read_bytes()).hexdigest()
                           for name in ('native_host.lib', 'early.lib', 'cleanup.lib')}}
    (directory / 'host-build.json').write_text(json.dumps(record, indent=2) + '\n')
    print('Metadata-only Rust host cross-build: PASS; native execution/strict qualification: NO')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    build(parser.parse_args().directory)
