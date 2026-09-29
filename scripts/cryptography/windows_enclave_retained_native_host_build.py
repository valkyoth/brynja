#!/usr/bin/env python3
"""Build a private resource-owning host for the existing public retained image."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

from windows_enclave_sha256_build import vectors

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'assurance/windows-enclave-probe'
FILES = ('retained_host.rs', 'retained_native_host.rs', 'retained_native_campaign.rs',
         'retained_native_transport.c', 'retained_page_admission.h', 'native_host.h', 'native_host_resource.c')
SOURCES = tuple('assurance/windows-enclave-probe/' + n for n in FILES) + (
    'scripts/cryptography/windows_enclave_retained_native_host_build.py',
    'scripts/cryptography/windows_enclave_retained_native_host_run.py',
    'scripts/cryptography/test-windows-enclave-retained-native-host.py',
    'assurance/windows-enclave-probe/retained_native_adapter_tests.rs',
    'scripts/cryptography/windows_enclave_sha256_build.py')
VARIANTS = {'normal': None, 'early': 'probe_retained_host_early_commit',
            'reopen': 'probe_retained_host_reopen_abandoned', 'receipt': 'probe_retained_host_ignore_receipt'}


def replace(source, before, after):
    if source.count(before) != 1:
        raise ValueError('retained host build anchor absent or ambiguous: ' + before[:60])
    return source.replace(before, after, 1)


def prepare(directory):
    directory.mkdir(parents=True, exist_ok=True)
    for name in FILES:
        shutil.copyfile(SOURCE / name, directory / name)
    model = replace((SOURCE / 'retained_host.rs').read_text(), '#![no_std]\n', '')
    model = replace(model, '#[cfg(test)]\n#[path = "retained_host_tests.rs"]\nmod tests;', '')
    (directory / 'retained_model.rs').write_text(model)
    header = replace((SOURCE / 'native_host.h').read_text(),
        'LPENCLAVE_ROUTINE wire, window, registration, control, guard;',
        'LPENCLAVE_ROUTINE wire, window, registration, control, guard, output;\n'
        '    ULONG_PTR slot;\n    BOOL slot_locked, uncertain;')
    (directory / 'native_host.h').write_text(header)
    resource = (SOURCE / 'native_host_resource.c').read_text()
    resource = replace(resource, '    if (instance->base) {',
        '    if (instance->slot || instance->slot_locked || instance->uncertain) {\n'
        '        cleanup_errors += 1; return 0; /* Never delete as a substitute for clearing. */\n'
        '    }\n    if (instance->base) {')
    resource = replace(resource, '"PublicWire"', '"PublicRetained"')
    resource = replace(resource, '"PublicWireControl"', '"PublicRetainedControl"')
    resource = replace(resource, '    return instance;',
        '    instance->output = (LPENCLAVE_ROUTINE)GetProcAddress((HMODULE)instance->base, "PublicRetainedOutput");\n'
        '    if (!instance->output) { goto failed; }\n    return instance;')
    (directory / 'native_host_resource.c').write_text(resource)
    rows = ['const DIGESTS: [[u8;32];20] = [']
    rows += ['[' + ','.join(map(str, hashlib.sha256(v).digest())) + '],' for v in vectors()]
    (directory / 'retained_native_vectors.rs').write_text('\n'.join(rows + ['];', '']))
    (directory / 'retained_native_main.c').write_text(MAIN)


MAIN = r'''#include "native_host.h"
#include <stdio.h>
#include <wchar.h>
extern uint32_t HostCampaign(const wchar_t*, size_t);
int wmain(int argc, wchar_t** argv) {
    uint32_t result;
    if (argc != 2) { return 99; }
    result = HostCampaign(argv[1], wcslen(argv[1]) + 1);
    printf("{\"result\":%u,\"created\":%llu,\"deleted\":%llu,\"calls\":%llu,"
           "\"retained\":%llu,\"cleanup_errors\":%llu}\n", result,
           HostCounter(0), HostCounter(1), HostCounter(2), HostCounter(3), HostCounter(4));
#if defined(BRYNJA_HOST_FAIL_DELETE)
    return result == 15 && HostCounter(0) == 1 && HostCounter(1) == 0 && HostCounter(2) == 160
        && HostCounter(3) == 1 && HostCounter(4) == 3 ? 0 : 96;
#elif defined(BRYNJA_HOST_FAIL_CREATE) || defined(BRYNJA_HOST_FAIL_LOAD) || defined(BRYNJA_HOST_FAIL_INIT)
    return result == 10 && HostCounter(0) == 1 && HostCounter(1) == 1 && HostCounter(2) == 0
        && HostCounter(3) == 0 && HostCounter(4) == 0 ? 0 : 98;
#else
    return result == 0 && HostCounter(0) == 7 && HostCounter(1) == 7 && HostCounter(2) == 178
        && HostCounter(3) == 0 && HostCounter(4) == 0 ? 0 : 97;
#endif
}
'''


def build(directory):
    directory = directory.resolve()
    prepare(directory)
    commands = []
    for name, cfg in VARIANTS.items():
        command = ['rustc', '+1.98.1', '--edition=2024', '--target', 'x86_64-pc-windows-msvc',
                   '--crate-type', 'staticlib', '--crate-name', 'retained_native_host',
                   '-C', 'opt-level=2', '-C', 'panic=abort', '-C', 'overflow-checks=yes', '-D', 'warnings',
                   str(directory / 'retained_native_host.rs'), '-o', str(directory / (name + '.lib'))]
        if cfg:
            command += ['--cfg', cfg]
        subprocess.run(command, check=True, timeout=120)
        commands.append(command)
    generated = ('retained_model.rs', 'native_host.h', 'native_host_resource.c',
                 'retained_native_vectors.rs', 'retained_native_main.c')
    record = {'native_executed': False, 'strict_qualified': False, 'synthetic_transport': False,
              'public_vectors_only': True, 'commands': commands,
              'rustc': subprocess.check_output(['rustc', '+1.98.1', '-vV'], text=True),
              'source_sha256': {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in SOURCES},
              'generated_sha256': {p: hashlib.sha256((directory / p).read_bytes()).hexdigest() for p in generated},
              'archives': {n + '.lib': hashlib.sha256((directory / (n + '.lib')).read_bytes()).hexdigest() for n in VARIANTS}}
    (directory / 'retained-native-host-build.json').write_text(json.dumps(record, indent=2) + '\n')
    print('Retained native host cross-build: PASS; native execution/strict qualification: NO')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    build(parser.parse_args().directory)
