#!/usr/bin/env python3
"""Controlled native prefix-copy experiment; never production support."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import windows_enclave_retained_rehash_worker_build as worker
import windows_enclave_retained_rehash_host_build as host

ROOT, SOURCE, replace = worker.ROOT, worker.SOURCE, worker.replace
SOURCES = tuple(sorted(set(worker.SOURCES) | set(host.SOURCES) | {
    'assurance/windows-enclave-probe/retained_partial_copy.h',
    'assurance/windows-enclave-probe/retained_partial_main.c',
    'scripts/cryptography/windows_enclave_retained_partial_build.py',
    'scripts/cryptography/windows_enclave_retained_partial_run.py',
    'scripts/cryptography/test-windows-enclave-retained-partial.py'}))


def prepare_image(directory):
    commands = worker.prepare(directory, 'x86_64-pc-windows-msvc')
    shutil.copyfile(SOURCE/'retained_partial_copy.h', directory/'retained_partial_copy.h')
    path = directory/'window_retained_borrowed.c'
    source = path.read_text()
    source = replace(source, 'static ULONG_PTR input_source,',
        '#include "retained_partial_copy.h"\nstatic uint64_t partial_command, partial_report[5];\nstatic ULONG_PTR input_source,')
    source = replace(source, '    result = EnclaveCopyIntoEnclave(destination, (const void*)source, size);', '''
    {
        uint64_t prefix = 0;
        if (partial_copy_plan(partial_command, kind, size, &prefix)) {
            partial_report[0] = partial_command; partial_report[1] = 1;
            partial_command = 0; /* one-shot, even if the OS prefix copy fails */
            if (prefix) {
#ifndef BRYNJA_PARTIAL_SKIP_COPY
                result = EnclaveCopyIntoEnclave(destination, (const void*)source, (SIZE_T)prefix);
                if (result != S_OK) { return result; }
                partial_report[2] = prefix; partial_report[3] = 1;
#endif
            }
#ifdef BRYNJA_PARTIAL_IGNORE_FAILURE
            input_report[kind * 2 + 1] += 1;
            return S_OK;
#else
            partial_report[4] = 1;
            return E_FAIL; /* deliberate failure AFTER the successful prefix copy */
#endif
        }
    }
    result = EnclaveCopyIntoEnclave(destination, (const void*)source, size);''')
    source = replace(source, '    input_source = (ULONG_PTR)context;',
        '    for (i = 0; i < 5; ++i) { partial_report[i] = 0; }\n    input_source = (ULONG_PTR)context;')
    source += '''
__declspec(dllexport) void* CALLBACK PublicPartialControl(void* context) {
    uint64_t command = (uint64_t)(ULONG_PTR)context, prefix = 0, kind = command >> 32;
    if (active || retained_call) { return 0; }
    if (command >= 16 && command <= 20) { return (void*)(ULONG_PTR)partial_report[command - 16]; }
    if (!command) { partial_command = 0; return (void*)1; }
    if (partial_command || kind < 1 || kind > 2 ||
        !partial_copy_plan(command, kind - 1, kind == 1 ? 32 : 1024, &prefix)) { return 0; }
    partial_command = command; return (void*)1;
}
'''
    path.write_text(source)
    return commands


def prepare_host(directory):
    host.prepare(directory)
    for name in ('retained_partial_copy.h', 'retained_partial_main.c'):
        shutil.copyfile(SOURCE/name, directory/name)
    path = directory/'native_host.h'
    path.write_text(replace(path.read_text(), 'BOOL slot_locked, uncertain;',
        'BOOL slot_locked, uncertain, partial_quarantine;\n    uint64_t partial_expected;'))
    path = directory/'retained_native_transport.c'
    source = replace(path.read_text(), '#include "retained_rehash_report.h"',
        '#include "retained_rehash_report.h"\n#include "retained_partial_copy.h"')
    source = replace(source, '    expected = op == 8 ?', '''
    if (owner->partial_expected) {
        ULONG_PTR observed[5];
        LPENCLAVE_ROUTINE control = (LPENCLAVE_ROUTINE)GetProcAddress((HMODULE)owner->base, "PublicPartialControl");
        if (op != 1 || inner[0] != 121) { return FALSE; }
        for (i = 0; i < 5; ++i) { if (!HostCall(control, i + 16, &observed[i])) { return FALSE; } }
        if (!partial_copy_report(observed, owner->partial_expected)) { return FALSE; }
    }
    expected = op == 2 && owner->partial_quarantine ? 107 : op == 8 ?''')
    # A rejected export performs no public-copy primitive call.
    source = replace(source, '    if (!retained_rehash_report(rehash, op, inner[0],',
        '    if (!retained_rehash_report(rehash, op == 2 && owner->partial_quarantine ? 4 : op, inner[0],')
    path.write_text(source)


def build(directory):
    directory = directory.resolve(); directory.mkdir()
    image = directory/'image'; host_dir = directory/'host'
    commands = prepare_image(image)
    commands += worker.compile(image, 'x86_64-pc-windows-msvc')
    prepare_host(host_dir)
    record = {'native_executed': False, 'strict_qualified': False,
        'public_vectors_only': True, 'commands': commands,
        'rustc': subprocess.check_output(['rustc', '+1.98.1', '-vV'], text=True),
        'source_sha256': {p: hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in SOURCES},
        'generated_sha256': {str(p.relative_to(directory)): hashlib.sha256(p.read_bytes()).hexdigest()
            for sub in (image, host_dir) for p in sorted(sub.iterdir()) if p.suffix in ('.rs', '.c', '.h', '.asm')},
        'archives': {'image/normal_rust.lib': hashlib.sha256((image/'normal_rust.lib').read_bytes()).hexdigest()}}
    (directory/'retained-partial-build.json').write_text(json.dumps(record, indent=2)+'\n')
    print('Partial-copy Windows cross-build: PASS; native qualification: NO')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    build(parser.parse_args().directory)
