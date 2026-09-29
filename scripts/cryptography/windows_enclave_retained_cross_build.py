#!/usr/bin/env python3
"""Two-live-instance routing experiment. Not a persistent/authenticated identity."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import windows_enclave_retained_rehash_worker_build as worker
import windows_enclave_retained_rehash_host_build as host

ROOT,SOURCE,replace = worker.ROOT,worker.SOURCE,worker.replace
SOURCES = tuple(sorted(set(worker.SOURCES)|set(host.SOURCES)|{
    'assurance/windows-enclave-probe/retained_cross_worker.rs',
    'assurance/windows-enclave-probe/retained_cross_report.h',
    'assurance/windows-enclave-probe/retained_cross_main.c',
    'scripts/cryptography/windows_enclave_retained_cross_build.py',
    'scripts/cryptography/windows_enclave_retained_cross_run.py',
    'scripts/cryptography/windows_enclave_retained_partial_run.py',
    'scripts/cryptography/test-windows-enclave-retained-cross.py'}))


def prepare_image(directory,target='x86_64-pc-windows-msvc',testing=False,identity_mutant=False):
    commands = worker.prepare(directory,target,testing)
    shutil.copyfile(SOURCE/'retained_cross_worker.rs',directory/'retained_cross_worker.rs')
    path = directory/'retained_input_worker.rs'; source = path.read_text()
    source = replace(source,'static mut EPOCH: u64 = 0;',
        'static mut EPOCH: u64 = 0;\nstatic INSTANCE_ANCHOR: u8 = 0;\nmod retained_cross_worker;')
    source = replace(source,'[0x52455441494e, next]',
        '[0x52455441494e, next]' if identity_mutant else '[core::ptr::addr_of!(INSTANCE_ANCHOR).addr() as u64, next]')
    if identity_mutant:
        source = replace(source,'static INSTANCE_ANCHOR: u8 = 0;','')
    source = replace(source,'        8 | 9 => {','''        10 => {
            let (status, next) = retained_cross_worker::rehash(owner, unsafe { EPOCH }, low, high);
            if let Some(next) = next { *token = next; }
            status
        }
        8 | 9 => {''')
    source += '''
/// # Safety
/// Private C entry: same one-thread serialization, inactive worker, public metadata only.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn RetainedTokenWord(index: usize) -> u64 {
    if index >= 4 { return 0; }
    // SAFETY: C refuses active/reentrant calls; token contains no secret bytes.
    unsafe { (*core::ptr::addr_of!(TOKEN))[index] }
}
'''
    path.write_text(source)
    path = directory/'window_retained.c'
    path.write_text(replace(path.read_text(),'(operation & 255) > 9','(operation & 255) > 10'))
    path = directory/'window_retained_borrowed.c'; source = path.read_text()
    source = replace(source,'static ULONG_PTR input_source,','#include <string.h>\nstatic ULONG_PTR cross_report[6];\nstatic ULONG_PTR input_source,')
    source = replace(source,'    input_source = (ULONG_PTR)context;',
        '    for (i = 0; i < 6; ++i) { cross_report[i] = 0; }\n    input_source = (ULONG_PTR)context;')
    source += '''
extern unsigned __int64 RetainedTokenWord(SIZE_T);
int PublicCrossCopy(unsigned char* destination) {
    ULONG_PTR address = (ULONG_PTR)destination;
    SIZE_T i; int result;
    if (!active || !retained_call || retained_operation != 10 || address < PublicLockedLow ||
        address > PublicLockedHigh || 32 > PublicLockedHigh - address || cross_report[0]) { return E_FAIL; }
    cross_report[0] = 1;
    result = EnclaveCopyIntoEnclave(destination, (const void*)input_source, 32);
    if (result == S_OK) {
        cross_report[1] = 1;
        for(i=0;i<4;++i) { memcpy(&cross_report[i+2], destination+8*i, 8); }
    }
    return result;
}
__declspec(dllexport) void* CALLBACK PublicCrossControl(void* context) {
    ULONG_PTR op = (ULONG_PTR)context;
    if (active || retained_call) { return 0; }
    if (op >= 16 && op <= 19) { return retained_live ? (void*)(ULONG_PTR)RetainedTokenWord(op-16) : 0; }
    if (op >= 32 && op <= 37) { return (void*)cross_report[op-32]; }
    return 0;
}
'''
    path.write_text(source)
    return commands


def prepare_host(directory):
    host.prepare(directory)
    for name in ('retained_cross_main.c','retained_cross_report.h'):
        shutil.copyfile(SOURCE/name,directory/name)
    path = directory/'retained_cross_main.c'
    rows = ['static const unsigned char oracle_digest[2][32] = {']
    for message in (b'abc',b'xyz'):
        rows.append('{'+','.join(map(str,hashlib.sha256(hashlib.sha256(message).digest()).digest()))+'},')
    path.write_text(replace(path.read_text(),'/* ORACLE */','\n'.join(rows+['};'])))
    path = directory/'native_host.h'
    path.write_text(replace(path.read_text(),'BOOL slot_locked, uncertain;',
        'BOOL slot_locked, uncertain, cross_quarantine;\n    uint64_t cross_expected, cross_token[4];'))
    path = directory/'retained_native_transport.c'; source = path.read_text()
    source = replace(source,'#include "retained_rehash_report.h"',
        '#include "retained_rehash_report.h"\n#include "retained_cross_report.h"')
    source = replace(source,'    if (!retained_rehash_report(rehash, op, inner[0],',
        '    if (op != 10 && !retained_rehash_report(rehash, op == 2 && owner->cross_quarantine ? 4 : op, inner[0],')
    source = replace(source,'    expected = op == 8 ?', '''
    if (op == 10) {
        ULONG_PTR copied[6];
        LPENCLAVE_ROUTINE control = (LPENCLAVE_ROUTINE)GetProcAddress((HMODULE)owner->base,"PublicCrossControl");
        for(i=0;i<6;++i) { if(!HostCall(control,i+32,&copied[i])) { return FALSE; } }
        if(!retained_cross_report(copied,rehash,owner->cross_token,inner[0],owner->cross_expected,
            call->low,call->low+65536,owner->result_generation,owner->input_epoch)) { return FALSE; }
    }
    expected = op == 10 ? owner->cross_expected : op == 2 && owner->cross_quarantine ? 107 : op == 8 ?''')
    source = replace(source,'op == 1 || op == 8 || op == 9','op == 1 || op == 8 || op == 9 || op == 10')
    source = replace(source,'if (op == 8) { owner->result_generation += 1; }',
        'if (op == 8 || (op == 10 && inner[0] == 8)) { owner->result_generation += 1; }')
    source = replace(source,'((op == 1) != (input != NULL))','((op == 1 || op == 10) != (input != NULL))')
    source = replace(source,'op != 6 && op != 8 && op != 9','op != 6 && op != 8 && op != 9 && op != 10')
    source = replace(source,'    if (input) { memcpy(&call.input_length, input + 16, sizeof(call.input_length)); }',
        '    if (op == 1) { memcpy(&call.input_length, input + 16, sizeof(call.input_length)); }')
    path.write_text(source)


def build(directory):
    directory = directory.resolve(); directory.mkdir()
    image = directory/'image'; commands = prepare_image(image)
    commands += worker.compile(image,'x86_64-pc-windows-msvc')
    commands += worker.compile(image,'x86_64-pc-windows-msvc',variant='token')
    # Collision mutant is a separate image retaining the old constant identity.
    identity = directory/'identity'; commands += prepare_image(identity,identity_mutant=True)
    commands += worker.compile(identity,'x86_64-pc-windows-msvc')
    prepare_host(directory/'host')
    record = {'native_executed':False,'strict_qualified':False,'public_vectors_only':True,
        'commands':commands,'rustc':subprocess.check_output(['rustc','+1.98.1','-vV'],text=True),
        'source_sha256':{p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in SOURCES},
        'generated_sha256':{str(p.relative_to(directory)):hashlib.sha256(p.read_bytes()).hexdigest()
            for sub in (image,identity,directory/'host') for p in sorted(sub.iterdir()) if p.suffix in ('.rs','.c','.h','.asm')},
        'archives':{str(p.relative_to(directory)):hashlib.sha256(p.read_bytes()).hexdigest()
            for sub in (image,identity) for p in sorted(sub.glob('*_rust.lib'))}}
    (directory/'retained-cross-build.json').write_text(json.dumps(record,indent=2)+'\n')
    print('Cross-instance Windows build: PASS; native qualification: NO')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__);parser.add_argument('directory',type=Path)
    build(parser.parse_args().directory)
