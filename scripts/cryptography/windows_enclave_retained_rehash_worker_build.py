#!/usr/bin/env python3
"""Separate composition image; earlier signed native images remain unchanged."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import windows_enclave_retained_input_worker_build as previous
import windows_enclave_retained_rehash_build as model

ROOT,SOURCE=model.ROOT,model.SOURCE
replace=previous.replace
VARIANTS={name:model.VARIANTS[name] for name in ('normal','scratch','token','commit','generation')}
SOURCES=tuple(sorted(set(previous.SOURCES)|set(model.SOURCES)|{
    'assurance/windows-enclave-probe/retained_rehash_worker.rs',
    'scripts/cryptography/windows_enclave_retained_rehash_worker_build.py',
    'scripts/cryptography/test-windows-enclave-retained-rehash-worker.py'}))


def prepare(directory,target,testing=False):
    commands=previous.prepare(directory,target,testing)
    more,_=model.prepare(directory,target,testing);commands+=more
    shutil.copyfile(SOURCE/'retained_rehash_worker.rs',directory/'retained_rehash_worker.rs')
    source=(directory/'retained_input_worker.rs').read_text()
    source=replace(source,'static mut EPOCH: u64 = 0;',
                   'static mut EPOCH: u64 = 0;\nstatic mut PREVIOUS_TOKEN: [u64; 4] = [0; 4];\nmod retained_rehash_worker;')
    source=replace(source,'        2 | 5 | 6 => {',
                   '        8 | 9 => {\n'
                   '            // SAFETY: same serialized one-worker metadata ownership.\n'
                   '            let supplied = if op == 9 { unsafe { PREVIOUS_TOKEN } } else { *token };\n'
                   '            let (status, next) = retained_rehash_worker::rehash(owner, supplied, unsafe { EPOCH }, low, high);\n'
                   '            if let Some(next) = next { unsafe { PREVIOUS_TOKEN = *token; } *token = next; }\n'
                   '            status\n        }\n        2 | 5 | 6 => {')
    source=replace(source,'unsafe { TOKEN = [0; 4] };','unsafe { TOKEN = [0; 4]; PREVIOUS_TOKEN = [0; 4]; };')
    (directory/'retained_input_worker.rs').write_text(source)
    c=(directory/'window_retained.c').read_text()
    c=replace(c,'static BOOL retained_call, retained_live;',
              'static BOOL retained_call, retained_live;\nstatic ULONG_PTR public_copy_calls;')
    c=replace(c,'    return EnclaveCopyOutOfEnclave(',
              '    public_copy_calls += 1; /* fixed bounded worker calls */\n    return EnclaveCopyOutOfEnclave(')
    c=replace(c,'(operation & 255) > 7','(operation & 255) > 9')
    c=replace(c,'    retained_operation = operation; retained_call = TRUE;',
              '    public_copy_calls = 0;\n    retained_operation = operation; retained_call = TRUE;')
    (directory/'window_retained.c').write_text(c)
    c=(directory/'window_retained_borrowed.c').read_text()
    c=replace(c,'static ULONG_PTR input_source, input_report[11];',
              'static ULONG_PTR input_source, input_report[11], rehash_report[8];')
    c=replace(c,'    input_source = (ULONG_PTR)context;',
              '    for (i = 0; i < 8; ++i) { rehash_report[i] = 0; }\n    input_source = (ULONG_PTR)context;')
    c+='''
int PublicRehashObserve(const ULONG_PTR* values) {
    SIZE_T i; ULONG_PTR address = (ULONG_PTR)values;
    if (!active || !retained_call || address < PublicLockedLow || address > PublicLockedHigh ||
        8 * sizeof(ULONG_PTR) > PublicLockedHigh - address) { return 0; }
    for (i = 0; i < 8; ++i) { rehash_report[i] = values[i]; }
    return 1;
}
__declspec(dllexport) void* CALLBACK PublicRehashControl(void* context) {
    ULONG_PTR op = (ULONG_PTR)context;
    if (active || retained_call || op < 16 || op > 24) { return 0; }
    return (void*)(op == 24 ? public_copy_calls : rehash_report[op - 16]);
}
'''
    (directory/'window_retained_borrowed.c').write_text(c)
    return commands


def compile(directory,target,testing=False,variant='normal'):
    commands=model.compile(directory,target,testing=testing,variant=variant)
    args=model.common(directory,target,'2',testing)
    for name in ('persistent_result','retained_placement'):
        args+=['--extern',name+'='+str(directory/('lib'+name+'_rehash.rlib'))]
    for name,source in [('retained_input','retained_input.rs'),('retained_borrowed','retained_borrowed_digest.rs')]:
        command=args+['--crate-name',name,'--crate-type','rlib',str(directory/source),'-o',str(directory/('lib'+name+'.rlib'))]
        if name=='retained_borrowed':command+=['--extern','retained_input='+str(directory/'libretained_input.rlib')]
        subprocess.run(command,check=True,capture_output=True,timeout=90);commands.append(command)
    command=args+['--crate-name','retained_rehash_worker','--extern','retained_input='+str(directory/'libretained_input.rlib'),
                  '--extern','retained_borrowed='+str(directory/'libretained_borrowed.rlib'),str(directory/'retained_input_worker.rs')]
    if testing:command+=['--test','-o',str(directory/(variant+'-test'))]
    else:command+=['--crate-type','staticlib','-C','lto=fat','--emit='+','.join(
        kind+'='+str(directory/(variant+'_rust.'+ext)) for kind,ext in [('link','lib'),('asm','s'),('llvm-ir','ll')])]
    subprocess.run(command,check=True,capture_output=True,timeout=120);commands.append(command)
    return commands


def build(directory):
    directory=directory.resolve();target='x86_64-pc-windows-msvc';commands=prepare(directory,target)
    for name in VARIANTS:commands+=compile(directory,target,variant=name)
    record={'native_executed':False,'strict_qualified':False,'commands':commands,
            'source_sha256':{p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in SOURCES},
            'rustc':subprocess.check_output(['rustc','+1.98.1','-vV'],text=True),
            'generated_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(directory.iterdir()) if p.suffix in ('.rs','.c','.h','.asm')},
            'archives':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(directory.glob('*_rust.lib'))}}
    (directory/'retained-rehash-worker-build.json').write_text(json.dumps(record,indent=2)+'\n')
    print('Retained composition worker cross-build: PASS; native qualification: NO')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('directory',type=Path)
    build(parser.parse_args().directory)
