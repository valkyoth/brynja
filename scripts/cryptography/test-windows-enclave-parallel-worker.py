#!/usr/bin/env python3
"""Private worker failure tests; ordinary processes, not enclave qualification."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

import windows_enclave_parallel_accelerated_worker_build as build

MUTANTS = (
    ('PublicParallelInput(0, buffers.header.as_mut_ptr(), source, 128) } != 0',
     'PublicParallelInput(0, buffers.header.as_mut_ptr(), source, 128) } == 99'),
    ('PublicParallelInput(1, input.as_mut_ptr(), request.source(), request.length()) }\n            != 0',
     'PublicParallelInput(1, input.as_mut_ptr(), request.source(), request.length()) }\n            == 99'),
    ('PublicParallelOutput(bytes.as_ptr(), bytes.len()) == 0',
     'PublicParallelOutput(bytes.as_ptr(), bytes.len()) != 99'),
    ('if !ok {\n        owner.quarantine();\n    }', 'if !ok {}'),
    ('buffers.clear();', ''),
    ('PublicParallelObserve(header, payload, usize::from(cleared)) } != 1',
     'PublicParallelObserve(header, payload, usize::from(cleared)) } == 99'),
    ('if *identity != address {', 'if false && *identity != address {'),
    ('high.checked_sub(low) != Some(65536)', 'false'),
    ('owner.quarantine();\n            return 201;', 'return 201;'),
)

C_STUB = r'''
#include <stdint.h>
#include <stddef.h>
#include <assert.h>
typedef uintptr_t ULONG_PTR;
typedef int BOOL;
#define TRUE 1
#define FALSE 0
#define INVALID_QUERY (~(ULONG_PTR)0)
static ULONG_PTR inventory[11];
static unsigned queries;
static void* PublicCpuInventory(void* context) {
    ++queries; return (void*)inventory[(uintptr_t)context];
}
#include "parallel_accelerated_gate.h"
static void reset(void) {
    const ULONG_PTR values[11]={0x42525943,1,15,7,1U<<26,0x1c000000U,(1U<<5),1,1,6,0};
    for (unsigned i=0;i<11;++i) inventory[i]=values[i];
    accelerated_rejected=FALSE; queries=0;
}
static void rejected(void) {
    assert(!ParallelAcceleratedReady());
    unsigned before=queries;
    /* Restoring the advertised bundle must not clear terminal rejection. */
    const ULONG_PTR values[11]={0x42525943,1,15,7,1U<<26,0x1c000000U,(1U<<5),1,1,6,0};
    for (unsigned i=0;i<11;++i) inventory[i]=values[i];
    assert(!ParallelAcceleratedReady()); assert(queries==before);
}
int main(void) {
    reset(); assert(ParallelAcceleratedReady()); assert(queries==11);
    assert(ParallelAcceleratedReady()); assert(queries==22);
    for(unsigned i=0;i<11;++i) { reset(); inventory[i]=INVALID_QUERY; rejected(); }
    const unsigned bits[][2]={{2,0},{2,1},{2,2},{2,3},{4,26},{5,26},{5,27},{5,28},{6,5},{9,1},{9,2}};
    for(unsigned i=0;i<sizeof(bits)/sizeof(bits[0]);++i) {
        reset(); inventory[bits[i][0]]&=~((ULONG_PTR)1<<bits[i][1]); rejected();
    }
    reset(); inventory[0]=0; rejected();
    reset(); inventory[1]=2; rejected();
    reset(); inventory[2]=31; rejected();
    reset(); inventory[3]=6; rejected();
    reset(); assert(ParallelAcceleratedReady()); inventory[6]=0; rejected();
    return 0;
}
'''
C_MUTANTS = ('words[i] == INVALID_QUERY', 'words[0] != 0x42525943',
             'words[1] != 1', 'words[2] != 15', 'words[3] < 7',
             '!(words[4] & (1U << 26))',
             '(words[5] & 0x1c000000U) != 0x1c000000U',
             '!(words[6] & (1U << 5))',
             '(words[9] & 6) != 6', 'accelerated_rejected = TRUE;')

ENTRY_STUB = r'''
#define __declspec(x)
#define CALLBACK
#define __try if (1)
#define __finally if (1)
#define S_OK 0
static BOOL active,retained_call;
static ULONG_PTR host_callback,retained_operation;
static unsigned windows;
static int restrict_result;
static int EnclaveRestrictContainingProcessAccess(BOOL value,void* unused) {
    assert(value && !unused); return restrict_result;
}
static void* PublicLockedWindow(ULONG_PTR op) {
    assert(!op && queries==11 && retained_call); ++windows; return (void*)42;
}
'''
ENTRY_TEST = r'''
static void entry_reset(void) {
    reset(); active=retained_call=FALSE; host_callback=1; windows=0; restrict_result=0;
}
int main(void) {
    (void)ParallelAcceleratedReady;
    entry_reset(); assert(PublicParallelAvx2Protocol(0)==(void*)(uintptr_t)0x42525032); assert(!windows);
    entry_reset(); assert(!PublicParallelAvx2Protocol((void*)1)); assert(!windows && !queries);
    entry_reset(); active=TRUE; assert(!PublicParallelAvx2Protocol(0)); assert(!windows);
    entry_reset(); retained_call=TRUE; assert(!PublicParallelAvx2Protocol(0)); assert(!windows);
    entry_reset(); inventory[6]=0; assert(!PublicParallelAvx2Protocol(0)); assert(!windows);
    const unsigned accepted[]={0,3,100,101,102,103,104,105,106,107,108};
    for(unsigned i=0;i<sizeof(accepted)/sizeof(accepted[0]);++i) {
        entry_reset(); assert(PublicRetained((void*)(uintptr_t)accepted[i])==(void*)42);
        assert(windows==1 && !retained_call && retained_operation==accepted[i]);
    }
    for(unsigned op=0;op<120;++op) {
        if(op==0 || op==3 || (op>=100 && op<=108)) continue;
        entry_reset(); assert(!PublicRetained((void*)(uintptr_t)op)); assert(!windows);
    }
    entry_reset(); active=TRUE; assert(!PublicRetained(0)); assert(!windows);
    entry_reset(); retained_call=TRUE; assert(!PublicRetained(0)); assert(!windows);
    entry_reset(); host_callback=0; assert(!PublicRetained(0)); assert(!windows);
    entry_reset(); restrict_result=-1; assert(!PublicRetained(0)); assert(!windows);
    entry_reset(); inventory[6]=0; assert(!PublicRetained(0)); assert(!windows);
    return 0;
}
'''


def checked(command, directory=None):
    result=subprocess.run(command,cwd=directory,capture_output=True,text=True,timeout=180)
    if result.returncode:raise RuntimeError(result.stdout+result.stderr)
    return result.stdout


def c_gate(directory,target):
    source=directory/'parallel_accelerated_gate.h'
    original_bytes=source.read_bytes()
    original=source.read_text()
    windows=target.endswith('windows-msvc')
    binary=directory/('gate-test.exe' if windows else 'gate-test')
    command=(['cl','/nologo','/std:c11','/W4','/WX','/Fegate-test.exe','gate-test.c'] if windows else
             ['cc','-std=c11','-Wall','-Wextra','-Werror','gate-test.c','-o',str(binary)])
    def test(text,success,fixture=C_STUB):
        source.write_text(text)
        (directory/'gate-test.c').write_text(fixture)
        checked(command,directory)
        result=subprocess.run([str(binary)],capture_output=True,text=True,timeout=10)
        if (result.returncode==0)!=success:raise AssertionError(result.stdout+result.stderr)
    try:
        test(original,True)
        for before in C_MUTANTS:
            if original.count(before)!=1:raise AssertionError('Stale C mutation: '+before)
            test(original.replace(before,';' if before.endswith(';') else '0'),False)
        test(original,True)
        # Compile the actual generated PublicRetained entry, not a copied model.
        retained=(directory/'window_retained.c').read_text()
        start=retained.index('__declspec(dllexport) void* CALLBACK PublicRetained(void* context)')
        end=retained.index('__declspec(dllexport) void* CALLBACK PublicRetainedControl',start)
        entry=retained[start:end]
        wrapper=(build.SOURCE/'window_parallel_accelerated.c').read_text()
        protocol=wrapper[wrapper.index('__declspec(dllexport) void* CALLBACK PublicParallelAvx2Protocol'):]
        prefix=C_STUB[:C_STUB.index('static void rejected(void)')]+ENTRY_STUB
        test(original,True,prefix+entry+protocol+ENTRY_TEST)
        for before,after in (
            (' || !ParallelAcceleratedReady()', ''),
            ('!(operation == 0 || operation == 3 || (operation >= 100 && operation <= 108))', '0'),
            ('active || retained_call || !host_callback', '0'),
            ('!= S_OK', '== 999'),
        ):
            if entry.count(before)!=1:raise AssertionError('Stale entry mutation: '+before)
            test(original,False,prefix+entry.replace(before,after)+protocol+ENTRY_TEST)
        for before,after in (
            ('context || ', '(context && 0) || '), ('active || retained_call || ', ''),
            ('!ParallelAcceleratedReady()', '0'), ('0x42525032','0x42525430'),
        ):
            if protocol.count(before)!=1:raise AssertionError('Stale protocol mutation: '+before)
            test(original,False,prefix+entry+protocol.replace(before,after)+ENTRY_TEST)
        test(original,True,prefix+entry+protocol+ENTRY_TEST)
    finally:source.write_bytes(original_bytes)
    return len(C_MUTANTS)+8


def run(directory,target,image=False):
    build.build(directory,target,image)
    command=build.command(directory,target,True)
    binary=directory/'parallel-worker-test'
    def execute(success):
        result=subprocess.run([str(binary)],capture_output=True,text=True,timeout=120)
        output=result.stdout+result.stderr
        if (result.returncode==0)!=success:raise AssertionError(output)
        if success and '1 passed; 0 failed' not in output:raise AssertionError(output)
        if not success and not any(token in output for token in ('FAILED','assertion','panicked')):
            raise AssertionError('Mutant failed without expected test diagnostic: '+output)
        return output
    initial=execute(True)
    path=directory/'parallel_accelerated_worker.rs';original=path.read_text()
    original_bytes=path.read_bytes()
    mutations=[]
    try:
        for before,after in MUTANTS:
            print('WORKER_MUTATION: '+before,flush=True)
            if original.count(before)!=1:raise AssertionError('Stale worker mutation: '+before)
            path.write_text(original.replace(before,after))
            checked(command+['-A','unused_variables'])
            mutations.append(dict(before=before,after=after,output=execute(False)))
    finally:path.write_bytes(original_bytes)
    checked(command)
    final=execute(True)
    gate_mutations=c_gate(directory,target)
    generated=json.loads((directory/'parallel-worker-build.json').read_text())['generated_sha256']
    for name,digest in generated.items():
        if hashlib.sha256((directory/name).read_bytes()).hexdigest()!=digest:
            raise AssertionError('Mutation test failed to restore exact artifact bytes: '+name)
    record=dict(schema=1,status='WORKER_COMPONENT_TESTS_PASS',enclave_execution=False,
                production_qualified=False,target=target,initial=initial,final=final,
                mutations=mutations,c_gate_mutations=gate_mutations,
                build_sha256=hashlib.sha256((directory/'parallel-worker-build.json').read_bytes()).hexdigest(),
                binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest())
    (directory/'parallel-worker-results.json').write_text(json.dumps(record,indent=2)+'\n')
    print(final,flush=True)
    print(f'Private AVX2 worker: {len(mutations)} compiled mutants and {gate_mutations} baseline C gate mutants rejected',flush=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory',type=Path)
    parser.add_argument('--attest-native-bundle',action='store_true',required=True)
    parser.add_argument('--image',action='store_true')
    args=parser.parse_args()
    target=subprocess.check_output(['rustc','+1.98.1','-vV'],text=True).split('host: ')[1].splitlines()[0]
    if not target.startswith('x86_64-'):parser.error('Native x86-64 AVX/AVX2 required')
    run(args.directory.resolve(),target,args.image)
