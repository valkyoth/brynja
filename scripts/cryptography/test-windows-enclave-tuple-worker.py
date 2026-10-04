#!/usr/bin/env python3
"""Private worker failure tests; ordinary processes, not enclave qualification."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

import windows_enclave_tuple_accelerated_worker_build as build

MUTANTS = (
    ('PublicTupleInput(0, buffers.header.as_mut_ptr(), source, 112) } != 0',
     'PublicTupleInput(0, buffers.header.as_mut_ptr(), source, 112) } == 99'),
    ('PublicTupleInput(1, input.as_mut_ptr(), request.source(), request.length()) }\n            != 0',
     'PublicTupleInput(1, input.as_mut_ptr(), request.source(), request.length()) }\n            == 99'),
    ('PublicTupleOutput(bytes.as_ptr(), bytes.len()) == 0',
     'PublicTupleOutput(bytes.as_ptr(), bytes.len()) != 99'),
    ('if !ok {\n        owner.quarantine();\n    }', 'if !ok {}'),
    ('buffers.clear();', ''),
    ('PublicTupleObserve(header, payload, usize::from(cleared)) } != 1',
     'PublicTupleObserve(header, payload, usize::from(cleared)) } == 99'),
    ('if *identity != address {', 'if false && *identity != address {'),
    ('high.checked_sub(low) != Some(65536)', 'false'),
    ('owner.quarantine();\n            return 201;', 'return 201;'),
)

C_STUB = r'''
#include <stdint.h>
#include <stddef.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
/* Test-only assertions: retain checks without CRT abort/WER latency or dialogs. */
#undef assert
#define assert(condition) do { if (!(condition)) { \
    fputs("BRYNJA_GATE_ASSERTION: " #condition "\n", stderr); exit(97); \
} } while (0)
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
#include "tuple_accelerated_gate.h"
static void reset(void) {
    const ULONG_PTR values[11]={0x42525943,1,15,7,1U<<26,0x1c000000U,(1U<<5),1,1,6,0};
    for (unsigned i=0;i<11;++i) inventory[i]=values[i];
    accelerated_rejected=FALSE; queries=0;
}
static void rejected(void) {
    assert(!TupleAcceleratedReady());
    unsigned before=queries;
    /* Restoring the advertised bundle must not clear terminal rejection. */
    const ULONG_PTR values[11]={0x42525943,1,15,7,1U<<26,0x1c000000U,(1U<<5),1,1,6,0};
    for (unsigned i=0;i<11;++i) inventory[i]=values[i];
    assert(!TupleAcceleratedReady()); assert(queries==before);
}
int main(void) {
    reset(); assert(TupleAcceleratedReady()); assert(queries==11);
    assert(TupleAcceleratedReady()); assert(queries==22);
    for(unsigned i=0;i<11;++i) { reset(); inventory[i]=INVALID_QUERY; rejected(); }
    const unsigned bits[][2]={{2,0},{2,1},{2,2},{2,3},{4,26},{5,26},{5,27},{5,28},{6,5},{9,1},{9,2}};
    for(unsigned i=0;i<sizeof(bits)/sizeof(bits[0]);++i) {
        reset(); inventory[bits[i][0]]&=~((ULONG_PTR)1<<bits[i][1]); rejected();
    }
    reset(); inventory[0]=0; rejected();
    reset(); inventory[1]=2; rejected();
    reset(); inventory[2]=31; rejected();
    reset(); inventory[3]=6; rejected();
    reset(); assert(TupleAcceleratedReady()); inventory[6]=0; rejected();
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
    (void)TupleAcceleratedReady;
    entry_reset(); assert(PublicTupleAvx2Protocol(0)==(void*)(uintptr_t)0x42525432); assert(!windows);
    entry_reset(); assert(!PublicTupleAvx2Protocol((void*)1)); assert(!windows && !queries);
    entry_reset(); active=TRUE; assert(!PublicTupleAvx2Protocol(0)); assert(!windows);
    entry_reset(); retained_call=TRUE; assert(!PublicTupleAvx2Protocol(0)); assert(!windows);
    entry_reset(); inventory[6]=0; assert(!PublicTupleAvx2Protocol(0)); assert(!windows);
    const unsigned accepted[]={0,3,60,61,62,63,64,65,66,67,68,69,70};
    for(unsigned i=0;i<sizeof(accepted)/sizeof(accepted[0]);++i) {
        entry_reset(); assert(PublicRetained((void*)(uintptr_t)accepted[i])==(void*)42);
        assert(windows==1 && !retained_call && retained_operation==accepted[i]);
    }
    for(unsigned op=0;op<80;++op) {
        if(op==0 || op==3 || (op>=60 && op<=70)) continue;
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


def validate_gate_result(result, success):
    output=result.stdout+result.stderr
    marker='BRYNJA_GATE_ASSERTION: '
    if success:
        valid=result.returncode==0 and marker not in output
    else:
        valid=result.returncode==97 and any(line.startswith(marker) for line in result.stderr.splitlines())
    if not valid:raise AssertionError(f'Unexpected C gate outcome ({result.returncode}): '+output)


def check_gate_result_validation():
    # A crash, timeout, missing diagnostic or unexpected success is not proof
    # that a compiled mutant reached a failing assertion.
    for code,out,err,success,accepted in (
        (0,'','',True,True), (97,'','BRYNJA_GATE_ASSERTION: sentinel\n',False,True),
        (0,'','',False,False), (97,'','',False,False),
        (1,'','BRYNJA_GATE_ASSERTION: sentinel\n',False,False),
        (-1073740791,'','',False,False), (97,'BRYNJA_GATE_ASSERTION: sentinel\n','',False,False),
        (0,'','BRYNJA_GATE_ASSERTION: sentinel\n',True,False),
    ):
        rejected=False
        try:validate_gate_result(subprocess.CompletedProcess([],code,out,err),success)
        except AssertionError:rejected=True
        if rejected==accepted:raise AssertionError('C gate validator regression')


def gate_invocation(directory,target,index):
    if type(index) is not int or index<0:raise ValueError('Nonnegative C gate index required')
    windows=target.endswith('windows-msvc')
    name=f'gate-test-{index:03}'
    binary=directory/(name+('.exe' if windows else ''))
    command=(['cl','/nologo','/std:c11','/W4','/WX','/Fe'+binary.name,
              '/Fo'+name+'.obj','gate-test.c'] if windows else
             ['cc','-std=c11','-Wall','-Wextra','-Werror','gate-test.c','-o',str(binary)])
    return binary,command


def check_gate_invocations():
    # Never relink over an executable just run: Windows observers may still
    # hold its file open after process exit. Preserve each compiled control.
    for target in ('x86_64-pc-windows-msvc','x86_64-unknown-linux-gnu'):
        products=[gate_invocation(Path('fixture'),target,index) for index in range(3)]
        if len({binary for binary,_ in products})!=3:raise AssertionError('Reused C gate executable')
        for index,(binary,command) in enumerate(products):
            if target.endswith('windows-msvc'):
                assert '/Fe'+binary.name in command and f'/Fogate-test-{index:03}.obj' in command
            else:assert command[-2:]==['-o',str(binary)]
    for invalid in (-1,True,'1'):
        try:gate_invocation(Path('fixture'),'x86_64-pc-windows-msvc',invalid)
        except ValueError:continue
        raise AssertionError('Invalid C gate index accepted')


def worker_invocation(command,binary):
    if command.count('-o')!=1 or command.index('-o')+1>=len(command):
        raise ValueError('Exactly one worker output required')
    copied=list(command)
    copied[copied.index('-o')+1]=str(binary)
    return copied


def check_worker_invocations():
    original=['rustc','--test','worker.rs','-o','initial']
    for name in ('mutant-000','mutant-001','restored'):
        result=worker_invocation(original,Path(name))
        assert result==['rustc','--test','worker.rs','-o',name] and original[-1]=='initial'
    for malformed in ([],['rustc','-o'],['rustc','-o','a','-o','b']):
        try:worker_invocation(malformed,Path('output'))
        except ValueError:continue
        raise AssertionError('Malformed worker output accepted')


def c_gate(directory,target):
    source=directory/'tuple_accelerated_gate.h'
    original_bytes=source.read_bytes()
    original=source.read_text()
    index=0; records=[]
    def test(text,success,fixture=C_STUB):
        nonlocal index
        binary,command=gate_invocation(directory,target,index)
        index+=1
        source.write_text(text)
        (directory/'gate-test.c').write_text(fixture)
        checked(command,directory)
        result=subprocess.run([str(binary)],capture_output=True,text=True,timeout=10)
        validate_gate_result(result,success)
        records.append(dict(binary=binary.name,command=command,expected_success=success,
            exit_code=result.returncode,stdout=result.stdout,stderr=result.stderr,
            binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
            fixture_sha256=hashlib.sha256((directory/'gate-test.c').read_bytes()).hexdigest(),
            gate_sha256=hashlib.sha256(source.read_bytes()).hexdigest()))
    try:
        # Compile both outcomes of the SAME assertion macro used by the real
        # generated gate/entry fixtures, including under NDEBUG.
        assertion=C_STUB[:C_STUB.index('typedef uintptr_t')]
        test(original,True,'#define NDEBUG\n'+assertion+'int main(void) { assert(1); return 0; }\n')
        test(original,False,'#define NDEBUG\n'+assertion+'int main(void) { assert(0); return 0; }\n')
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
        wrapper=(build.SOURCE/'window_tuple_accelerated.c').read_text()
        protocol=wrapper[wrapper.index('__declspec(dllexport) void* CALLBACK PublicTupleAvx2Protocol'):]
        prefix=C_STUB[:C_STUB.index('static void rejected(void)')]+ENTRY_STUB
        test(original,True,prefix+entry+protocol+ENTRY_TEST)
        for before,after in (
            (' || !TupleAcceleratedReady()', ''),
            ('!(operation == 0 || operation == 3 || (operation >= 60 && operation <= 70))', '0'),
            ('active || retained_call || !host_callback', '0'),
            ('!= S_OK', '== 999'),
        ):
            if entry.count(before)!=1:raise AssertionError('Stale entry mutation: '+before)
            test(original,False,prefix+entry.replace(before,after)+protocol+ENTRY_TEST)
        for before,after in (
            ('context || ', '(context && 0) || '), ('active || retained_call || ', ''),
            ('!TupleAcceleratedReady()', '0'), ('0x42525432','0x42525430'),
        ):
            if protocol.count(before)!=1:raise AssertionError('Stale protocol mutation: '+before)
            test(original,False,prefix+entry+protocol.replace(before,after)+ENTRY_TEST)
        test(original,True,prefix+entry+protocol+ENTRY_TEST)
    finally:source.write_bytes(original_bytes)
    (directory/'tuple-c-gate-results.json').write_text(json.dumps(dict(
        schema=1,status='COMPILED_GATE_ASSERTIONS_PASS',cases=records,
        production_code_changed=False),indent=2)+'\n')
    return len(C_MUTANTS)+8


def run(directory,target,image=False):
    check_gate_result_validation()
    check_gate_invocations()
    check_worker_invocations()
    build.build(directory,target,image)
    command=build.command(directory,target,True)
    binary=directory/'tuple-worker-test'
    def execute(success):
        result=subprocess.run([str(binary)],capture_output=True,text=True,timeout=120)
        output=result.stdout+result.stderr
        if (result.returncode==0)!=success:raise AssertionError(output)
        if success and '1 passed; 0 failed' not in output:raise AssertionError(output)
        if not success and not any(token in output for token in ('FAILED','assertion','panicked')):
            raise AssertionError('Mutant failed without expected test diagnostic: '+output)
        return output
    initial=execute(True)
    path=directory/'tuple_accelerated_worker.rs';original=path.read_text()
    original_bytes=path.read_bytes()
    mutations=[]
    try:
        for index,(before,after) in enumerate(MUTANTS):
            print('WORKER_MUTATION: '+before,flush=True)
            if original.count(before)!=1:raise AssertionError('Stale worker mutation: '+before)
            path.write_text(original.replace(before,after))
            binary=directory/f'tuple-worker-mutant-{index:03}'
            checked(worker_invocation(command,binary)+['-A','unused_variables'])
            mutations.append(dict(before=before,after=after,output=execute(False),
                binary=binary.name,binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest()))
    finally:path.write_bytes(original_bytes)
    binary=directory/'tuple-worker-restored-test'
    checked(worker_invocation(command,binary))
    final=execute(True)
    gate_mutations=c_gate(directory,target)
    generated=json.loads((directory/'tuple-worker-build.json').read_text())['generated_sha256']
    for name,digest in generated.items():
        if hashlib.sha256((directory/name).read_bytes()).hexdigest()!=digest:
            raise AssertionError('Mutation test failed to restore exact artifact bytes: '+name)
    record=dict(schema=1,status='WORKER_COMPONENT_TESTS_PASS',enclave_execution=False,
                production_qualified=False,target=target,initial=initial,final=final,
                mutations=mutations,c_gate_mutations=gate_mutations,
                build_sha256=hashlib.sha256((directory/'tuple-worker-build.json').read_bytes()).hexdigest(),
                binary=binary.name,binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest())
    (directory/'tuple-worker-results.json').write_text(json.dumps(record,indent=2)+'\n')
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
