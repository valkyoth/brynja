#!/usr/bin/env python3
"""Compile the actual baseline C gate, entry and copy adapter against OS doubles."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess

import windows_enclave_keccak_simd_image as image
SPEC=importlib.util.spec_from_file_location('prior_gate',Path(__file__).with_name('test-windows-enclave-sha2-batch-worker.py'))
prior=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(prior)

COPY_STUB=r'''
#define E_FAIL (-1)
typedef size_t SIZE_T;
static BOOL retained_live;
static ULONG_PTR retained_output,PublicLockedLow,PublicLockedHigh;
static unsigned input_calls,output_calls;
static int copy_failure;
static int EnclaveCopyIntoEnclave(void* dst,const void* src,SIZE_T size) {
    assert(dst && src && size); ++input_calls; return copy_failure;
}
static int EnclaveCopyOutOfEnclave(void* dst,const void* src,SIZE_T size) {
    assert(dst && src && size==1024); ++output_calls; return copy_failure;
}
'''
COPY_TEST=r'''
static void copy_reset(void) {
    active=retained_call=FALSE; retained_live=TRUE; retained_operation=100;
    PublicLockedLow=0x10000; PublicLockedHigh=0x20000; retained_output=0x30000;
    copy_failure=0; input_calls=output_calls=0;
    assert(PublicKeccakSimdInputSource((void*)0x40000)==(void*)1);
    active=retained_call=TRUE;
}
static int in(unsigned kind,size_t size) {
    return PublicKeccakSimdInput(kind,(unsigned char*)0x11000,0x40000,size);
}
int main(void) {
    /* Refer to the entry helper stub so warning-clean builds stay strict. */
    (void)EnclaveRestrictContainingProcessAccess; (void)PublicLockedWindow; (void)host_callback;
    reset(); assert(PublicKeccakSimdProtocol(0)==(void*)(uintptr_t)0x42524235);
    copy_reset(); assert(PublicKeccakSimdSource()==0x40000);
    assert(!PublicKeccakSimdInputSource(0)); assert(!PublicKeccakSimdControl((void*)16));
    assert(in(1,64)==E_FAIL); assert(!input_calls);
    assert(in(0,383)==E_FAIL); assert(in(0,385)==E_FAIL);
    assert(in(0,384)==S_OK); assert(in(0,384)==E_FAIL);
    assert(in(2,64)==S_OK); assert(simd_report[4]==1); assert(in(1,64)==E_FAIL);
    copy_reset(); assert(in(0,384)==S_OK);
    for(unsigned k=1;k<=12;++k) { assert(in(k,1025)==E_FAIL); assert(in(k,0)==E_FAIL);
        assert(in(k,64)==S_OK); assert(in(k,64)==E_FAIL); }
    assert(input_calls==13); assert(in(13,64)==E_FAIL);
    assert(PublicKeccakSimdOutput((void*)0x12000,1024)==E_FAIL);
    for(unsigned kind=0;kind<=12;++kind) {
        copy_reset(); for(unsigned k=0;k<kind;++k) assert(in(k,k?64:384)==S_OK);
        copy_failure=-2; assert(in(kind,kind?64:384)==-2);
        unsigned before=input_calls; copy_failure=0;
        assert(in(kind,kind?64:384)==E_FAIL); assert(input_calls==before);
    }
    copy_reset(); assert(in(0,384)==S_OK);
    assert(PublicKeccakSimdOutput((void*)0x12000,1024)==E_FAIL); assert(!output_calls);
    copy_reset(); retained_operation=101;
    assert(PublicKeccakSimdOutput((void*)0x12000,1024)==E_FAIL);
    assert(in(0,384)==S_OK); assert(in(1,64)==E_FAIL);
    assert(PublicKeccakSimdOutput((void*)0x12000,1023)==E_FAIL);
    assert(PublicKeccakSimdOutput((void*)0x12000,1024)==S_OK);
    assert(PublicKeccakSimdOutput((void*)0x12000,1024)==E_FAIL); assert(output_calls==1);
    copy_reset(); retained_operation=101; assert(in(0,384)==S_OK);
    copy_failure=-2; assert(PublicKeccakSimdOutput((void*)0x12000,1024)==-2);
    copy_failure=0; assert(PublicKeccakSimdOutput((void*)0x12000,1024)==E_FAIL);
    copy_reset();
    assert(PublicKeccakSimdInput(0,(void*)0xffff,0x40000,384)==E_FAIL);
    assert(PublicKeccakSimdInput(0,(void*)0x20000,0x40000,384)==E_FAIL);
    assert(PublicKeccakSimdInput(0,(void*)(uintptr_t)-1,0x40000,384)==E_FAIL);
    assert(PublicKeccakSimdInput(0,(void*)0x11000,0,384)==E_FAIL);
    active=FALSE; assert(in(0,384)==E_FAIL); assert(!PublicKeccakSimdObserve(1,2,1));
    active=TRUE; retained_call=FALSE; assert(in(0,384)==E_FAIL);
    return 0;
}
'''

def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def run(directory):
    directory.mkdir(parents=True,exist_ok=False)
    image.prepare(directory)
    header=directory/'keccak_simd_gate.h'; original=header.read_bytes()
    target=subprocess.check_output(['rustc','+1.98.1','-vV'],text=True).split('host: ')[1].splitlines()[0]
    windows=target.endswith('windows-msvc'); results=[]
    def adapted(text):
        return text.replace('sha2_batch_accelerated_gate.h','keccak_simd_gate.h').replace(
            'Sha2BatchAcceleratedReady','KeccakSimdReady').replace('accelerated_rejected','simd_rejected').replace(
            'PublicSha2BatchShaNiProtocol','PublicKeccakSimdProtocol').replace('0x42524232','0x42524235').replace(
            '{6,29},','').replace('80,81,82,83,84,85,86','100,101,102').replace('op>=80 && op<=86','op>=100 && op<=102')
    fixture=adapted(prior.C_STUB)
    def test(text,body,success):
        header.write_text(text)
        name='gate-'+str(len(results)); source=directory/(name+'.c')
        binary=directory/(name+('.exe' if windows else ''))
        source.write_text(body)
        command=(['cl','/nologo','/std:c11','/W4','/WX','/Fe'+str(binary),'/Fo'+str(directory/(name+'.obj')),str(source)]
                 if windows else ['cc','-std=c11','-Wall','-Wextra','-Werror',str(source),'-o',str(binary)])
        result=subprocess.run(command,capture_output=True,text=True,timeout=60)
        if result.returncode: raise RuntimeError(result.stdout+result.stderr)
        result=subprocess.run([str(binary)],capture_output=True,text=True,timeout=15)
        if (result.returncode==0)!=success: raise AssertionError(result.stdout+result.stderr)
        results.append(dict(command=command,expected_success=success,exit_code=result.returncode,
            output=result.stdout+result.stderr,binary=binary.name,binary_sha256=digest(binary),source_sha256=digest(source)))
    try:
        text=original.decode(); test(text,fixture,True)
        for before in prior.C_MUTANTS:
            if '1U << 29' in before: continue
            before=adapted(before)
            assert text.count(before)==1,before
            test(text.replace(before,';' if before.endswith(';') else '0'),fixture,False)
        retained=(directory/'window_retained.c').read_text()
        entry=retained[retained.index('__declspec(dllexport) void* CALLBACK PublicRetained(void* context)'):]
        entry=entry[:entry.index('__declspec(dllexport) void* CALLBACK PublicRetainedControl')]
        adapter=(directory/'window_keccak_simd.c').read_text()
        protocol=adapter[adapter.index('__declspec(dllexport) void* CALLBACK PublicKeccakSimdProtocol'):]
        prefix=fixture[:fixture.index('static void rejected(void)')]+prior.ENTRY_STUB
        body=prefix+entry+protocol+adapted(prior.ENTRY_TEST)
        test(text,body,True)
        for before,after in (
            (' || !KeccakSimdReady()', ''),
            ('!(operation == 0 || operation == 3 || (operation >= 100 && operation <= 102))','0'),
            ('active || retained_call || !host_callback','0'),('!= S_OK','== 999'),
        ):
            assert entry.count(before)==1,before
            test(text,prefix+entry.replace(before,after)+protocol+adapted(prior.ENTRY_TEST),False)
        copy_body=prefix+COPY_STUB+adapter[adapter.index('static ULONG_PTR simd_source'):]+COPY_TEST
        test(text,copy_body,True)
        for before,after in (('kind > 12','kind > 99'),('kind <= simd_last_kind','0'),
            ('|| simd_report[6]', '|| 0'),('retained_operation != 101','0'),('size != 1024','0'), ('simd_last_kind=0;',';'), ('++simd_report[4];','simd_report[4]=kind;')):
            assert before in adapter,before
            changed=adapter[adapter.index('static ULONG_PTR simd_source'):].replace(before,after)
            test(text,prefix+COPY_STUB+changed+COPY_TEST,False)
        test(text,copy_body,True)
    finally: header.write_bytes(original)
    paths=[image.SOURCE/name for name in image.FILES]+[Path(__file__).resolve(),Path(image.__file__),Path(prior.__file__)]
    result=dict(status='SIMD_BASELINE_C_DOUBLES_PASS',target=target,enclave_execution=False,
        mutations_rejected=sum(not r['expected_success'] for r in results),results=results,
        source_sha256={p.relative_to(image.ROOT).as_posix():digest(p) for p in paths})
    (directory/'keccak-simd-gate-results.json').write_text(json.dumps(result,indent=2)+'\n')
    print('SIMD baseline C admission/entry/copy checks PASS; mutants='+str(result['mutations_rejected']))

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument('directory',type=Path)
    run(parser.parse_args().directory.resolve())
