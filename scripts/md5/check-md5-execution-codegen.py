#!/usr/bin/env python3
"""Emitted operational call-chain checks; not side-channel/cleanup approval."""
import os
import re
import subprocess
import tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]

def functions(text):
    result={}
    for match in re.finditer(r'^([_A-Za-z][_A-Za-z0-9.$]*):\n(.*?)^\s*\.size\s+\1\s*,',text,re.M|re.S):
        result[match[1]]=match[2]
    return result

def exact(all_functions,tokens):
    found=[(name,body) for name,body in all_functions.items() if all(t in name for t in tokens)]
    if len(found)!=1: raise ValueError('missing/ambiguous operational function: '+repr(tokens))
    return found[0]

def check(text,target):
    bodies=functions(text)
    kernel,kbody=exact(bodies,('Md5BackendSession','compress'))
    vector,vbody=exact(bodies,('batch','vector','execute'))
    _,digest=exact(bodies,('Executor','digest'))
    _,startup=exact(bodies,('Md5BackendSession','initialize'))
    for caller,callee in ((digest,vector),(vbody,kernel),(startup,kernel)):
        if not re.search(r'^\s*(?:callq?|jmpq?|bl|b)\s+[^\n]*'+re.escape(callee),caller,re.M):
            raise ValueError('operational startup/digest SIMD call chain lost')
    instructions=('vpaddd','vpsllvd','vpsrlvd') if target.startswith('x86_64') else ('add','ushl')
    for instruction in instructions:
        pattern=r'^\s*'+instruction+r'\s+[^\n]*(?:%ymm|v\d+\.4[si])'
        if not re.search(pattern,kbody,re.M):
            raise ValueError('operational session omitted vector instruction: '+instruction)

def main():
    with tempfile.TemporaryDirectory(prefix='brynja-md5-operational-codegen-') as directory:
        for compiler in ('1.90.0','1.98.1'):
            for target,features in (('x86_64-unknown-linux-gnu','+avx2'),('aarch64-unknown-linux-gnu','+neon')):
                output=Path(directory)/(compiler+'-'+target)
                env=dict(os.environ)
                for name in ('CARGO_ENCODED_RUSTFLAGS','RUSTDOCFLAGS','CARGO_BUILD_TARGET'): env.pop(name,None)
                env.update(CARGO_TARGET_DIR=str(output),RUSTFLAGS='-C target-feature='+features)
                subprocess.run(['cargo','+'+compiler,'rustc','--locked','--offline','--release',
                    '-p','brynja-legacy-md5','--features','execution','--target',target,'--lib','--','--emit=asm'],
                    cwd=ROOT,env=env,check=True,timeout=180)
                files=list((output/target/'release/deps').glob('brynja_legacy_md5*.s'))
                if len(files)!=1: raise ValueError('ambiguous MD5 assembly artifact')
                text=files[0].read_text(); check(text,target)
                # Alter the artifact, not the implementation: both a missing
                # real call and scalarized session body must fail this checker.
                for changed in (re.sub(r'^\s*(?:callq?|bl)\s+[^\n]*Md5BackendSession[^\n]*compress[^\n]*','',text,flags=re.M),
                                re.sub(r'\b(?:vpaddd|vpsllvd|vpsrlvd|ushl)\b','omitted',text)):
                    try: check(changed,target)
                    except ValueError: pass
                    else: raise AssertionError('operational codegen mutation escaped')
                print(f'MD5 ordinary startup/digest -> vector -> SIMD session: PASS; {compiler}; {target}')

if __name__=='__main__': main()
