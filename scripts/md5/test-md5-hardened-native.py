#!/usr/bin/env python3
"""Reject corrupted/missing native assertions; synthetic records are tests only."""
import copy
import md5_hardened_native as evidence
import md5_hardened_policy as policy

def main():
    sources=policy.snapshot()
    commit='a'*40
    count=0
    for lane,kernel in evidence.LANES.items():
        target='aarch64-apple-darwin' if lane=='apple-m2-aarch64' else ('x86_64-unknown-linux-gnu' if 'x86_64' in lane else 'aarch64-unknown-linux-gnu')
        width='8' if 'x86_64' in lane else '4'
        def complete(n): return f'test result: ok. {n} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s'
        record=dict(schema=1,version='0.24.44',lane=lane,commit=commit,
            compiler=f'release: 1.98.1\nhost: {target}',
            cpu={'amd-x86_64':'AuthenticAMD','intel-x86_64':'GenuineIntel','apple-m2-aarch64':'Apple M2 Pro',
                 'aws-aarch64':'operator-labelled AWS Arm; provider identity not authenticated'}[lane],
            system='Darwin' if lane=='apple-m2-aarch64' else 'Linux',
            features='+avx2' if width=='8' else '+neon',source_sha256=sources,
            native='operator-self-attested',profile='hardened-source-owned',independent_review=False,fips_validated=False,
            results={'portable':complete(5),
                     'static':complete(5)+'\nMD5_HARDENED: '+kernel+'; cases=2048; actual SIMD',
                     'hosted':complete(1)+'\nMD5_HOSTED_HARDENED: '+('None' if width=='8' else 'Some(Aarch64Neon)'),
                     'packaged':'Packaged hardened MD5: 19 ownership/classification negatives; 4 compiled algorithm/health mutants rejected\nPackaged hardened MD5 cleanup: 5 compiled whole-region/Drop mutants rejected\nmode=require; width='+width,
                     'codegen':'\n'.join('MD5 hardened MIR/LLVM/SIMD assembly: PASS; 1.98.1; '+target+'; panic='+p for p in ('abort','unwind'))})
        evidence.record_check(record,lane,commit,sources)
        mutants=[]
        for key in record:
            changed=copy.deepcopy(record); del changed[key]; mutants.append(changed)
            changed=copy.deepcopy(record); changed[key]=None; mutants.append(changed)
        for key in record['results']:
            changed=copy.deepcopy(record); changed['results'][key]=''; mutants.append(changed)
            changed=copy.deepcopy(record); del changed['results'][key]; mutants.append(changed)
        for key in ('portable','static','hosted'):
            for old,new in (('0 failed','1 failed'),('0 ignored','1 ignored'),('0 filtered out','1 filtered out')):
                changed=copy.deepcopy(record); changed['results'][key]=changed['results'][key].replace(old,new); mutants.append(changed)
        changed=copy.deepcopy(record); changed['schema']=True; mutants.append(changed)
        changed=copy.deepcopy(record); changed['source_sha256']={}; mutants.append(changed)
        for changed in mutants:
            try: evidence.record_check(changed,lane,commit,sources)
            except (ValueError,KeyError,TypeError): count+=1
            else: raise AssertionError('native evidence corruption accepted')
    print(f'Hardened MD5 native evidence rejects {count} schema, result, route, compiler and source mutations')

if __name__=='__main__': main()
