#!/usr/bin/env python3
"""Tamper tests use synthetic records; they do not create release evidence."""
import copy
import md5_execution_native as evidence

def record(lane):
    x86='x86_64' in lane
    apple=lane=='apple-m2-aarch64'
    target='aarch64-apple-darwin' if apple else ('x86_64-unknown-linux-gnu' if x86 else 'aarch64-unknown-linux-gnu')
    cpu={'amd-x86_64':'AuthenticAMD','intel-x86_64':'GenuineIntel','apple-m2-aarch64':'Apple M2 Pro','aws-aarch64':'operator-labelled AWS Arm; provider identity not authenticated'}[lane]
    return dict(schema=1,version='0.24.44',lane=lane,commit='a'*40,
        compiler='release: 1.98.1\nhost: '+target,cpu=cpu,system='Darwin' if apple else 'Linux',
        features='+avx2' if x86 else '+neon',source_sha256={'test':'b'*64},
        native='operator-self-attested',profile='ordinary-public-only',independent_review=False,fips_validated=False,
        results=dict(portable='test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.1s',
            hosted='test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.1s\nMD5_HOSTED_OPERATIONAL: '+('None' if x86 else 'Some(Aarch64Neon)'),
            static='test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.1s\nMD5_OPERATIONAL: '+evidence.LANES[lane]+'; cases=2048; normal-build SIMD',
            packaged='Packaged MD5 operational: 13 ownership/classification negatives; 6 compiled output/report mutants rejected\nmode=require; width='+('8' if x86 else '4')))

def main():
    count=0
    for lane in evidence.LANES:
        good=record(lane)
        check=lambda value: evidence.record_check(value,lane,'a'*40,{'test':'b'*64})
        check(good)
        mutants=[]
        for name in good:
            value=copy.deepcopy(good); del value[name]; mutants.append(value)
        for name,wrong in (('schema',True),('version','0.24.22'),('commit','c'*40),('lane','unknown'),
            ('compiler','release: 1.98.1\nhost: wasm32-unknown-unknown'),('cpu','unknown'),
            ('system','unknown'),('features',''),('source_sha256',{}),('native','qemu'),
            ('profile','hardened'),('independent_review',True),('fips_validated',True)):
            value=copy.deepcopy(good); value[name]=wrong; mutants.append(value)
        for name in good['results']:
            value=copy.deepcopy(good); value['results'][name]=''; mutants.append(value)
        value=copy.deepcopy(good); value['compiler']=value['compiler'].replace('1.98.1','1.98.10'); mutants.append(value)
        for old,new in (('3 passed','13 passed'),('0 ignored','1 ignored'),('0 filtered out','1 filtered out')):
            value=copy.deepcopy(good); value['results']['static']=value['results']['static'].replace(old,new); mutants.append(value)
        for value in mutants:
            try: check(value)
            except (ValueError,KeyError,TypeError): count+=1
            else: raise AssertionError('native evidence tamper accepted')
    print(f'MD5 native record policy rejects {count} missing, identity, route, source and claim regressions')

if __name__=='__main__': main()
