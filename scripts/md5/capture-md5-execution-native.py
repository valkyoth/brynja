#!/usr/bin/env python3
"""Capture current-source ordinary MD5 operations, never historical admission."""
import argparse
import importlib.util
import json
import os
import platform
import sys
from pathlib import Path
import md5_execution_policy as policy
import md5_execution_native as evidence

spec=importlib.util.spec_from_file_location('candidate_capture',Path(__file__).with_name('capture-md5-cpu-native.py'))
host=importlib.util.module_from_spec(spec); spec.loader.exec_module(host)

def capture(args):
    if not args.attest_native: raise ValueError('native operator attestation required')
    policy.validate()
    if host.run(['git','status','--porcelain']) or args.output.exists():
        raise ValueError('capture requires clean checkout and new output')
    commit=host.run(['git','rev-parse','HEAD']); sources=policy.snapshot()
    cpu,features=host.host(args.lane)
    compiler=host.run(['rustc','+1.98.1','-vV'])
    env=dict(os.environ)
    for key in ('RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTDOCFLAGS','CARGO_BUILD_TARGET','BRYNJA_REQUIRE_MD5_EXECUTION'):
        env.pop(key,None)
    env['RUSTUP_TOOLCHAIN']='1.98.1'
    test=['cargo','+1.98.1','test','--locked','--offline','--release']
    results={}
    results['portable']=host.run(test+['-p','brynja-legacy-md5','--features','execution','--test','execution'],env)
    results['hosted']=host.run(test+['-p','brynja-legacy-md5-std','--features','runtime-execution','--test','execution','--','--nocapture'],env)
    env['RUSTFLAGS']='-C target-feature='+features
    env['BRYNJA_REQUIRE_MD5_EXECUTION']='1'
    results['static']=host.run(test+['-p','brynja-legacy-md5','--features','execution','--test','execution','--','--nocapture'],env)
    results['packaged']=host.run([sys.executable,'scripts/md5/check-md5-package.py','--execution'],env)
    if host.run(['git','status','--porcelain']) or host.run(['git','rev-parse','HEAD'])!=commit or sources!=policy.snapshot():
        raise ValueError('capture source changed')
    record=dict(schema=1,version='0.24.43',lane=args.lane,commit=commit,compiler=compiler,cpu=cpu,
        system=platform.system(),features=features,source_sha256=sources,results=results,
        native='operator-self-attested',profile='ordinary-public-only',independent_review=False,fips_validated=False)
    evidence.record_check(record,args.lane,commit,sources)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open('x') as output: json.dump(record,output,indent=2); output.write('\n')
    print(f'Native ordinary MD5 capture: PASS; {args.lane}; commit={commit}')

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('lane',choices=evidence.LANES)
    parser.add_argument('output',type=Path)
    parser.add_argument('--attest-native',action='store_true')
    capture(parser.parse_args())
