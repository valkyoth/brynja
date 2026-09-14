#!/usr/bin/env python3
"""Short native CI correctness, not four-lane release qualification."""
import argparse
import importlib.util
import os
import platform
from pathlib import Path

spec=importlib.util.spec_from_file_location('capture',Path(__file__).with_name('capture-md5-cpu-native.py'))
host=importlib.util.module_from_spec(spec); spec.loader.exec_module(host)

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('architecture',choices=('x86_64','aarch64'))
    args=parser.parse_args()
    if platform.system()!='Linux' or platform.machine()!=args.architecture:
        raise ValueError('native MD5 CI host mismatch')
    lane='aws-aarch64'
    if args.architecture=='x86_64':
        lane='amd-x86_64' if 'AuthenticAMD' in Path('/proc/cpuinfo').read_text() else 'intel-x86_64'
    _,features=host.host(lane)
    env=dict(os.environ)
    for key in ('RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTDOCFLAGS','CARGO_BUILD_TARGET'):
        env.pop(key,None)
    env.update(RUSTFLAGS='-C target-feature='+features,BRYNJA_REQUIRE_HARDENED_MD5='1')
    output=host.run(['cargo','+1.98.1','test','--locked','--release','-p','brynja-legacy-md5',
        '--features','hardened-execution','--lib','--test','hardened_execution','--','--nocapture'],env)
    backend='legacy-x86_64-avx2-md5' if args.architecture=='x86_64' else 'legacy-aarch64-neon-md5'
    if 'MD5_HARDENED: '+backend+'; cases=2048; actual SIMD' not in output.splitlines():
        raise ValueError('native MD5 CI did not execute the required operational kernel')
    if '5 passed; 0 failed' not in output: raise ValueError('native MD5 CI incomplete suite')
    print(output)
    print('Hardened MD5 native CI: PASS; correctness only, not deployment qualification')

if __name__=='__main__': main()
