#!/usr/bin/env python3
"""Native ordinary AVX2 batch ASan/LSan, never a portable-only success."""
import os
import platform
import subprocess
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]

def main():
    if platform.system()!='Linux' or platform.machine()!='x86_64':
        raise ValueError('native MD5 ASan requires Linux x86_64')
    flags=[set(line.split(':',1)[1].split()) for line in Path('/proc/cpuinfo').read_text().splitlines() if line.startswith('flags')]
    if not flags or not all('avx2' in row for row in flags): raise ValueError('native AVX2 missing')
    env=dict(os.environ)
    for name in ('RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTDOCFLAGS','CARGO_BUILD_TARGET'):
        env.pop(name,None)
    env['RUSTFLAGS']='-Zsanitizer=address -C target-feature=+avx2'
    env['BRYNJA_REQUIRE_MD5_EXECUTION']='1'
    env['ASAN_OPTIONS']='detect_leaks=1:halt_on_error=1:exitcode=1'
    env['LSAN_OPTIONS']='exitcode=23'
    subprocess.run(['cargo','+nightly-2026-09-11','test','--locked','--offline',
        '-p','brynja-legacy-md5','--features','execution','--lib','--test','execution',
        '--target','x86_64-unknown-linux-gnu'],cwd=ROOT,env=env,check=True,timeout=300)
    print('Native operational MD5 AVX2 ASan and LeakSanitizer: PASS')

if __name__=='__main__': main()
