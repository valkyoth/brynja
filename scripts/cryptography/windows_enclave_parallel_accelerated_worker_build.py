#!/usr/bin/env python3
"""Build the private AVX2 worker, with baseline C gate before Rust entry."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

import windows_enclave_parallel_accelerated_build as base

ROOT=base.ROOT
SOURCE=base.SOURCE
FILES=('parallel_accelerated_worker.rs','parallel_accelerated_worker_tests.rs',
       'window_parallel_accelerated.c','parallel_accelerated_gate.h','cpu_inventory.c',
       'window_parallel_stream.c','window_retained.c','window_guard.c','window_lock.c',
       'synthetic.c','window_rust_x64.asm')


def run(command):
    result=subprocess.run(command,capture_output=True,text=True,timeout=180)
    if result.returncode:raise RuntimeError(result.stdout+result.stderr)
    return result.stdout


def replace_exact(text,before,after):
    if text.count(before)!=1:raise ValueError('Changed image integration anchor: '+before)
    return text.replace(before,after)


def image_sources(directory):
    text=(SOURCE/'cpu_inventory.c').read_text()
    text=replace_exact(text,'#include "synthetic.c"','#include <winenclave.h>')
    (directory/'cpu_inventory.c').write_text(text)
    text=(SOURCE/'window_parallel_stream.c').read_text()
    text=replace_exact(text,'size != 112','size != 128')
    (directory/'window_parallel_stream.c').write_text(text)
    text=(SOURCE/'window_retained.c').read_text()
    text=replace_exact(text,'(operation & 255) > 7 || operation >> 8 > 19',
                       '!(operation == 0 || operation == 3 || (operation >= 100 && operation <= 108)) || !ParallelAcceleratedReady()')
    (directory/'window_retained.c').write_text(text)


def command(directory,target,testing):
    args=['rustc','+1.98.1','--edition=2024','--target',target,'--crate-name','parallel_accelerated_worker',
          '-D','warnings','-C','opt-level=2','-C','overflow-checks=yes',
          '-C','target-feature=+avx,+avx2','-C','panic='+('unwind' if testing else 'abort'),
          '-L','dependency='+str(directory),str(directory/'parallel_accelerated_worker.rs')]
    for dep in ('brynja_core','parallel_accelerated','parallel_accelerated_resident'):
        args+=['--extern',dep+'='+str(directory/('lib'+dep+'.rlib'))]
    if testing:args+=['--test','-o',str(directory/'parallel-worker-test')]
    else:args+=['--crate-type','staticlib','-C','lto=fat',
                '--emit='+','.join(kind+'='+str(directory/('normal_rust.'+ext))
                                  for kind,ext in (('link','lib'),('asm','s'),('llvm-ir','ll')))]
    return args


def build(directory,target,image=False):
    base.build(directory,target)
    component=json.loads((directory/'parallel-accelerated-build.json').read_text())
    common=component['commands'][-1][:component['commands'][-1].index('--crate-name')]
    shutil.copyfile(SOURCE/'parallel_accelerated_resident.rs',directory/'parallel_accelerated_resident.rs')
    resident=common+['--crate-name','parallel_accelerated_resident','--crate-type','rlib',
        str(directory/'parallel_accelerated_resident.rs'),'-o',str(directory/'libparallel_accelerated_resident.rlib')]
    for dep in ('brynja_crypto_cpu','parallel_accelerated'):
        resident+=['--extern',dep+'='+str(directory/('lib'+dep+'.rlib'))]
    run(resident)
    for name in FILES:shutil.copyfile(SOURCE/name,directory/name)
    image_sources(directory)
    invocation=command(directory,target,True)
    run(invocation)
    record=json.loads((directory/'parallel-accelerated-build.json').read_text())
    record['commands'].extend([resident,invocation])
    if image:
        if target!='x86_64-pc-windows-msvc':raise ValueError('Windows MSVC image required')
        invocation=command(directory,target,False)
        run(invocation);record['commands'].append(invocation)
        (directory/'link.cmd').write_text('@echo off\nsetlocal\n'
            'if "%VCToolsInstallDir%"=="" exit /b 90\ncd /d "%~dp0"\n'
            'ml64 /nologo /c /Fowindow.obj window_rust_x64.asm\nif errorlevel 1 exit /b 1\n'
            'cl /nologo /std:c11 /LD /O2 /W4 /WX /MT /guard:cf /Fonormal.obj /Fenormal.dll '
            'window_parallel_accelerated.c window.obj normal_rust.lib /link /ENCLAVE /NODEFAULTLIB '
            '/INCREMENTAL:NO /INTEGRITYCHECK /GUARD:MIXED '
            '/LIBPATH:"%VCToolsInstallDir%lib\\x64\\enclave" '
            '/LIBPATH:"%WindowsSdkDir%Lib\\%WindowsSDKVersion%ucrt_enclave\\x64" '
            'libcmt.lib libvcruntime.lib ucrt.lib vertdll.lib bcrypt.lib\nif errorlevel 1 exit /b 1\n'
            '"%WindowsSdkDir%bin\\%WindowsSDKVersion%x64\\veiid.exe" normal.dll\nexit /b %ERRORLEVEL%\n')
    record.update(status='IMAGE_BUILD_ONLY' if image else 'WORKER_COMPONENT_ONLY',enclave_executed=False)
    paths=[SOURCE/name for name in FILES]+[SOURCE/'parallel_accelerated_resident.rs']+[Path(__file__).resolve(),ROOT/'scripts/cryptography/test-windows-enclave-parallel-worker.py']
    record['source_sha256'].update({p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in paths})
    record['generated_sha256']={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in directory.iterdir()
                                if p.suffix in ('.rs','.c','.h','.asm','.cmd','.s','.ll','.lib')}
    (directory/'parallel-worker-build.json').write_text(json.dumps(record,indent=2)+'\n')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory',type=Path)
    parser.add_argument('--image',action='store_true')
    args=parser.parse_args()
    target=subprocess.check_output(['rustc','+1.98.1','-vV'],text=True).split('host: ')[1].splitlines()[0]
    build(args.directory.resolve(),target,args.image)
