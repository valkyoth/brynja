#!/usr/bin/env python3
"""Build-only development image from a verified SIMD worker test directory."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

ROOT=Path(__file__).resolve().parents[2]
SOURCE=ROOT/'assurance/windows-enclave-probe'
FILES=('window_sha256_simd.c','sha256_simd_gate.h','cpu_inventory.c','window_retained.c',
       'window_guard.c','window_lock.c','synthetic.c','window_rust_x64.asm')
def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def replace(text,before,after):
    if text.count(before)!=1: raise ValueError('Image integration anchor drift: '+before)
    return text.replace(before,after)

def prepare(directory):
    for name in FILES: shutil.copyfile(SOURCE/name,directory/name)
    path=directory/'cpu_inventory.c'
    path.write_text(replace(path.read_text(),'#include "synthetic.c"','#include <winenclave.h>'))
    path=directory/'window_retained.c'
    path.write_text(replace(path.read_text(),'(operation & 255) > 7 || operation >> 8 > 19',
        '!(operation == 0 || operation == 3 || (operation >= 100 && operation <= 102)) || !Sha256SimdReady()'))

def build(directory):
    record=json.loads((directory/'sha256-simd-worker-results.json').read_text())
    if record['target']!='x86_64-pc-windows-msvc': raise ValueError('Native Windows MSVC build required')
    for name,value in record['source_sha256'].items():
        if digest(ROOT/name)!=value: raise ValueError('Worker source drift: '+name)
    for name,value in record['generated_sha256'].items():
        if digest(directory/name)!=value: raise ValueError('Worker artifact drift: '+name)
    prepare(directory)
    command=record['commands'][-1].copy()
    command.remove('--test')
    index=command.index('-o'); del command[index:index+2]
    command[command.index('panic=unwind')]='panic=abort'
    command+=['--crate-type','staticlib','-C','lto=fat',
        '--emit='+','.join(kind+'='+str(directory/('normal_rust.'+ext))
            for kind,ext in (('link','lib'),('asm','s'),('llvm-ir','ll')))]
    subprocess.run(command,check=True,timeout=240)
    # Use the unchanged MSVC/SDK enclave linker recipe, with our own C adapter.
    script=directory/'link.cmd'
    script.write_text('@echo off\nsetlocal\n'
        'if "%VCToolsInstallDir%"=="" exit /b 90\ncd /d "%~dp0"\n'
        'ml64 /nologo /c /Fowindow.obj window_rust_x64.asm\nif errorlevel 1 exit /b 1\n'
        'cl /nologo /std:c11 /LD /O2 /W4 /WX /MT /guard:cf /Fonormal.obj /Fenormal.dll '
        'window_sha256_simd.c window.obj normal_rust.lib /link /ENCLAVE /NODEFAULTLIB '
        '/INCREMENTAL:NO /INTEGRITYCHECK /GUARD:MIXED '
        '/LIBPATH:"%VCToolsInstallDir%lib\\x64\\enclave" '
        '/LIBPATH:"%WindowsSdkDir%Lib\\%WindowsSDKVersion%ucrt_enclave\\x64" '
        'libcmt.lib libvcruntime.lib ucrt.lib vertdll.lib bcrypt.lib\nif errorlevel 1 exit /b 1\n'
        '"%WindowsSdkDir%bin\\%WindowsSDKVersion%x64\\veiid.exe" normal.dll\nexit /b %ERRORLEVEL%\n')
    subprocess.run(['cmd','/c',str(script)],check=True,timeout=240)
    source_paths=[SOURCE/name for name in FILES]+[Path(__file__).resolve()]
    result=dict(status='SIMD_WORKER_IMAGE_BUILD_ONLY',enclave_execution=False,production_qualified=False,
        worker_record_sha256=digest(directory/'sha256-simd-worker-results.json'),
        commands=[command,['cmd','/c',str(script)]],
        source_sha256={p.relative_to(ROOT).as_posix():digest(p) for p in source_paths},
        artifacts={p.name:digest(p) for p in directory.iterdir()
            if p.suffix in ('.c','.h','.asm','.cmd','.s','.ll','.lib','.dll')})
    (directory/'sha256-simd-image-build.json').write_text(json.dumps(result,indent=2)+'\n')
    print('SIMD worker image build PASS; not signed, loaded or execution-qualified')

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory',type=Path)
    build(parser.parse_args().directory.resolve())
