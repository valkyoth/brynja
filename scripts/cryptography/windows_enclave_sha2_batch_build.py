#!/usr/bin/env python3
"""Build the private sequential SHA-2 batch image; not native qualification."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import windows_enclave_sha2_stream_build as base

ROOT, SOURCE, run = base.ROOT, base.SOURCE, base.run
FILES = ('sha2_batch.rs', 'sha2_batch_tests.rs', 'sha2_batch_wire.rs',
         'sha2_batch_wire_tests.rs')


def build(directory, target):
    directory = directory.resolve()
    base.build(directory, target)
    for name in FILES: shutil.copyfile(SOURCE/name, directory/name)
    artifact = directory/'libsha2_batch.rlib'
    command = ['rustc', '+1.98.1', '--edition=2024', '--target', target,
        '--crate-type', 'rlib', '--crate-name', 'sha2_batch', '-D', 'warnings',
        '-C', 'panic=abort', '-C', 'opt-level=2', '-C', 'embed-bitcode=yes',
        '-C', 'overflow-checks=yes', '-L', 'dependency='+str(directory),
        str(directory/'sha2_batch.rs'), '-o', str(artifact)]
    for name in ('brynja_core', 'brynja_hash_sha2', 'sha2_stream'):
        command += ['--extern', name+'='+str(directory/('lib'+name+'.rlib'))]
    run(command)
    record = json.loads((directory/'sha2-stream-build.json').read_text())
    record['commands'].append(command)
    record['status'] = 'COMPONENT_BUILD_ONLY'
    record['source_sha256'].update({str(p.relative_to(ROOT)):
        hashlib.sha256(p.read_bytes()).hexdigest()
        for p in (Path(__file__), *(SOURCE/name for name in FILES))})
    record['artifact_sha256'] = hashlib.sha256(artifact.read_bytes()).hexdigest()
    (directory/'sha2-batch-build.json').write_text(json.dumps(record, indent=2)+'\n')
    return artifact


def image(directory):
    directory = directory.resolve()
    build(directory, 'x86_64-pc-windows-msvc')
    names = ('window_sha2_batch.c','window_guard.c','window_lock.c','synthetic.c',
             'window_rust_x64.asm','sha2_batch_worker.rs','sha2_batch_placement_tests.rs')
    for name in names: shutil.copyfile(SOURCE/name,directory/name)
    original = (SOURCE/'window_retained.c').read_text()
    anchor = '(operation & 255) > 7 || operation >> 8 > 19'
    if original.count(anchor)!=1: raise ValueError('Retained admission anchor changed')
    (directory/'window_retained.c').write_text(original.replace(anchor,
        '!(operation == 0 || operation == 3 || (operation >= 80 && operation <= 86))'))
    command = ['rustc','+1.98.1','--edition=2024','--target','x86_64-pc-windows-msvc',
        '--crate-type','staticlib','--crate-name','sha2_batch_worker','-D','warnings',
        '-C','panic=abort','-C','opt-level=2','-C','lto=fat','-C','overflow-checks=yes',
        '-L','dependency='+str(directory),str(directory/'sha2_batch_worker.rs'),
        '--emit='+','.join(kind+'='+str(directory/('normal_rust.'+suffix))
                          for kind,suffix in [('link','lib'),('asm','s'),('llvm-ir','ll')])]
    for name in ('brynja_core','brynja_hash_sha2','sha2_stream','sha2_batch'):
        command+=['--extern',name+'='+str(directory/('lib'+name+'.rlib'))]
    run(command)
    (directory/'link.cmd').write_text('@echo off\nsetlocal\n'
        'if "%VCToolsInstallDir%"=="" exit /b 90\ncd /d "%~dp0"\n'
        'ml64 /nologo /c /Fowindow.obj window_rust_x64.asm\nif errorlevel 1 exit /b 1\n'
        'cl /nologo /std:c11 /LD /O2 /W4 /WX /MT /guard:cf /Fonormal.obj /Fenormal.dll '
        'window_sha2_batch.c window.obj normal_rust.lib /link /ENCLAVE /NODEFAULTLIB '
        '/INCREMENTAL:NO /INTEGRITYCHECK /GUARD:MIXED '
        '/LIBPATH:"%VCToolsInstallDir%lib\\x64\\enclave" '
        '/LIBPATH:"%WindowsSdkDir%Lib\\%WindowsSDKVersion%ucrt_enclave\\x64" '
        'libcmt.lib libvcruntime.lib ucrt.lib vertdll.lib bcrypt.lib\n'
        'if errorlevel 1 exit /b 1\n'
        '"%WindowsSdkDir%bin\\%WindowsSDKVersion%x64\\veiid.exe" normal.dll\n'
        'exit /b %ERRORLEVEL%\n')
    record=json.loads((directory/'sha2-batch-build.json').read_text())
    record['commands'].append(command)
    record['source_sha256'].update({'assurance/windows-enclave-probe/'+name:
        hashlib.sha256((SOURCE/name).read_bytes()).hexdigest() for name in (*names,'window_retained.c')})
    record['generated_sha256']={p.name:hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(directory.iterdir()) if p.suffix in ('.rs','.c','.asm','.lib','.s','.ll')}
    (directory/'sha2-batch-worker-build.json').write_text(json.dumps(record,indent=2)+'\n')
    return directory/'normal_rust.lib'


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--target', default='x86_64-pc-windows-msvc')
    parser.add_argument('--image', action='store_true')
    args = parser.parse_args()
    print(image(args.directory) if args.image else build(args.directory, args.target))
