#!/usr/bin/env python3
"""Build the private scalar batch component, not a qualified enclave image."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import windows_enclave_sha3_stream_build as base
import windows_enclave_sha3_batch_oracle as oracle

FILES = ('sha3_batch.rs', 'sha3_batch_tests.rs', 'sha3_batch_wire.rs', 'sha3_batch_wire_tests.rs')


def build(directory, target, testing=False):
    directory = directory.resolve()
    base.build(directory, target, testing=testing)
    record = json.loads((directory / 'sha3-stream-build.json').read_text())
    if testing:
        previous = record['commands'][-1]
        if previous[-3] != '--test':
            raise ValueError('Changed component build shape')
        dependency = previous[:-3] + ['--crate-type', 'rlib', '-o', str(directory / 'libsha3_stream.rlib')]
        base.run(dependency)
        record['commands'].append(dependency)
    for name in FILES:
        shutil.copyfile(base.SOURCE / name, directory / name)
    count = oracle.generate(directory / 'sha3-batch-oracle.txt') if testing else 0
    artifact = directory / (('batch-tests.exe' if 'windows' in target else 'batch-tests')
                            if testing else 'libsha3_batch.rlib')
    command = ['rustc', '+1.98.1', '--edition=2024', '--target', target, '-D', 'warnings',
               '-C', 'opt-level=2', '-C', 'overflow-checks=yes', '-C', 'embed-bitcode=yes',
               '-C', 'panic=' + ('unwind' if testing else 'abort'), '-L', 'dependency=' + str(directory),
               '--crate-name', 'sha3_batch', str(directory / 'sha3_batch.rs'), '-o', str(artifact)]
    command += ['--test'] if testing else ['--crate-type', 'rlib']
    for name in ('brynja_core', 'brynja_hash_sha3', 'sha3_stream'):
        command += ['--extern', name + '=' + str(directory / ('lib' + name + '.rlib'))]
    base.run(command)
    record['commands'].append(command)
    record['status'] = 'COMPONENT_BUILD_ONLY'
    record['independent_test_cases'] = count
    record['source_sha256'].update({str(p.relative_to(base.ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in (Path(__file__), Path(oracle.__file__), *(base.SOURCE / name for name in FILES),
                  base.ROOT / 'scripts/sha3/check-sha3-bit-differential.py',
                  base.ROOT / 'scripts/sha3/check-cshake-differential.py',
                  base.ROOT / 'crates/brynja-hash-sha3/tests/vectors/nist-bit-selected.txt')})
    record['artifact_sha256'] = hashlib.sha256(artifact.read_bytes()).hexdigest()
    if testing:
        record['test_corpus_sha256'] = hashlib.sha256((directory / 'sha3-batch-oracle.txt').read_bytes()).hexdigest()
    (directory / 'sha3-batch-build.json').write_text(json.dumps(record, indent=2) + '\n')
    return command, artifact, count


def image(directory):
    directory = directory.resolve()
    build(directory, 'x86_64-pc-windows-msvc')
    names = ('window_sha3_batch.c','window_guard.c','window_lock.c','synthetic.c',
             'window_rust_x64.asm','sha3_batch_worker.rs','sha3_batch_placement_tests.rs')
    for name in names: shutil.copyfile(base.SOURCE/name,directory/name)
    original = (base.SOURCE/'window_retained.c').read_text()
    anchor = '(operation & 255) > 7 || operation >> 8 > 19'
    if original.count(anchor)!=1: raise ValueError('Retained admission anchor changed')
    (directory/'window_retained.c').write_text(original.replace(anchor,
        '!(operation == 0 || operation == 3 || (operation >= 90 && operation <= 99))'))
    command = ['rustc','+1.98.1','--edition=2024','--target','x86_64-pc-windows-msvc',
        '--crate-type','staticlib','--crate-name','sha3_batch_worker','-D','warnings',
        '-C','panic=abort','-C','opt-level=2','-C','lto=fat','-C','overflow-checks=yes',
        '-L','dependency='+str(directory),str(directory/'sha3_batch_worker.rs'),
        '--emit='+','.join(kind+'='+str(directory/('normal_rust.'+suffix))
                          for kind,suffix in [('link','lib'),('asm','s'),('llvm-ir','ll')])]
    for name in ('brynja_core','brynja_hash_sha3','sha3_stream','sha3_batch'):
        command+=['--extern',name+'='+str(directory/('lib'+name+'.rlib'))]
    base.run(command)
    (directory/'link.cmd').write_text('@echo off\nsetlocal\n'
        'if "%VCToolsInstallDir%"=="" exit /b 90\ncd /d "%~dp0"\n'
        'ml64 /nologo /c /Fowindow.obj window_rust_x64.asm\nif errorlevel 1 exit /b 1\n'
        'cl /nologo /std:c11 /LD /O2 /W4 /WX /MT /guard:cf /Fonormal.obj /Fenormal.dll '
        'window_sha3_batch.c window.obj normal_rust.lib /link /ENCLAVE /NODEFAULTLIB '
        '/INCREMENTAL:NO /INTEGRITYCHECK /GUARD:MIXED '
        '/LIBPATH:"%VCToolsInstallDir%lib\\x64\\enclave" '
        '/LIBPATH:"%WindowsSdkDir%Lib\\%WindowsSDKVersion%ucrt_enclave\\x64" '
        'libcmt.lib libvcruntime.lib ucrt.lib vertdll.lib bcrypt.lib\n'
        'if errorlevel 1 exit /b 1\n'
        '"%WindowsSdkDir%bin\\%WindowsSDKVersion%x64\\veiid.exe" normal.dll\n'
        'exit /b %ERRORLEVEL%\n')
    record=json.loads((directory/'sha3-batch-build.json').read_text())
    record['commands'].append(command)
    record['source_sha256'].update({'assurance/windows-enclave-probe/'+name:
        hashlib.sha256((base.SOURCE/name).read_bytes()).hexdigest() for name in (*names,'window_retained.c')})
    record['generated_sha256']={p.name:hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(directory.iterdir()) if p.suffix in ('.rs','.c','.asm','.lib','.s','.ll')}
    (directory/'sha3-batch-worker-build.json').write_text(json.dumps(record,indent=2)+'\n')
    return directory/'normal_rust.lib'


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--target', default='x86_64-pc-windows-msvc')
    parser.add_argument('--test', action='store_true')
    parser.add_argument('--image', action='store_true')
    args = parser.parse_args()
    if args.image and args.test:
        parser.error('--image and --test are separate builds')
    print(image(args.directory) if args.image else build(args.directory, args.target, args.test)[1])
