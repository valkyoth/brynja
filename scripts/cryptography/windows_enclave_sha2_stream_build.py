#!/usr/bin/env python3
"""Build/test the enclave SHA-2 worker component; not platform qualification."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

import windows_enclave_sha256_build as sha

ROOT = sha.ROOT
SOURCE = ROOT / 'assurance/windows-enclave-probe'
FILES = ('sha2_stream.rs', 'sha2_stream_state.rs', 'sha2_stream_tests.rs')
WORKER_FILES = ('window_sha2_stream.c','window_retained.c','window_guard.c',
                'window_lock.c','synthetic.c','window_rust_x64.asm','sha2_stream_worker.rs',
                'sha2_stream_placement_tests.rs')


def run(command, timeout=120):
    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f'{command}\n{result.stdout}\n{result.stderr}')
    return result.stdout


def build(directory, target, testing=False):
    sha.check_graph()
    directory = directory.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    common = ['rustc', '+1.98.1', '--edition=2024', '--target', target,
        '-D', 'warnings', '-C', 'opt-level=2', '-C', 'overflow-checks=yes',
        '-C', 'embed-bitcode=yes', '-C', 'panic='+('unwind' if testing else 'abort'),
        '-L', 'dependency='+str(directory)]
    commands = []
    for name in sha.CRATES:
        crate = name.replace('-', '_')
        command = common + ['--crate-type', 'rlib', '--crate-name', crate,
            str(ROOT/'crates'/name/'src/lib.rs'), '-o', str(directory/('lib'+crate+'.rlib'))]
        if name == 'brynja-hash-sha2':
            command += ['--cfg', 'feature="general-sha512-t"']
            for dep in ('brynja_core', 'brynja_hash_core'):
                command += ['--extern', dep+'='+str(directory/('lib'+dep+'.rlib'))]
        run(command); commands.append(command)
    for name in FILES:
        shutil.copyfile(SOURCE/name, directory/name)
    tests = directory/'sha2_stream_tests.rs'
    rows = ['#[test]', 'fn independent_hashlib_named_oracle() {']
    for identity, name in enumerate(('sha224', 'sha256', 'sha384', 'sha512', 'sha512_224', 'sha512_256'), 1):
        for message in (b'', b'abc', bytes(range(256))*4, b'a'*1_000_000):
            # Generate long input inside the test rather than a megabyte literal.
            expression = 'std::vec![b\'a\'; 1_000_000]' if len(message) == 1_000_000 else \
                'std::vec!['+','.join(map(str, message))+']'
            expected = ','.join(map(str, hashlib.new(name, message).digest()))
            rows.extend(['{', f'let data = {expression}; let mut owner = Owner::new();',
                f'owner.begin(1, {identity}).unwrap(); let mut sequence=1;',
                'for chunk in data.chunks(1024) { sequence+=1; owner.update(sequence, chunk).unwrap(); }',
                'sequence+=1; owner.finish(sequence, &[], 0).unwrap(); sequence+=1;',
                f'owner.export_public(sequence, {identity}, |bytes| {{ assert_eq!(bytes, &[{expected}]); true }}).unwrap();', '}'])
    tests.write_text(tests.read_text()+'\n'+'\n'.join(rows+['}', '']))
    command = common + ['--crate-name', 'sha2_stream', str(directory/'sha2_stream.rs')]
    for dep in ('brynja_core', 'brynja_hash_sha2'):
        command += ['--extern', dep+'='+str(directory/('lib'+dep+'.rlib'))]
    executable = directory/('sha2-stream-test.exe' if 'windows' in target else 'sha2-stream-test')
    command += ['--test', '-o', str(executable)] if testing else \
        ['--crate-type', 'rlib', '-o', str(directory/'libsha2_stream.rlib')]
    run(command); commands.append(command)
    record = dict(schema=1, status='BUILD_ONLY', production_qualified=False, target=target,
        commands=commands, source_sha256={p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest()
        for p in (*sha.source_files(), *('assurance/windows-enclave-probe/'+n for n in FILES),
                  'scripts/cryptography/windows_enclave_sha2_stream_build.py')})
    (directory/'sha2-stream-build.json').write_text(json.dumps(record, indent=2)+'\n')
    return executable


def image(directory):
    """Separate image; never modify or relabel previously captured artifacts."""
    directory = directory.resolve()
    build(directory, 'x86_64-pc-windows-msvc')
    for name in ('window_sha2_stream.c', 'window_guard.c', 'window_lock.c',
                 'synthetic.c', 'window_rust_x64.asm', 'sha2_stream_worker.rs'):
        shutil.copyfile(SOURCE/name, directory/name)
    text = (SOURCE/'window_retained.c').read_text()
    before = '(operation & 255) > 7 || operation >> 8 > 19'
    if text.count(before) != 1:
        raise ValueError('retained entry admission anchor changed')
    text = text.replace(before, '!(operation == 0 || operation == 3 || (operation >= 11 && operation <= 16))')
    (directory/'window_retained.c').write_text(text)
    command = ['rustc', '+1.98.1', '--edition=2024', '--target', 'x86_64-pc-windows-msvc',
        '--crate-type', 'staticlib', '--crate-name', 'sha2_stream_worker', '-D', 'warnings',
        '-C', 'panic=abort', '-C', 'opt-level=2', '-C', 'lto=fat', '-C', 'overflow-checks=yes',
        '-L', 'dependency='+str(directory), str(directory/'sha2_stream_worker.rs'),
        '--emit='+','.join(kind+'='+str(directory/('normal_rust.'+extension))
                          for kind,extension in [('link','lib'),('asm','s'),('llvm-ir','ll')])]
    for name in ('brynja_core','sha2_stream'):
        command += ['--extern',name+'='+str(directory/('lib'+name+'.rlib'))]
    run(command)
    (directory/'link.cmd').write_text('@echo off\nsetlocal\n'
        'if "%VCToolsInstallDir%"=="" exit /b 90\ncd /d "%~dp0"\n'
        'ml64 /nologo /c /Fowindow.obj window_rust_x64.asm\nif errorlevel 1 exit /b 1\n'
        'cl /nologo /std:c11 /LD /O2 /W4 /WX /MT /guard:cf /Fonormal.obj /Fenormal.dll '
        'window_sha2_stream.c window.obj normal_rust.lib /link /ENCLAVE /NODEFAULTLIB '
        '/INCREMENTAL:NO /INTEGRITYCHECK /GUARD:MIXED '
        '/LIBPATH:"%VCToolsInstallDir%lib\\x64\\enclave" '
        '/LIBPATH:"%WindowsSdkDir%Lib\\%WindowsSDKVersion%ucrt_enclave\\x64" '
        'libcmt.lib libvcruntime.lib ucrt.lib vertdll.lib bcrypt.lib\n'
        'if errorlevel 1 exit /b 1\n'
        '"%WindowsSdkDir%bin\\%WindowsSDKVersion%x64\\veiid.exe" normal.dll\n'
        'exit /b %ERRORLEVEL%\n')
    record = json.loads((directory/'sha2-stream-build.json').read_text())
    record['commands'].append(command)
    record['source_sha256'].update({'assurance/windows-enclave-probe/'+name:
        hashlib.sha256((SOURCE/name).read_bytes()).hexdigest() for name in WORKER_FILES})
    record['generated_sha256'] = {p.name:hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(directory.iterdir()) if p.suffix in ('.rs','.c','.asm','.lib','.s','.ll')}
    (directory/'sha2-worker-build.json').write_text(json.dumps(record,indent=2)+'\n')
    return directory/'normal_rust.lib'


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--target', default='x86_64-pc-windows-msvc')
    parser.add_argument('--test', action='store_true')
    parser.add_argument('--image', action='store_true')
    args = parser.parse_args()
    if args.image and args.test:
        parser.error('--image and --test are distinct build products')
    print(image(args.directory) if args.image else build(args.directory, args.target, args.test))
