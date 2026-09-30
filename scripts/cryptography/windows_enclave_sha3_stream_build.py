#!/usr/bin/env python3
"""Compile the private scalar SHA-3 worker, not a native qualification gate."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tomllib

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'assurance/windows-enclave-probe'
CRATES = ('brynja-core', 'brynja-hash-core', 'brynja-hash-sha3')
FILES = ('sha3_stream.rs', 'sha3_stream_state.rs', 'sha3_stream_tests.rs')


def run(command):
    result = subprocess.run(command, text=True, capture_output=True, timeout=180)
    if result.returncode:
        raise RuntimeError(f'{command}\n{result.stdout}\n{result.stderr}')
    return result.stdout


def build(directory, target, testing=False):
    directory = directory.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    common = ['rustc', '+1.98.1', '--edition=2024', '--target', target,
              '-D', 'warnings', '-C', 'opt-level=2', '-C', 'overflow-checks=yes',
              '-C', 'panic='+('unwind' if testing else 'abort'),
              '-L', 'dependency='+str(directory)]
    commands, sources = [], [Path(__file__).resolve()]
    for name in CRATES:
        folder = ROOT/'crates'/name
        manifest = folder/'Cargo.toml'
        policy = tomllib.loads(manifest.read_text())
        if policy.get('features', {}).get('default') or policy.get('build-dependencies') or policy['package'].get('build'):
            raise ValueError('Unexpected worker build graph')
        deps = policy.get('dependencies', {})
        if name.endswith('sha3'):
            if set(deps) != {'brynja-core', 'brynja-hash-core', 'brynja-crypto-cpu'} or not deps['brynja-crypto-cpu'].get('optional'):
                raise ValueError('Unexpected SHA-3 dependencies')
            if any(not d.get('workspace') or d.get('features') for d in deps.values()):
                raise ValueError('Unexpected dependency features')
        elif deps:
            raise ValueError('Unexpected foundation dependencies')
        sources += [manifest, *sorted((folder/'src').rglob('*.rs'))]
        crate = name.replace('-', '_')
        command = common+['--crate-name', crate, '--crate-type', 'rlib', str(folder/'src/lib.rs'),
                          '-o', str(directory/('lib'+crate+'.rlib'))]
        if name.endswith('sha3'):
            for dep in ('brynja_core', 'brynja_hash_core'):
                command += ['--extern', dep+'='+str(directory/('lib'+dep+'.rlib'))]
        run(command); commands.append(command)
    for name in FILES:
        shutil.copyfile(SOURCE/name, directory/name)
        sources.append(SOURCE/name)
    for name in ('cshake-execution.txt', 'nist-bit-selected.txt'):
        path = ROOT/'crates/brynja-hash-sha3/tests/vectors'/name
        shutil.copyfile(path, directory/name); sources.append(path)
    rows = ['#[test]', 'fn independent_hashlib_oracle() {']
    for identity, algorithm in enumerate(('sha3_224','sha3_256','sha3_384','sha3_512','shake_128','shake_256'), 1):
        for length in (0,3,71,72,73,135,136,137,143,144,145,167,168,169,1024,1_000_000):
            data = bytes(i % 251 for i in range(length))
            digest = hashlib.new(algorithm,data)
            expected = digest.digest(333) if identity > 4 else digest.digest()
            rows.append('{ let input: std::vec::Vec<u8> = (0..'+str(length)+').map(|i| (i%251) as u8).collect();')
            rows.append('let expected = ['+','.join(map(str,expected))+'];')
            rows.append(f'check_case({identity}, empty(), empty(), &input, {8 if length else 0}, &expected, 8); }}')
    rows.append('}')
    tests = directory/'sha3_stream_tests.rs'
    tests.write_text(tests.read_text()+'\n'+'\n'.join(rows)+'\n')
    artifact = directory/('sha3-tests.exe' if 'windows' in target else 'sha3-tests') if testing else directory/'libsha3_stream.rlib'
    command = common+['--crate-name','sha3_stream',str(directory/'sha3_stream.rs')]
    for dep in ('brynja_core','brynja_hash_sha3'):
        command += ['--extern',dep+'='+str(directory/('lib'+dep+'.rlib'))]
    command += ['--test'] if testing else ['--crate-type','rlib']
    command += ['-o',str(artifact)]
    run(command); commands.append(command)
    record = dict(schema=1, status='BUILD_ONLY', production_qualified=False, target=target,
        commands=commands, source_sha256={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sources},
        artifact_sha256=hashlib.sha256(artifact.read_bytes()).hexdigest())
    (directory/'sha3-stream-build.json').write_text(json.dumps(record,indent=2)+'\n')
    return artifact


def image(directory):
    directory = directory.resolve()
    build(directory, 'x86_64-pc-windows-msvc')
    names = ('window_sha3_stream.c','window_guard.c','window_lock.c','synthetic.c',
             'window_rust_x64.asm','sha3_stream_worker.rs','sha3_stream_placement_tests.rs')
    for name in names: shutil.copyfile(SOURCE/name,directory/name)
    original = (SOURCE/'window_retained.c').read_text()
    anchor = '(operation & 255) > 7 || operation >> 8 > 19'
    if original.count(anchor)!=1: raise ValueError('Retained admission anchor changed')
    (directory/'window_retained.c').write_text(original.replace(anchor,
        '!(operation == 0 || operation == 3 || (operation >= 21 && operation <= 31))'))
    command = ['rustc','+1.98.1','--edition=2024','--target','x86_64-pc-windows-msvc',
        '--crate-type','staticlib','--crate-name','sha3_stream_worker','-D','warnings',
        '-C','panic=abort','-C','opt-level=2','-C','lto=fat','-C','overflow-checks=yes',
        '-L','dependency='+str(directory),str(directory/'sha3_stream_worker.rs'),
        '--emit='+','.join(kind+'='+str(directory/('normal_rust.'+suffix))
                          for kind,suffix in [('link','lib'),('asm','s'),('llvm-ir','ll')])]
    for name in ('brynja_core','brynja_hash_sha3','sha3_stream'):
        command+=['--extern',name+'='+str(directory/('lib'+name+'.rlib'))]
    run(command)
    (directory/'link.cmd').write_text('@echo off\nsetlocal\n'
        'if "%VCToolsInstallDir%"=="" exit /b 90\ncd /d "%~dp0"\n'
        'ml64 /nologo /c /Fowindow.obj window_rust_x64.asm\nif errorlevel 1 exit /b 1\n'
        'cl /nologo /std:c11 /LD /O2 /W4 /WX /MT /guard:cf /Fonormal.obj /Fenormal.dll '
        'window_sha3_stream.c window.obj normal_rust.lib /link /ENCLAVE /NODEFAULTLIB '
        '/INCREMENTAL:NO /INTEGRITYCHECK /GUARD:MIXED '
        '/LIBPATH:"%VCToolsInstallDir%lib\\x64\\enclave" '
        '/LIBPATH:"%WindowsSdkDir%Lib\\%WindowsSDKVersion%ucrt_enclave\\x64" '
        'libcmt.lib libvcruntime.lib ucrt.lib vertdll.lib bcrypt.lib\n'
        'if errorlevel 1 exit /b 1\n'
        '"%WindowsSdkDir%bin\\%WindowsSDKVersion%x64\\veiid.exe" normal.dll\n'
        'exit /b %ERRORLEVEL%\n')
    record=json.loads((directory/'sha3-stream-build.json').read_text())
    record['commands'].append(command)
    record['source_sha256'].update({'assurance/windows-enclave-probe/'+name:
        hashlib.sha256((SOURCE/name).read_bytes()).hexdigest() for name in (*names,'window_retained.c')})
    record['generated_sha256']={p.name:hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(directory.iterdir()) if p.suffix in ('.rs','.c','.asm','.lib','.s','.ll')}
    (directory/'sha3-worker-build.json').write_text(json.dumps(record,indent=2)+'\n')
    return directory/'normal_rust.lib'


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory',type=Path)
    parser.add_argument('--target',default='x86_64-pc-windows-msvc')
    parser.add_argument('--test',action='store_true')
    parser.add_argument('--image',action='store_true')
    args = parser.parse_args()
    if args.image and args.test: parser.error('--image and --test are distinct products')
    print(image(args.directory) if args.image else build(args.directory,args.target,args.test))
