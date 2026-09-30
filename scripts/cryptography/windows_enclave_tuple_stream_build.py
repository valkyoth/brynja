#!/usr/bin/env python3
"""Build isolated TupleHash framing over hardened cSHAKE; no native claims."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import windows_enclave_sha3_stream_build as base

ROOT, SOURCE, run = base.ROOT, base.SOURCE, base.run
FILES = ('tuple_stream.rs', 'tuple_stream_state.rs', 'tuple_stream_tests.rs',
         'tuple_stream_wire.rs', 'tuple_stream_wire_tests.rs', 'tuple_host_wire_tests.rs')
HOST_WIRE = ROOT/'crates/brynja-crypto-cpu-std/src/windows_enclave/tuple_wire.rs'


def oracle_tests():
    path = ROOT/'scripts/tuplehash/check-tuplehash-differential.py'
    spec = importlib.util.spec_from_file_location('tuple_oracle', path)
    oracle = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(oracle)
    oracle.verify_oracle()
    selected = oracle.cases()
    identities = ('tuple128', 'tuple256', 'tuplexof128', 'tuplexof256')
    for identity, rate in zip(identities, (168,136,168,136)):
        for bits in (8191,8192,8193,32769):
            custom = oracle.oracle.canonical(31,16391)
            item = oracle.oracle.canonical(47,bits)
            expected = oracle.tuple_hash(rate,[oracle.oracle.byte_bits(item)[:bits]],
                oracle.oracle.byte_bits(custom)[:16391],271,'xof' in identity)
            selected.append((identity,custom,16391,[(item,bits)],271,expected))
    lines = ['#[test]', 'fn independent_bit_oracle() {']
    def array(value): return '&['+','.join(map(str,value))+']'
    for identity,custom,custom_bits,items,out_bits,expected in selected:
        item_text = '&['+','.join('('+array(value)+','+str(bits)+')' for value,bits in items)+']'
        last = ((out_bits-1)%8+1) if out_bits else 0
        arguments=f'({identities.index(identity)+1},{array(custom)},{custom_bits},{item_text},{array(expected)},{last});'
        lines.append('check_case'+arguments)
        lines.append('super::tuple_stream_wire_tests::check_case'+arguments)
    lines.append('}')
    return '\n'.join(lines)+'\n', len(selected)


def build(directory, target, testing=False):
    directory = directory.resolve()
    # Reuse the reviewed default-off first-party dependency builder. Its SHA-3
    # fixture is built but is not linked into the TupleHash component.
    base.build(directory,target,testing)
    for name in FILES: shutil.copyfile(SOURCE/name,directory/name)
    shutil.copyfile(HOST_WIRE,directory/'tuple_host_wire.rs')
    entry=directory/'tuple_stream.rs'
    entry.write_text(entry.read_text()+'\n#[cfg(test)]\nmod tuple_host_wire_tests;\n')
    generated,count=oracle_tests()
    tests=directory/'tuple_stream_tests.rs'
    tests.write_text(tests.read_text()+'\n'+generated)
    artifact=directory/('tuple-tests.exe' if 'windows' in target else 'tuple-tests') if testing else directory/'libtuple_stream.rlib'
    command=['rustc','+1.98.1','--edition=2024','--target',target,'-D','warnings',
        '-C','opt-level=2','-C','overflow-checks=yes','-C','panic='+('unwind' if testing else 'abort'),
        '-L','dependency='+str(directory),'--crate-name','tuple_stream',str(directory/'tuple_stream.rs')]
    for name in ('brynja_core','brynja_hash_sha3'):
        command+=['--extern',name+'='+str(directory/('lib'+name+'.rlib'))]
    command+=['--test'] if testing else ['--crate-type','rlib']
    command+=['-o',str(artifact)]
    run(command)
    sources=[Path(__file__),HOST_WIRE,*(SOURCE/name for name in FILES),ROOT/'scripts/tuplehash/check-tuplehash-differential.py',
        ROOT/'scripts/sha3/check-cshake-differential.py',ROOT/'scripts/sha3/check-sha3-bit-differential.py']
    hashes=json.loads((directory/'sha3-stream-build.json').read_text())['source_sha256']
    hashes.update({str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sources})
    record=dict(schema=1,status='COMPONENT_BUILD_ONLY',production_qualified=False,target=target,
        oracle_cases=count,commands=[command],source_sha256=hashes,
        artifact_sha256=hashlib.sha256(artifact.read_bytes()).hexdigest(),
        generated_tests_sha256=hashlib.sha256(tests.read_bytes()).hexdigest())
    (directory/'tuple-stream-build.json').write_text(json.dumps(record,indent=2)+'\n')
    return artifact


def image(directory):
    directory = directory.resolve()
    build(directory, 'x86_64-pc-windows-msvc')
    names = ('window_tuple_stream.c','window_guard.c','window_lock.c','synthetic.c',
             'window_rust_x64.asm','tuple_stream_worker.rs','tuple_stream_placement_tests.rs')
    for name in names: shutil.copyfile(SOURCE/name,directory/name)
    original = (SOURCE/'window_retained.c').read_text()
    anchor = '(operation & 255) > 7 || operation >> 8 > 19'
    if original.count(anchor)!=1: raise ValueError('Retained admission anchor changed')
    (directory/'window_retained.c').write_text(original.replace(anchor,
        '!(operation == 0 || operation == 3 || (operation >= 60 && operation <= 70))'))
    command = ['rustc','+1.98.1','--edition=2024','--target','x86_64-pc-windows-msvc',
        '--crate-type','staticlib','--crate-name','tuple_stream_worker','-D','warnings',
        '-C','panic=abort','-C','opt-level=2','-C','lto=fat','-C','overflow-checks=yes',
        '-L','dependency='+str(directory),str(directory/'tuple_stream_worker.rs'),
        '--emit='+','.join(kind+'='+str(directory/('normal_rust.'+suffix))
                          for kind,suffix in [('link','lib'),('asm','s'),('llvm-ir','ll')])]
    for name in ('brynja_core','brynja_hash_sha3','tuple_stream'):
        command+=['--extern',name+'='+str(directory/('lib'+name+'.rlib'))]
    run(command)
    (directory/'link.cmd').write_text('@echo off\nsetlocal\n'
        'if "%VCToolsInstallDir%"=="" exit /b 90\ncd /d "%~dp0"\n'
        'ml64 /nologo /c /Fowindow.obj window_rust_x64.asm\nif errorlevel 1 exit /b 1\n'
        'cl /nologo /std:c11 /LD /O2 /W4 /WX /MT /guard:cf /Fonormal.obj /Fenormal.dll '
        'window_tuple_stream.c window.obj normal_rust.lib /link /ENCLAVE /NODEFAULTLIB '
        '/INCREMENTAL:NO /INTEGRITYCHECK /GUARD:MIXED '
        '/LIBPATH:"%VCToolsInstallDir%lib\\x64\\enclave" '
        '/LIBPATH:"%WindowsSdkDir%Lib\\%WindowsSDKVersion%ucrt_enclave\\x64" '
        'libcmt.lib libvcruntime.lib ucrt.lib vertdll.lib bcrypt.lib\n'
        'if errorlevel 1 exit /b 1\n'
        '"%WindowsSdkDir%bin\\%WindowsSDKVersion%x64\\veiid.exe" normal.dll\n'
        'exit /b %ERRORLEVEL%\n')
    record=json.loads((directory/'tuple-stream-build.json').read_text())
    record['commands'].append(command)
    record['source_sha256'].update({'assurance/windows-enclave-probe/'+name:
        hashlib.sha256((SOURCE/name).read_bytes()).hexdigest() for name in (*names,'window_retained.c')})
    record['generated_sha256']={p.name:hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(directory.iterdir()) if p.suffix in ('.rs','.c','.asm','.lib','.s','.ll')}
    (directory/'tuple-worker-build.json').write_text(json.dumps(record,indent=2)+'\n')
    return directory/'normal_rust.lib'


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory',type=Path)
    parser.add_argument('--target',default='x86_64-pc-windows-msvc')
    parser.add_argument('--test',action='store_true')
    parser.add_argument('--image',action='store_true')
    args=parser.parse_args()
    if args.image and args.test: parser.error('--image and --test are distinct products')
    print(image(args.directory) if args.image else build(args.directory,args.target,args.test))
