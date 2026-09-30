#!/usr/bin/env python3
"""Build isolated sequential ParallelHash framing; no native enclave claim."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import windows_enclave_sha3_stream_build as base

ROOT, SOURCE, run = base.ROOT, base.SOURCE, base.run
FILES = ('parallel_stream.rs', 'parallel_stream_state.rs', 'parallel_stream_input.rs',
         'parallel_stream_encoding.rs', 'parallel_stream_tests.rs',
         'parallel_stream_wire.rs', 'parallel_stream_wire_tests.rs',
         'parallel_retained_tests.rs', 'parallel_host_wire_tests.rs')
HOST_WIRE = ROOT/'crates/brynja-crypto-cpu-std/src/windows_enclave/parallel_wire.rs'


def oracle_tests():
    path = ROOT / 'scripts/parallelhash/check-parallelhash-differential.py'
    spec = importlib.util.spec_from_file_location('parallel_oracle', path)
    oracle = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(oracle)
    selected = oracle.cases()
    identities = ('parallel128', 'parallel256', 'parallelxof128', 'parallelxof256')
    # Cross-check every official fixed/XOF sample already retained by the crate.
    official = (ROOT / 'crates/brynja-hash-parallel/tests/official_vectors.rs').read_text()
    expected = re.findall(r'"([0-9A-F]{64,128})"', official)
    if len(expected) != 12:
        raise ValueError('Official ParallelHash vector inventory changed')
    for i, digest in enumerate(expected):
        variant = i // 3
        algorithm = identities[variant]
        long = i % 3 == 2
        message = bytes(16 * group + byte for group in range(6 if long else 3)
                        for byte in range(12 if long else 8))
        custom = b'Parallel Data' if i % 3 else b''
        block = 12 if long else 8
        result = oracle.parallel_hash(168 if variant % 2 == 0 else 136,
            oracle.oracle.byte_bits(message), block, oracle.oracle.byte_bits(custom),
            len(digest) * 4, variant >= 2)
        if result.hex().upper() != digest:
            raise ValueError('Independent oracle disagrees with NIST sample')
        selected.append((algorithm, custom, len(custom)*8, message, len(message)*8,
                         block, len(digest)*4, result))
    for algorithm, rate in zip(identities, (168,136,168,136)):
        for block in (1,7,168,1025):
            for size in (block*8-1, block*8, block*8+1, block*16+3):
                custom_bits = 16391
                custom = oracle.oracle.canonical(31, custom_bits)
                message = oracle.oracle.canonical(47, size)
                out_bits = 8191 if block == 1025 else 271
                result = oracle.parallel_hash(rate, oracle.oracle.byte_bits(message)[:size],
                    block, oracle.oracle.byte_bits(custom)[:custom_bits], out_bits, 'xof' in algorithm)
                selected.append((algorithm,custom,custom_bits,message,size,block,out_bits,result))
    rows=['#[test]', 'fn independent_bit_oracle() {']
    vectors=[]
    def array(data): return '&['+','.join(map(str,data))+']'
    for identity,custom,custom_bits,message,message_bits,block,out_bits,expected in selected:
        last = ((out_bits-1)%8+1) if out_bits else 0
        rows.append(f'check_case({identities.index(identity)+1},{block},{array(custom)},'
                    f'{custom_bits},{array(message)},{message_bits},{array(expected)},{last});')
        vectors.append(' '.join(map(str,('D',identities.index(identity)+1,block,custom_bits,message_bits,last,
            custom.hex() or '-',message.hex() or '-',expected.hex() or '-'))))
    rows.append('}')
    retained=['#[test]', 'fn independent_retained_oracle() {']
    for source in range(1,5):
        for target in range(1,5):
            for last in range(1,9):
                for block in (1,7):
                    previous=oracle.parallel_hash(168 if source%2 else 136,
                        oracle.oracle.byte_bits(b'abc'),8,[],256+last,source>2)
                    expected=oracle.parallel_hash(168 if target%2 else 136,
                        oracle.oracle.byte_bits(previous)[:256+last],block,
                        oracle.oracle.byte_bits(bytes([19]))[:5],259,target>2)
                    retained.append(f'check_rehash({source},{target},{last},{block},{array(expected)});')
                    vectors.append(f'R {source} {target} {last} {block} {expected.hex()}')
    retained.append('}')
    return '\n'.join(rows)+'\n', len(selected), '\n'.join(retained)+'\n', '\n'.join(vectors)+'\n'


def build(directory, target, testing=False):
    directory=directory.resolve()
    base.build(directory,target,testing)
    for name in FILES: shutil.copyfile(SOURCE/name,directory/name)
    shutil.copyfile(HOST_WIRE,directory/'parallel_host_wire.rs')
    entry=directory/'parallel_stream.rs'
    entry.write_text(entry.read_text()+'\n#[cfg(test)]\nmod parallel_retained_tests;\n#[cfg(test)]\nmod parallel_host_wire_tests;\n')
    generated,count,retained,vectors=oracle_tests() if testing else ('',0,'','')
    (directory/'parallel-vectors.txt').write_text(vectors)
    tests=directory/'parallel_stream_tests.rs'
    tests.write_text(tests.read_text()+'\n'+generated)
    retained_tests=directory/'parallel_retained_tests.rs'
    retained_tests.write_text(retained_tests.read_text()+'\n'+retained)
    artifact=directory/('parallel-tests.exe' if 'windows' in target else 'parallel-tests') if testing else directory/'libparallel_stream.rlib'
    command=['rustc','+1.98.1','--edition=2024','--target',target,'-D','warnings',
        '-C','opt-level=2','-C','overflow-checks=yes','-C','panic='+('unwind' if testing else 'abort'),
        '-L','dependency='+str(directory),'--crate-name','parallel_stream',str(directory/'parallel_stream.rs')]
    for name in ('brynja_core','brynja_hash_sha3'):
        command+=['--extern',name+'='+str(directory/('lib'+name+'.rlib'))]
    command+=['--test'] if testing else ['--crate-type','rlib']
    command+=['-o',str(artifact)]
    run(command)
    sources=[Path(__file__),HOST_WIRE,*(SOURCE/name for name in FILES),
        ROOT/'scripts/parallelhash/check-parallelhash-differential.py',
        ROOT/'scripts/sha3/check-cshake-differential.py',ROOT/'scripts/sha3/check-sha3-bit-differential.py',
        ROOT/'crates/brynja-hash-parallel/tests/official_vectors.rs']
    hashes=json.loads((directory/'sha3-stream-build.json').read_text())['source_sha256']
    hashes.update({str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sources})
    record=dict(schema=1,status='COMPONENT_BUILD_ONLY',production_qualified=False,target=target,
        oracle_cases=count,commands=[command],source_sha256=hashes,
        artifact_sha256=hashlib.sha256(artifact.read_bytes()).hexdigest(),
        generated_tests_sha256=hashlib.sha256(tests.read_bytes()).hexdigest())
    (directory/'parallel-stream-build.json').write_text(json.dumps(record,indent=2)+'\n')
    return artifact


def image(directory):
    directory = directory.resolve()
    build(directory, 'x86_64-pc-windows-msvc')
    names = ('window_parallel_stream.c','window_guard.c','window_lock.c','synthetic.c',
             'window_rust_x64.asm','parallel_stream_worker.rs','parallel_stream_placement_tests.rs')
    for name in names: shutil.copyfile(SOURCE/name,directory/name)
    original = (SOURCE/'window_retained.c').read_text()
    anchor = '(operation & 255) > 7 || operation >> 8 > 19'
    if original.count(anchor)!=1: raise ValueError('Retained admission anchor changed')
    (directory/'window_retained.c').write_text(original.replace(anchor,
        '!(operation == 0 || operation == 3 || (operation >= 100 && operation <= 108))'))
    command = ['rustc','+1.98.1','--edition=2024','--target','x86_64-pc-windows-msvc',
        '--crate-type','staticlib','--crate-name','parallel_stream_worker','-D','warnings',
        '-C','panic=abort','-C','opt-level=2','-C','lto=fat','-C','overflow-checks=yes',
        '-L','dependency='+str(directory),str(directory/'parallel_stream_worker.rs'),
        '--emit='+','.join(kind+'='+str(directory/('normal_rust.'+suffix))
                          for kind,suffix in [('link','lib'),('asm','s'),('llvm-ir','ll')])]
    for name in ('brynja_core','brynja_hash_sha3','parallel_stream'):
        command+=['--extern',name+'='+str(directory/('lib'+name+'.rlib'))]
    run(command)
    (directory/'link.cmd').write_text('@echo off\nsetlocal\n'
        'if "%VCToolsInstallDir%"=="" exit /b 90\ncd /d "%~dp0"\n'
        'ml64 /nologo /c /Fowindow.obj window_rust_x64.asm\nif errorlevel 1 exit /b 1\n'
        'cl /nologo /std:c11 /LD /O2 /W4 /WX /MT /guard:cf /Fonormal.obj /Fenormal.dll '
        'window_parallel_stream.c window.obj normal_rust.lib /link /ENCLAVE /NODEFAULTLIB '
        '/INCREMENTAL:NO /INTEGRITYCHECK /GUARD:MIXED '
        '/LIBPATH:"%VCToolsInstallDir%lib\\x64\\enclave" '
        '/LIBPATH:"%WindowsSdkDir%Lib\\%WindowsSDKVersion%ucrt_enclave\\x64" '
        'libcmt.lib libvcruntime.lib ucrt.lib vertdll.lib bcrypt.lib\n'
        'if errorlevel 1 exit /b 1\n'
        '"%WindowsSdkDir%bin\\%WindowsSDKVersion%x64\\veiid.exe" normal.dll\n'
        'exit /b %ERRORLEVEL%\n')
    record=json.loads((directory/'parallel-stream-build.json').read_text())
    record['commands'].append(command)
    record['source_sha256'].update({'assurance/windows-enclave-probe/'+name:
        hashlib.sha256((SOURCE/name).read_bytes()).hexdigest() for name in (*names,'window_retained.c')})
    record['generated_sha256']={p.name:hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(directory.iterdir()) if p.suffix in ('.rs','.c','.asm','.lib','.s','.ll')}
    (directory/'parallel-worker-build.json').write_text(json.dumps(record,indent=2)+'\n')
    return directory/'normal_rust.lib'


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory',type=Path)
    parser.add_argument('--target',default='x86_64-pc-windows-msvc')
    parser.add_argument('--test',action='store_true')
    parser.add_argument('--image',action='store_true')
    args=parser.parse_args()
    if args.image and args.test: parser.error('--image and --test are separate products')
    print(image(args.directory) if args.image else build(args.directory,args.target,args.test))
