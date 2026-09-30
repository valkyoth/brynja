#!/usr/bin/env python3
"""Build the lifetime-bound SHA-NI component, not a shipping enclave image."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT/'assurance/windows-enclave-probe'
FILES = ('sha2_accelerated.rs', 'sha2_accelerated_state.rs', 'sha2_accelerated_tests.rs',
         'sha2_accelerated_wire.rs', 'sha2_accelerated_wire_tests.rs',
         'sha2_accelerated_resident.rs', 'sha2_accelerated_resident_tests.rs',
         'sha2_stream.rs', 'sha2_stream_state.rs')


def build(directory, target):
    directory.mkdir()
    for name in FILES:
        shutil.copyfile(SOURCE/name, directory/name)
    common = ['rustc','+1.98.1','--edition=2024','--target',target,'-D','warnings',
              '-C','opt-level=2','-C','overflow-checks=yes','-C','panic=unwind',
              '-C','target-feature=+sha,+sse2,+avx,+avx2','-L','dependency='+str(directory)]
    commands=[]
    def compile(command):
        result=subprocess.run(command,capture_output=True,text=True,timeout=120)
        if result.returncode: raise RuntimeError(result.stdout+result.stderr)
        commands.append(command)
    crates=('brynja-core','brynja-hash-core','brynja-crypto-cpu','brynja-hash-sha2')
    for name in crates:
        crate=name.replace('-','_')
        command=common+['--crate-type','rlib','--crate-name',crate,str(ROOT/'crates'/name/'src/lib.rs'),
                        '-o',str(directory/('lib'+crate+'.rlib'))]
        features=[];dependencies=[]
        if name=='brynja-crypto-cpu':
            dependencies=['brynja_core'];features=['static-execution','hardened-execution']
        if name=='brynja-hash-sha2':
            dependencies=['brynja_core','brynja_hash_core','brynja_crypto_cpu']
            features=['cpu','static-execution','hardened-execution','general-sha512-t']
        for feature in features:command+=['--cfg',f'feature="{feature}"']
        for dep in dependencies:command+=['--extern',dep+'='+str(directory/('lib'+dep+'.rlib'))]
        compile(command)
    dependencies=['brynja_core','brynja_hash_sha2']
    for name in ('sha2_stream','sha2_accelerated'):
        if name=='sha2_accelerated':dependencies+=['sha2_stream','brynja_crypto_cpu']
        command=common+['--crate-type','rlib','--crate-name',name,str(directory/(name+'.rs')),
                        '-o',str(directory/('lib'+name+'.rlib'))]
        for dep in dependencies:command+=['--extern',dep+'='+str(directory/('lib'+dep+'.rlib'))]
        compile(command)
    rows=['\n#[test]\nfn independent_hashlib_byte_oracle() {']
    for identity, name in ((1,'sha224'),(2,'sha256')):
        for length in (0,1,55,56,63,64,65,119,120,127,128,129,1023,1024,2049,1_000_000):
            data=bytes((i*17)%256 for i in range(length))
            expected=list(hashlib.new(name,data).digest())
            rows.append('{ let authority=make_authority(); let mut owner=Owner::new(&authority).unwrap();'
                        f' let input: Vec<u8>=(0..{length}).map(|i| (i as u8).wrapping_mul(17)).collect();'
                        f' owner.begin(1,{identity}).unwrap(); let mut sequence=1;'
                        ' for chunk in input.chunks(1024) {sequence+=1;owner.update(sequence,chunk).unwrap();}'
                        ' sequence+=1;owner.finish(sequence,&[],0).unwrap();sequence+=1;'
                        f' owner.export_public(sequence,{identity},|bytes| {{assert_eq!(bytes,&{expected});true}}).unwrap(); }}')
    rows.append('}\n')
    tests=directory/'sha2_accelerated_tests.rs'
    tests.write_text(tests.read_text()+'\n'.join(rows))
    command=common+['--test','--crate-name','sha2_accelerated',str(directory/'sha2_accelerated.rs'),
                    '-o',str(directory/'sha2-accelerated-test')]
    for dep in dependencies:command+=['--extern',dep+'='+str(directory/('lib'+dep+'.rlib'))]
    compile(command)
    resident=common+['--crate-name','sha2_accelerated_resident',str(directory/'sha2_accelerated_resident.rs')]
    for dep in ('sha2_accelerated','brynja_crypto_cpu','brynja_hash_sha2'):
        resident+=['--extern',dep+'='+str(directory/('lib'+dep+'.rlib'))]
    compile(resident+['--crate-type','rlib','-o',str(directory/'libsha2_accelerated_resident.rlib')])
    resident+=['--test','-o',str(directory/'sha2-resident-test')]
    compile(resident)
    sources={'scripts/cryptography/windows_enclave_sha2_accelerated_build.py',
             'scripts/cryptography/test-windows-enclave-sha2-accelerated.py'}
    sources.update('assurance/windows-enclave-probe/'+name for name in FILES)
    for crate in crates:
        sources.add(f'crates/{crate}/Cargo.toml')
        sources.update(p.relative_to(ROOT).as_posix() for p in (ROOT/'crates'/crate/'src').rglob('*.rs'))
    record=dict(status='COMPONENT_ONLY',production_qualified=False,target=target,commands=commands,
                resident_test_command=resident,
                source_sha256={name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in sorted(sources)})
    (directory/'sha2-accelerated-build.json').write_text(json.dumps(record,indent=2)+'\n')
    return command


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory',type=Path)
    parser.add_argument('--target',default='x86_64-pc-windows-msvc')
    args=parser.parse_args()
    build(args.directory.resolve(),args.target)
