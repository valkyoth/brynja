#!/usr/bin/env python3
"""Bounded SIMD worker with OS-copy doubles; not native VBS qualification."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil

ROOT=Path(__file__).resolve().parents[2]
SOURCE=ROOT/'assurance/windows-enclave-probe'
FILES=('keccak_simd_resident.rs','keccak_simd_worker.rs','keccak_simd_wire.rs','keccak_simd_worker_tests.rs','keccak_simd_worker_oracles.rs')
SPEC=importlib.util.spec_from_file_location('simd_component',Path(__file__).with_name('test-windows-enclave-keccak-simd.py'))
base=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(base)
def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()

def run(directory):
    directory.mkdir(parents=True,exist_ok=False)
    component=directory/'component'
    base.check(component)
    record=json.loads((component/'keccak-simd-results.json').read_text())
    common=record['commands'][-1]
    common=common[:common.index('--crate-name')]+['-L','dependency='+str(directory)]
    for name in FILES: shutil.copyfile(SOURCE/name,directory/name)
    count=record['independent_cases']
    shutil.copyfile(component/'keccak-simd-vectors.txt',directory/'keccak-simd-vectors.txt')
    sources=dict(record['source_sha256'])
    sources.update({p.relative_to(ROOT).as_posix():digest(p) for p in [SOURCE/name for name in FILES]+[Path(__file__).resolve()]})
    commands=[]
    def compile(command):
        base.run(command); commands.append(command)
    def deps(names):
        return [part for name in names for part in ('--extern',name+'='+str(
            (directory if name=='keccak_simd_resident' else component)/('lib'+name+'.rlib')))]
    compile(common+['--crate-name','keccak_simd_resident','--crate-type','rlib',str(directory/FILES[0]),
        '-o',str(directory/'libkeccak_simd_resident.rlib')]+deps(('keccak_simd','brynja_hash_sha3')))
    invocation=common+['--crate-name','keccak_simd_worker','--test',str(directory/FILES[1])]+deps(
        ('keccak_simd_resident','keccak_simd','brynja_hash_sha3','brynja_core'))
    suffix='.exe' if 'windows' in record['target'] else ''
    def execute(label,success):
        binary=directory/(label+suffix)
        assert not binary.exists()
        compile(invocation+['-o',str(binary)])
        output=base.run([str(binary),'--test-threads=1'],success)
        assert ('2 passed; 0 failed' if success else 'FAILED') in output,output
        return dict(binary=binary.name,binary_sha256=digest(binary),output=output)
    initial=execute('initial',True)
    mutations=[]
    for name,before,after in (
        (FILES[1],'source, 384) } != 0','source, 384) } == 99'),
        (FILES[1],'} != 0\n            {','} == 99\n            {'),
        (FILES[1],'PublicKeccakSimdOutput(bytes.as_ptr(), bytes.len()) == 0',
         'PublicKeccakSimdOutput(bytes.as_ptr(), bytes.len()) != 99'),
        (FILES[1],'high.checked_sub(low) != Some(65536)','high.checked_sub(low) == Some(0)'),
        (FILES[1],'owner.quarantine();\n            return 201;','core::hint::black_box(owner);\n            return 201;'),
        (FILES[1],'if *identity != address {','if *identity != address && false {'),
        (FILES[1],'if !ok {','if !ok && false {'),
        (FILES[1],'if !cleared || unsafe','if !cleared && unsafe'),
        (FILES[1],'brynja_core::clear_owned_region(&mut self.header)','core::hint::black_box(&mut self.header)'),
        (FILES[1],'brynja_core::clear_owned_region(self.payload.as_flattened_mut())','core::hint::black_box(self.payload.as_flattened_mut())'),
        (FILES[1],'.digest(request.sequence, lanes, request.budget)', '.digest(request.sequence, lanes, request.budget.saturating_add(1000))'),
        (FILES[2],'words[0] != 22','words[0] != 22 && false'),
        (FILES[2],'words[3] != 2','words[3] != 2 && false'),
        (FILES[2],'operation != DIGEST && words[2] != 0','operation != DIGEST && words[2] != 0 && false'),
    ):
        path=directory/name; original=path.read_bytes()
        assert original.decode().count(before)==1,before
        print('SIMD_WORKER_MUTATION: '+before,flush=True)
        try:
            path.write_text(original.decode().replace(before,after))
            mutations.append(dict(file=name,before=before,after=after,**execute(f'mutant-{len(mutations)}',False)))
        finally: path.write_bytes(original)
    final=execute('restored',True)
    assert all(digest(ROOT/name)==expected for name,expected in sources.items()),'Source drift'
    result=dict(status='BOUNDED_KECCAK_AVX2_WORKER_DOUBLES_PASS',target=record['target'],
        enclave_execution=False,production_qualified=False,independent_cases=count,lane_comparisons=count*4,
        tests=2,initial=initial,final=final,mutations=mutations,commands=commands,
        source_sha256=sources,generated_sha256={name:digest(directory/name) for name in (*FILES,'keccak-simd-vectors.txt')},
        component_record_sha256=digest(component/'keccak-simd-results.json'))
    (directory/'keccak-simd-worker-results.json').write_text(json.dumps(result,indent=2)+'\n')
    print(f'KECCAK SIMD worker: {count} oracle cases; bounded copies/rollback; 14 compiled mutants PASS')

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory',type=Path)
    parser.add_argument('--attest-native-avx2',action='store_true',required=True)
    run(parser.parse_args().directory.resolve())
