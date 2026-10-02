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
FILES=('sha512_simd_resident.rs','sha512_simd_worker.rs','sha512_simd_wire.rs','sha512_simd_worker_tests.rs')
SPEC=importlib.util.spec_from_file_location('simd_component',Path(__file__).with_name('test-windows-enclave-sha512-simd.py'))
base=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(base)
def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()

def run(directory):
    directory.mkdir(parents=True,exist_ok=False)
    component=directory/'component'
    base.check(component)
    record=json.loads((component/'sha512-simd-results.json').read_text())
    common=record['commands'][-1]
    common=common[:common.index('--crate-name')]+['-L','dependency='+str(directory)]
    for name in FILES: shutil.copyfile(SOURCE/name,directory/name)
    generated,count=base.oracle_tests()
    anchor='    for &(layout,expected) in cases {'
    assert generated.count(anchor)==1
    generated=generated.split(anchor)[0]+'''    for &(layout,expected) in cases {
        let mut page=Box::new(Page::empty());
        let pointer=(&mut *page as *mut Page).cast();
        assert_eq!(invoke(0,pointer),1);
        request(DIGEST,1,layout);
        assert_eq!(invoke(DIGEST,pointer),success(DIGEST));
        request(EXPORT,2,layout);
        assert_eq!(invoke(EXPORT,pointer),success(EXPORT));
        assert_eq!(IO.lock().unwrap().output,expected,"layout={layout:?}");
        destroy(pointer);
    }
}
'''
    tests=directory/FILES[-1]
    tests.write_text(tests.read_text()+generated)
    sources=dict(record['source_sha256'])
    sources.update({p.relative_to(ROOT).as_posix():digest(p) for p in [SOURCE/name for name in FILES]+[Path(__file__).resolve()]})
    commands=[]
    def compile(command):
        base.run(command); commands.append(command)
    def deps(names):
        return [part for name in names for part in ('--extern',name+'='+str(
            (directory if name=='sha512_simd_resident' else component)/('lib'+name+'.rlib')))]
    compile(common+['--crate-name','sha512_simd_resident','--crate-type','rlib',str(directory/FILES[0]),
        '-o',str(directory/'libsha512_simd_resident.rlib')]+deps(('sha512_simd','brynja_hash_sha2')))
    invocation=common+['--crate-name','sha512_simd_worker','--test',str(directory/FILES[1])]+deps(
        ('sha512_simd_resident','sha512_simd','brynja_hash_sha2','brynja_core'))
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
        (FILES[1],'source, 160) } != 0','source, 160) } == 99'),
        (FILES[1],'} != 0\n            {','} == 99\n            {'),
        (FILES[1],'PublicSha512SimdOutput(bytes.as_ptr(), bytes.len()) == 0',
         'PublicSha512SimdOutput(bytes.as_ptr(), bytes.len()) != 99'),
        (FILES[1],'high.checked_sub(low) != Some(65536)','high.checked_sub(low) == Some(0)'),
        (FILES[1],'owner.quarantine();\n            return 201;','core::hint::black_box(owner);\n            return 201;'),
        (FILES[1],'if *identity != address {','if *identity != address && false {'),
        (FILES[1],'if !ok {','if !ok && false {'),
        (FILES[1],'if !cleared || unsafe','if !cleared && unsafe'),
        (FILES[1],'brynja_core::clear_owned_region(&mut self.header)','core::hint::black_box(&mut self.header)'),
        (FILES[1],'brynja_core::clear_owned_region(self.payload.as_flattened_mut())','core::hint::black_box(self.payload.as_flattened_mut())'),
        (FILES[1],'.digest(request.sequence, lanes, request.budget)', '.digest(request.sequence, lanes, request.budget.saturating_add(1000))'),
        (FILES[2],'words[0] != 20','words[0] != 20 && false'),
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
    result=dict(status='BOUNDED_SHA512_AVX2_WORKER_DOUBLES_PASS',target=record['target'],
        enclave_execution=False,production_qualified=False,independent_cases=count,lane_comparisons=count*4,
        tests=2,initial=initial,final=final,mutations=mutations,commands=commands,
        source_sha256=sources,generated_sha256={name:digest(directory/name) for name in FILES},
        component_record_sha256=digest(component/'sha512-simd-results.json'))
    (directory/'sha512-simd-worker-results.json').write_text(json.dumps(result,indent=2)+'\n')
    print('SHA512 SIMD worker: 602 oracle cases; bounded copies/rollback; 14 compiled mutants PASS')

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory',type=Path)
    parser.add_argument('--attest-native-avx2',action='store_true',required=True)
    run(parser.parse_args().directory.resolve())
