#!/usr/bin/env python3
"""Real AVX2 page-placement tests, separate from OS/VBS qualification."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess

ROOT=Path(__file__).resolve().parents[2]
SOURCE=ROOT/'assurance/windows-enclave-probe'
FILES=('sha256_simd_resident.rs','sha256_simd_resident_tests.rs')
SPEC=importlib.util.spec_from_file_location('simd_component',Path(__file__).with_name('test-windows-enclave-sha256-simd.py'))
base=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(base)
def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()

def run(directory):
    directory.mkdir(parents=True,exist_ok=False)
    component=directory/'component'
    base.check(component)
    record=json.loads((component/'sha256-simd-results.json').read_text())
    common=record['commands'][-1]
    common=common[:common.index('--crate-name')]
    for name in FILES: shutil.copyfile(SOURCE/name,directory/name)
    generated,count=base.oracle_tests()
    before='let a=authority(); let mut owner=Owner::new(&a).unwrap();'
    assert generated.count(before)==1 and generated.count('cleared(&owner);')==1
    generated=generated.replace(before,'let mut page=Box::new(Page([MaybeUninit::new(0xa5);PAGE_BYTES])); let mut owner=Resident::new(&mut page).unwrap();')
    generated=generated.replace('cleared(&owner);','drop(owner); cleared(&page);')
    tests=directory/FILES[1]
    tests.write_text(tests.read_text()+generated)
    sources=dict(record['source_sha256'])
    sources.update({p.relative_to(ROOT).as_posix():digest(p) for p in [SOURCE/name for name in FILES]+[Path(__file__).resolve()]})
    deps=[part for name in ('sha256_simd','brynja_hash_sha2') for part in
          ('--extern',name+'='+str(component/('lib'+name+'.rlib')))]
    compile_base=common+['--crate-name','sha256_simd_resident',str(directory/FILES[0])]+deps
    commands=[]
    def compile(command):
        output=base.run(command)
        commands.append(command)
        return output
    suffix='.exe' if 'windows' in record['target'] else ''
    def execute(label,expected):
        binary=directory/(label+suffix)
        assert not binary.exists()
        command=compile_base+['--test','-o',str(binary)]
        compile(command)
        output=base.run([str(binary)],expected)
        if ('4 passed; 0 failed' if expected else 'FAILED') not in output: raise AssertionError(output)
        return dict(output=output,binary=binary.name,binary_sha256=digest(binary))
    initial=execute('initial',True)
    path=directory/FILES[0]
    original=path.read_bytes()
    mutations=[]
    for before,after in (
        ('unsafe { self.owner.as_mut() }.quarantine();','let _ = self.owner;'),
        ('pointer.as_ptr().add(offset).write_volatile(0)','pointer.as_ptr().add(offset).write_volatile(0xa5)'),
        ('for offset in 0..PAGE_BYTES','for offset in 0..PAGE_BYTES - 1'),
        ('.digest(sequence, lanes, budget)','.digest(sequence, lanes, budget.saturating_add(1000))'),
    ):
        assert original.decode().count(before)==1,before
        print('SIMD_RESIDENT_MUTATION: '+before,flush=True)
        try:
            path.write_text(original.decode().replace(before,after))
            mutations.append(dict(before=before,after=after,**execute(f'mutant-{len(mutations)}',False)))
        finally: path.write_bytes(original)
    final=execute('restored',True)
    library=directory/'libsha256_simd_resident.rlib'
    compile(compile_base+['--crate-type','rlib','-o',str(library)])
    negatives=[]
    for name,source,code in [
        *[(trait,'fn need<T: '+trait+'>() {} fn main() {need::<Resident>();}','E0277')
          for trait in ('Send','Sync','Copy','Clone','core::fmt::Debug')],
        ('escape',"fn escape()->Resident<'static> {let mut p=Page::empty(); Resident::new(&mut p).unwrap()} fn main() {}",'E0515'),
        ('move-page','fn main() {let mut p=Page::empty(); let r=Resident::new(&mut p).unwrap(); drop(p); drop(r);}','E0505'),
        ('reuse-page','fn main() {let mut p=Page::empty(); let r=Resident::new(&mut p).unwrap(); let s=Resident::new(&mut p).unwrap(); drop(r); drop(s);}','E0499'),
    ]:
        probe=directory/'negative.rs'
        probe.write_text('use sha256_simd_resident::{Resident,Page};\n'+source)
        output=base.run(common+['-A','unused_imports','--crate-name','negative',str(probe),'--emit=metadata',
            '-o',str(directory/'negative.rmeta'),'--extern','sha256_simd_resident='+str(library)],False)
        assert code in output,output
        negatives.append(dict(name=name,diagnostic=code,output=output))
    assert all(digest(ROOT/name)==expected for name,expected in sources.items()),'Source drift'
    record=dict(status='BOUNDED_SHA256_AVX2_RESIDENT_PASS',target=record['target'],
        enclave_execution=False,production_qualified=False,independent_cases=count,lane_comparisons=count*8,
        tests=4,initial=initial,final=final,mutations=mutations,negatives=negatives,commands=commands,
        source_sha256=sources,generated_sha256={name:digest(directory/name) for name in FILES},
        component_record_sha256=digest(component/'sha256-simd-results.json'))
    (directory/'sha256-simd-resident-results.json').write_text(json.dumps(record,indent=2)+'\n')
    print(f'SHA256 SIMD resident: {count} independent cases; full-page clearing; 4 mutants; 8 ownership negatives PASS')

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory',type=Path)
    parser.add_argument('--attest-native-avx2',action='store_true',required=True)
    run(parser.parse_args().directory.resolve())
