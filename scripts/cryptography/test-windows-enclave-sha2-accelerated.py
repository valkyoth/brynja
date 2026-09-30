#!/usr/bin/env python3
"""Explicit native-bundle component checks; no release-gate changes."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

import windows_enclave_sha2_accelerated_build as build


def compile_checked(command):
    result=subprocess.run(command,capture_output=True,text=True,timeout=120)
    if result.returncode:
        raise RuntimeError(result.stdout+result.stderr)

MUTANTS=(
    ('sha2_accelerated.rs','self.phase != phase || self.phase == Phase::Quarantined','self.phase == Phase::Quarantined'),
    ('sha2_accelerated.rs','self.sequence.checked_add(1) != Some(sequence)','false'),
    ('sha2_accelerated.rs','check_authority(guard.owner.authority)?;',''),
    ('sha2_accelerated.rs','self.authority.quarantine();',''),
    ('sha2_accelerated.rs','self.owner.quarantine();',''),
    ('sha2_accelerated.rs','clear_owned_region(&mut self.output)','clear_owned_region(&mut self.output[..0])'),
    ('sha2_accelerated.rs','input.len() > 1024','input.len() > 2048'),
    ('sha2_accelerated.rs','algorithm.encode() != identity','false'),
    ('sha2_accelerated.rs','if !copy(','if false && !copy('),
    ('sha2_accelerated_state.rs','Execution::from_static(authority).map_err(|_| Error::Backend)?','Execution::portable()'),
    ('sha2_accelerated_wire.rs','version != 13','false'),
    ('sha2_accelerated_wire.rs','route != 1','false'),
    ('sha2_accelerated_wire.rs','reserved != 0','false'),
    ('sha2_accelerated_wire.rs','source.checked_add(length).is_none()','false'),
    ('sha2_accelerated_wire.rs','input.len() != self.length','false'),
)


def run(directory,target):
    command=build.build(directory,target)
    binary=directory/'sha2-accelerated-test'
    def execute(success):
        result=subprocess.run([str(binary)],capture_output=True,text=True,timeout=120)
        if (result.returncode==0)!=success or ('9 passed; 0 failed' if success else 'FAILED') not in result.stdout:
            raise AssertionError(result.stdout+result.stderr)
        return result.stdout
    initial=execute(True)
    print(initial,flush=True)
    mutations=[]
    for name,before,after in MUTANTS:
        path=directory/name;original=path.read_text()
        if before not in original:raise AssertionError('Stale mutation: '+before)
        try:
            path.write_text(original.replace(before,after))
            subprocess.run(command+['-A','unused_variables'],check=True,capture_output=True,text=True,timeout=120)
            mutations.append(dict(source=name, before=before, after=after, output=execute(False)))
        finally:path.write_text(original)
    subprocess.run(command,check=True,capture_output=True,text=True,timeout=120)
    final=execute(True)
    print(final,flush=True)
    # Compile actual ownership violations against the real component library.
    common=command[:command.index('--test')]
    deps=[]
    for dep in ('sha2_accelerated','brynja_crypto_cpu'):
        deps+=['--extern',dep+'='+str(directory/('lib'+dep+'.rlib'))]
    probes=[f'fn bound<T:{trait}>(){{}} fn main(){{bound::<sha2_accelerated::Owner<\'static>>();}}'
            for trait in ('Send','Sync','Copy','Clone','core::fmt::Debug')]
    probes.append('fn main(){let owner={let authority=brynja_crypto_cpu::static_execution::Authority::new('
                  'brynja_crypto_cpu::static_execution::Kernel::X86Sha256).unwrap();'
                  'sha2_accelerated::Owner::new(&authority).unwrap()};drop(owner);}')
    positive=directory/'positive.rs'
    positive.write_text('fn main(){let a=brynja_crypto_cpu::static_execution::Authority::new('
                        'brynja_crypto_cpu::static_execution::Kernel::X86Sha256).unwrap();'
                        'let o=sha2_accelerated::Owner::new(&a).unwrap();drop(o);}')
    subprocess.run(common+deps+[str(positive),'--emit=metadata','-o',str(directory/'positive.rmeta')],
                   check=True,capture_output=True,text=True,timeout=120)
    negatives=[]
    for i,probe in enumerate(probes):
        path=directory/f'negative_{i}.rs';path.write_text(probe)
        result=subprocess.run(common+deps+[str(path),'--emit=metadata','-o',str(directory/f'negative_{i}.rmeta')],
                              capture_output=True,text=True,timeout=120)
        code='E0597' if i==5 else 'E0277'
        if result.returncode==0 or code not in result.stderr:raise AssertionError(result.stderr)
        negatives.append(dict(source=probe, error_code=code, diagnostics=result.stderr))
    resident_command=json.loads((directory/'sha2-accelerated-build.json').read_text())['resident_test_command']
    resident_binary=directory/'sha2-resident-test'
    def resident_run(success):
        result=subprocess.run([str(resident_binary)],capture_output=True,text=True,timeout=120)
        if (result.returncode==0)!=success or ('4 passed; 0 failed' if success else 'FAILED') not in result.stdout:
            raise AssertionError(result.stdout+result.stderr)
        return result.stdout
    resident_initial=resident_run(True)
    resident_path=directory/'sha2_accelerated_resident.rs'
    original=resident_path.read_text()
    resident_mutations=[]
    for before,after in (
        ('owner.quarantine();',''),
        ('unsafe { self.owner.as_mut() }.quarantine();','let _ = unsafe { self.owner.as_mut() };'),
        ('pointer.as_ptr().add(offset).write_volatile(0)','pointer.as_ptr().add(offset).write_volatile(0xa5)'),
    ):
        if before not in original:raise AssertionError('Stale placement mutation: '+before)
        try:
            resident_path.write_text(original.replace(before,after))
            compile_checked(resident_command)
            resident_mutations.append(dict(before=before,after=after,output=resident_run(False)))
        finally:resident_path.write_text(original)
    subprocess.run(resident_command,check=True,capture_output=True,text=True,timeout=120)
    resident_final=resident_run(True)
    print(resident_final,flush=True)
    resident_probes=[f'fn bound<T:{trait}>(){{}} fn main(){{bound::<sha2_accelerated_resident::Resident<\'static>>();}}'
                     for trait in ('Send','Sync','Copy','Clone','core::fmt::Debug')]
    resident_probes.append('fn main(){let resident={let mut page=sha2_accelerated_resident::Page::empty();'
                           'sha2_accelerated_resident::Resident::new(&mut page).unwrap()};drop(resident);}')
    resident_probes.append('fn main(){let mut page=sha2_accelerated_resident::Page::empty();'
                           'let resident=sha2_accelerated_resident::Resident::new(&mut page).unwrap();'
                           'drop(page);drop(resident);}')
    resident_negatives=[]
    for i,probe in enumerate(resident_probes):
        path=directory/f'resident_negative_{i}.rs';path.write_text(probe)
        result=subprocess.run(common+['--extern','sha2_accelerated_resident='+str(directory/'libsha2_accelerated_resident.rlib'),
                              str(path),'--emit=metadata','-o',str(directory/f'resident_negative_{i}.rmeta')],
                              capture_output=True,text=True,timeout=120)
        code='E0597' if i==5 else 'E0505' if i==6 else 'E0277'
        if result.returncode==0 or code not in result.stderr:raise AssertionError(result.stderr)
        resident_negatives.append(dict(source=probe,error_code=code,diagnostics=result.stderr))
    record=dict(schema=1, status='COMPONENT_TESTS_PASS', enclave_execution=False,
                production_qualified=False, target=target,
                compiler=subprocess.check_output(['rustc','+1.98.1','-vV'],text=True),
                initial=initial, final=final, mutations=mutations, negatives=negatives,
                resident_initial=resident_initial,resident_final=resident_final,
                resident_mutations=resident_mutations,resident_negatives=resident_negatives,
                build_sha256=hashlib.sha256((directory/'sha2-accelerated-build.json').read_bytes()).hexdigest(),
                binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest())
    (directory/'sha2-accelerated-results.json').write_text(json.dumps(record,indent=2)+'\n')
    print('Nine accelerated component tests; fifteen compiled mutants and six ownership negatives rejected',flush=True)
    print('Four placement tests; three compiled mutants and seven ownership negatives rejected',flush=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory',type=Path)
    parser.add_argument('--attest-native-bundle',action='store_true',required=True)
    args=parser.parse_args()
    target=subprocess.check_output(['rustc','+1.98.1','-vV'],text=True).split('host: ')[1].splitlines()[0]
    if not target.startswith('x86_64-'):parser.error('Native x86-64 SHA/SSE2/AVX/AVX2 required')
    run(args.directory.resolve(),target)
