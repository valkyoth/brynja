#!/usr/bin/env python3
"""Private bounded AVX2 component tests; not VBS/whole-image qualification."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import windows_enclave_keccak_simd_oracle as oracle

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT/'assurance/windows-enclave-probe'
MUTATIONS = (
    ('lane.message.bit_len() > 8192', 'false'),
    ('lane.name.bit_len() > 8192', 'false'),
    ('lane.custom.bit_len() > 8192', 'false'),
    ('lane.slot.output_bits > 2048', 'false'),
    ('lane.name,\n                    lane.custom,',
     'Fips202BitString::new(&[], 0).unwrap(),\n                    Fips202BitString::new(&[], 0).unwrap(),'),
    ('Control::new(budget,', 'Control::new(budget.saturating_add(1000),'),
    ('self.sequence.checked_add(1) != Some(sequence)', 'false'),
    ('self.phase != phase', 'self.phase == Phase::Quarantined && phase == Phase::Empty'),
    ('guard.owner.plan != Some(plan)', 'guard.owner.plan.is_none() && plan.is_empty()'),
    ('if !copy(&guard.owner.output)', 'if copy(&guard.owner.output) && false'),
    ('check(guard.owner.authority)?;', 'core::hint::black_box(guard.owner.authority);'),
    ('let _ = clear_owned_region(&mut self.output);', 'core::hint::black_box(&mut self.output);'),
    ('self.authority.quarantine();', 'core::hint::black_box(self.authority);'),
    ('if !self.complete {', 'if false && !self.complete {'),
)


def run(command, success=True):
    r = subprocess.run(command, capture_output=True, text=True, timeout=240)
    if (r.returncode == 0) != success:
        raise RuntimeError(str(command)+'\n'+r.stdout+r.stderr)
    return r.stdout+r.stderr


def check(directory):
    directory.mkdir(parents=True, exist_ok=False)
    target=run(['rustc','+1.98.1','-vV']).split('host: ')[1].splitlines()[0]
    if not target.startswith('x86_64-'): raise ValueError('native x86-64 required')
    common=['rustc','+1.98.1','--edition=2024','--target',target,'-D','warnings',
            '-C','opt-level=2','-C','overflow-checks=yes','-C','panic=unwind',
            '-C','target-feature=+avx,+avx2','-L','dependency='+str(directory)]
    commands=[]; sources={Path(__file__).resolve()}
    crates=('brynja-core','brynja-hash-core','brynja-crypto-cpu','brynja-hash-sha3')
    def compile(command): run(command); commands.append(command)
    for name in crates:
        crate=name.replace('-','_'); deps=[]; features=[]
        if name=='brynja-crypto-cpu': deps=['brynja_core']; features=['keccak-hardened-batch']
        if name=='brynja-hash-sha3':
            deps=['brynja_core','brynja_hash_core','brynja_crypto_cpu']
            features=['cpu','hardened-batch-execution']
        command=common+['--crate-name',crate,'--crate-type','rlib',str(ROOT/'crates'/name/'src/lib.rs'),'-o',str(directory/('lib'+crate+'.rlib'))]
        for feature in features: command += ['--cfg',f'feature="{feature}"']
        for dep in deps: command += ['--extern',dep+'='+str(directory/('lib'+dep+'.rlib'))]
        compile(command)
        sources.add(ROOT/'crates'/name/'Cargo.toml')
        sources.update((ROOT/'crates'/name/'src').rglob('*.rs'))
    for name in ('keccak_simd.rs','keccak_simd_tests.rs','keccak_simd_oracle_tests.rs'):
        sources.add(SOURCE/name); shutil.copyfile(SOURCE/name,directory/name)
    count=oracle.generate(directory)
    sources.update(ROOT/name for name in oracle.SOURCES)
    source_hashes={p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(sources)}
    source=directory/'keccak_simd.rs'
    deps=['--extern','brynja_core='+str(directory/'libbrynja_core.rlib'),
          '--extern','brynja_hash_sha3='+str(directory/'libbrynja_hash_sha3.rlib')]
    binary=directory/('keccak-simd-test.exe' if 'windows' in target else 'keccak-simd-test')
    command=common+['--crate-name','keccak_simd','--test',str(source),'-o',str(binary)]+deps
    compile(command)
    def execute(path, success):
        output=run([str(path)],success)
        if ('8 passed; 0 failed' if success else 'FAILED') not in output: raise AssertionError(output)
        return output
    initial=execute(binary,True); mutations=[]
    # Windows may retain an executable image handle briefly after process exit.
    # Preserve every compiled variant under a fresh path; never retry a failed
    # link or treat a compiler failure as a successfully rejected mutant.
    output_index=command.index('-o')+1
    def variant(name):
        path=binary.with_name(name+binary.suffix)
        if path.exists(): raise ValueError('Refusing to overwrite test variant: '+str(path))
        changed=command.copy(); changed[output_index]=str(path)
        return changed,path
    original=source.read_bytes()
    for before,after in MUTATIONS:
        # Some mutations deliberately touch every boundary, and compile first.
        assert before in original.decode(),before
        print('SIMD_MUTATION: '+before,flush=True)
        try:
            source.write_text(original.decode().replace(before,after))
            mutated, path=variant(f'keccak-simd-mutant-{len(mutations):02}')
            compile(mutated)
            mutations.append(dict(before=before,after=after,output=execute(path,False),
                binary=path.name,binary_sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
        finally: source.write_bytes(original)
    restored,binary=variant('keccak-simd-final')
    compile(restored); final=execute(binary,True)
    library=common+['--crate-name','keccak_simd','--crate-type','rlib',str(source),'-o',str(directory/'libkeccak_simd.rlib')]+deps
    compile(library)
    negatives=[]
    for trait in ('Send','Sync','Copy','Clone','core::fmt::Debug'):
        probe=directory/'negative.rs'
        probe.write_text(f'extern crate keccak_simd; fn require<T: {trait}>() {{}} fn main() {{require::<keccak_simd::Owner>();}}')
        output=run(common+[str(probe),'--extern','keccak_simd='+str(directory/'libkeccak_simd.rlib'),'-o',str(directory/'negative')],False)
        assert 'error[E0277]' in output,output
        negatives.append(dict(trait=trait,output=output))
    probe=directory/'negative.rs'
    probe.write_text("extern crate keccak_simd; use keccak_simd::{Owner,Authority,Kernel}; fn escape()->Owner<'static> { let a=Authority::for_compiled_target(Kernel::Avx2).unwrap(); Owner::new(&a).unwrap() } fn main() { let _=escape(); }")
    output=run(common+[str(probe),'--extern','keccak_simd='+str(directory/'libkeccak_simd.rlib'),'-o',str(directory/'negative')],False)
    assert 'error[E0515]' in output,output
    negatives.append(dict(trait='owner cannot outlive authority',output=output))
    assert source_hashes == {p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}, 'Source changed during capture'
    record=dict(status='BOUNDED_KECCAK_AVX2_COMPONENT_PASS',production_qualified=False,enclave_execution=False,
        target=target,independent_cases=count,lane_comparisons=count*4,tests=8,initial=initial,final=final,
        mutations=mutations,ownership_negatives=negatives,commands=commands,
        source_sha256=source_hashes,
        generated_sha256={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in directory.iterdir() if p.suffix in ('.rs','.txt')},
        binary=binary.name,binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest())
    (directory/'keccak-simd-results.json').write_text(json.dumps(record,indent=2)+'\n')
    print(f'Bounded KECCAK AVX2: {count} independent cases; {count*4} lane comparisons; {len(mutations)} mutants; {len(negatives)} ownership negatives PASS')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory',type=Path)
    parser.add_argument('--attest-native-avx2',action='store_true',required=True)
    check(parser.parse_args().directory.resolve())
