#!/usr/bin/env python3
"""Private bounded AVX2 component tests; not VBS/whole-image qualification."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT/'assurance/windows-enclave-probe'


def run(command, success=True):
    r = subprocess.run(command, capture_output=True, text=True, timeout=240)
    if (r.returncode == 0) != success:
        raise RuntimeError(str(command)+'\n'+r.stdout+r.stderr)
    return r.stdout+r.stderr


def oracle_tests():
    spec = importlib.util.spec_from_file_location('simd_bit_oracle', ROOT/'scripts/sha2/check-sha2-bit-differential.py')
    bits = importlib.util.module_from_spec(spec); spec.loader.exec_module(bits)
    # One runtime loop, rather than hundreds of separately optimized functions:
    # identical cases, much less repeated compiler work for the mutation campaign.
    rows = ['\n#[test]\nfn independent_oracles_all_identities_and_lane_isolation() {',
            'let cases: &[([(u16, usize, u8); 8], [u8; 256])] = &[']
    # Every final-bit width at the block and both padding boundaries; exact
    # maximum input, unequal lengths, and all 256 SHA-224/SHA-256 lane plans.
    cases = [[(name, size, last)]*8 for name in ('sha224','sha256')
        for size in (64,65,119,120,127,128,129,255,1023,1024)
        for last in range(1,9) if not (size==64 and last!=8)]
    lengths = (65,119,120,127,128,129,1023,1024)
    cases += [[('sha256' if mask & (1<<lane) else 'sha224',
                lengths[(mask+lane*3)%8], 1+(mask+lane)%8)
               for lane in range(8)] for mask in range(256)]
    for lanes in cases:
        expected, layout = [], []
        for lane, (identity,size,last) in enumerate(lanes):
            data = bytearray((i*17+lane*29) % 256 for i in range(size))
            data[-1] &= (255 << (8-last)) & 255
            nbits=(size-1)*8+last
            answer = bytes.fromhex(bits.digest32(data,nbits,*bits.CONFIG[identity]))
            if last==8: assert answer == hashlib.new(identity,data).digest()
            expected.extend(answer.ljust(32,b'\0'))
            code = {'sha224':224,'sha256':256}[identity]
            layout.append(f'({code},{size},{last})')
        rows.append('(['+','.join(layout)+f'],{expected}),')
    rows += [''' ];
    for &(layout,expected) in cases {
        let plan=layout.map(|(code,_,_)| match code {
            224=>Algorithm::Sha224, 256=>Algorithm::Sha256,
            _=>panic!("invalid test identity"),
        });
        let a=authority(); let mut owner=Owner::new(&a).unwrap();
        let mut data:[[u8;1024];8]=core::array::from_fn(|lane|
            core::array::from_fn(|i|((i*17+lane*29)%256) as u8));
        for (lane,(_,size,last)) in data.iter_mut().zip(layout) {lane[size-1] &= 255 << (8-last);}
        let lanes=core::array::from_fn(|lane| Lane {
            identity:plan[lane],bytes:&data[lane][..layout[lane].1],last:layout[lane].2});
        let report=owner.digest(1,lanes,1000).unwrap();
        assert_eq!(report.kernel,Some(Kernel::Avx2));
        assert!(report.vector_calls>0);
        owner.export_public(2,plan,|out|{assert_eq!(out,&expected,"layout={layout:?}");true}).unwrap();
        cleared(&owner);
    }
}
''']
    return '\n'.join(rows), len(cases)


def check(directory):
    directory.mkdir(parents=True, exist_ok=False)
    target=run(['rustc','+1.98.1','-vV']).split('host: ')[1].splitlines()[0]
    if not target.startswith('x86_64-'): raise ValueError('native x86-64 required')
    common=['rustc','+1.98.1','--edition=2024','--target',target,'-D','warnings',
            '-C','opt-level=2','-C','overflow-checks=yes','-C','panic=unwind',
            '-C','target-feature=+avx,+avx2','-L','dependency='+str(directory)]
    commands=[]; sources={Path(__file__).resolve()}
    crates=('brynja-core','brynja-hash-core','brynja-crypto-cpu','brynja-hash-sha2')
    def compile(command): run(command); commands.append(command)
    for name in crates:
        crate=name.replace('-','_'); deps=[]; features=[]
        if name=='brynja-crypto-cpu': deps=['brynja_core']; features=['sha256-hardened-batch']
        if name=='brynja-hash-sha2':
            deps=['brynja_core','brynja_hash_core','brynja_crypto_cpu']
            features=['cpu','hardened-batch-execution']
        command=common+['--crate-name',crate,'--crate-type','rlib',str(ROOT/'crates'/name/'src/lib.rs'),'-o',str(directory/('lib'+crate+'.rlib'))]
        for feature in features: command += ['--cfg',f'feature="{feature}"']
        for dep in deps: command += ['--extern',dep+'='+str(directory/('lib'+dep+'.rlib'))]
        compile(command)
        sources.add(ROOT/'crates'/name/'Cargo.toml')
        sources.update((ROOT/'crates'/name/'src').rglob('*.rs'))
    for name in ('sha256_simd.rs','sha256_simd_tests.rs'):
        sources.add(SOURCE/name); shutil.copyfile(SOURCE/name,directory/name)
    generated,count=oracle_tests()
    tests=directory/'sha256_simd_tests.rs'; tests.write_text(tests.read_text()+generated)
    sources.add(ROOT/'scripts/sha2/check-sha2-bit-differential.py')
    source_hashes={p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(sources)}
    source=directory/'sha256_simd.rs'
    deps=['--extern','brynja_core='+str(directory/'libbrynja_core.rlib'),
          '--extern','brynja_hash_sha2='+str(directory/'libbrynja_hash_sha2.rlib')]
    binary=directory/('sha256-simd-test.exe' if 'windows' in target else 'sha256-simd-test')
    command=common+['--crate-name','sha256_simd','--test',str(source),'-o',str(binary)]+deps
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
    for before,after in (
        ('batch::Mode::Require','batch::Mode::Prefer'),
        ('lane.bytes.len() > 1024','false'),
        ('BitString::new(lane.bytes, lane.last)','BitString::new(lane.bytes, 8)'),
        ('Control::new(budget,','Control::new(budget.saturating_add(1000),'),
        ('self.sequence.checked_add(1) != Some(sequence)','false'),
        ('self.phase != phase','self.phase == Phase::Quarantined && phase == Phase::Empty'),
        ('guard.owner.plan != Some(plan)','guard.owner.plan.is_none() && plan.is_empty()'),
        ('if !copy(&guard.owner.output)','if copy(&guard.owner.output) && false'),
        ('check(guard.owner.authority)?;','core::hint::black_box(guard.owner.authority);'),
        ('let _ = clear_owned_region(&mut self.output);','core::hint::black_box(&mut self.output);'),
        ('self.authority.quarantine();','core::hint::black_box(self.authority);'),
        ('if !self.complete {','if false && !self.complete {'),
    ):
        # Some mutations deliberately touch every boundary, and compile first.
        assert before in original.decode(),before
        print('SIMD_MUTATION: '+before,flush=True)
        try:
            source.write_text(original.decode().replace(before,after))
            mutated, path=variant(f'sha256-simd-mutant-{len(mutations):02}')
            compile(mutated)
            mutations.append(dict(before=before,after=after,output=execute(path,False),
                binary=path.name,binary_sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
        finally: source.write_bytes(original)
    restored,binary=variant('sha256-simd-final')
    compile(restored); final=execute(binary,True)
    library=common+['--crate-name','sha256_simd','--crate-type','rlib',str(source),'-o',str(directory/'libsha256_simd.rlib')]+deps
    compile(library)
    negatives=[]
    for trait in ('Send','Sync','Copy','Clone','core::fmt::Debug'):
        probe=directory/'negative.rs'
        probe.write_text(f'extern crate sha256_simd; fn require<T: {trait}>() {{}} fn main() {{require::<sha256_simd::Owner>();}}')
        output=run(common+[str(probe),'--extern','sha256_simd='+str(directory/'libsha256_simd.rlib'),'-o',str(directory/'negative')],False)
        assert 'error[E0277]' in output,output
        negatives.append(dict(trait=trait,output=output))
    probe=directory/'negative.rs'
    probe.write_text("extern crate sha256_simd; use sha256_simd::{Owner,Authority,Kernel}; fn escape()->Owner<'static> { let a=Authority::for_compiled_target(Kernel::Avx2).unwrap(); Owner::new(&a).unwrap() } fn main() { let _=escape(); }")
    output=run(common+[str(probe),'--extern','sha256_simd='+str(directory/'libsha256_simd.rlib'),'-o',str(directory/'negative')],False)
    assert 'error[E0515]' in output,output
    negatives.append(dict(trait='owner cannot outlive authority',output=output))
    assert source_hashes == {p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}, 'Source changed during capture'
    record=dict(status='BOUNDED_SHA256_AVX2_COMPONENT_PASS',production_qualified=False,enclave_execution=False,
        target=target,independent_cases=count,lane_comparisons=count*8,tests=8,initial=initial,final=final,
        mutations=mutations,ownership_negatives=negatives,commands=commands,
        source_sha256=source_hashes,
        generated_sha256={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in directory.iterdir() if p.suffix=='.rs'},
        binary=binary.name,binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest())
    (directory/'sha256-simd-results.json').write_text(json.dumps(record,indent=2)+'\n')
    print(f'Bounded SHA256 AVX2: {count} independent cases; {count*8} lane comparisons; {len(mutations)} mutants; {len(negatives)} ownership negatives PASS')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory',type=Path)
    parser.add_argument('--attest-native-avx2',action='store_true',required=True)
    check(parser.parse_args().directory.resolve())
