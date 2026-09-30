#!/usr/bin/env python3
"""Private enclave SHA-2 batch component: correctness and fail-closed regressions."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import windows_enclave_sha2_stream_build as base
import windows_enclave_sha2_batch_placement as placement

SOURCE=base.SOURCE
MUTANTS=(
    ('self.phase != phase','false'),
    ('self.sequence.checked_add(1) != Some(sequence)','false'),
    ('op.owner.next() != Some(slot)','false'),
    ('self.active != Some(slot)','false'),
    ('bytes > 1024','bytes > 2048'),
    ('op.owner.next().is_some()','false'),
    ('expected != op.owner.plan','false'),
    ('if !copy(&op.owner.output)','if false && !copy(&op.owner.output)'),
    ('if !self.complete','if false'),
    ('clear_owned_region(&mut self.output)','clear_owned_region(&mut self.output[..0])'),
    ('.checked_sub(u64::try_from(bytes)', '.checked_add(u64::try_from(bytes)'),
)
WIRE_MUTANTS=(
    ('version != VERSION', 'false'),
    ('sequence == 0', 'false'),
    ('reserved != 0', 'false'),
    ('length > 1024', 'length > 2048'),
    ('last > 8', 'last > 9'),
    ('slot >= 8', 'slot > 8'),
    ('operation != BEGIN && budget != 0', 'false'),
    ('!planned && plan != [0; 8]', 'false'),
    ('planned && plan == [0; 8]', 'false'),
    ('source.checked_add(length).ok_or(Error::Length)?;', 'let _ = source.wrapping_add(length);'),
    ('input.len() != self.length', 'false'),
)

def build(directory,target):
    base.build(directory,target,testing=True)
    previous=json.loads((directory/'sha2-stream-build.json').read_text())['commands'][-1]
    if previous[-3]!='--test':raise ValueError('Changed component build shape')
    base.run(previous[:-3]+['--crate-type','rlib','-o',str(directory/'libsha2_stream.rlib')])
    for name in ('sha2_batch.rs','sha2_batch_tests.rs','sha2_batch_wire.rs','sha2_batch_wire_tests.rs'):
        shutil.copyfile(SOURCE/name,directory/name)
    rows=['#[test]','fn independent_hashlib_named_batch_oracle() {']
    for identity,name in enumerate(('sha224','sha256','sha384','sha512','sha512_224','sha512_256'),1):
        for length in (0,1,55,56,63,64,111,112,127,128,1024,2049):
            digest=','.join(map(str,hashlib.new(name,b'a'*length).digest()))
            rows.append(f'check_case({identity},&std::vec![b\'a\';{length}],{8 if length else 0},&[{digest}]);')
    test=directory/'sha2_batch_tests.rs'
    test.write_text(test.read_text()+'\n'+'\n'.join(rows+['}'])+'\n')
    executable=directory/('batch-tests.exe' if 'windows' in target else 'batch-tests')
    command=['rustc','+1.98.1','--edition=2024','--target',target,'-D','warnings',
             '-C','opt-level=2','-C','overflow-checks=yes','-L','dependency='+str(directory),
             '--crate-name','sha2_batch','--test',str(directory/'sha2_batch.rs'),'-o',str(executable)]
    for name in ('brynja_core','brynja_hash_sha2','sha2_stream'):
        command+=['--extern',name+'='+str(directory/('lib'+name+'.rlib'))]
    base.run(command)
    return command,executable

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--miri-toolchain')
    args=parser.parse_args()
    target=subprocess.check_output(['rustc','+1.98.1','-vV'],text=True).split('host: ')[1].splitlines()[0]
    with tempfile.TemporaryDirectory(prefix='enclave-sha2-batch-') as tmp:
        directory=Path(tmp);command,executable=build(directory,target)
        result=base.run([str(executable)])
        if '9 passed; 0 failed' not in result:raise AssertionError(result)
        path=directory/'sha2_batch.rs';original=path.read_text()
        for filename,mutants in (('sha2_batch.rs',MUTANTS),('sha2_batch_wire.rs',WIRE_MUTANTS)):
            mutant_path=directory/filename;original=mutant_path.read_text()
            for before,after in mutants:
                if original.count(before)!=1:raise ValueError('Stale mutant '+before)
                try:
                    mutant_path.write_text(original.replace(before,after))
                    base.run(command+['-A','unused_variables'])
                    outcome=subprocess.run([str(executable)],capture_output=True,text=True,timeout=120)
                    if outcome.returncode==0 or 'FAILED' not in outcome.stdout:raise AssertionError('Mutant survived: '+before)
                finally:mutant_path.write_text(original)
        placement.check(directory,args.miri_toolchain)
        if args.miri_toolchain:
            fixture=directory/'fixture';fixture.mkdir()
            manifest='[package]\nname="enclave-sha2-batch-miri"\nversion="0.0.0"\nedition="2024"\n[lib]\npath='+json.dumps(str(path))+'\n[dependencies]\n'
            for name in ('brynja-core','brynja-hash-sha2'):
                manifest+=name+'={path='+json.dumps(str(base.ROOT/'crates'/name))+',features='+('[]' if name=='brynja-core' else '["general-sha512-t"]')+'}\n'
            dep=directory/'stream-fixture';dep.mkdir()
            dep_manifest=manifest.replace('enclave-sha2-batch-miri','sha2_stream').replace(str(path),str(directory/'sha2_stream.rs'))
            (dep/'Cargo.toml').write_text(dep_manifest+'[workspace]\n')
            manifest+='sha2_stream={path='+json.dumps(str(dep))+'}\n[workspace]\n'
            (fixture/'Cargo.toml').write_text(manifest)
            for test in ('copy_failure_unwind_and_cancellation_clear_every_result',
                         'copied_length_and_bits_fail_closed_and_copy_unwind_erases'):
                output=base.run(['cargo','+'+args.miri_toolchain,'miri','test','--offline','--manifest-path',str(fixture/'Cargo.toml'),
                                 '--lib',test])
                if '1 passed; 0 failed' not in output:raise AssertionError(output)
                print(output)
    print('SHA-2 enclave batch: nine tests; 72 hashlib cases; 255 activity masks; 4080 general-t bit cases; 22 compiled mutants rejected; no native qualification')

if __name__=='__main__':main()
