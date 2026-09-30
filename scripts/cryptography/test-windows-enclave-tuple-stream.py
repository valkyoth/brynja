#!/usr/bin/env python3
"""TupleHash component regressions; not a release gate or native enclave claim."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import windows_enclave_tuple_stream_build as build

MUTANTS = (
    ('tuple_stream.rs', '!allowed.contains(&self.phase)', 'false'),
    ('tuple_stream.rs', 'self.sequence.checked_add(1) != Some(sequence)', 'false'),
    ('tuple_stream.rs', 'op.owner.remaining != [0; 16]', 'false'),
    ('tuple_stream.rs', 'identity != op.owner.identity', 'false'),
    ('tuple_stream.rs', 'width != op.owner.width || last != op.owner.last', 'false'),
    ('tuple_stream.rs', 'if !copy(', 'if false && !copy('),
    ('tuple_stream.rs', 'self.owner.quarantine();', 'self.owner.phase = Phase::Empty;'),
    ('tuple_stream.rs', 'clear_owned_region(&mut self.output)', 'clear_owned_region(&mut self.output[..0])'),
    ('tuple_stream.rs', 'if !terminal && last !=', 'if false && !terminal && last !='),
    ('tuple_stream.rs', 'left_encode_u128(bits)', 'right_encode_u128(bits)'),
    ('tuple_stream.rs', 'right_encode_u128(bits)', 'right_encode_u128(0)'),
    ('tuple_stream.rs', 'input.as_bytes().len() > 1024', 'input.as_bytes().len() > 2048'),
    ('tuple_stream_state.rs', 'b"TupleHash"', 'b"TupleHASH"'),
    ('tuple_stream_state.rs', 'self.used = 0;', 'self.used = 1;'),
    ('tuple_stream_wire.rs', 'version != VERSION', 'false'),
    ('tuple_stream_wire.rs', 'sequence == 0', 'false'),
    ('tuple_stream_wire.rs', 'length > 1024', 'length > 2048'),
    ('tuple_stream_wire.rs', 'source.checked_add(length).ok_or(Error::Length)?;', 'let _ = source;'),
    ('tuple_stream_wire.rs', 'guard.complete = result.is_ok();', 'guard.complete = true;'),
    ('tuple_host_wire.rs', 'self.sequence == 0', 'false'),
    ('tuple_host_wire.rs', 'self.width > 1024', 'self.width > 8192'),
    ('tuple_host_wire.rs', 'self.item_bits.to_le_bytes()', 'self.custom_bits.to_le_bytes()'),
    ('tuple_host_wire.rs', 'if self.op == 68', 'if self.op == 67'),
)


def placement(directory, miri_toolchain):
    fixture=directory/'placement';fixture.mkdir()
    worker=fixture/'tuple_stream_worker.rs'
    for name in ('tuple_stream_worker.rs','tuple_stream_placement_tests.rs'):
        shutil.copyfile(build.SOURCE/name,fixture/name)
    manifest='[package]\nname="enclave-tuple-placement"\nversion="0.0.0"\nedition="2024"\n'
    manifest+='[lib]\nname="tuple_stream"\npath='+json.dumps(str(build.SOURCE/'tuple_stream.rs'))+'\n'
    manifest+='[[test]]\nname="placement"\npath='+json.dumps(str(worker))+'\n[dependencies]\n'
    for name in ('brynja-core','brynja-hash-sha3'):
        manifest+=name+'={path='+json.dumps(str(build.ROOT/'crates'/name))+'}\n'
    (fixture/'Cargo.toml').write_text(manifest+'[workspace]\n')
    command=['cargo','+'+(miri_toolchain or '1.98.1')]
    if miri_toolchain:command+=['miri']
    arguments=['test','--offline','--manifest-path',str(fixture/'Cargo.toml'),'--test','placement']
    output=build.run(command+arguments)
    if '1 passed; 0 failed' not in output:raise AssertionError(output)
    print(output,flush=True)
    original=worker.read_text()
    for before,after in (('for offset in 0..4096 {','for offset in 0..0 {'),('*live = None;','')):
        if original.count(before)!=1:raise AssertionError('Stale placement mutant: '+before)
        try:
            worker.write_text(original.replace(before,after))
            build.run(['cargo','+1.98.1',*arguments,'--no-run'])
            result=subprocess.run(['cargo','+1.98.1',*arguments],capture_output=True,text=True,timeout=120)
            if result.returncode==0 or 'placed_owner_is_destroyed_before_full_page_clear_and_can_be_recreated ... FAILED' not in result.stdout:
                raise AssertionError('Placement mutant survived or failed unexpectedly: '+result.stdout+result.stderr)
        finally:worker.write_text(original)
    print('TupleHash placement: two compiled allocation-clear/lifetime mutants rejected',flush=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--miri-toolchain')
    args=parser.parse_args()
    target=subprocess.check_output(['rustc','+1.98.1','-vV'],text=True).split('host: ')[1].splitlines()[0]
    with tempfile.TemporaryDirectory(prefix='enclave-tuple-stream-') as tmp:
        directory=Path(tmp)
        artifact=build.build(directory,target,testing=True)
        command=json.loads((directory/'tuple-stream-build.json').read_text())['commands'][-1]
        def check(success):
            result=subprocess.run([str(artifact)],capture_output=True,text=True,timeout=120)
            if success:
                if result.returncode or '8 passed' not in result.stdout:
                    raise AssertionError(result.stdout+result.stderr)
            elif result.returncode==0 or 'FAILED' not in result.stdout:
                raise AssertionError('Mutant survived or did not fail assertions: '+result.stdout+result.stderr)
        check(True)
        for name,before,after in MUTANTS:
            path=directory/name
            original=path.read_text()
            if before not in original:raise AssertionError('Stale mutant: '+before)
            try:
                path.write_text(original.replace(before,after))
                build.run(command+['-A','unused_variables','-A','unused_imports','-A','dead_code'])
                try:check(False)
                except AssertionError as error:raise AssertionError(before+': '+str(error)) from error
            finally:path.write_text(original)
        build.run(command);check(True)
        placement(directory,args.miri_toolchain)
        if args.miri_toolchain:
            fixture=directory/'fixture';fixture.mkdir()
            manifest='[package]\nname="enclave-tuple-lifecycle"\nversion="0.0.0"\nedition="2024"\n'
            manifest+='[lib]\npath='+json.dumps(str(directory/'tuple_stream.rs'))+'\n[dependencies]\n'
            for name in ('brynja-core','brynja-hash-sha3'):
                manifest+=name+'={path='+json.dumps(str(build.ROOT/'crates'/name))+'}\n'
            (fixture/'Cargo.toml').write_text(manifest+'[workspace]\n')
            for selected in ('copy_failure_unwind_cancel_and_shapes_clear_retained_storage',
                             'malformed_copied_bits_quarantine_before_further_work'):
                output=build.run(['cargo','+'+args.miri_toolchain,'miri','test','--offline',
                    '--manifest-path',str(fixture/'Cargo.toml'),'--lib',selected])
                if '1 passed; 0 failed' not in output:raise AssertionError(output)
                print(output,flush=True)
    print('TupleHash component: eight tests, host/worker metadata parity, 272 independent bit cases through direct and wire paths, 128 retained rehash cases; 23 compiled mutants rejected; no native enclave claim')


if __name__=='__main__':main()
