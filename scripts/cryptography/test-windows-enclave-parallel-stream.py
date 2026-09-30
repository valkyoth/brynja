#!/usr/bin/env python3
"""ParallelHash component/placement regressions, not native qualification."""
import argparse
import contextlib
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import windows_enclave_parallel_stream_build as build

MUTANTS = (
    ('parallel_stream.rs', '!allowed.contains(&self.phase)', 'false'),
    ('parallel_stream.rs', 'self.sequence.checked_add(1) != Some(sequence)', 'false'),
    ('parallel_stream.rs', 'identity != op.owner.identity', 'false'),
    ('parallel_stream.rs', 'width != op.owner.width || last != op.owner.last', 'false'),
    ('parallel_stream.rs', 'if !copy(', 'if false && !copy('),
    ('parallel_stream.rs', 'self.owner.quarantine();', 'self.owner.phase = Phase::Empty;'),
    ('parallel_stream.rs', 'clear_owned_region(&mut self.output)', 'clear_owned_region(&mut self.output[..0])'),
    ('parallel_stream.rs', 'input.len() > 1024', 'input.len() > 2048'),
    ('parallel_stream.rs', '.checked_sub(u64::try_from(input.len())', '.checked_add(u64::try_from(input.len())'),
    # Ignoring this error alone is still rejected by the following state.update;
    # replace setup with a ready uncustomized state to exercise a real bypass.
    ('parallel_stream.rs', 'op.owner.root.finish_custom()?;', 'op.owner.root = State::leaf(op.owner.identity)?;'),
    ('parallel_stream.rs', 'if !terminal && last !=', 'if false && !terminal && last !='),
    ('parallel_stream.rs', 'suffix.right(bits)?;', 'suffix.right(0)?;'),
    ('parallel_stream_input.rs', 'self.check_complete()?;', ''),
    ('parallel_stream_input.rs', 'suffix.right(u128::from_le_bytes(self.leaves))?;', 'suffix.right(0)?;'),
    ('parallel_stream_input.rs', 'root.update(output)?;', 'let _ = output;'),
    ('parallel_stream_input.rs', 'self.leaf.finish(tail)?;', 'self.leaf.finish(empty()?)?;'),
    ('parallel_stream_state.rs', 'b"ParallelHash"', 'b"ParallelHASH"'),
    ('parallel_stream_wire.rs', 'version != VERSION', 'false'),
    ('parallel_stream_wire.rs', 'sequence == 0', 'false'),
    ('parallel_stream_wire.rs', 'reserved != 0', 'false'),
    ('parallel_stream_wire.rs', 'length > 1024', 'length > 2048'),
    ('parallel_stream_wire.rs', 'source.checked_add(length).ok_or(Error::Length)?;', 'let _ = source;'),
    ('parallel_stream_wire.rs', 'guard.complete = result.is_ok();', 'guard.complete = true;'),
    ('parallel_stream_wire.rs', 'owner.begin(n, self.identity, self.block, self.custom, self.budget)',
     'owner.begin(n, self.identity, 1, self.custom, self.budget)'),
    ('parallel_stream.rs', 'self.next_width = 0;', 'self.next_width = 1;'),
    ('parallel_stream.rs', 'if op.owner.phase == Phase::CustomRetained', 'if false'),
    ('parallel_stream.rs', '.checked_sub(u64::try_from(op.owner.width)', '.checked_add(u64::try_from(op.owner.width)'),
    ('parallel_host_wire.rs', 'self.sequence == 0', 'false'),
    ('parallel_host_wire.rs', 'self.width > 1024', 'self.width > 8192'),
    ('parallel_host_wire.rs', 'self.custom_bits.to_le_bytes()', '0_u128.to_le_bytes()'),
    ('parallel_host_wire.rs', 'if self.op == 106 {', 'if self.op == 105 {'),
)


def fixture_manifest(directory, entry, worker=None):
    manifest='[package]\nname="enclave-parallel-component"\nversion="0.0.0"\nedition="2024"\n'
    manifest+='[lib]\nname="parallel_stream"\npath='+json.dumps(str(entry))+'\n'
    if worker:
        manifest+='[[test]]\nname="placement"\npath='+json.dumps(str(worker))+'\n'
    manifest+='[dependencies]\n'
    for name in ('brynja-core','brynja-hash-sha3'):
        manifest+=name+'={path='+json.dumps(str(build.ROOT/'crates'/name))+'}\n'
    directory.mkdir()
    (directory/'Cargo.toml').write_text(manifest+'[workspace]\n')


def placement(directory, miri_toolchain):
    fixture=directory/'placement'
    fixture_manifest(fixture,build.SOURCE/'parallel_stream.rs',fixture/'parallel_stream_worker.rs')
    worker=fixture/'parallel_stream_worker.rs'
    for name in ('parallel_stream_worker.rs','parallel_stream_placement_tests.rs'):
        shutil.copyfile(build.SOURCE/name,fixture/name)
    arguments=['test','--offline','--manifest-path',str(fixture/'Cargo.toml'),'--test','placement']
    command=['cargo','+'+(miri_toolchain or '1.98.1')]+(['miri'] if miri_toolchain else [])
    output=build.run(command+arguments)
    if '1 passed; 0 failed' not in output: raise AssertionError(output)
    print(output,flush=True)
    original=worker.read_text()
    for before,after in (('for offset in 0..4096 {','for offset in 0..0 {'),('*live = None;','')):
        if original.count(before)!=1: raise AssertionError('Stale placement mutant: '+before)
        try:
            worker.write_text(original.replace(before,after))
            build.run(['cargo','+1.98.1',*arguments,'--no-run'])
            result=subprocess.run(['cargo','+1.98.1',*arguments],capture_output=True,text=True,timeout=120)
            if result.returncode==0 or 'placed_owner_is_destroyed_before_full_page_clear_and_can_be_recreated ... FAILED' not in result.stdout:
                raise AssertionError('Placement mutant survived or failed unexpectedly: '+result.stdout+result.stderr)
        finally: worker.write_text(original)
    print('ParallelHash placement: two allocation-clear/lifetime mutants rejected',flush=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--miri-toolchain')
    parser.add_argument('--directory',type=Path)
    args=parser.parse_args()
    target=subprocess.check_output(['rustc','+1.98.1','-vV'],text=True).split('host: ')[1].splitlines()[0]
    manager=contextlib.nullcontext(args.directory) if args.directory else tempfile.TemporaryDirectory(prefix='enclave-parallel-')
    with manager as tmp:
        directory=Path(tmp).resolve()
        artifact=build.build(directory,target,testing=True)
        command=json.loads((directory/'parallel-stream-build.json').read_text())['commands'][-1]
        def check(success):
            result=subprocess.run([str(artifact)],capture_output=True,text=True,timeout=120)
            if success:
                if result.returncode or '16 passed; 0 failed' not in result.stdout: raise AssertionError(result.stdout+result.stderr)
                print(result.stdout,flush=True)
            elif result.returncode==0 or 'FAILED' not in result.stdout:
                raise AssertionError('Mutant survived or failed unexpectedly: '+result.stdout+result.stderr)
        check(True)
        for name,before,after in MUTANTS:
            path=directory/name;original=path.read_text()
            if original.count(before)!=1: raise AssertionError('Stale or ambiguous mutant: '+before)
            try:
                path.write_text(original.replace(before,after))
                build.run(command+['-A','unused_variables','-A','unused_imports','-A','dead_code'])
                try: check(False)
                except AssertionError as error: raise AssertionError(before+': '+str(error)) from error
            finally: path.write_text(original)
        placement(directory,args.miri_toolchain)
        if args.miri_toolchain:
            fixture=directory/'lifecycle'
            fixture_manifest(fixture,directory/'parallel_stream.rs')
            for selected in ('copy_failure_unwind_and_cancel_128',
                             'copy_failure_unwind_and_cancel_256',
                             'copy_failure_unwind_and_cancel_xof128',
                             'copy_failure_unwind_and_cancel_xof256',
                             'exact_leaf_completion_and_counter_overflow_are_load_bearing',
                             'copied_payload_failure_clears_an_active_owner',
                             'retained_setup_rejection_and_cancel_clear_previous_output'):
                output=build.run(['cargo','+'+args.miri_toolchain,'miri','test','--offline',
                    '--manifest-path',str(fixture/'Cargo.toml'),'--lib',selected])
                if '1 passed; 0 failed' not in output: raise AssertionError(output)
                print(output,flush=True)
        build.run(command);check(True)
        build_record=json.loads((directory/'parallel-stream-build.json').read_text())
        record=dict(schema=1,status='COMPONENT_TESTS_PASS',production_qualified=False,
            native_enclave_execution=False,tests=16,oracle_cases=build_record['oracle_cases'],retained_cases=256,
            compiled_mutants=len(MUTANTS),placement_mutants=2,miri_toolchain=args.miri_toolchain,
            clean_executable_sha256=hashlib.sha256(artifact.read_bytes()).hexdigest(),
            initial_build_record_sha256=hashlib.sha256((directory/'parallel-stream-build.json').read_bytes()).hexdigest(),
            source_sha256={str(p.relative_to(build.ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()
                for p in (Path(__file__),build.SOURCE/'parallel_stream_worker.rs',build.SOURCE/'parallel_stream_placement_tests.rs')})
        (directory/'parallel-stream-tests.json').write_text(json.dumps(record,indent=2)+'\n')
    print(f'ParallelHash scalar component: sixteen tests, 332 independent cases including 12 NIST samples, 256 retained-composition cases, {len(MUTANTS)} compiled mutants; no native enclave claim')


if __name__=='__main__':main()
