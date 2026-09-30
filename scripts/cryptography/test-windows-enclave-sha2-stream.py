#!/usr/bin/env python3
"""Real-source SHA-2 worker tests and compiled negative controls, not a gate."""
import argparse
import json
import subprocess
import tempfile
from pathlib import Path
import windows_enclave_sha2_stream_build as build

MUTANTS = (
    ('self.phase != phase || self.phase == Phase::Quarantined', 'self.phase == Phase::Quarantined'),
    ('sequence == 0 || self.sequence.checked_add(1) != Some(sequence)', 'sequence == 0'),
    ('if input.len() > 1024 {', 'if input.len() > 2048 {'),
    ('if algorithm.encode() != expected_algorithm {', 'if algorithm.encode() == u64::MAX && expected_algorithm == 0 {'),
    ('let _ = clear_owned_region(&mut self.output);', 'let _ = self.output.len();'),
    ('self.owner.quarantine();', 'self.owner.phase = Phase::Empty;'),
    ('if !copy(', 'if false && !copy('),
    ('if last_bits == 0 { 8 } else { last_bits }', '8'),
)


def placement(directory,miri_toolchain):
    fixture=directory/'placement';fixture.mkdir()
    manifest='[package]\nname="enclave-sha2-placement"\nversion="0.0.0"\nedition="2024"\n'
    manifest+='[lib]\nname="sha2_stream"\npath='+json.dumps(str(build.SOURCE/'sha2_stream.rs'))+'\n'
    manifest+='[[test]]\nname="placement"\npath='+json.dumps(str(build.SOURCE/'sha2_stream_worker.rs'))+'\n[dependencies]\n'
    for name in ('brynja-core','brynja-hash-sha2'):
        features=', features=["general-sha512-t"]' if name.endswith('sha2') else ''
        manifest+=name+'={path='+json.dumps(str(build.ROOT/'crates'/name))+features+'}\n'
    (fixture/'Cargo.toml').write_text(manifest+'[workspace]\n')
    command=['cargo','+'+(miri_toolchain or '1.98.1')]
    if miri_toolchain:command+=['miri']
    command+=['test','--offline','--manifest-path',str(fixture/'Cargo.toml'),'--test','placement']
    output=build.run(command)
    if '1 passed; 0 failed' not in output:raise AssertionError(output)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--miri-toolchain',help='Optional installed Miri toolchain for the focused placement test')
    args=parser.parse_args()
    target = subprocess.check_output(['rustc','+1.98.1','-vV'],text=True).split('host: ')[1].splitlines()[0]
    with tempfile.TemporaryDirectory(prefix='enclave-sha2-stream-') as tmp:
        directory=Path(tmp)
        executable=build.build(directory,target,testing=True)
        def execute(success):
            result=subprocess.run([str(executable)],capture_output=True,text=True,timeout=60)
            if success:
                if result.returncode or '7 passed' not in result.stdout: raise AssertionError(result.stdout+result.stderr)
            elif result.returncode==0 or 'FAILED' not in result.stdout:
                raise AssertionError('Mutant survived or did not fail an assertion: '+result.stdout+result.stderr)
        execute(True)
        source=directory/'sha2_stream.rs'; original=source.read_text()
        command=json.loads((directory/'sha2-stream-build.json').read_text())['commands'][-1]
        for before,after in MUTANTS:
            if before not in original: raise AssertionError('Stale mutation anchor: '+before)
            source.write_text(original.replace(before,after))
            # An otherwise unused public metadata variable in one deliberate
            # mutant is not a security diagnostic or a mutant rejection.
            mutant_command=command+['-A','unused_variables']
            build.run(mutant_command)
            try: execute(False)
            except AssertionError as error: raise AssertionError('Mutation '+before+': '+str(error)) from error
        source.write_text(original);build.run(command);execute(True)
        placement(directory,args.miri_toolchain)
    print('Enclave SHA-2 worker: seven tests; eight compiled lifecycle/bit/cleanup mutants rejected; placement lifetime PASS')


if __name__=='__main__':main()
