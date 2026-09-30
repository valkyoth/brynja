#!/usr/bin/env python3
"""Exercise the real private KMAC worker; bounded author tests, not a release gate."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile
import windows_enclave_kmac_stream_build as build

MUTANTS = (
    ('!allowed.contains(&self.phase)', 'false'),
    ('self.sequence.checked_add(1) != Some(sequence)', 'false'),
    ('if input.len() > 1024', 'if input.len() > 2048'),
    ('if !terminal && last !=', 'if false && !terminal && last !='),
    ('algorithm.encode() != identity', 'false'),
    ('width != op.owner.width || last != op.owner.last', 'false'),
    ('if !copy(', 'if false && !copy('),
    ('self.owner.quarantine();', 'self.owner.phase = Phase::Empty;'),
    ('clear_owned_region(&mut self.output)', 'clear_owned_region(&mut self.output[..0])'),
    ('accumulate_secret_byte_difference(&mut difference.0[0], left, right);',
     'let _ = (left, right);'),
    ('op.owner.last,', '8,'),
)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--miri-toolchain')
    args=parser.parse_args()
    target=subprocess.check_output(['rustc','+1.98.1','-vV'],text=True).split('host: ')[1].splitlines()[0]
    with tempfile.TemporaryDirectory(prefix='enclave-kmac-stream-') as tmp:
        directory=Path(tmp)
        executable=build.build(directory,target,testing=True)
        command=json.loads((directory/'kmac-stream-build.json').read_text())['commands'][-1]
        def check(success):
            result=subprocess.run([str(executable)],capture_output=True,text=True,timeout=120)
            if success:
                if result.returncode or '7 passed' not in result.stdout:
                    raise AssertionError(result.stdout+result.stderr)
            elif result.returncode==0 or 'FAILED' not in result.stdout:
                raise AssertionError('Mutant survived or did not fail an assertion: '+result.stdout+result.stderr)
        check(True)
        source=directory/'kmac_stream.rs';original=source.read_text()
        for before,after in MUTANTS:
            if before not in original:raise AssertionError('Stale mutation anchor: '+before)
            source.write_text(original.replace(before,after))
            # Compile errors never count as mutant rejection.
            build.run(command+['-A','unused_variables','-A','unused_imports','-A','unused_mut'])
            try:check(False)
            except AssertionError as error:raise AssertionError(before+': '+str(error)) from error
        source.write_text(original);build.run(command);check(True)
        if args.miri_toolchain:
            fixture=directory/'fixture';fixture.mkdir()
            manifest='[package]\nname="enclave-kmac-lifecycle"\nversion="0.0.0"\nedition="2024"\n'
            manifest+='[lib]\npath='+json.dumps(str(source))+'\n[dependencies]\n'
            for name in ('brynja-core','brynja-mac-kmac'):
                manifest+=name+'={path='+json.dumps(str(build.ROOT/'crates'/name))+'}\n'
            (fixture/'Cargo.toml').write_text(manifest+'[workspace]\n')
            output=build.run(['cargo','+'+args.miri_toolchain,'miri','test','--offline',
                '--manifest-path',str(fixture/'Cargo.toml'),'--lib','focused_memory_lifecycle'])
            if '1 passed; 0 failed' not in output:raise AssertionError(output)
            print(output,flush=True)
    print('KMAC worker component: seven tests, 256 independent bit cases, 128 retained rekey cases; eleven compiled mutants rejected; no native enclave claim')


if __name__=='__main__':main()
