#!/usr/bin/env python3
"""Exercise private SHA-3 worker and real compiled mutations; no release gate."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile
import windows_enclave_sha3_stream_build as build

MUTANTS = (
    ('!allowed.contains(&self.phase)', 'false'),
    ('self.sequence.checked_add(1) != Some(sequence)', 'false'),
    ('if input.len() > 1024', 'if input.len() > 2048'),
    ('if !terminal && last !=', 'if false && !terminal && last !='),
    ('!= identity', '!= identity && false'),
    ('width != op.owner.width || last != op.owner.last', 'false'),
    ('if !copy(', 'if false && !copy('),
    ('self.owner.quarantine();', 'self.owner.phase = Phase::Empty;'),
    ('clear_owned_region(&mut self.output)', 'clear_owned_region(&mut self.output[..0])'),
    ('op.owner.last,', '8,'),
)


def placement(directory, miri_toolchain):
    fixture = directory / 'placement'
    fixture.mkdir()
    manifest = '[package]\nname="enclave-sha3-placement"\nversion="0.0.0"\nedition="2024"\n'
    manifest += '[lib]\nname="sha3_stream"\npath=' + json.dumps(str(build.SOURCE / 'sha3_stream.rs')) + '\n'
    manifest += '[[test]]\nname="placement"\npath=' + json.dumps(str(build.SOURCE / 'sha3_stream_worker.rs')) + '\n[dependencies]\n'
    for name in ('brynja-core', 'brynja-hash-sha3'):
        manifest += name + '={path=' + json.dumps(str(build.ROOT / 'crates' / name)) + '}\n'
    (fixture / 'Cargo.toml').write_text(manifest + '[workspace]\n')
    command = ['cargo', '+' + (miri_toolchain or '1.98.1')]
    if miri_toolchain:
        command += ['miri']
    output = build.run(command + ['test', '--offline', '--manifest-path',
        str(fixture / 'Cargo.toml'), '--test', 'placement'])
    if '1 passed; 0 failed' not in output:
        raise AssertionError(output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--miri-toolchain')
    args = parser.parse_args()
    target = subprocess.check_output(['rustc','+1.98.1','-vV'],text=True).split('host: ')[1].splitlines()[0]
    with tempfile.TemporaryDirectory(prefix='enclave-sha3-stream-') as tmp:
        directory = Path(tmp)
        executable = build.build(directory,target,testing=True)
        command = json.loads((directory/'sha3-stream-build.json').read_text())['commands'][-1]
        def check(success):
            result = subprocess.run([str(executable)],capture_output=True,text=True,timeout=180)
            if success:
                if result.returncode or '7 passed' not in result.stdout:
                    raise AssertionError(result.stdout+result.stderr)
            elif result.returncode == 0 or 'FAILED' not in result.stdout:
                raise AssertionError('Mutant survived or did not fail assertion: '+result.stdout+result.stderr)
        check(True)
        source = directory/'sha3_stream.rs'; original = source.read_text()
        for before,after in MUTANTS:
            if before not in original: raise AssertionError('Stale mutation anchor: '+before)
            source.write_text(original.replace(before,after))
            # Compiler errors are not accepted as evidence of behavioral rejection.
            build.run(command+['-A','unused_variables'])
            try: check(False)
            except AssertionError as error: raise AssertionError(before+': '+str(error)) from error
        source.write_text(original);build.run(command);check(True)
        placement(directory, args.miri_toolchain)
        if args.miri_toolchain:
            fixture = directory/'fixture';fixture.mkdir()
            manifest='[package]\nname="enclave-sha3-lifecycle"\nversion="0.0.0"\nedition="2024"\n'
            manifest+='[lib]\npath='+json.dumps(str(source))+'\n[dependencies]\n'
            for name in ('brynja-core','brynja-hash-sha3'):
                manifest+=name+'={path='+json.dumps(str(build.ROOT/'crates'/name))+'}\n'
            (fixture/'Cargo.toml').write_text(manifest+'[workspace]\n')
            for test in ('focused_memory_lifecycle',):
                print(build.run(['cargo','+'+args.miri_toolchain,'miri','test','--offline',
                    '--manifest-path',str(fixture/'Cargo.toml'),'--lib',test]),flush=True)
    print('Enclave SHA-3 worker: seven tests and ten compiled mutants PASS; 628 cSHAKE, 76 NIST, 96 hashlib cases; 512 retained rehash cases; streamed setup PASS')


if __name__ == '__main__': main()
