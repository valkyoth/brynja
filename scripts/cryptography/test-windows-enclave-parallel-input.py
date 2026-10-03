"""Copied ingress regressions and oracle; explicitly NOT native enclave evidence."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

import windows_enclave_parallel_input_build as build

MUTANTS = (
    ('parallel_wave_input.rs', 'if !self.complete {', 'if false {'),
    ('parallel_wave_input.rs', 'clear_owned_region(&mut self.header)', 'clear_owned_region(&mut self.header[..0])'),
    ('parallel_wave_input.rs', 'clear_owned_region(&mut self.custom)', 'clear_owned_region(&mut self.custom[..0])'),
    ('parallel_wave_input.rs', 'clear_owned_region(&mut self.wave)', 'clear_owned_region(&mut self.wave[..0])'),
    ('parallel_wave_input.rs', 'clear_owned_region(&mut guard.frame.wave)', 'clear_owned_region(&mut guard.frame.wave[..0])'),
    ('parallel_wave_input.rs', 'let offset = loaded / 8;', 'let offset = loaded / 16;'),
    ('parallel_wave_input.rs', 'self.phase = Phase::Dead;', 'self.phase = Phase::Fresh;'),
    ('parallel_wave_input.rs', 'guard.frame.loaded_bits != guard.frame.request.ok_or(Error::State)?.input_bits',
     'guard.frame.loaded_bits > guard.frame.request.ok_or(Error::State)?.input_bits'),
    ('parallel_wave_request.rs', '|| route != 1', '|| route > 2'),
    ('parallel_wave_request.rs', '[r0, r1, r2, r3, r4, r5] != [0; 6]', '[r0, r1, r2, r3, r4, r5] == [9; 6]'),
    ('parallel_wave_request.rs', 'if input_bits > limit {', 'if input_bits > limit + 1 {'),
)


def run(command):
    return subprocess.run(command, capture_output=True, text=True, timeout=180)


def negatives(command, directory):
    common = command[:command.index('--crate-name')]
    dependencies = ['--extern', 'parallel_input=' + str(directory / 'libparallel_input.rlib')]
    setup = ('struct Copier; impl parallel_input::CopyIn for Copier {fn copy_into(&mut self,'
        '_:parallel_input::Kind,_:usize,_:&mut[u8])->bool{true}} '
        'fn main(){let mut frame=parallel_input::InputFrame::new(); let mut copy=Copier;')
    probes = [(trait, f'fn need<T:{trait}>(){{}} fn main(){{need::<parallel_input::InputFrame>();}}', 'E0277')
              for trait in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug')]
    probes += [(name, setup + body + '}', error) for name, body, error in (
        ('next-while-borrowed', 'let chunk=frame.next_wave(&mut copy).unwrap(); let _=frame.next_wave(&mut copy); let _=chunk.bytes();', 'E0499'),
        ('cancel-while-borrowed', 'let chunk=frame.next_wave(&mut copy).unwrap(); frame.cancel(); let _=chunk.bytes();', 'E0499'),
        ('drop-while-borrowed', 'let chunk=frame.next_wave(&mut copy).unwrap(); drop(frame); let _=chunk.bytes();', 'E0505'),
        ('private-wave', 'let _=frame.wave;', 'E0616'),
        ('arbitrary-offset', 'let _=frame.next_wave(&mut copy,64);', 'E0061'),
    )]
    records = []
    for name, source, error in probes:
        path = directory / 'negative.rs'
        path.write_text(source)
        result = run(common + ['--crate-name', 'negative', str(path), '--emit=metadata',
                              '-o', str(directory / 'negative.rmeta')] + dependencies)
        if result.returncode == 0 or error not in result.stderr:
            raise AssertionError(name + '\n' + result.stderr)
        records.append(dict(name=name, diagnostic=error, stderr=result.stderr))
    return records


def check(directory, baseline_only):
    target = subprocess.check_output(['rustc', '+1.98.1', '-vV'], text=True).split('host: ')[1].splitlines()[0]
    command, binary = build.build(directory, target)
    result = run([str(binary), '--nocapture'])
    if result.returncode or '7 passed; 0 failed' not in result.stdout:
        raise AssertionError(result.stdout + result.stderr)
    initial = result.stdout
    print(initial, flush=True)
    mutations = []
    if not baseline_only:
        for number, (name, before, after) in enumerate(MUTANTS):
            path = directory / name
            original = path.read_bytes()
            try:
                text = original.decode('utf-8')
                if text.count(before) != 1: raise ValueError('mutation anchor: ' + before)
                path.write_bytes(text.replace(before, after).encode('utf-8'))
                mutant = directory / ('input-mutant-' + str(number) + ('.exe' if 'windows' in target else ''))
                args = list(command)
                args[args.index('-o') + 1] = str(mutant)
                compiled = run(args)
                if compiled.returncode: raise AssertionError('mutant must compile: ' + compiled.stderr)
                result = run([str(mutant), '--skip', 'copied_ingress_independent_oracle', '--nocapture'])
                if result.returncode != 101 or 'test result: FAILED.' not in result.stdout or '\nrunning 0 tests\n' in result.stdout:
                    raise AssertionError('mutant escaped: ' + before + '\n' + result.stdout + result.stderr)
                mutations.append(dict(file=name, before=before, after=after, output=result.stdout, stderr=result.stderr))
                print('REJECTED: ' + before, flush=True)
            finally:
                path.write_bytes(original)
    rejected = negatives(command, directory)
    record = json.loads((directory / 'parallel-input-build.json').read_text())
    for name, digest in record['source_sha256'].items():
        assert hashlib.sha256((build.ROOT / name).read_bytes()).hexdigest() == digest, name
    for name, digest in record['generated_sha256'].items():
        assert hashlib.sha256((directory / name).read_bytes()).hexdigest() == digest, name
    result = run([str(binary), '--nocapture'])
    if result.returncode or '7 passed; 0 failed' not in result.stdout:
        raise AssertionError(result.stdout + result.stderr)
    record.update(status='PRIVATE_COPIED_INGRESS_PASS', full_mutation_campaign=not baseline_only,
                  initial=initial, final=result.stdout, mutations=mutations, negatives=rejected,
                  binary=binary.name, binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest())
    (directory / 'parallel-input-results.json').write_text(json.dumps(record, indent=2) + '\n')
    print(f'Private copied ingress: PASS; 532 oracle cases x two orders; {len(mutations)} mutants; {len(rejected)} compiled negatives; NOT enclave execution')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--baseline-only', action='store_true')
    args = parser.parse_args()
    check(args.directory.resolve(), args.baseline_only)
