#!/usr/bin/env python3
"""Native AVX2 TupleHash component tests; not native enclave qualification."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import windows_enclave_tuple_accelerated_build as build

MUTANTS = (
    ('tuple_accelerated.rs', '!allowed.contains(&self.phase)', 'false'),
    ('tuple_accelerated.rs', 'self.sequence.checked_add(1) != Some(sequence)', 'false'),
    ('tuple_accelerated.rs', 'check_authority(op.owner.authority)?;', ''),
    ('tuple_accelerated.rs', 'check_authority(op.owner.authority)?;\n        let more',
     'let more'),
    ('tuple_accelerated.rs', 'self.authority.quarantine();', ''),
    ('tuple_accelerated.rs', 'self.owner.quarantine();', ''),
    ('tuple_accelerated.rs', 'op.owner.remaining != [0; 16]', 'false'),
    ('tuple_accelerated.rs', '.checked_sub(u128::try_from(input.bit_len()).map_err(|_| Error::Length)?)',
     '.checked_add(u128::try_from(input.bit_len()).map_err(|_| Error::Length)?)'),
    ('tuple_accelerated.rs', 'identity != op.owner.identity', 'false'),
    ('tuple_accelerated.rs', 'width != op.owner.width || last != op.owner.last', 'false'),
    ('tuple_accelerated.rs', 'if !copy(', 'if false && !copy('),
    ('tuple_accelerated.rs', 'clear_owned_region(&mut self.output)', 'clear_owned_region(&mut self.output[..0])'),
    ('tuple_accelerated.rs', 'if !terminal && last !=', 'if false && !terminal && last !='),
    ('tuple_accelerated.rs', 'left_encode_u128(bits)', 'right_encode_u128(bits)'),
    ('tuple_accelerated.rs', 'right_encode_u128(bits)', 'right_encode_u128(0)'),
    ('tuple_accelerated.rs', 'input.as_bytes().len() > 1024', 'input.as_bytes().len() > 2048'),
    ('tuple_accelerated.rs', 'if !fixed && bits != 0', 'if false && !fixed && bits != 0'),
    ('tuple_accelerated.rs', 'op.owner.last,', '8,'),
    ('tuple_accelerated_state.rs', 'b"TupleHash"', 'b"TupleHASH"'),
    ('tuple_accelerated_state.rs', '72, bits', '72, 0'),
    ('tuple_accelerated_packer.rs', 'self.used = 0;', 'self.used = 1;'),
    ('tuple_accelerated_packer.rs', 'clear_owned_region(&mut self.pending)', 'clear_owned_region(&mut self.pending[..0])'),
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    directory = args.directory.resolve()
    target = subprocess.check_output(['rustc', '+1.98.1', '-vV'], text=True).split('host: ')[1].splitlines()[0]
    command, binary = build.build(directory, target)
    def execute(success):
        result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=120)
        if ((result.returncode == 0) != success or
                ('0 failed' if success else 'FAILED') not in result.stdout or
                'running 0 tests' in result.stdout):
            raise AssertionError(result.stdout+result.stderr)
        return result.stdout+result.stderr
    initial = execute(True)
    print(initial, flush=True)
    mutations = []
    for filename, before, after in MUTANTS:
        path = directory/filename
        original = path.read_bytes()
        if before not in original.decode(): raise AssertionError('Stale mutant: '+before)
        try:
            path.write_text(original.decode().replace(before, after))
            # Compilation failures are not accepted as rejected runtime mutants.
            build.base.run(command+['-A', 'unused_variables', '-A', 'unused_imports', '-A', 'unused_mut', '-A', 'dead_code'])
            try: output = execute(False)
            except AssertionError as error: raise AssertionError('Survived: '+before+'\n'+str(error)) from error
            mutations.append(dict(file=filename, before=before, after=after, output=output))
            print('REJECTED: '+filename+': '+before, flush=True)
        finally: path.write_bytes(original)
    build.base.run(command)
    final = execute(True)
    negatives = []
    common = command[:command.index('--crate-name')]
    for name, source, diagnostic in [
        *[(trait, 'fn need<T: '+trait+'>() {} fn main() { need::<tuple_accelerated::Owner>(); }', 'E0277')
          for trait in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug')],
        ('lifetime', "fn escape() -> tuple_accelerated::Owner<'static> { let a = brynja_crypto_cpu::static_execution::Authority::new(brynja_crypto_cpu::static_execution::Kernel::X86Keccak).unwrap(); tuple_accelerated::Owner::new(&a).unwrap() } fn main() {}", 'E0515'),
    ]:
        probe = directory/'negative.rs'
        probe.write_text(source)
        result = subprocess.run(common+['--crate-name', 'negative', str(probe), '--emit=metadata',
            '-o', str(directory/'negative.rmeta'), '--extern',
            'tuple_accelerated='+str(directory/'libtuple_accelerated.rlib'), '--extern',
            'brynja_crypto_cpu='+str(directory/'libbrynja_crypto_cpu.rlib')],
            capture_output=True, text=True, timeout=120)
        if result.returncode == 0 or diagnostic not in result.stderr: raise AssertionError(result.stderr)
        negatives.append(dict(name=name, diagnostic=diagnostic, stderr=result.stderr))
    record = json.loads((directory/'tuple-accelerated-build.json').read_text())
    record['source_sha256'][Path(__file__).resolve().relative_to(build.ROOT).as_posix()] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    record.update(status='TUPLEHASH_AVX2_COMPONENT_PASS', initial=initial, final=final,
                  mutations=mutations, negatives=negatives,
                  binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest())
    for name, expected in record['generated_sha256'].items():
        assert hashlib.sha256((directory/name).read_bytes()).hexdigest() == expected
    (directory/'tuple-accelerated-results.json').write_text(json.dumps(record, indent=2)+'\n')
    print(f"TupleHash AVX2 component: PASS; {record['oracle_cases']} independent cases; 128 retained rehashes; {len(mutations)} compiled mutants and {len(negatives)} ownership negatives rejected; no enclave claim")


if __name__ == '__main__': main()
