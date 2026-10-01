#!/usr/bin/env python3
"""Native AVX2 ParallelHash component tests; not native enclave qualification."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import windows_enclave_parallel_accelerated_build as build

MUTANTS = (
    ('parallel_accelerated.rs', '!allowed.contains(&self.phase)', 'false'),
    ('parallel_accelerated.rs', 'self.sequence.checked_add(1) != Some(sequence)', 'false'),
    ('parallel_accelerated.rs', 'check_authority(op.owner.authority)?;', ''),
    ('parallel_accelerated.rs', 'check_authority(op.owner.authority)?;\n        let more', 'let more'),
    ('parallel_accelerated.rs', 'self.authority.quarantine();', ''),
    ('parallel_accelerated.rs', 'self.owner.quarantine();', ''),
    ('parallel_accelerated.rs', 'identity != op.owner.identity', 'false'),
    ('parallel_accelerated.rs', 'width != op.owner.width || last != op.owner.last', 'false'),
    ('parallel_accelerated.rs', 'if !copy(', 'if false && !copy('),
    ('parallel_accelerated.rs', 'clear_owned_region(&mut self.output)', 'clear_owned_region(&mut self.output[..0])'),
    ('parallel_accelerated.rs', 'input.len() > 1024', 'input.len() > 2048'),
    ('parallel_accelerated.rs', '.checked_sub(u64::try_from(input.len())', '.checked_add(u64::try_from(input.len())'),
    ('parallel_accelerated.rs', 'op.owner.root.finish_custom()?;', 'op.owner.root = State::leaf(op.owner.authority, op.owner.identity)?;'),
    ('parallel_accelerated.rs', 'if !terminal && last !=', 'if false && !terminal && last !='),
    ('parallel_accelerated.rs', 'suffix.right(bits)?;', 'suffix.right(0)?;'),
    ('parallel_accelerated.rs', 'self.next_width = 0;', 'self.next_width = 1;'),
    ('parallel_accelerated.rs', 'if op.owner.phase == Phase::CustomRetained', 'if false'),
    ('parallel_accelerated.rs', '.checked_sub(u64::try_from(op.owner.width)', '.checked_add(u64::try_from(op.owner.width)'),
    ('parallel_accelerated_input.rs', 'self.check_complete()?;', ''),
    ('parallel_accelerated_input.rs', 'suffix.right(u128::from_le_bytes(self.leaves))?;', 'suffix.right(0)?;'),
    ('parallel_accelerated_input.rs', 'root.update(output)?;', 'let _ = output;'),
    ('parallel_accelerated_input.rs', 'self.leaf.finish(tail)?;', 'self.leaf.finish(empty()?)?;'),
    ('parallel_accelerated_state.rs', 'b"ParallelHash"', 'b"ParallelHASH"'),
    ('parallel_accelerated_wire.rs', 'version != VERSION', 'false'),
    ('parallel_accelerated_wire.rs', 'sequence == 0', 'false'),
    ('parallel_accelerated_wire.rs', 'reserved != 0', 'false'),
    ('parallel_accelerated_wire.rs', 'route != 1', 'false'),
    ('parallel_accelerated_wire.rs', 'reserved_route != 0', 'false'),
    ('parallel_accelerated_wire.rs', 'length > 1024', 'length > 2048'),
    ('parallel_accelerated_wire.rs', 'source.checked_add(length).ok_or(Error::Length)?;', 'let _ = source;'),
    ('parallel_accelerated_wire.rs', 'guard.complete = result.is_ok();', 'guard.complete = true;'),
    ('parallel_accelerated_wire.rs', 'owner.begin(n, self.identity, self.block, self.custom, self.budget)', 'owner.begin(n, self.identity, 1, self.custom, self.budget)'),
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
        *[(trait, 'fn need<T: '+trait+'>() {} fn main() { need::<parallel_accelerated::Owner>(); }', 'E0277')
          for trait in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug')],
        ('lifetime', "fn escape() -> parallel_accelerated::Owner<'static> { let a = brynja_crypto_cpu::static_execution::Authority::new(brynja_crypto_cpu::static_execution::Kernel::X86Keccak).unwrap(); parallel_accelerated::Owner::new(&a).unwrap() } fn main() {}", 'E0515'),
    ]:
        probe = directory/'negative.rs'
        probe.write_text(source)
        result = subprocess.run(common+['--crate-name', 'negative', str(probe), '--emit=metadata',
            '-o', str(directory/'negative.rmeta'), '--extern',
            'parallel_accelerated='+str(directory/'libparallel_accelerated.rlib'), '--extern',
            'brynja_crypto_cpu='+str(directory/'libbrynja_crypto_cpu.rlib')],
            capture_output=True, text=True, timeout=120)
        if result.returncode == 0 or diagnostic not in result.stderr: raise AssertionError(result.stderr)
        negatives.append(dict(name=name, diagnostic=diagnostic, stderr=result.stderr))
    record = json.loads((directory/'parallel-accelerated-build.json').read_text())
    record['source_sha256'][Path(__file__).resolve().relative_to(build.ROOT).as_posix()] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    record.update(status='PARALLELHASH_AVX2_COMPONENT_PASS', initial=initial, final=final,
                  mutations=mutations, negatives=negatives,
                  binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest())
    for name, expected in record['generated_sha256'].items():
        assert hashlib.sha256((directory/name).read_bytes()).hexdigest() == expected
    (directory/'parallel-accelerated-results.json').write_text(json.dumps(record, indent=2)+'\n')
    print(f"ParallelHash AVX2 component: PASS; {record['oracle_cases']} independent cases; 256 retained rehashes; {len(mutations)} compiled mutants and {len(negatives)} ownership negatives rejected; no enclave claim")


if __name__ == '__main__': main()
