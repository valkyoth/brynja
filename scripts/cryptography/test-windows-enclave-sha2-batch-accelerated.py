#!/usr/bin/env python3
"""Native SHA-NI Sequential SHA-224/256 batch component tests; not native enclave qualification."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import windows_enclave_sha2_batch_accelerated_build as build

MUTANTS = (
    ('sha2_batch_accelerated.rs', 'self.phase != phase', 'false'),
    ('sha2_batch_accelerated.rs', 'self.sequence.checked_add(1) != Some(sequence)', 'false'),
    ('sha2_batch_accelerated.rs', 'op.owner.next() != Some(slot)', 'false'),
    ('sha2_batch_accelerated.rs', 'self.active != Some(slot)', 'false'),
    ('sha2_batch_accelerated.rs', 'bytes > 1024', 'bytes > 2048'),
    ('sha2_batch_accelerated.rs', 'op.owner.next().is_some()', 'false'),
    ('sha2_batch_accelerated.rs', 'expected != op.owner.plan', 'false'),
    ('sha2_batch_accelerated.rs', 'if !copy(&op.owner.output)', 'if false && !copy(&op.owner.output)'),
    ('sha2_batch_accelerated.rs', 'if !self.complete', 'if false'),
    ('sha2_batch_accelerated.rs', 'clear_owned_region(&mut self.output)', 'clear_owned_region(&mut self.output[..0])'),
    ('sha2_batch_accelerated.rs', '.checked_sub(u64::try_from(bytes)', '.checked_add(u64::try_from(bytes)'),
    ('sha2_batch_accelerated.rs', 'check_authority(op.owner.authority)?;', ''),
    ('sha2_batch_accelerated.rs', 'check_authority(op.owner.authority)?;\n        op.owner.clear();', 'op.owner.clear();'),
    ('sha2_batch_accelerated.rs', 'self.authority.quarantine();', ''),
    ('sha2_batch_accelerated.rs', 'fn drop(&mut self) {\n        self.quarantine();', 'fn drop(&mut self) {\n        self.clear();'),
    ('sha2_accelerated_state.rs', 'Execution::from_static(authority).map_err(|_| Error::Backend)?', 'Execution::portable()'),
    ('sha2_batch_accelerated_wire.rs', 'version != VERSION', 'false'),
    ('sha2_batch_accelerated_wire.rs', 'route != 1', 'false'),
    ('sha2_batch_accelerated_wire.rs', 'reserved_route != 0', 'false'),
    ('sha2_batch_accelerated_wire.rs', 'sequence == 0', 'false'),
    ('sha2_batch_accelerated_wire.rs', 'reserved != 0', 'false'),
    ('sha2_batch_accelerated_wire.rs', 'length > 1024', 'length > 2048'),
    ('sha2_batch_accelerated_wire.rs', 'last > 8', 'last > 9'),
    ('sha2_batch_accelerated_wire.rs', 'slot >= 8', 'slot > 8'),
    ('sha2_batch_accelerated_wire.rs', 'operation != BEGIN && budget != 0', 'false'),
    ('sha2_batch_accelerated_wire.rs', '!planned && plan != [0; 8]', 'false'),
    ('sha2_batch_accelerated_wire.rs', 'narrow(identity)?;', 'let _ = identity;'),
    ('sha2_batch_accelerated_wire.rs', 'source.checked_add(length).ok_or(Error::Length)?;', 'let _ = source.wrapping_add(length);'),
    ('sha2_batch_accelerated_wire.rs', 'input.len() != self.length', 'false'),
)



def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--attest-native-bundle', action='store_true', required=True)
    args = parser.parse_args()
    directory = args.directory.resolve()
    target = subprocess.check_output(['rustc', '+1.98.1', '-vV'], text=True).split('host: ')[1].splitlines()[0]
    if not target.startswith('x86_64-'): parser.error('Native SHA/SSE2/AVX/AVX2 required')
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
            build.run(command+['-A', 'unused_variables', '-A', 'unused_imports', '-A', 'unused_mut', '-A', 'dead_code'])
            try: output = execute(False)
            except AssertionError as error: raise AssertionError('Survived: '+before+'\n'+str(error)) from error
            mutations.append(dict(file=filename, before=before, after=after, output=output))
            print('REJECTED: '+filename+': '+before, flush=True)
        finally: path.write_bytes(original)
    build.run(command)
    final = execute(True)
    negatives = []
    common = command[:command.index('--crate-name')]
    for name, source, diagnostic in [
        *[(trait, 'fn need<T: '+trait+'>() {} fn main() { need::<sha2_batch_accelerated::Owner>(); }', 'E0277')
          for trait in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug')],
        ('lifetime', "fn escape() -> sha2_batch_accelerated::Owner<'static> { let a = brynja_crypto_cpu::static_execution::Authority::new(brynja_crypto_cpu::static_execution::Kernel::X86Sha256).unwrap(); sha2_batch_accelerated::Owner::new(&a).unwrap() } fn main() {}", 'E0515'),
    ]:
        probe = directory/'negative.rs'
        probe.write_text(source)
        result = subprocess.run(common+['--crate-name', 'negative', str(probe), '--emit=metadata',
            '-o', str(directory/'negative.rmeta'), '--extern',
            'sha2_batch_accelerated='+str(directory/'libsha2_batch_accelerated.rlib'), '--extern',
            'brynja_crypto_cpu='+str(directory/'libbrynja_crypto_cpu.rlib')],
            capture_output=True, text=True, timeout=120)
        if result.returncode == 0 or diagnostic not in result.stderr: raise AssertionError(result.stderr)
        negatives.append(dict(name=name, diagnostic=diagnostic, stderr=result.stderr))
    record = json.loads((directory/'sha2-batch-accelerated-build.json').read_text())
    record['source_sha256'][Path(__file__).resolve().relative_to(build.ROOT).as_posix()] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    record.update(status='SEQUENTIAL_SHA2_BATCH_SHA_NI_COMPONENT_PASS', initial=initial, final=final,
                  mutations=mutations, negatives=negatives,
                  binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest())
    for name, expected in record['generated_sha256'].items():
        assert hashlib.sha256((directory/name).read_bytes()).hexdigest() == expected
    (directory/'sha2-batch-accelerated-results.json').write_text(json.dumps(record, indent=2)+'\n')
    print(f"Sequential SHA-224/256 batch SHA-NI component: PASS; {record['oracle_cases']} independent cases; 255 mixed activity masks; {len(mutations)} compiled mutants and {len(negatives)} ownership negatives rejected; sequential slots; no multi-message SIMD or enclave claim")


if __name__ == '__main__': main()
