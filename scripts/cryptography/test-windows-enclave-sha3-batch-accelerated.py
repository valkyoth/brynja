#!/usr/bin/env python3
"""Native AVX2 Sequential SHA-3 batch component tests; not native enclave qualification."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import windows_enclave_sha3_batch_accelerated_build as build

MUTANTS = (
    ('sha3_batch_accelerated.rs', "self.phase != phase", "false"),
    ('sha3_batch_accelerated.rs', "self.sequence.checked_add(1) != Some(sequence)", "false"),
    ('sha3_batch_accelerated.rs', "op.owner.next() != Some(slot)", "false"),
    ('sha3_batch_accelerated.rs', "self.active != Some(slot)", "false"),
    ('sha3_batch_accelerated.rs', "bytes > 1024", "bytes > 2048"),
    ('sha3_batch_accelerated.rs', "op.owner.next().is_some()", "false"),
    ('sha3_batch_accelerated.rs', "expected != op.owner.plan", "false"),
    ('sha3_batch_accelerated.rs', "if !copy(&op.owner.output)", "if false && !copy(&op.owner.output)"),
    ('sha3_batch_accelerated.rs', "if !self.complete", "if false"),
    ('sha3_batch_accelerated.rs', "clear_owned_region(&mut self.output)", "clear_owned_region(&mut self.output[..0])"),
    ('sha3_batch_accelerated.rs', ".checked_sub(u64::try_from(bytes)", ".checked_add(u64::try_from(bytes)"),
    ('sha3_batch_accelerated.rs', "self.width != width || self.last != 8", "false"),
    ('sha3_batch_accelerated.rs', "self.width > 1024", "self.width > 2048"),
    ('sha3_batch_accelerated.rs', "if width > 1024 ||", "if false ||"),
    ('sha3_batch_accelerated.rs', "self.last > 8", "self.last > 9"),
    ('sha3_batch_accelerated.rs', "name != 0 || custom != 0", "false"),
    ('sha3_batch_accelerated.rs', "op.owner.state.finish_setup().map_err(|_| Error::Crypto)?;", "let _ = op.owner.state.finish_setup();"),
    ('sha3_batch_accelerated.rs', "check_authority(op.owner.authority)?;", ""),
    ('sha3_batch_accelerated.rs', "check_authority(op.owner.authority)?;\n        op.owner.clear();", "op.owner.clear();"),
    ('sha3_batch_accelerated.rs', "self.authority.quarantine();", ""),
    ('sha3_batch_accelerated.rs', "fn drop(&mut self) {\n        self.quarantine();", "fn drop(&mut self) {\n        self.clear();"),
    ('sha3_batch_accelerated_wire.rs', 'words.get(36) != Some(&1)', 'false'),
    ('sha3_batch_accelerated_wire.rs', 'words.get(37) != Some(&0)', 'false'),
    ('sha3_batch_accelerated_wire.rs', 'version != VERSION', 'false'),
    ('sha3_batch_accelerated_wire.rs', 'sequence == 0', 'false'),
    ('sha3_batch_accelerated_wire.rs', 'reserved != 0', 'false'),
    ('sha3_batch_accelerated_wire.rs', 'length > 1024', 'length > 2048'),
    ('sha3_batch_accelerated_wire.rs', 'last > 8', 'last > 9'),
    ('sha3_batch_accelerated_wire.rs', 'slot >= 8', 'slot > 8'),
    ('sha3_batch_accelerated_wire.rs', 'operation != BEGIN && budget != 0', 'false'),
    ('sha3_batch_accelerated_wire.rs', 'operation != START && (name != 0 || custom != 0)', 'false'),
    ('sha3_batch_accelerated_wire.rs', '!planned && plan != [Slot::default(); 8]', 'false'),
    ('sha3_batch_accelerated_wire.rs', 'Owner::validate_plan(&plan)?;', 'let _ = plan;'),
    ('sha3_batch_accelerated_wire.rs', 'source.checked_add(length).ok_or(Error::Length)?;', 'let _ = source.wrapping_add(length);'),
    ('sha3_batch_accelerated_wire.rs', 'input.len() != self.length', 'false'),
    ('sha3_batch_accelerated_wire.rs', 'self.operation == NAME', 'self.operation == CUSTOM'),
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
        *[(trait, 'fn need<T: '+trait+'>() {} fn main() { need::<sha3_batch_accelerated::Owner>(); }', 'E0277')
          for trait in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug')],
        ('lifetime', "fn escape() -> sha3_batch_accelerated::Owner<'static> { let a = brynja_crypto_cpu::static_execution::Authority::new(brynja_crypto_cpu::static_execution::Kernel::X86Keccak).unwrap(); sha3_batch_accelerated::Owner::new(&a).unwrap() } fn main() {}", 'E0515'),
    ]:
        probe = directory/'negative.rs'
        probe.write_text(source)
        result = subprocess.run(common+['--crate-name', 'negative', str(probe), '--emit=metadata',
            '-o', str(directory/'negative.rmeta'), '--extern',
            'sha3_batch_accelerated='+str(directory/'libsha3_batch_accelerated.rlib'), '--extern',
            'brynja_crypto_cpu='+str(directory/'libbrynja_crypto_cpu.rlib')],
            capture_output=True, text=True, timeout=120)
        if result.returncode == 0 or diagnostic not in result.stderr: raise AssertionError(result.stderr)
        negatives.append(dict(name=name, diagnostic=diagnostic, stderr=result.stderr))
    record = json.loads((directory/'sha3-batch-accelerated-build.json').read_text())
    record['source_sha256'][Path(__file__).resolve().relative_to(build.ROOT).as_posix()] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    record.update(status='SEQUENTIAL_SHA3_BATCH_AVX2_COMPONENT_PASS', initial=initial, final=final,
                  mutations=mutations, negatives=negatives,
                  binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest())
    for name, expected in record['generated_sha256'].items():
        assert hashlib.sha256((directory/name).read_bytes()).hexdigest() == expected
    (directory/'sha3-batch-accelerated-results.json').write_text(json.dumps(record, indent=2)+'\n')
    print(f"Sequential SHA-3 batch AVX2 component: PASS; {record['oracle_cases']} independent cases; 255 mixed activity masks; {len(mutations)} compiled mutants and {len(negatives)} ownership negatives rejected; sequential slots; no multi-message SIMD or enclave claim")


if __name__ == '__main__': main()
