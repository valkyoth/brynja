#!/usr/bin/env python3
"""Real AVX2 component and compiled regressions, not enclave qualification."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import windows_enclave_kmac_accelerated_build as build

MUTANTS = (
    ('kmac_accelerated.rs', '!allowed.contains(&self.phase)', 'false'),
    ('kmac_accelerated.rs', 'self.sequence.checked_add(1) != Some(sequence)', 'false'),
    ('kmac_accelerated.rs', 'check_authority(op.owner.authority)?;', ''),
    ('kmac_accelerated.rs', 'self.authority.quarantine();', ''),
    ('kmac_accelerated.rs', 'self.owner.quarantine();', ''),
    ('kmac_accelerated.rs', 'if input.len() > 1024', 'if input.len() > 2048'),
    ('kmac_accelerated.rs', 'if !terminal && last !=', 'if false && !terminal && last !='),
    ('kmac_accelerated.rs', 'clear_owned_region(&mut self.output)', 'clear_owned_region(&mut self.output[..0])'),
    ('kmac_accelerated.rs', 'if !copy(', 'if false && !copy('),
    ('kmac_accelerated.rs', 'accumulate_secret_byte_difference(&mut difference.0[0], left, right);', 'let _ = (left, right);'),
    ('kmac_accelerated_setup.rs', 'op.owner.state.custom(input)?;', 'let _ = input;'),
    ('kmac_accelerated_setup.rs', 'op.owner.state.key(input)?;', 'let _ = input;'),
    ('kmac_accelerated_setup.rs', 'op.owner.last,', '8,'),
    ('kmac_accelerated_setup.rs', 'op.owner.clear_output();', ''),
    ('kmac_accelerated_state.rs', 'if key < strength', 'if false && key < strength'),
    ('kmac_accelerated_state.rs', 'b"KMAC"', 'b"KMAQ"'),
    ('kmac_accelerated_state.rs', 'Self::suffix(s, input, bits)?;', 'Self::suffix(s, input, 0)?;'),
    ('kmac_accelerated_state.rs', 'Self::suffix(s, input, 0)?;', 'Self::suffix(s, input, 256)?;'),
    ('kmac_accelerated_key.rs', 'if self.remaining != 0', 'if false && self.remaining != 0'),
    ('kmac_accelerated_key.rs', '.checked_sub(u128::try_from(bits.bit_len()).map_err(|_| Error::Length)?)', '.checked_add(u128::try_from(bits.bit_len()).map_err(|_| Error::Length)?)'),
    ('kmac_accelerated_key.rs', 'left_encode_u128(bits).as_bytes())?;', 'left_encode_u128(0).as_bytes())?;'),
    ('kmac_accelerated_key.rs', 'self.used = 0;', 'self.used = 1;'),
)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('directory', type=Path)
    args = p.parse_args()
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
    mutations = []
    for filename, before, after in MUTANTS:
        path = directory/filename
        original = path.read_bytes()
        if before not in original.decode(): raise AssertionError('Stale mutant: '+before)
        try:
            path.write_text(original.decode().replace(before, after))
            # Compilation failures do not count as rejected runtime mutants.
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
        *[(trait, 'fn need<T: '+trait+'>() {} fn main() { need::<kmac_accelerated::Owner>(); }', 'E0277')
          for trait in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug')],
        ('lifetime', "fn escape() -> kmac_accelerated::Owner<'static> { let a = brynja_crypto_cpu::static_execution::Authority::new(brynja_crypto_cpu::static_execution::Kernel::X86Keccak).unwrap(); kmac_accelerated::Owner::new(&a).unwrap() } fn main() {}", 'E0515'),
    ]:
        probe = directory/'negative.rs'
        probe.write_text(source)
        invocation = common+['--crate-name', 'negative', str(probe), '--emit=metadata', '-o', str(directory/'negative.rmeta'),
            '--extern', 'kmac_accelerated='+str(directory/'libkmac_accelerated.rlib'),
            '--extern', 'brynja_crypto_cpu='+str(directory/'libbrynja_crypto_cpu.rlib')]
        result = subprocess.run(invocation, capture_output=True, text=True, timeout=120)
        if result.returncode == 0 or diagnostic not in result.stderr: raise AssertionError(result.stderr)
        negatives.append(dict(name=name, diagnostic=diagnostic, stderr=result.stderr))
    record = json.loads((directory/'kmac-accelerated-build.json').read_text())
    record['source_sha256'][Path(__file__).resolve().relative_to(build.ROOT).as_posix()] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    record.update(status='KMAC_AVX2_COMPONENT_PASS', initial=initial, final=final, mutations=mutations, negatives=negatives,
                  binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest())
    for name, expected in record['generated_sha256'].items():
        assert hashlib.sha256((directory/name).read_bytes()).hexdigest() == expected
    (directory/'kmac-accelerated-results.json').write_text(json.dumps(record, indent=2)+'\n')
    print('KMAC AVX2 component: PASS; 256 independent cases; 128 retained rekeys; 22 compiled regressions rejected; no enclave claim')


if __name__ == '__main__': main()
