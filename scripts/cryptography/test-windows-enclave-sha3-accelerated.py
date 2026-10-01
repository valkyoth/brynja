#!/usr/bin/env python3
"""Native AVX2 private component regressions; not VBS or release qualification."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

import windows_enclave_sha3_accelerated_build as build

MUTANTS = (
    ('sha3_accelerated.rs', '!allowed.contains(&self.phase)', 'false'),
    ('sha3_accelerated.rs', 'self.sequence.checked_add(1) != Some(sequence)', 'false'),
    ('sha3_accelerated.rs', 'check_authority(op.owner.authority)?;', ''),
    ('sha3_accelerated.rs', 'self.authority.quarantine();', ''),
    ('sha3_accelerated.rs', 'self.owner.quarantine();', ''),
    ('sha3_accelerated.rs', 'if input.len() > 1024', 'if input.len() > 2048'),
    ('sha3_accelerated.rs', 'if !terminal && last !=', 'if false && !terminal && last !='),
    ('sha3_accelerated.rs', '!= identity', '!= identity && false'),
    ('sha3_accelerated.rs', 'width != op.owner.width || last != op.owner.last', 'false'),
    ('sha3_accelerated.rs', 'if !copy(', 'if false && !copy('),
    ('sha3_accelerated.rs', 'clear_owned_region(&mut self.output)', 'clear_owned_region(&mut self.output[..0])'),
    ('sha3_accelerated.rs', 'op.owner.last,', '8,'),
    ('sha3_accelerated_state.rs', 'Algorithm::Sha3_224 => 144', 'Algorithm::Sha3_224 => 136'),
    ('sha3_accelerated_state.rs', 'if name != 0 || custom != 0 { 0x04 }', 'if name != 0 || custom != 0 { 0x1f }'),
    ('sha3_accelerated_state.rs', 'prefix.as_ref().ok_or(Error::Terminal)?.complete()?;', 'prefix.as_ref().ok_or(Error::Terminal)?;'),
    ('sha3_accelerated_prefix.rs', 'if self.phase != if name', 'if false && self.phase != if name'),
    ('sha3_accelerated_prefix.rs', '.checked_sub(bits)', '.checked_sub(bits.min(self.remaining))'),
    ('sha3_accelerated_prefix.rs', 'left_encode_u128(self.custom)', 'left_encode_u128(0)'),
    ('sha3_accelerated_prefix.rs', 'if self.remaining != 0', 'if false && self.remaining != 0'),
    ('sha3_accelerated_prefix.rs', 'self.pending[0], byte, position, count, self.used', 'self.pending[0], byte, position, count, 0'),
    ('sha3_accelerated_prefix.rs', 'clear_owned_region(&mut self.pending).map_err', 'clear_owned_region(&mut self.pending[..0]).map_err'),
)


def prefix_model(directory, toolchain):
    fixture = directory/'prefix-model'
    fixture.mkdir()
    manifest = '[package]\nname="enclave-sha3-prefix-model"\nversion="0.0.0"\nedition="2024"\n'
    manifest += '[lib]\npath='+json.dumps(str(build.SOURCE/'sha3_accelerated_prefix_model.rs'))+'\n[dependencies]\n'
    for crate in ('brynja-core', 'brynja-hash-sha3'):
        manifest += crate+'={path='+json.dumps(str(build.ROOT/'crates'/crate))+'}\n'
    (fixture/'Cargo.toml').write_text(manifest+'[workspace]\n')
    command = ['cargo', '+'+toolchain, 'miri', 'test', '--offline', '--manifest-path', str(fixture/'Cargo.toml'), '--lib']
    output = build.run(command)
    if '3 passed; 0 failed' not in output:
        raise AssertionError(output)
    (directory/'prefix-model-miri.json').write_text(json.dumps(dict(command=command, output=output,
        scope='prefix bit-packing and completion only; synthetic byte sink, not AVX2 or VBS'), indent=2)+'\n')
    print(output, flush=True)


def run(directory, target, miri_toolchain=None):
    for name, before, _ in MUTANTS:
        if before not in (build.SOURCE/name).read_text():
            raise AssertionError('Stale source mutation: '+before)
    test_command = build.build(directory, target)
    binary = directory/'sha3-accelerated-test'
    record = json.loads((directory/'sha3-accelerated-build.json').read_text())
    state_command = record['commands'][-3]
    def execute(success):
        result = subprocess.run([str(binary), '--test-threads=1'], capture_output=True, text=True, timeout=180)
        marker = '11 passed; 0 failed' if success else 'FAILED'
        if (result.returncode == 0) != success or marker not in result.stdout:
            raise AssertionError(result.stdout+result.stderr)
        return result.stdout
    initial = execute(True)
    print(initial, flush=True)
    mutations = []
    for name, before, after in MUTANTS:
        print('MUTANT: '+name+': '+before, flush=True)
        path = directory/name
        original = path.read_bytes()
        text = original.decode()
        if before not in text:
            raise AssertionError('Stale mutation: '+before)
        try:
            path.write_text(text.replace(before, after))
            if name != 'sha3_accelerated.rs':
                build.run(state_command+['-A', 'unused_variables', '-A', 'dead_code'])
            build.run(test_command+['-A', 'unused_variables', '-A', 'dead_code'])
            mutations.append(dict(source=name, before=before, after=after, output=execute(False)))
        finally:
            path.write_bytes(original)
            if name != 'sha3_accelerated.rs':
                build.run(state_command)
    # Restore all native products as well as source bytes.
    build.run(record['commands'][-2])
    build.run(test_command)
    final = execute(True)
    common = test_command[:test_command.index('--crate-name')]
    deps = []
    for name in ('brynja_crypto_cpu', 'sha3_accelerated'):
        deps += ['--extern', name+'='+str(directory/('lib'+name+'.rlib'))]
    positive = directory/'positive.rs'
    positive.write_text('fn main(){let a=brynja_crypto_cpu::static_execution::Authority::new('
                        'brynja_crypto_cpu::static_execution::Kernel::X86Keccak).unwrap();'
                        'let o=sha3_accelerated::Owner::new(&a).unwrap();drop(o);}')
    build.run(common+deps+[str(positive), '--emit=metadata', '-o', str(directory/'positive.rmeta')])
    cases = [f'fn bound<T:{trait}>(){{}} fn main(){{bound::<sha3_accelerated::Owner<\'static>>();}}'
             for trait in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug')]
    cases.append('fn main(){let owner={let a=brynja_crypto_cpu::static_execution::Authority::new('
                 'brynja_crypto_cpu::static_execution::Kernel::X86Keccak).unwrap();'
                 'sha3_accelerated::Owner::new(&a).unwrap()};drop(owner);}')
    negatives = []
    for i, case in enumerate(cases):
        path = directory/f'negative_{i}.rs'
        path.write_text(case)
        result = subprocess.run(common+deps+[str(path), '--emit=metadata', '-o', str(directory/f'negative_{i}.rmeta')],
                                capture_output=True, text=True, timeout=120)
        code = 'E0597' if i == 5 else 'E0277'
        if result.returncode == 0 or code not in result.stderr:
            raise AssertionError(result.stderr)
        negatives.append(dict(source=case, expected_error=code, diagnostics=result.stderr))
    for name, digest in record['generated_sha256'].items():
        if hashlib.sha256((directory/name).read_bytes()).hexdigest() != digest:
            raise AssertionError('Generated artifact changed after restoration: '+name)
    result = dict(schema=1, status='COMPONENT_TESTS_PASS', enclave_execution=False,
                  production_qualified=False, target=target, initial=initial, final=final,
                  mutations=mutations, ownership_negatives=negatives,
                  oracle_cases=dict(cshake=628, nist_bits=76, hashlib=96,
                                    retained_rehash=512, fractional_setup=578),
                  compiler=subprocess.check_output(['rustc', '+1.98.1', '-vV'], text=True),
                  build_sha256=hashlib.sha256((directory/'sha3-accelerated-build.json').read_bytes()).hexdigest(),
                  binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest())
    (directory/'sha3-accelerated-results.json').write_text(json.dumps(result, indent=2)+'\n')
    print(f'AVX2 SHA-3 component: 11 tests, {len(mutations)} compiled mutants and {len(negatives)} ownership negatives PASS', flush=True)
    if miri_toolchain:
        prefix_model(directory, miri_toolchain)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--attest-native-bundle', action='store_true', required=True)
    parser.add_argument('--miri-toolchain')
    args = parser.parse_args()
    target = subprocess.check_output(['rustc', '+1.98.1', '-vV'], text=True).split('host: ')[1].splitlines()[0]
    if not target.startswith('x86_64-'):
        parser.error('Native x86-64 AVX/AVX2 required')
    run(args.directory.resolve(), target, args.miri_toolchain)
