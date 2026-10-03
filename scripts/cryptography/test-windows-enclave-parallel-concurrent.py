#!/usr/bin/env python3
"""Concurrent leaf/root tests and real compiled mutants; no OS protection claim."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

import windows_enclave_parallel_concurrent_build as build

MUTANTS = (
    ('parallel_concurrent.rs', 'if leaves > 4', 'if leaves > 5'),
    ('parallel_concurrent.rs', 'self.cancelled.load(Ordering::Acquire)', 'false'),
    ('parallel_concurrent.rs', '.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)',
     '.compare_exchange(false, false, Ordering::AcqRel, Ordering::Acquire)'),
    ('parallel_concurrent.rs', 'if op.batch.phase != Phase::Working', 'if false'),
    ('parallel_concurrent.rs', 'framing.right(u128::try_from(consumed).map_err(|_| Error::Length)?)?', 'framing.right(0)?'),
    ('parallel_concurrent.rs', 'u128::try_from(plan.output_bits).map_err(|_| Error::Length)?', '0'),
    ('parallel_concurrent.rs', 'clear_owned_region(&mut self.output)', 'clear_owned_region(&mut self.output[..0])'),
    ('parallel_concurrent.rs', 'if !self.complete {', 'if false {'),
    ('parallel_concurrent.rs', 'check_authority(op.batch.authority)?;', ''),
    ('parallel_concurrent_slot.rs', 'if op.slot.phase != Phase::Pending', 'if false'),
    ('parallel_concurrent_slot.rs', 'input.bit_len() != plan.leaf_bits(op.slot.index)?', 'false'),
    ('parallel_concurrent_slot.rs', '!core::ptr::eq(self.plan, plan)', 'false'),
    ('parallel_concurrent_slot.rs', 'self.index != index', 'false'),
    ('parallel_concurrent_slot.rs', 'clear_owned_region(&mut self.cv)', 'clear_owned_region(&mut self.cv[..0])'),
    ('parallel_concurrent_slot.rs', 'if !self.complete {', 'if false {'),
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--baseline-only', action='store_true')
    args = parser.parse_args()
    directory = args.directory.resolve()
    target = subprocess.check_output(['rustc', '+1.98.1', '-vV'], text=True).split('host: ')[1].splitlines()[0]
    command, binary = build.build(directory, target)

    def execute(success):
        result = subprocess.run([str(binary), '--nocapture'], capture_output=True, text=True, timeout=120)
        if (result.returncode == 0) != success or ('0 failed' if success else 'FAILED') not in result.stdout:
            raise AssertionError(result.stdout + result.stderr)
        return result.stdout + result.stderr

    initial = execute(True)
    print(initial, flush=True)
    mutations = []
    if not args.baseline_only:
        for index, (filename, before, after) in enumerate(MUTANTS):
            path = directory / filename
            original = path.read_bytes()
            if original.decode().count(before) != 1:
                raise ValueError('mutation location changed: ' + before)
            try:
                path.write_text(original.decode().replace(before, after))
                # Windows scanners can retain a just-executed EXE handle. Keep
                # each mutation's artifact rather than overwriting executables.
                binary = directory / (f'mutant-{index}.exe' if 'windows' in target else f'mutant-{index}')
                mutant_command = command.copy()
                mutant_command[mutant_command.index('-o') + 1] = str(binary)
                build.base.run(mutant_command + ['-A', 'unused_variables', '-A', 'unused_imports', '-A', 'unused_mut', '-A', 'dead_code'])
                output = execute(False)
                mutations.append(dict(file=filename, before=before, after=after, output=output))
                print('REJECTED: ' + before, flush=True)
            finally:
                path.write_bytes(original)
    binary = directory / ('parallel-concurrent-final.exe' if 'windows' in target else 'parallel-concurrent-final')
    final_command = command.copy()
    final_command[final_command.index('-o') + 1] = str(binary)
    build.base.run(final_command)
    final = execute(True)
    common = command[:command.index('--crate-name')]
    dependencies = [part for name in ('parallel_concurrent', 'brynja_crypto_cpu')
                    for part in ('--extern', name + '=' + str(directory / ('lib' + name + '.rlib')))]
    negatives = []
    probes = [(kind + ':' + trait,
               f"fn need<T: {trait}>() {{}} fn main() {{ need::<parallel_concurrent::{kind}>(); }}", 'E0277')
              for kind, traits in (("Batch<'static>", ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug')),
                                   ("Slot<'static>", ('Copy', 'Clone', 'core::fmt::Debug')),
                                   ('Plan', ('Copy', 'Clone')))
              for trait in traits]
    setup = ('let plan=parallel_concurrent::Plan::new(1,1,8,0,256).unwrap(); '
             'let authority=brynja_crypto_cpu::static_execution::Authority::new('
             'brynja_crypto_cpu::static_execution::Kernel::X86Keccak).unwrap(); '
             'let mut batch=parallel_concurrent::Batch::new(&plan,&authority).unwrap(); ')
    probes.append(('private-cv', 'fn main(){'+setup+'let slot=&batch.workers().unwrap()[0]; let _=slot.cv;}', 'E0616'))
    probes.append(('premature-root', 'fn main(){'+setup+
                   'let slots=batch.workers().unwrap(); let _=batch.workers(); let _=slots.len();}', 'E0499'))
    probes.append(('premature-drop', 'fn main(){'+setup+
                   'let slots=batch.workers().unwrap(); drop(batch); let _=slots.len();}', 'E0505'))
    for name, source, diagnostic in probes:
        path = directory / 'negative.rs'
        path.write_text(source)
        result = subprocess.run(common + ['--crate-name', 'negative', str(path), '--emit=metadata',
                                '-o', str(directory / 'negative.rmeta')] + dependencies,
                                capture_output=True, text=True, timeout=120)
        if result.returncode == 0 or diagnostic not in result.stderr:
            raise AssertionError(name + '\n' + result.stderr)
        negatives.append(dict(name=name, diagnostic=diagnostic, stderr=result.stderr))
    record = json.loads((directory / 'parallel-concurrent-build.json').read_text())
    for name, expected in record['generated_sha256'].items():
        assert hashlib.sha256((directory / name).read_bytes()).hexdigest() == expected
    record.update(status='CONCURRENT_PARALLELHASH_COMPONENT_PASS', initial=initial, final=final,
                  mutations=mutations, negatives=negatives, full_mutation_campaign=not args.baseline_only,
                  final_command=final_command, final_binary=binary.name,
                  binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest())
    (directory / 'parallel-concurrent-results.json').write_text(json.dumps(record, indent=2) + '\n')
    print(f"Concurrent ParallelHash component: PASS; {record['oracle_cases']} oracle cases x two orders; {len(mutations)} compiled mutants rejected; NOT enclave qualification")


if __name__ == '__main__':
    main()
