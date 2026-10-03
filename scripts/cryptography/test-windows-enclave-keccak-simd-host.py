#!/usr/bin/env python3
"""Compile actual host lifecycle/encoder mutations and affine ownership negatives.

Standalone focused diagnostic; does not add or change a release gate.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import windows_enclave_image_pin_build as build

ROOT = build.ROOT
SOURCE = ROOT/'crates/brynja-crypto-cpu-std/src/windows_enclave'
MUTANTS = (
    ('mod.rs', 'self.sequence.checked_add(1).ok_or(Error::Exhausted)?', 'self.sequence.wrapping_add(1)'),
    ('mod.rs', 'self.transport.request(request, input, output)?;', 'let _ = self.transport.request(request, input, output);'),
    ('mod.rs', 'self.transport.close()?;', 'let _ = self.transport.close();'),
    ('mod.rs', 'self.owner.state = State::Quarantined;', 'self.owner.state = State::Ready;'),
    ('mod.rs', 'if self.state != State::Ready {', 'if false {'),
    ('mod.rs', 'if matches!(self.state, State::Quarantined | State::Closed) {', 'if false {'),
    ('mod.rs', 'slot.output_bits > 2048', 'false'),
    ('wire.rs', 'self.sequence == 0', 'false'),
    ('wire.rs', '[22, self.sequence, self.budget, 2]', '[21, self.sequence, self.budget, 2]'),
    ('wire.rs', '[22, self.sequence, self.budget, 2]', '[22, self.sequence, self.budget, 1]'),
    ('wire.rs', 'length > 1024', 'false'),
    ('wire.rs', '!(1..=8).contains(&part.last)', 'false'),
    ('wire.rs', 'part.last != 0', 'false'),
    ('wire.rs', 'index != 0', 'false'),
    ('wire.rs', '(self.op != DIGEST && self.budget != 0)', 'false'),
    ('wire.rs', '|| clear != 1', '|| false'),
    ('wire.rs', '|| headers != 1', '|| false'),
    ('wire.rs', '|| error != 0', '|| false'),
    ('wire.rs', 'payloads != expected_payloads', 'false'),
    ('wire.rs', 'expected_payloads > 12', 'false'),
    ('wire.rs', '(operation != DIGEST && expected_payloads != 0)', 'false'),
)

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('directory', type=Path)
    args = p.parse_args()
    directory = args.directory.resolve()
    directory.mkdir()
    target = subprocess.check_output(['rustc', '+1.98.1', '-vV'], text=True).split('host: ')[1].splitlines()[0]
    if not target.endswith('linux-gnu'):
        raise ValueError('Linux host model only; use native capture for Windows')
    build.dependencies(directory, target, testing=True)
    subprocess.run(['rustc', '+1.98.1', '--edition=2024', '--crate-type=rlib', '--crate-name=brynja_hash_sha3', str(ROOT/'crates/brynja-hash-sha3/src/lib.rs'), '-L', 'dependency='+str(directory), '--extern', 'brynja_core='+str(directory/'libbrynja_core.rlib'), '--extern', 'brynja_hash_core='+str(directory/'libbrynja_hash_core.rlib'), '-o', str(directory/'libbrynja_hash_sha3.rlib')], check=True, capture_output=True, timeout=120)
    shutil.copytree(SOURCE, directory/'windows_enclave')
    (directory/'lib.rs').write_text('pub mod windows_enclave;\n')
    common = ['rustc', '+1.98.1', '--edition=2024', '--cfg', 'feature="strict-sha3-acceleration"',
              '-D', 'warnings', '-C', 'opt-level=1', '-L', 'dependency='+str(directory),
              '--extern', 'brynja_hash_sha2='+str(directory/'libbrynja_hash_sha2.rlib'), '--cfg', 'feature="strict-sha3"', '--extern', 'brynja_hash_sha3='+str(directory/'libbrynja_hash_sha3.rlib')]
    def checked(command):
        result = subprocess.run(command, capture_output=True, text=True, timeout=180)
        if result.returncode:
            raise RuntimeError('Compilation failure is not mutant rejection:\n'+result.stderr)
    command = common+['--test', str(directory/'lib.rs'), '-o', str(directory/'tests')]
    def execute(success):
        checked(command + ([] if success else ['-A', 'unused_variables']))
        r = subprocess.run([str(directory/'tests'), 'windows_enclave::keccak_simd::tests::'],
                           capture_output=True, text=True, timeout=60)
        if (r.returncode == 0) != success or ('5 passed; 0 failed' if success else 'FAILED') not in r.stdout:
            raise ValueError('Unexpected mutant result:\n'+r.stdout+r.stderr)
        return r.stdout+r.stderr
    record = dict(schema=1, production_qualified=False, initial=execute(True), mutations=[], negatives=[])
    for file, before, after in MUTANTS:
        path = directory/'windows_enclave/keccak_simd'/file
        original = path.read_text()
        if original.count(before) != 1:
            raise ValueError('Stale/ambiguous mutation: '+before)
        try:
            path.write_text(original.replace(before, after))
            record['mutations'].append(dict(file=file, before=before, after=after, output=execute(False)))
        finally:
            path.write_text(original)
        print('REJECTED: '+before, flush=True)
    record['final'] = execute(True)
    checked(common+['--crate-name', 'host', '--crate-type', 'rlib', str(directory/'lib.rs'), '-o', str(directory/'libhost.rlib')])
    for kind in ('Session', "Retained<'static>"):
        for trait in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug'):
            source = directory/'negative.rs'
            source.write_text(f'fn require<T: {trait}>() {{}} fn main() {{ require::<host::windows_enclave::keccak_simd::{kind}>(); }}')
            r = subprocess.run(common+['--extern', 'host='+str(directory/'libhost.rlib'), str(source), '--emit=metadata', '-o', str(directory/'negative.rmeta')],
                               capture_output=True, text=True, timeout=60)
            if r.returncode == 0 or 'error[E0277]' not in r.stderr:
                raise ValueError(r.stderr)
            record['negatives'].append(dict(kind=kind, trait=trait, stderr=r.stderr))
    paths = [*SOURCE.rglob('*.rs'), Path(__file__).resolve()]
    record.update(status='HOST_MODEL_PASS', source_sha256={p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths})
    (directory/'host-model-results.json').write_text(json.dumps(record, indent=2)+'\n')
    print('Keccak SIMD host model: PASS; twenty-one compiled mutations and ten ownership negatives rejected')

if __name__ == '__main__':
    main()
