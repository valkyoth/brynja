#!/usr/bin/env python3
"""Compile shipping SHA-NI metadata against the actual worker decoder; no OS claims."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import windows_enclave_sha2_batch_accelerated_build as build


def checked(command):
    r = subprocess.run(command, capture_output=True, text=True, timeout=180)
    if r.returncode:
        raise RuntimeError(r.stdout+r.stderr)
    return r.stdout


def run(directory, target):
    command, binary = build.build(directory, target)
    paths = [build.SOURCE/'sha2_batch_sha_ni_host_wire_tests.rs']
    host = build.ROOT/'crates/brynja-crypto-cpu-std/src/windows_enclave'
    for name, renamed in [('sha2_batch_wire.rs', 'sha2_batch_host_wire.rs'), ('sha2_batch_sha_ni_wire.rs', 'sha2_batch_host_sha_ni_wire.rs'), ('sha2_batch_receipt.rs', 'sha2_batch_host_receipt.rs')]:
        paths.append(host/name)
        shutil.copyfile(host/name, directory/renamed)
    shutil.copyfile(paths[0], directory/paths[0].name)
    source = directory/'sha2_batch_accelerated.rs'
    source.write_text(source.read_text()+'\n#[cfg(test)]\nmod sha2_batch_sha_ni_host_wire_tests;\n')
    checked(command)
    def execute(success):
        r = subprocess.run([str(binary), 'shipping_sha_ni_encoder_and_worker_agree'],
                           capture_output=True, text=True, timeout=120)
        if ((r.returncode == 0) != success or
                ('1 passed; 0 failed' if success else 'FAILED') not in r.stdout):
            raise AssertionError(r.stdout+r.stderr)
        return r.stdout+r.stderr
    initial = execute(True)
    mutations = []
    for filename, before, after in (
        ('sha2_batch_host_sha_ni_wire.rs','19_u64','10_u64'),
        ('sha2_batch_host_sha_ni_wire.rs','1_u64','0_u64'),
        ('sha2_batch_host_sha_ni_wire.rs','request.plan.iter().any(|id| !matches!(id, 0..=2))','false'),
        ('sha2_batch_host_wire.rs','self.sequence == 0','false'),
        ('sha2_batch_host_wire.rs','input.len() > 1024','false'),
        ('sha2_batch_host_wire.rs','self.slot >= 8','false'),
        ('sha2_batch_host_wire.rs','self.last > 8','false'),
        ('sha2_batch_host_wire.rs','(!planned && self.plan != [0; 8])','false'),
        ('sha2_batch_host_wire.rs','(planned && self.plan == [0; 8])','false'),
        ('sha2_batch_host_wire.rs','(self.op != 80 && self.budget != 0)','false'),
    ):
        print('ENCODER_MUTATION: '+before, flush=True)
        path = directory/filename
        original = path.read_bytes()
        if original.decode().count(before) != 1:
            raise AssertionError('Stale encoder mutant: '+before)
        try:
            path.write_text(original.decode().replace(before, after))
            checked(command)
            mutations.append(dict(file=filename, before=before, after=after, output=execute(False)))
        finally:
            path.write_bytes(original)
    checked(command)
    final = execute(True)
    record = json.loads((directory/'sha2-batch-accelerated-build.json').read_text())
    paths.append(Path(__file__).resolve())
    record['source_sha256'].update({p.relative_to(build.ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths})
    record.update(status='HOST_ENCODER_PARITY_PASS', enclave_execution=False, production_qualified=False,
                  initial=initial, final=final, mutations=mutations)
    record['generated_sha256'] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in directory.glob('*.rs')}
    (directory/'sha2-batch-host-wire-results.json').write_text(json.dumps(record, indent=2)+'\n')
    print('Actual host/worker metadata parity passes; ten compiled encoder mutants rejected')


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('directory', type=Path)
    args = p.parse_args()
    target = checked(['rustc', '+1.98.1', '-vV']).split('host: ')[1].splitlines()[0]
    run(args.directory.resolve(), target)
