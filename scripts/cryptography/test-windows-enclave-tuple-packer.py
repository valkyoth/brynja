#!/usr/bin/env python3
"""Run actual TupleHash bit-packer under Miri with a noncryptographic sink."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT/'assurance/windows-enclave-probe'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--miri-toolchain', default='nightly-2026-09-11')
    args = parser.parse_args()
    directory = args.directory.resolve()
    directory.mkdir()
    model = SOURCE/'tuple_accelerated_packer_model.rs'
    packer = SOURCE/'tuple_accelerated_packer.rs'
    shutil.copyfile(model, directory/model.name)
    # include! requires outer comments. Preserve every executable byte.
    contents = packer.read_text()
    body = ''.join(line for line in contents.splitlines(keepends=True) if not line.startswith('//!'))
    path = directory/'tuple_accelerated_packer_body.rs'
    path.write_text(body)
    manifest = '[package]\nname="tuple-packer-model"\nversion="0.0.0"\nedition="2024"\n'
    manifest += '[lib]\npath="tuple_accelerated_packer_model.rs"\n[dependencies]\n'
    for name in ('brynja-core', 'brynja-hash-sha3'):
        manifest += name+'={path='+json.dumps(str(ROOT/'crates'/name))+'}\n'
    (directory/'Cargo.toml').write_text(manifest+'[workspace]\n')
    command = ['cargo', '+'+args.miri_toolchain, 'miri', 'test', '--offline',
               '--manifest-path', str(directory/'Cargo.toml'), '--lib']
    def run(success):
        result = subprocess.run(command, capture_output=True, text=True, timeout=180)
        if (result.returncode == 0) != success or ('2 passed; 0 failed' if success else 'FAILED') not in result.stdout:
            raise AssertionError(result.stdout+result.stderr)
        return result.stdout+result.stderr
    initial = run(True)
    mutants = []
    for before, after in (
        ('clear_owned_region(&mut self.pending)', 'clear_owned_region(&mut self.pending[..0])'),
        ('self.used = 0;', 'self.used = 1;'),
        ('xor_secret_byte_bits(&mut self.pending[0], byte, bit, 1, self.used)',
         'xor_secret_byte_bits(&mut self.pending[0], byte, 0, 1, self.used)'),
    ):
        if body.count(before) != 1: raise AssertionError('Stale packer mutant: '+before)
        try:
            path.write_text(body.replace(before, after))
            compile_result = subprocess.run(['cargo', '+1.98.1', 'test', '--offline',
                '--manifest-path', str(directory/'Cargo.toml'), '--lib', '--no-run'],
                capture_output=True, text=True, timeout=180)
            if compile_result.returncode: raise AssertionError(compile_result.stderr)
            mutants.append(dict(before=before, after=after, output=run(False)))
        finally: path.write_text(body)
    sources = {model, packer, Path(__file__).resolve()}
    for name in ('brynja-core', 'brynja-hash-core', 'brynja-hash-sha3'):
        crate = ROOT/'crates'/name
        sources.add(crate/'Cargo.toml')
        sources.update((crate/'src').rglob('*.rs'))
    record = dict(schema=1, status='PACKER_MIRI_MODEL_PASS', crypto_execution=False,
        enclave_execution=False, production_qualified=False, command=command,
        initial=initial, final=run(True), mutations=mutants,
        source_sha256={p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                       for p in sources},
        generated_sha256={name: hashlib.sha256((directory/name).read_bytes()).hexdigest()
                          for name in ('Cargo.toml', 'Cargo.lock', model.name, path.name)})
    (directory/'tuple-packer-results.json').write_text(json.dumps(record, indent=2)+'\n')
    print('Actual TupleHash packer Miri model: PASS; 2 tests, 3 compiled mutants rejected; no cryptography/VBS claim')


if __name__ == '__main__': main()
