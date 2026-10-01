#!/usr/bin/env python3
"""Focused actual key-prefix memory model; not native AVX2/VBS qualification."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('directory', type=Path)
    p.add_argument('--miri-toolchain')
    args = p.parse_args()
    directory = args.directory.resolve()
    directory.mkdir()
    paths = [ROOT/'assurance/windows-enclave-probe'/name for name in
             ('kmac_accelerated_key.rs', 'kmac_accelerated_key_model.rs')]
    for path in paths: shutil.copyfile(path, directory/path.name)
    manifest = '[package]\nname="kmac-key-model"\nversion="0.0.0"\nedition="2024"\n[workspace]\n[lib]\npath="kmac_accelerated_key_model.rs"\n[dependencies]\n'
    for name in ('brynja-core', 'brynja-hash-sha3'):
        manifest += name+'={path='+json.dumps(str(ROOT/'crates'/name))+',default-features=false}\n'
    (directory/'Cargo.toml').write_text(manifest)
    command = ['cargo', '+'+(args.miri_toolchain or '1.98.1')]
    if args.miri_toolchain: command += ['miri']
    command += ['test', '--offline', '--manifest-path', str(directory/'Cargo.toml'), '--lib']
    r = subprocess.run(command, capture_output=True, text=True, timeout=180)
    if r.returncode or '2 passed; 0 failed' not in r.stdout: raise RuntimeError(r.stdout+r.stderr)
    paths.append(Path(__file__).resolve())
    for name in ('brynja-core', 'brynja-hash-core', 'brynja-hash-sha3'):
        paths += [ROOT/'crates'/name/'Cargo.toml', *sorted((ROOT/'crates'/name/'src').rglob('*.rs'))]
    record = dict(status='KEY_MEMORY_MODEL_PASS', miri=bool(args.miri_toolchain),
        enclave_execution=False, native_kernel_execution=False, production_qualified=False,
        command=command, stdout=r.stdout, stderr=r.stderr,
        source_sha256={path.relative_to(ROOT).as_posix():hashlib.sha256(path.read_bytes()).hexdigest() for path in paths})
    (directory/'key-model-results.json').write_text(json.dumps(record, indent=2)+'\n')
    print('Actual KMAC key-prefix model: PASS; two tests; no native kernel or enclave claim')


if __name__ == '__main__': main()
