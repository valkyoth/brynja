#!/usr/bin/env python3
"""Capture exact-source development-image host tests; never production trust evidence."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def sources():
    paths = [ROOT/'Cargo.toml', ROOT/'Cargo.lock', ROOT/'rust-toolchain.toml', Path(__file__).resolve()]
    for crate in ('brynja-core', 'brynja-hash-core', 'brynja-crypto-cpu',
                  'brynja-hash-sha2', 'brynja-hash-sha3', 'brynja-crypto-cpu-std'):
        folder = ROOT/'crates'/crate
        paths += [folder/'Cargo.toml', *sorted((folder/'src').rglob('*.rs'))]
    import windows_enclave_keccak_simd_oracle as oracle
    paths += [ROOT/p for p in oracle.SOURCES]
    return {p.relative_to(ROOT).as_posix(): digest(p) for p in paths}

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('image', type=Path)
    p.add_argument('directory', type=Path)
    p.add_argument('--other-image', type=Path, required=True)
    args = p.parse_args()
    if sys.platform != 'win32':
        raise ValueError('native Windows required')
    image = args.image.resolve(strict=True)
    other = args.other_image.resolve(strict=True)
    if other == image:
        raise ValueError('wrong-protocol image must be distinct')
    out = args.directory.resolve()
    out.mkdir()  # Never overwrite a previous observation.
    env = os.environ.copy()
    for name in ('RUSTFLAGS', 'RUSTDOCFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'CARGO_BUILD_TARGET'):
        env.pop(name, None)
    env['BRYNJA_ENCLAVE_KECCAK_SIMD_IMAGE'] = str(image)
    env['BRYNJA_ENCLAVE_KECCAK_SIMD_SHA256'] = digest(image)
    env['BRYNJA_ENCLAVE_OTHER_SIMD_IMAGE'] = str(other)
    env['BRYNJA_ENCLAVE_OTHER_SIMD_SHA256'] = digest(other)
    import windows_enclave_keccak_simd_oracle as oracle
    if oracle.generate(out) != 520:
        raise ValueError('incomplete independent vectors')
    env['BRYNJA_KECCAK_SIMD_VECTORS'] = str(out/'keccak-simd-vectors.txt')
    before = sources()
    record = dict(schema=1, status='RUNNING', production_qualified=False,
                  source_sha256=before, image_sha256=digest(image), other_image_sha256=digest(other), commands=[], binaries={})
    def run(label, command):
        result = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True, timeout=900)
        logs = {}
        for name in ('stdout', 'stderr'):
            path = out/(label+'.'+name)
            path.write_text(getattr(result, name))
            logs[name+'_sha256'] = digest(path)
        record['commands'].append(dict(label=label, command=command, exit_code=result.returncode, **logs))
        (out/'host-results.json').write_text(json.dumps(record, indent=2)+'\n')
        if result.returncode:
            raise RuntimeError(label+'\n'+result.stdout[-6000:]+result.stderr[-6000:])
        return result.stdout
    record['rustc'] = run('rustc', ['rustc', '+1.98.1', '-vV'])
    for profile in ('debug', 'release'):
        command = ['cargo', '+1.98.1', 'test', '--locked', '--offline', '-p', 'brynja-crypto-cpu-std',
                   '--features', 'strict-sha2,strict-sha3-acceleration', '--lib', '--no-run', '--message-format=json']
        if profile == 'release':
            command += ['--release']
        output = run('build-'+profile, command)
        artifacts = [json.loads(line) for line in output.splitlines() if line.startswith('{')]
        binaries = [Path(r['executable']) for r in artifacts
                    if r.get('reason') == 'compiler-artifact' and r.get('executable')]
        if len(binaries) != 1:
            raise ValueError('ambiguous test binary')
        binary = out/(profile+'-host-tests.exe')
        shutil.copyfile(binaries[0], binary)
        record['binaries'][binary.name] = digest(binary)
        output = run(profile+'-native', [str(binary),
            'windows_enclave::keccak_simd::tests::native::development_keccak_simd_host_campaign',
            '--ignored', '--exact', '--nocapture'])
        if '1 passed; 0 failed' not in output or 'batches=521; digests=2084;' not in output:
            raise ValueError('incomplete native host campaign')
        output = run(profile+'-lifecycle', [str(binary), 'windows_enclave::'])
        if '0 failed' not in output or 'running 0 tests' in output:
            raise ValueError('incomplete host regression suite')
        print(profile+': 521 four-lane batches PASS', flush=True)
    run('clippy', ['cargo', '+1.98.1', 'clippy', '--locked', '--offline', '-p', 'brynja-crypto-cpu-std',
        '--features', 'strict-sha2,strict-sha3-acceleration', '--all-targets', '--', '-D', 'warnings',
        '-A', 'clippy::chunks_exact_to_as_chunks'])
    if sources() != before or digest(image) != record['image_sha256'] or digest(other) != record['other_image_sha256']:
        raise ValueError('source/image changed during capture')
    if any(digest(out/name) != value for name, value in record['binaries'].items()):
        raise ValueError('test executable changed during capture')
    record['oracle_sha256'] = digest(out/'keccak-simd-vectors.txt')
    record['status'] = 'NATIVE_HOST_DEVELOPMENT_PASS'
    (out/'host-results.json').write_text(json.dumps(record, indent=2)+'\n')
    print('KECCAK_SIMD_HOST: PASS; development-only; exact-source debug/release', flush=True)

if __name__ == '__main__':
    main()
