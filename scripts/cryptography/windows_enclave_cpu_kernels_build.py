#!/usr/bin/env python3
"""Build public-only specialized enclave kernel diagnostics; no shipping policy."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess

import windows_enclave_cpu_inventory as inventory

ROOT = inventory.ROOT
FILES = ('cpu_kernels.rs', 'cpu_kernel_entry.c', 'cpu_inventory.c', 'synthetic.c')
FEATURES = ('static-execution', 'hardened-execution', 'sha256-hardened-batch',
            'sha512-hardened-batch', 'keccak-hardened-batch')


def vectors():
    path = ROOT / 'scripts/sha3/check-sha3-bit-differential.py'
    spec = importlib.util.spec_from_file_location('independent_keccak', path)
    oracle = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(oracle)
    rows = []
    def emit(name, values, width):
        rows.append(f'pub const {name}: [[u8; {width}]; {len(values)}] = '+repr([list(v) for v in values])+';')
    for name, width, limit, iv in (
        ('SHA256', 64, 56, '6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19'),
        ('SHA512', 128, 112, '6a09e667f3bcc908bb67ae8584caa73b3c6ef372fe94f82ba54ff53a5f1d36f1'
         '510e527fade682d19b05688c2b3e6c1f1f83d9abfb41bd6b5be0cd19137e2179')):
        messages = [bytes((j * 17 + case) % 256 for j in range((case * 13) % limit)) for case in range(32)]
        blocks = [message + b'\x80' + bytes(width - len(message) - 9) + (len(message) * 8).to_bytes(8, 'big')
                  for message in messages]
        rows.append(f'pub const {name}_IV: [u8; {len(bytes.fromhex(iv))}] = '+repr(list(bytes.fromhex(iv)))+';')
        emit(name+'_BLOCKS', blocks, width)
        emit(name+'_EXPECTED', [hashlib.new(name.lower(), m).digest() for m in messages], width // 2)
    inputs = [bytes(200)] + [bytes((i * 29 + case) % 256 for i in range(200)) for case in range(1, 16)]
    outputs = []
    for data in inputs:
        state = [int.from_bytes(data[i:i+8], 'little') for i in range(0, 200, 8)]
        oracle.permute(state)
        outputs.append(b''.join(v.to_bytes(8, 'little') for v in state))
    emit('KECCAK_INPUT', inputs, 200)
    emit('KECCAK_EXPECTED', outputs, 200)
    return '\n'.join(rows)+'\n'


def build(directory, target, testing=False):
    inventory.build(directory)
    for name in FILES:
        shutil.copyfile(ROOT / 'assurance/windows-enclave-probe' / name, directory / name)
    (directory / 'cpu_vectors.rs').write_text(vectors())
    common = ['rustc', '+1.98.1', '--edition=2024', '--target', target, '-D', 'warnings',
              '-C', 'opt-level=2', '-C', 'overflow-checks=yes', '-C', 'embed-bitcode=yes',
              '-C', 'target-feature=+sha,+sse2,+avx,+avx2', '-C', 'panic='+('unwind' if testing else 'abort'),
              '-L', 'dependency='+str(directory)]
    commands = []
    def run(command):
        result = subprocess.run(command, capture_output=True, text=True, timeout=120)
        if result.returncode:
            raise RuntimeError(result.stdout+result.stderr)
        commands.append(command)
    for name in ('brynja-core', 'brynja-crypto-cpu'):
        crate = name.replace('-', '_')
        command = common + ['--crate-type', 'rlib', '--crate-name', crate,
                            str(ROOT/'crates'/name/'src/lib.rs'), '-o', str(directory/('lib'+crate+'.rlib'))]
        if name == 'brynja-crypto-cpu':
            command += ['--extern', 'brynja_core='+str(directory/'libbrynja_core.rlib')]
            for feature in FEATURES:
                command += ['--cfg', f'feature="{feature}"']
        run(command)
    command = common + ['--crate-name', 'cpu_kernels', str(directory/'cpu_kernels.rs'),
                         '--extern', 'brynja_crypto_cpu='+str(directory/'libbrynja_crypto_cpu.rlib')]
    if testing:
        command += ['--test', '-o', str(directory/'cpu-kernels-test')]
    else:
        command += ['--crate-type', 'staticlib', '-C', 'lto=fat',
                    '--emit='+','.join(kind+'='+str(directory/('kernels.'+ext))
                                       for kind, ext in [('link', 'lib'), ('asm', 's'), ('llvm-ir', 'll')])]
    run(command)
    script = (directory/'link.cmd').read_text().replace('cpu_inventory.c /link', 'cpu_kernel_entry.c kernels.lib /link')
    (directory/'link.cmd').write_text(script)
    sources = set(inventory.SOURCES) | {'scripts/cryptography/windows_enclave_cpu_kernels_build.py',
        'scripts/cryptography/test-windows-enclave-cpu-kernels.py',
        'scripts/sha3/check-sha3-bit-differential.py'} | {'assurance/windows-enclave-probe/'+name for name in FILES}
    for crate in ('brynja-core', 'brynja-crypto-cpu'):
        sources.add(f'crates/{crate}/Cargo.toml')
        sources.update(p.relative_to(ROOT).as_posix() for p in (ROOT/'crates'/crate/'src').rglob('*.rs'))
    record = dict(status='BUILD_ONLY', production_qualified=False, target=target, commands=commands,
                  sources={name: hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in sorted(sources)},
                  vectors_sha256=hashlib.sha256((directory/'cpu_vectors.rs').read_bytes()).hexdigest())
    (directory/'cpu-kernels-build.json').write_text(json.dumps(record, indent=2)+'\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--target', default='x86_64-pc-windows-msvc')
    parser.add_argument('--test', action='store_true')
    args = parser.parse_args()
    build(args.directory.resolve(), args.target, args.test)
