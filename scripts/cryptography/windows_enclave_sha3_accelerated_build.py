#!/usr/bin/env python3
"""Build private AVX2 SHA-3 component using the unchanged hardened engine source.

Not a native enclave qualification gate. Requires a native AVX2 test host.
The existing scalar worker tests are adapted only to supply explicit authority;
the source and adapted artifact are both recorded. Production crates are unchanged.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'assurance/windows-enclave-probe'
FILES = ('sha3_accelerated.rs', 'sha3_accelerated_state.rs',
         'sha3_accelerated_wire.rs',
         'sha3_accelerated_prefix.rs', 'sha3_accelerated_authority_tests.rs',
         'sha3_accelerated_prefix_model.rs', 'sha3_accelerated_prefix_tests.rs',
         'sha3_stream.rs', 'sha3_stream_state.rs', 'sha3_stream_tests.rs')
CRATES = ('brynja-core', 'brynja-hash-core', 'brynja-crypto-cpu', 'brynja-hash-sha3')


def run(command):
    result = subprocess.run(command, capture_output=True, text=True, timeout=180)
    if result.returncode:
        raise RuntimeError(str(command) + '\n' + result.stdout + result.stderr)
    return result.stdout


def build(directory, target):
    directory.mkdir()
    common = ['rustc', '+1.98.1', '--edition=2024', '--target', target, '-D', 'warnings',
              '-C', 'opt-level=2', '-C', 'overflow-checks=yes', '-C', 'panic=unwind',
              '-C', 'target-feature=+avx,+avx2', '-L', 'dependency='+str(directory)]
    commands, sources = [], {Path(__file__).resolve(),
                            ROOT/'scripts/cryptography/test-windows-enclave-sha3-accelerated.py'}
    def compile(command):
        run(command)
        commands.append(command)
    def dependencies(names):
        return [part for name in names for part in
                ('--extern', name+'='+str(directory/('lib'+name+'.rlib')))]
    for name in CRATES:
        crate = name.replace('-', '_')
        folder = ROOT/'crates'/name
        sources.update((folder/'src').rglob('*.rs'))
        sources.add(folder/'Cargo.toml')
        deps, features = [], []
        if name == 'brynja-crypto-cpu':
            deps = ['brynja_core']
            features = ['static-execution', 'hardened-execution']
        elif name == 'brynja-hash-sha3':
            deps = ['brynja_core', 'brynja_hash_core', 'brynja_crypto_cpu']
            features = ['cpu', 'static-execution', 'hardened-execution']
        compile(common+['--crate-name', crate, '--crate-type', 'rlib', str(folder/'src/lib.rs'),
                       '-o', str(directory/('lib'+crate+'.rlib'))]+dependencies(deps)+
                [part for f in features for part in ('--cfg', f'feature="{f}"')])
    for name in FILES:
        shutil.copyfile(SOURCE/name, directory/name)
        sources.add(SOURCE/name)
    engine = ROOT/'crates/brynja-hash-sha3/src/hardened/accelerated/engine.rs'
    shutil.copyfile(engine, directory/'keccak_engine.rs')
    for name in ('cshake-execution.txt', 'nist-bit-selected.txt'):
        path = ROOT/'crates/brynja-hash-sha3/tests/vectors'/name
        shutil.copyfile(path, directory/name)
        sources.add(path)
    deps = ['brynja_core', 'brynja_hash_sha3']
    for name in ('sha3_stream', 'sha3_accelerated_state', 'sha3_accelerated'):
        if name == 'sha3_accelerated_state':
            deps += ['sha3_stream', 'brynja_crypto_cpu']
        if name == 'sha3_accelerated':
            deps += ['sha3_accelerated_state']
        compile(common+['--crate-name', name, '--crate-type', 'rlib', str(directory/(name+'.rs')),
                        '-o', str(directory/('lib'+name+'.rlib'))]+dependencies(deps))
    tests = (SOURCE/'sha3_stream_tests.rs').read_text()
    anchor = 'let mut owner = Owner::new();'
    if tests.count(anchor) != 22:
        raise ValueError('Scalar test adaptation changed; review authority lifetimes')
    tests = tests.replace(anchor, 'let authority = make_authority(); let mut owner = Owner::new(&authority).unwrap();')
    tests = tests.replace('&Owner)', "&Owner<'_>)").replace('&mut Owner,', "&mut Owner<'_>,")
    tests += '\nfn make_authority() -> Authority { Authority::new(Kernel::X86Keccak).unwrap() }\n'
    tests += '#[test]\nfn independent_hashlib_byte_oracle() {\n'
    for identity, algorithm in enumerate(('sha3_224', 'sha3_256', 'sha3_384', 'sha3_512', 'shake_128', 'shake_256'), 1):
        for length in (0, 3, 71, 72, 73, 135, 136, 137, 143, 144, 145, 167, 168, 169, 1024, 1_000_000):
            data = bytes(i % 251 for i in range(length))
            h = hashlib.new(algorithm, data)
            expected = list(h.digest(333) if identity > 4 else h.digest())
            tests += ('{ let input: Vec<u8> = (0..'+str(length)+').map(|i| (i%251) as u8).collect();'
                      f'check_case({identity}, empty(), empty(), &input, {8 if length else 0}, &{expected}, 8); }}\n')
    tests += '}\n'
    (directory/'sha3_accelerated_tests.rs').write_text(tests)
    command = common+['--crate-name', 'sha3_accelerated', '--test', str(directory/'sha3_accelerated.rs'),
                      '-o', str(directory/'sha3-accelerated-test')]+dependencies(deps)
    compile(command)
    record = dict(schema=1, status='COMPONENT_BUILD_ONLY', enclave_execution=False,
                  production_qualified=False, target=target, commands=commands,
                  shared_engine='crates/brynja-hash-sha3/src/hardened/accelerated/engine.rs',
                  test_adaptation='Only scalar test owner construction/lifetime annotations; additional explicit authority tests',
                  source_sha256={p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(sources)},
                  generated_sha256={p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in directory.iterdir()
                                    if p.suffix in ('.rs', '.txt')})
    (directory/'sha3-accelerated-build.json').write_text(json.dumps(record, indent=2)+'\n')
    return command


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--target', default='x86_64-pc-windows-msvc')
    args = parser.parse_args()
    build(args.directory.resolve(), args.target)
