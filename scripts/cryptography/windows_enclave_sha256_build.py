#!/usr/bin/env python3
"""Build only the explicit public-vector experiment; no Cargo/gate changes."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tomllib

ROOT = Path(__file__).resolve().parents[2]
CRATES = ('brynja-core', 'brynja-hash-core', 'brynja-hash-sha2')
VARIANTS = {'normal': None, 'missing-local-clear': 'probe_skip_sha256_clear',
            'wrong-digest': 'probe_bad_sha256_digest'}
LENGTHS = (0, 3, 56, 112, 1, 55, 56, 63, 64, 65, 119, 120, 127, 128, 129, 255, 256, 511, 512, 1024)
TEXT = (b'', b'abc', b'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq',
        b'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu')


def vectors():
    return [TEXT[i] if i < 4 else bytes((j * 17 + i) % 256 for j in range(n))
            for i, n in enumerate(LENGTHS)]


def vector_source():
    rows = ['// Independent Python hashlib oracle; public test vectors only.',
            'pub const LENGTHS: [usize; 20] = [' + ', '.join(map(str, LENGTHS)) + '];',
            'pub const EXPECTED: [[u8; 32]; 20] = [']
    for data in vectors():
        rows.append('    [' + ', '.join(f'0x{b:02x}' for b in hashlib.sha256(data).digest()) + '],')
    return '\n'.join(rows + ['];', ''])


def check_graph(root=ROOT):
    for crate in CRATES:
        data = tomllib.loads((root / 'crates' / crate / 'Cargo.toml').read_text())
        assert not data.get('features', {}).get('default')
        assert not data.get('build-dependencies') and not data['package'].get('build')
        deps = data.get('dependencies', {})
        if crate == 'brynja-hash-sha2':
            assert set(deps) == {'brynja-core', 'brynja-hash-core', 'brynja-crypto-cpu'}
            assert deps['brynja-crypto-cpu'].get('optional') is True
            assert all(dep.get('workspace') is True and not dep.get('features') for dep in deps.values())
        else:
            assert not deps


def source_files(root=ROOT):
    paths = ['Cargo.toml']
    for crate in CRATES:
        folder = root / 'crates' / crate
        paths.append((folder / 'Cargo.toml').relative_to(root).as_posix())
        paths.extend(p.relative_to(root).as_posix() for p in sorted((folder / 'src').rglob('*.rs')))
    return paths


def build(directory, target, testing=False):
    check_graph()
    assert (ROOT / 'assurance/windows-enclave-probe/sha256_vectors.rs').read_text() == vector_source()
    directory = directory.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    commands = []
    def run(args):
        command = ['rustc', '+1.98.1', '--edition=2024', '-C', 'opt-level=2',
                   '-C', 'overflow-checks=yes', '-C', 'codegen-units=1',
                   '-C', 'force-unwind-tables=yes', '-C', 'embed-bitcode=yes',
                   '-C', 'panic=' + ('unwind' if testing else 'abort'), '--target', target, *args]
        commands.append(command)
        subprocess.run(command, cwd=ROOT, check=True, timeout=120)
    for crate in CRATES:
        name = crate.replace('-', '_')
        args = ['--crate-type', 'rlib', '--crate-name', name, 'crates/' + crate + '/src/lib.rs',
                '-o', str(directory / ('lib' + name + '.rlib'))]
        if crate == 'brynja-hash-sha2':
            for dep in ('brynja_core', 'brynja_hash_core'):
                args += ['--extern', dep + '=' + str(directory / ('lib' + dep + '.rlib'))]
        run(args)
    for variant, cfg in VARIANTS.items():
        args = ['assurance/windows-enclave-probe/window_sha256.rs', '--crate-name', 'enclave_sha256',
                '-L', 'dependency=' + str(directory), '--extern',
                'brynja_hash_sha2=' + str(directory / 'libbrynja_hash_sha2.rlib')]
        if cfg:
            args += ['--cfg', cfg]
        if testing:
            suffix = '.exe' if 'windows' in target else ''
            run(args + ['--test', '-o', str(directory / (variant + suffix))])
        else:
            run(args + ['--crate-type', 'staticlib', '-C', 'lto=fat',
                        '--emit=' + ','.join(kind + '=' + str(directory / (variant + '_rust.' + suffix))
                                             for kind, suffix in [('link', 'lib'), ('asm', 's'), ('llvm-ir', 'll')])])
    return commands


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    commands = build(args.output, 'x86_64-pc-windows-msvc')
    identity = subprocess.check_output(['rustc', '+1.98.1', '-vV'], text=True)
    (args.output / 'rustc-info.txt').write_text(identity)
    record = {'commands': commands, 'rustc': identity, 'features': [],
              'source_sha256': {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in source_files()},
              'archives': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in args.output.glob('*_rust.lib')}}
    (args.output / 'rust-build.json').write_text(json.dumps(record, indent=2) + '\n')
    print('Public-vector SHA-256 archives built; no native execution or qualification implied')
