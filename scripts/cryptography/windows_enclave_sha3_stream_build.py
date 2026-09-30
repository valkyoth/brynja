#!/usr/bin/env python3
"""Compile the private scalar SHA-3 worker, not a native qualification gate."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tomllib

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'assurance/windows-enclave-probe'
CRATES = ('brynja-core', 'brynja-hash-core', 'brynja-hash-sha3')
FILES = ('sha3_stream.rs', 'sha3_stream_state.rs', 'sha3_stream_tests.rs')


def run(command):
    result = subprocess.run(command, text=True, capture_output=True, timeout=180)
    if result.returncode:
        raise RuntimeError(f'{command}\n{result.stdout}\n{result.stderr}')
    return result.stdout


def build(directory, target, testing=False):
    directory = directory.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    common = ['rustc', '+1.98.1', '--edition=2024', '--target', target,
              '-D', 'warnings', '-C', 'opt-level=2', '-C', 'overflow-checks=yes',
              '-C', 'panic='+('unwind' if testing else 'abort'),
              '-L', 'dependency='+str(directory)]
    commands, sources = [], [Path(__file__).resolve()]
    for name in CRATES:
        folder = ROOT/'crates'/name
        manifest = folder/'Cargo.toml'
        policy = tomllib.loads(manifest.read_text())
        if policy.get('features', {}).get('default') or policy.get('build-dependencies') or policy['package'].get('build'):
            raise ValueError('Unexpected worker build graph')
        deps = policy.get('dependencies', {})
        if name.endswith('sha3'):
            if set(deps) != {'brynja-core', 'brynja-hash-core', 'brynja-crypto-cpu'} or not deps['brynja-crypto-cpu'].get('optional'):
                raise ValueError('Unexpected SHA-3 dependencies')
            if any(not d.get('workspace') or d.get('features') for d in deps.values()):
                raise ValueError('Unexpected dependency features')
        elif deps:
            raise ValueError('Unexpected foundation dependencies')
        sources += [manifest, *sorted((folder/'src').rglob('*.rs'))]
        crate = name.replace('-', '_')
        command = common+['--crate-name', crate, '--crate-type', 'rlib', str(folder/'src/lib.rs'),
                          '-o', str(directory/('lib'+crate+'.rlib'))]
        if name.endswith('sha3'):
            for dep in ('brynja_core', 'brynja_hash_core'):
                command += ['--extern', dep+'='+str(directory/('lib'+dep+'.rlib'))]
        run(command); commands.append(command)
    for name in FILES:
        shutil.copyfile(SOURCE/name, directory/name)
        sources.append(SOURCE/name)
    for name in ('cshake-execution.txt', 'nist-bit-selected.txt'):
        path = ROOT/'crates/brynja-hash-sha3/tests/vectors'/name
        shutil.copyfile(path, directory/name); sources.append(path)
    rows = ['#[test]', 'fn independent_hashlib_oracle() {']
    for identity, algorithm in enumerate(('sha3_224','sha3_256','sha3_384','sha3_512','shake_128','shake_256'), 1):
        for length in (0,3,71,72,73,135,136,137,143,144,145,167,168,169,1024,1_000_000):
            data = bytes(i % 251 for i in range(length))
            digest = hashlib.new(algorithm,data)
            expected = digest.digest(333) if identity > 4 else digest.digest()
            rows.append('{ let input: std::vec::Vec<u8> = (0..'+str(length)+').map(|i| (i%251) as u8).collect();')
            rows.append('let expected = ['+','.join(map(str,expected))+'];')
            rows.append(f'check_case({identity}, empty(), empty(), &input, {8 if length else 0}, &expected, 8); }}')
    rows.append('}')
    tests = directory/'sha3_stream_tests.rs'
    tests.write_text(tests.read_text()+'\n'+'\n'.join(rows)+'\n')
    artifact = directory/('sha3-tests.exe' if 'windows' in target else 'sha3-tests') if testing else directory/'libsha3_stream.rlib'
    command = common+['--crate-name','sha3_stream',str(directory/'sha3_stream.rs')]
    for dep in ('brynja_core','brynja_hash_sha3'):
        command += ['--extern',dep+'='+str(directory/('lib'+dep+'.rlib'))]
    command += ['--test'] if testing else ['--crate-type','rlib']
    command += ['-o',str(artifact)]
    run(command); commands.append(command)
    record = dict(schema=1, status='BUILD_ONLY', production_qualified=False, target=target,
        commands=commands, source_sha256={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sources},
        artifact_sha256=hashlib.sha256(artifact.read_bytes()).hexdigest())
    (directory/'sha3-stream-build.json').write_text(json.dumps(record,indent=2)+'\n')
    return artifact


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory',type=Path)
    parser.add_argument('--target',default='x86_64-pc-windows-msvc')
    parser.add_argument('--test',action='store_true')
    args = parser.parse_args()
    print(build(args.directory,args.target,args.test))
