#!/usr/bin/env python3
"""Development-only hosted hardened batch graph and compiled mutation checks.

No release workflow changes or native qualification are implied by this driver.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
FAMILIES = ('sha256', 'sha512', 'keccak')
FEATURES = ','.join(family + '-hardened-batch' for family in FAMILIES)


def run(command, root, env, success=True):
    result = subprocess.run(command, cwd=root, env=env, capture_output=True, text=True, timeout=300)
    if success and result.returncode:
        raise RuntimeError(str(command) + '\n' + result.stdout[-3000:] + result.stderr[-3000:])
    return result


def graphs(root, env, cargo):
    for family in FAMILIES:
        result = run([*cargo, 'metadata', '--locked', '--offline', '--format-version=1',
                      '--no-default-features', '--features',
                      'brynja-crypto-cpu-std/' + family + '-hardened-batch'], root, env)
        nodes = json.loads(result.stdout)['resolve']['nodes']
        forbidden = {'batch-execution', 'batch512-execution', 'keccak-batch',
                     'sha256-batch', 'sha512-batch', 'static-execution', 'runtime-execution'}
        for node in nodes:
            if forbidden.intersection(node['features']):
                raise ValueError('hardened hosted feature enabled ordinary execution: ' + node['id'])
    print('Three isolated hardened hosted feature closures: PASS')


def mutants(root, env, cargo, target):
    command = [*cargo, 'test', '--locked', '--offline', '-p', 'brynja-crypto-cpu-std',
               '--no-default-features', '--features', FEATURES, '--target', target,
               '--lib', 'hardened_batch']
    run(command, root, env)
    run(command[:-2] + ['--doc', 'hardened_batch'], root, env)
    count = 0
    for family in FAMILIES:
        path = root / f'crates/brynja-crypto-cpu-std/src/{family}_hardened_batch/mod.rs'
        original = path.read_text()
        cases = [
            ('if mode == Mode::Portable {', 'if false {'),
            ('Err(Error::Unavailable) if mode == Mode::Prefer => None,',
             'Err(_) if mode == Mode::Prefer => None,'),
            ('if minimum_work == 0 {', 'if false {'),
            ('owner.quarantine();', '// lost owner revocation'),
            ('None => Ok(Executor::portable()),', 'None => Err(Error::Unavailable),'),
            ('owner.session().map_err(backend)?,', 'return Ok(Executor::portable()),'),
        ]
        for before, after in cases:
            if original.count(before) != 1:
                raise ValueError('ambiguous mutation anchor: ' + before)
            try:
                path.write_text(original.replace(before, after))
                result = run(command, root, env, success=False)
                if result.returncode == 0 or 'test result: FAILED' not in result.stdout:
                    raise ValueError('mutant survived or failed compilation: ' + before + '\n' + result.stderr[-2500:])
                count += 1
            finally:
                path.write_text(original)
    run(command, root, env)
    print(f'Hosted hardened selection/revocation compiled mutants: {count} rejected')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', default='x86_64-unknown-linux-gnu')
    parser.add_argument('--toolchain', default='1.98.1')
    args = parser.parse_args()
    if not args.target.startswith(('x86_64-', 'aarch64-')):
        raise ValueError('unsupported target')
    with tempfile.TemporaryDirectory(prefix='brynja-hosted-hardened-batch-') as directory:
        root = Path(directory)
        for crate in ('brynja-core', 'brynja-hash-core', 'brynja-crypto-cpu',
                      'brynja-hash-sha2', 'brynja-hash-sha3', 'brynja-crypto-cpu-std'):
            shutil.copytree(ROOT / 'crates' / crate, root / 'crates' / crate,
                            ignore=shutil.ignore_patterns('target'))
        manifest = (ROOT / 'Cargo.toml').read_text().replace(
            'default-members = ["crates/brynja"]', 'default-members = ["crates/brynja-crypto-cpu-std"]')
        (root / 'Cargo.toml').write_text(manifest)
        env = dict(os.environ, CARGO_TARGET_DIR=str(root / 'target'))
        for key in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS', 'CARGO_BUILD_TARGET'):
            env.pop(key, None)
        env['RUSTFLAGS'] = '-C target-feature=' + ('+avx,+avx2' if args.target.startswith('x86_64') else '+neon')
        if args.target == 'aarch64-unknown-linux-musl':
            env['RUSTFLAGS'] += ' -C linker=rust-lld'
        env['RUSTDOCFLAGS'] = env['RUSTFLAGS']
        env['BRYNJA_REQUIRE_HOSTED_HARDENED_BATCH'] = '1'
        cargo = ['cargo', '+' + args.toolchain]
        run([*cargo, 'generate-lockfile', '--offline'], root, env)
        graphs(root, env, cargo)
        mutants(root, env, cargo, args.target)


if __name__ == '__main__':
    main()
