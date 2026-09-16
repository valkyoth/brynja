#!/usr/bin/env python3
"""Development Kani proofs of actual ParallelHash batch/completion predicates.

Does not change the global harness inventory or release gates. Does not prove
hash algorithms, transfer provenance, cleanup, threading or native instructions.
"""
import argparse
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import tomllib

import parallel_batch_proofs as proofs

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('batch_kani', Path(__file__).with_name('check-hardened-batch-kani.py'))
results = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(results)


def changed_source(original, before, after):
    if original.count(before) != 1:
        raise ValueError('non-unique source mutation: ' + before)
    return original.replace(before, after)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--proof', choices=tuple(proofs.HARNESSES) + ('all',), default='all')
    args = parser.parse_args()
    policy = tomllib.loads((ROOT / 'assurance/policy.toml').read_text())
    toolchain = policy['toolchains']['kani']
    version = next(tool['version'] for tool in policy['tools'] if tool['id'] == 'kani')
    prefix = ['rustup', 'run', toolchain, 'cargo']
    installed = results.run([*prefix, 'kani', '--version'], ROOT, os.environ)
    if installed.returncode or installed.stdout.strip() != 'cargo-kani ' + version:
        raise ValueError('repository-pinned Kani installation required')
    selected = tuple(proofs.HARNESSES) if args.proof == 'all' else (args.proof,)
    with tempfile.TemporaryDirectory(prefix='brynja-parallel-batch-kani-') as directory:
        root = Path(directory)
        for package in ('brynja-core', 'brynja-hash-core', 'brynja-crypto-cpu',
                        'brynja-crypto-cpu-std', 'brynja-hash-sha2', 'brynja-hash-sha3', 'brynja-hash-parallel'):
            shutil.copytree(ROOT / 'crates' / package, root / 'crates' / package,
                            ignore=shutil.ignore_patterns('target'))
        (root / 'Cargo.toml').write_text((ROOT / 'Cargo.toml').read_text().replace(
            'default-members = ["crates/brynja"]', 'default-members = ["crates/brynja-hash-parallel"]'))
        env = dict(os.environ, CARGO_TARGET_DIR=str(root / 'target'), CARGO_NET_OFFLINE='true')
        for key in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS', 'CARGO_BUILD_TARGET', 'RUSTUP_TOOLCHAIN'):
            env.pop(key, None)
        subprocess.run([*prefix, 'generate-lockfile', '--offline'], cwd=root, env=env, check=True, timeout=60)
        base = root / 'crates/brynja-hash-parallel/src'
        originals = {name: (base / name).read_text() for name in proofs.SOURCES}
        for name, harness in proofs.SOURCES.items():
            (base / name).write_text(originals[name] + harness)
        count = 0
        for key in selected:
            command = [*prefix, 'kani', '-p', 'brynja-hash-parallel', '--no-default-features',
                       '--features', 'hardened-batch-execution', '--harness', proofs.HARNESSES[key]]
            results.require_success(results.run(command, root, env))
            print('ParallelHash batch Kani proof: PASS; ' + key, flush=True)
            for owner, name, before, after in proofs.MUTANTS:
                if owner != key:
                    continue
                path = base / name
                try:
                    path.write_text(changed_source(originals[name], before, after) + proofs.SOURCES[name])
                    results.require_counterexample(results.run(command, root, env))
                    count += 1
                    print('ParallelHash batch Kani counterexample: PASS; ' + before, flush=True)
                finally:
                    path.write_text(originals[name] + proofs.SOURCES[name])
            results.require_success(results.run(command, root, env))
        print(f'ParallelHash batch predicates: PASS; {len(selected)} proofs; {count} real-source '
              f'counterexamples; Kani {version}; {toolchain}', flush=True)


if __name__ == '__main__':
    main()
