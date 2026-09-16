#!/usr/bin/env python3
"""Development compiler checks for ParallelHash batch workspace, stream and transport."""
import argparse
import os
from pathlib import Path
import subprocess
import tempfile

import batch_cleanup_codegen as check
import batch_worker_cleanup as worker

ROOT = Path(__file__).resolve().parents[2]


def compile_row(root, target, toolchain, platform, panic, workers=False):
    package = 'brynja-hash-parallel-std' if workers else 'brynja-hash-parallel'
    feature = 'runtime-batch-execution' if workers else 'hardened-batch-execution'
    env = dict(os.environ, CARGO_TARGET_DIR=str(target), CARGO_PROFILE_RELEASE_PANIC=panic)
    for key in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS', 'CARGO_BUILD_TARGET'):
        env.pop(key, None)
    subprocess.run(['cargo', '+' + toolchain, 'rustc', '--locked', '--offline', '--release',
                    '-p', package, '--no-default-features', '--features', feature,
                    '--target', platform, '--lib', '--', '--emit=mir,llvm-ir,asm'],
                   cwd=root, env=env, check=True, timeout=300)
    row = {}
    for extension in ('mir', 'll', 's'):
        paths = list(target.rglob(package.replace('-', '_') + '-*.' + extension))
        check.require(len(paths) == 1, 'unique emitted ParallelHash artifact')
        row[extension] = paths[0].read_text()
    return row


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--toolchain', choices=('1.90.0', '1.98.1'), default='1.98.1')
    parser.add_argument('--target', choices=('x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-musl',
                                            'aarch64-apple-darwin'), default='x86_64-unknown-linux-gnu')
    return parser.parse_args()


def main():
    args = arguments()
    with tempfile.TemporaryDirectory(prefix='brynja-parallel-batch-cleanup-') as directory:
        for panic in ('abort', 'unwind'):
            row = compile_row(ROOT, Path(directory) / panic, args.toolchain, args.target, panic)
            count = check.mutations(row, panic)
            print(f'ParallelHash batch cleanup MIR/LLVM/assembly: PASS; {args.toolchain}; '
                  f'{args.target}; panic={panic}; rejected={count}', flush=True)
            row = compile_row(ROOT, Path(directory) / (panic + '-workers'), args.toolchain, args.target, panic, True)
            count = worker.mutations(row, panic)
            print(f'ParallelHash worker storage MIR/LLVM: PASS; {args.toolchain}; '
                  f'{args.target}; panic={panic}; rejected={count}', flush=True)


if __name__ == '__main__':
    main()
