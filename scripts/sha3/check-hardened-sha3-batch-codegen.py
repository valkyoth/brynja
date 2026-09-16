#!/usr/bin/env python3
"""Inspect SHA-3 batch frame/workspace cleanup; cross-compilation is not native evidence."""
import argparse
import os
from pathlib import Path
import subprocess
import tempfile

import sha3_hardened_batch_codegen as check

ROOT = Path(__file__).resolve().parents[2]


def compile_row(root, target, toolchain, platform, panic):
    env = dict(os.environ, CARGO_TARGET_DIR=str(target), CARGO_PROFILE_RELEASE_PANIC=panic)
    for key in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS', 'CARGO_BUILD_TARGET'):
        env.pop(key, None)
    subprocess.run(['cargo', '+' + toolchain, 'rustc', '--locked', '--offline', '--release',
                    '-p', 'brynja-hash-sha3', '--no-default-features', '--features', 'hardened-batch-execution',
                    '--target', platform, '--lib', '--', '--emit=mir,llvm-ir,asm'],
                   cwd=root, env=env, check=True, timeout=300)
    row = {}
    for extension in ('mir', 'll', 's'):
        paths = list(target.rglob('brynja_hash_sha3-*.' + extension))
        check.require(len(paths) == 1, 'unique emitted SHA-3 artifact')
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
    with tempfile.TemporaryDirectory(prefix='brynja-sha3-batch-cleanup-') as directory:
        for panic in ('abort', 'unwind'):
            row = compile_row(ROOT, Path(directory) / panic, args.toolchain, args.target, panic)
            count = check.mutations(row, panic)
            print(f'Hardened SHA-3 batch frame/workspace MIR/LLVM/assembly: PASS; {args.toolchain}; '
                  f'{args.target}; panic={panic}; rejected={count}', flush=True)


if __name__ == '__main__':
    main()
