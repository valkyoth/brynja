#!/usr/bin/env python3
"""Development compiler checks for ParallelHash batch workspace, stream and transport."""
import argparse
import os
from pathlib import Path
import subprocess
import tempfile

import batch_cleanup_codegen as check
import batch_worker_cleanup as worker
import batch_worker_lifecycle as lifecycle
import batch_worker_arguments as arguments_check
import batch_worker_drop_glue as drop_glue
import batch_worker_inline as inline
import batch_worker_provenance as provenance
import batch_worker_scalar as scalar
import batch_worker_machine as machine
import batch_worker_handoff as handoff

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
            print(f'ParallelHash worker storage MIR/LLVM/assembly: PASS; {args.toolchain}; '
                  f'{args.target}; panic={panic}; rejected={count}', flush=True)
            states, count = lifecycle.mutations(row, panic)
            print(f'ParallelHash worker coordinator MIR lifecycle: PASS; {args.toolchain}; '
                  f'{args.target}; panic={panic}; states={states}; rejected={count}', flush=True)
            count = arguments_check.mutations(row)
            print(f'ParallelHash worker destructor arguments LLVM/assembly: PASS; {args.toolchain}; '
                  f'{args.target}; panic={panic}; rejected={count}', flush=True)
            count = drop_glue.mutations(row, panic)
            print(f'ParallelHash retained worker drop glue: {"PASS" if count else "not emitted; see separate inlined checks"}; '
                  f'{args.toolchain}; {args.target}; panic={panic}; rejected={count}', flush=True)
            states, count = inline.mutations(row, panic)
            print(f'ParallelHash inlined post-spawn LLVM cleanup reachability: PASS; {args.toolchain}; '
                  f'{args.target}; panic={panic}; states={states}; rejected={count}', flush=True)
            if args.toolchain == '1.98.1' and args.target.startswith('aarch64-') and panic == 'abort':
                states, sites, count = scalar.mutations(row, panic)
                print(f'ParallelHash scalar inlined arguments: PASS; {args.toolchain}; '
                      f'{args.target}; panic={panic}; states={states}; sites={sites}; rejected={count}', flush=True)
            else:
                states, sites, count = provenance.mutations(row, panic)
                print(f'ParallelHash inlined memory-backed arguments: PASS; {args.toolchain}; '
                      f'{args.target}; panic={panic}; states={states}; sites={sites}; rejected={count}', flush=True)
            states, count = machine.mutations(row, panic)
            print(f'ParallelHash machine normal-path cleanup reachability: PASS; {args.toolchain}; '
                  f'{args.target}; panic={panic}; states={states}; rejected={count}; unwind/arguments excluded', flush=True)
            if args.toolchain == '1.98.1' and args.target.startswith('aarch64-'):
                print(f'ParallelHash machine argument handoff: PENDING; {args.toolchain}; '
                      f'{args.target}; panic={panic}; register-held owner requires separate qualification', flush=True)
            else:
                root, sites, count = handoff.mutations(row, panic)
                print(f'ParallelHash machine stack-owner handoff: PASS; {args.toolchain}; '
                      f'{args.target}; panic={panic}; root={root}; sites={sites}; rejected={count}; '
                      'preceding memory provenance/unwind excluded', flush=True)


if __name__ == '__main__':
    main()
