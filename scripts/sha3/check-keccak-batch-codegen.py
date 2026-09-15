#!/usr/bin/env python3
"""Compile and inspect the exact ordinary multibuffer Keccak kernel."""
import argparse
import keccak_batch_codegen as codegen

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--target')
    parser.add_argument('--toolchain', default='1.98.1')
    args = parser.parse_args()
    target = args.target
    if target is None:
        version = codegen.run(['rustc', '+' + args.toolchain, '-vV'])
        target = next(line.removeprefix('host: ') for line in version.splitlines() if line.startswith('host: '))
    codegen.check(target, args.toolchain)
