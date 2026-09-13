#!/usr/bin/env python3
"""Check both supported compiler endpoints and native instruction architectures."""
import argparse
from pathlib import Path
import tempfile
import hardened_codegen as evidence


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--compiler', choices=('1.90.0', '1.98.1'))
    parser.add_argument('--target', choices=('x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-gnu', 'aarch64-apple-darwin'))
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='brynja-sha1-hardened-codegen-') as temporary:
        for compiler in (args.compiler,) if args.compiler else ('1.90.0', '1.98.1'):
            for target in (args.target,) if args.target else ('x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-gnu'):
                for panic in ('abort', 'unwind'):
                    evidence.compile_and_check(Path(temporary) / (compiler + '-' + target + '-' + panic), compiler, target, panic)
                print(f'Hardened SHA-1 MIR/LLVM/assembly: PASS; {compiler}; {target}; seven owned regions; no register-erasure claim')


if __name__ == '__main__': main()
