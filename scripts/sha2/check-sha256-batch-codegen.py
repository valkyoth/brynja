#!/usr/bin/env python3
"""Inspect the exact independent-message SIMD compression body, not another kernel."""
import argparse
import os
from pathlib import Path
import re
import tempfile
import sha256_batch_acceptance as acceptance


def inspect(assembly, target):
    architecture = 'x86' if target.startswith('x86_64') else 'arm'
    pattern = r'^[_A-Za-z][^\n]*sha256_batch[^\n]*' + architecture + r'[^\n]*compress[^\n]*:\s*(?://[^\n]*)?\n'
    starts = list(re.finditer(pattern, assembly, re.M))
    if len(starts) != 1: raise ValueError('missing/ambiguous batch compression symbol')
    tail = assembly[starts[0].end():]
    if '.cfi_endproc' not in tail: raise ValueError('missing compression function end')
    body = tail.split('.cfi_endproc', 1)[0]
    if architecture == 'x86':
        required = (r'\bvpaddd\b', r'\bvpxor\b', r'\bvpsrld\b', r'\bymm\d+\b')
        forbidden = r'\bsha256\w+\b'
    else:
        required = (r'\badd(?:\s+v\d+\.4s|\.4s\s+v\d+)',
                    r'\beor(?:3)?(?:\s+v\d+\.|\.16b\s+v\d+)',
                    r'\bushr(?:\s+v\d+\.4s|\.4s\s+v\d+)')
        forbidden = r'\bsha256\w+\b'
    if any(not re.search(token, body) for token in required) or re.search(forbidden, body):
        raise ValueError('independent SIMD instructions absent or dedicated SHA substituted')


def check(target, toolchain='1.98.1'):
    with tempfile.TemporaryDirectory(prefix='brynja-sha256-batch-codegen-') as directory:
        env = dict(os.environ, CARGO_TARGET_DIR=directory)
        for key in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'CARGO_BUILD_TARGET'): env.pop(key, None)
        acceptance.run(['cargo', '+' + toolchain, 'rustc', '--locked', '--offline', '--release',
                        '-p', 'brynja-crypto-cpu', '--features', 'sha256-batch', '--target', target,
                        '--', '--emit=asm'], env=env)
        paths = list((Path(directory) / target / 'release/deps').glob('brynja_crypto_cpu-*.s'))
        if len(paths) != 1: raise ValueError('missing/ambiguous emitted artifact')
        assembly = paths[0].read_text()
        inspect(assembly, target)
        # The exact inspector must reject scalar-only/no-op vector substitutions.
        for before, after in (('vpaddd', 'scalar_add'), ('vpxor', 'scalar_xor')) if target.startswith('x86') else (('eor', 'scalar_xor'), ('ushr', 'scalar_shift')):
            try: inspect(assembly.replace(before, after), target)
            except ValueError: pass
            else: raise ValueError('SIMD inspector accepted instruction-removal mutant')
    print(f'SHA-224/256 independent SIMD codegen: PASS; {toolchain}; {target}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--target')
    parser.add_argument('--toolchain', default='1.98.1')
    args = parser.parse_args()
    target = args.target
    if target is None:
        version = acceptance.run(['rustc', '+' + args.toolchain, '-vV']).stdout
        target = next(line.removeprefix('host: ') for line in version.splitlines() if line.startswith('host: '))
    if not target.startswith(('x86_64', 'aarch64')): raise ValueError('unsupported SIMD evidence target')
    check(target, args.toolchain)
