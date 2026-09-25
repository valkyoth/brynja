#!/usr/bin/env python3
"""Focused optimized resource-call checks, not whole-call erasure qualification.

This checks retained eager locking and clear/release calls in exact functions.
Native protection, conditional control flow, full payload coverage and joins
are tested separately by the real resource tests and packaged source mutants.
No release-gate change or claim of arbitrary-register/abort-time cleanup.
"""
import argparse
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def require(condition, label):
    if not condition:
        raise ValueError('Protected resource compiler check: ' + label)


def function(llvm, tokens):
    matches = [body for body in re.findall(r'^define .*?^}', llvm, re.M | re.S)
               if all(token in body.splitlines()[0] for token in tokens)]
    require(len(matches) == 1, 'unique function ' + repr(tokens))
    return matches[0]


def inspect(llvm, assembly):
    require(not re.search(r'@mlock\(', llvm), 'no intercepted mlock fallback')
    constructor = function(llvm, ('protected_memory', 'Mapping3new'))
    calls = re.findall(r'^.*call .*@mlock2\([^\n]+', constructor, re.M)
    require(len(calls) == 1 and re.search(r', i32(?: noundef)? 0\)', calls[0]),
            'exact eager mlock2 zero flags')
    for tokens in (('protected_memory', 'Mapping5clear'),
                   ('protected_memory', 'Mapping', 'Drop', '4drop'),
                   ('protected_memory', 'ProtectedBytes5close'),
                   ('protected_memory', 'ProtectedStack5close')):
        body = function(llvm, tokens)
        require(re.search(r'^\s*(?:%[^\s]+ = )?(?:tail )?(?:call|invoke) .*clear_owned_region',
                          body, re.M), 'retained full-resource clear call/invoke')
        if tokens[-1] != 'Mapping5clear':
            require('@munmap(' in body and body.index('clear_owned_region') < body.index('@munmap('),
                    'clear and release call ordering (not a dominance proof)')
        symbol = re.search(r'@("[^"]+"|[^ (]+)\(', body.splitlines()[0])[1].strip('"')
        match = re.search(r'^' + re.escape(symbol) + r':[^\n]*\n(.*?)^\.Lfunc_end\d+:',
                          assembly, re.M | re.S)
        require(match is not None, 'exact machine function')
        machine = match[1]
        require(re.search(r'\b(?:callq?|b|bl|jmpq?)\b[^\n]*clear_owned_region', machine),
                'retained machine clear call')
        if tokens[-1] != 'Mapping5clear':
            require(re.search(r'\b(?:callq?|b|bl|jmpq?)\b[^\n]*munmap', machine),
                    'retained machine release call')


def regressions(llvm, assembly):
    cases = [
        (llvm.replace('@mlock2(', '@mlock(', 1), assembly),
        (re.sub(r'(@mlock2\([^\n]*, i32(?: noundef)? )0\)', r'\g<1>1)', llvm), assembly),
        (llvm.replace('clear_owned_region', 'removed_clear'), assembly),
        (re.sub(r'^([^;\n]*)(clear_owned_region)', r'\1removed_clear', llvm, flags=re.M), assembly),
        (llvm.replace('@munmap(', '@removed_release('), assembly),
        (llvm, assembly.replace('clear_owned_region', 'removed_clear')),
        (llvm, assembly.replace('munmap', 'removed_release')),
    ]
    for index, (changed, machine) in enumerate(cases):
        require((changed, machine) != (llvm, assembly), 'live mutation')
        try:
            inspect(changed, machine)
        except ValueError:
            continue
        raise ValueError('accepted resource compiler mutation ' + str(index))
    return len(cases)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--toolchain', choices=('1.90.0', '1.98.1'), default='1.98.1')
    parser.add_argument('--target', choices=('x86_64-unknown-linux-gnu',
                                           'aarch64-unknown-linux-gnu'),
                        default='x86_64-unknown-linux-gnu')
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='brynja-protected-codegen-') as directory:
        for panic in ('abort', 'unwind'):
            target = Path(directory) / panic
            env = dict(os.environ, CARGO_TARGET_DIR=str(target), CARGO_PROFILE_RELEASE_PANIC=panic)
            for key in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS', 'CARGO_BUILD_TARGET'):
                env.pop(key, None)
            subprocess.run(['cargo', '+' + args.toolchain, 'rustc', '--locked', '--offline',
                            '--release', '-p', 'brynja-crypto-cpu-std', '--no-default-features',
                            '--features', 'protected-memory', '--target', args.target,
                            '--lib', '--', '--emit=mir,llvm-ir,asm'], cwd=ROOT, env=env,
                           check=True, timeout=300)
            artifacts = []
            for suffix in ('ll', 's'):
                paths = list(target.rglob('brynja_crypto_cpu_std-*.' + suffix))
                require(len(paths) == 1, 'unique artifact ' + suffix)
                artifacts.append(paths[0].read_text())
            inspect(*artifacts)
            count = regressions(*artifacts)
            print(f'Protected resource LLVM/assembly calls: PASS; {args.toolchain}; '
                  f'{args.target}; panic={panic}; rejected={count}', flush=True)


if __name__ == '__main__':
    main()
