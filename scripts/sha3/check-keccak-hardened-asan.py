#!/usr/bin/env python3
"""Explicit native AVX2 sanitizer campaign; unavailable hardware is a blocker."""
import os
from pathlib import Path
import platform
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def main():
    if platform.system() != 'Linux' or platform.machine() != 'x86_64':
        raise ValueError('native hardened Keccak ASan requires Linux x86_64')
    if 'avx2' not in Path('/proc/cpuinfo').read_text().split():
        raise ValueError('native hardened Keccak ASan requires AVX2')
    env = dict(os.environ)
    for name in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS', 'CARGO_BUILD_TARGET'):
        env.pop(name, None)
    env['RUSTFLAGS'] = '-Zsanitizer=address -C target-feature=+avx2'
    for package, selection in (
        ('brynja-crypto-cpu', ['--lib', 'hardened_execution::keccak::tests']),
        ('brynja-hash-sha3', ['--lib', 'hardened::accelerated::engine::tests']),
        ('brynja-hash-sha3', ['--test', 'hardened_execution']),
    ):
        subprocess.run(['cargo', '+nightly-2026-09-11', 'test', '--locked', '--offline',
                        '-p', package, '--features', 'hardened-execution',
                        '--target', 'x86_64-unknown-linux-gnu', *selection,
                        '--', '--nocapture'], cwd=ROOT, env=env, check=True, timeout=600)
    print('Native AVX2 hardened Keccak ASan: PASS')


if __name__ == '__main__':
    main()
