#!/usr/bin/env python3
"""Native ordinary SIMD ASan/LSan: unsupported hosts and skipped kernels fail."""
import os
from pathlib import Path
import platform
import keccak_batch_codegen as command


def main():
    if platform.system() != 'Linux': raise ValueError('Linux sanitizer host required')
    machine = platform.machine().lower()
    if machine == 'x86_64':
        field, required, features, kernel, width = 'flags', {'avx', 'avx2'}, '+avx,+avx2', 'Avx2', 4
    elif machine == 'aarch64':
        field, required, features, kernel, width = 'Features', {'asimd'}, '+neon', 'Neon', 2
    else: raise ValueError('native AVX2/NEON host required')
    rows = [set(line.split(':', 1)[1].split()) for line in Path('/proc/cpuinfo').read_text().splitlines()
            if line.startswith(field + '\t') or line.startswith(field + ' ')]
    if not rows or not all(required <= row for row in rows): raise ValueError('CPU feature bundle incomplete')
    env = dict(os.environ)
    for key in ('CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS', 'CARGO_BUILD_TARGET'):
        env.pop(key, None)
    env['RUSTFLAGS'] = '-Zsanitizer=address -C target-feature=' + features
    env['ASAN_OPTIONS'] = 'detect_leaks=1:halt_on_error=1:exitcode=1'
    env['LSAN_OPTIONS'] = 'exitcode=23'
    output = command.run(['cargo', '+nightly-2026-09-11', 'test', '--locked', '--offline',
        '-p', 'brynja-hash-sha3', '-p', 'brynja-crypto-cpu',
        '--features', 'brynja-hash-sha3/batch-execution,brynja-crypto-cpu/keccak-batch',
        '--target', machine + '-unknown-linux-gnu', '--lib', 'batch', '--', '--show-output'], env)
    for marker in (f'KECCAK_BATCH_NATIVE: {kernel}; calls=1024; width={width}',
                   f'KECCAK_BATCH_API: {kernel}; comparisons=512'):
        if marker not in output.splitlines(): raise ValueError('actual SIMD execution absent: ' + marker)
    print(f'Native Keccak batch ASan/forced LeakSanitizer: PASS; {kernel}')


if __name__ == '__main__': main()
