#!/usr/bin/env python3
"""Require actual native SIMD under ASan and fatal LeakSanitizer enforcement."""
import os
import platform
from pathlib import Path
import sha256_batch_acceptance as acceptance


def main():
    if platform.system() != 'Linux': raise ValueError('Linux native sanitizer host required')
    machine = platform.machine().lower()
    cpu = Path('/proc/cpuinfo').read_text()
    if machine == 'x86_64':
        rows = [set(line.split(':', 1)[1].split()) for line in cpu.splitlines() if line.startswith('flags')]
        if not rows or not all({'avx', 'avx2'} <= row for row in rows): raise ValueError('native AVX2 required')
        features, kernel, target = '+avx,+avx2', 'Avx2', 'x86_64-unknown-linux-gnu'
    elif machine == 'aarch64':
        rows = [set(line.split(':', 1)[1].split()) for line in cpu.splitlines() if line.startswith('Features')]
        if not rows or not all('asimd' in row for row in rows): raise ValueError('native NEON required')
        features, kernel, target = '+neon', 'Neon', 'aarch64-unknown-linux-gnu'
    else: raise ValueError('native SIMD architecture required')
    env = dict(os.environ)
    for key in ('CARGO_ENCODED_RUSTFLAGS', 'CARGO_BUILD_TARGET', 'RUSTDOCFLAGS'): env.pop(key, None)
    env['RUSTFLAGS'] = '-Zsanitizer=address -C target-feature=' + features
    env['ASAN_OPTIONS'] = 'detect_leaks=1:halt_on_error=1:exitcode=1'
    env['LSAN_OPTIONS'] = 'exitcode=23'
    env['BRYNJA_REQUIRE_SHA256_BATCH'] = '1'
    result = acceptance.run(['cargo', '+nightly-2026-09-11', 'test', '--locked', '--offline',
        '-p', 'brynja-hash-sha2', '--features', 'batch-execution', '--test', 'batch',
        '--target', target, '--', '--nocapture'], env=env)
    if 'SHA256_BATCH_VECTOR: ' + kernel + '; calls=' not in result.stdout: raise ValueError('actual SIMD absent')
    print('Native SHA-224/256 batch ASan and enforced LeakSanitizer: PASS; ' + kernel)


if __name__ == '__main__': main()
