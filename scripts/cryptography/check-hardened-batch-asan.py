#!/usr/bin/env python3
"""Standalone Linux hardened-multibuffer ASan/LSan development check, not a tag gate."""
import os
import platform
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
CPU_FEATURES = 'sha256-hardened-batch,sha512-hardened-batch,keccak-hardened-batch'
REQUIRED = ('SHA256_HARDENED_BATCH', 'SHA512_HARDENED_BATCH',
            'KECCAK_HARDENED_BATCH', 'HARDENED_KECCAK_LEAF',
            'HOSTED_HARDENED_BATCH', 'PARALLELHASH_BATCH')
SUITES = (
    ('brynja-crypto-cpu', CPU_FEATURES, 'hardened_batch', (
        'sha256_hardened_batch::tests::native_lane_distinct_differential_and_actual_dispatch',
        'sha512_hardened_batch::tests::native_lane_distinct_differential_and_actual_dispatch',
        'keccak_hardened_batch::tests::native_word_and_byte_entries_match_independent_reference')),
    ('brynja-hash-sha2', 'hardened-batch-execution,hardened-batch512-execution', 'hardened_batch', (
        'hardened_batch::tests::differential::native_mixed_lanes_match_portable_and_required_route_is_real',
        'hardened_batch512::tests::differential::native_mixed_lanes_match_portable_and_required_route_is_real')),
    ('brynja-hash-sha3', 'hardened-batch-execution', 'hardened_batch', (
        'hardened_batch::tests::native_differential_uses_hardened_vector_authority',)),
    ('brynja-crypto-cpu-std', CPU_FEATURES, 'hardened_batch', tuple(
        family + '_hardened_batch::tests::actual_hardened_routes_clear_outputs_and_never_recover_revoked_authority'
        for family in ('sha256', 'sha512', 'keccak'))),
    ('brynja-hash-parallel', 'hardened-batch-execution', 'execution', (
        'execution::batch::tests::vector_domains_bits_boundaries_and_actual_leaf_counts',
        'execution::stream::batch::tests::vector_chunk_bit_and_xof_campaign')),
    ('brynja-hash-parallel-std', 'runtime-batch-execution', 'execution::batch', (
        'execution::batch::tests::preferred_threads_bits_outputs_and_counters',
        *(('execution::batch::worker::tests::coordinator_unwind::coordinator_unwind_' + identity)
          for identity in ('fixed128', 'fixed256', 'xof128', 'xof256')))),
)


def native_host():
    if platform.system() != 'Linux':
        raise ValueError('Linux sanitizer host required')
    machine = platform.machine().lower()
    if machine == 'x86_64':
        field, needed, flags, kernel = 'flags', {'avx', 'avx2'}, '+avx,+avx2', 'Avx2'
    elif machine == 'aarch64':
        field, needed, flags, kernel = 'Features', {'asimd'}, '+neon', 'Neon'
    else:
        raise ValueError('unsupported sanitizer architecture')
    rows = [set(value.split()) for line in Path('/proc/cpuinfo').read_text().splitlines()
            if ':' in line for key, value in [line.split(':', 1)] if key.strip() == field]
    if not rows or not all(needed <= row for row in rows):
        raise ValueError('required SIMD features missing on a listed CPU')
    return flags, kernel, machine + '-unknown-linux-gnu'


def environment(flags, directory):
    env = dict(os.environ)
    # Do not inherit Cargo runner, wrapper, target, flag or test-filter overrides.
    for key in tuple(env):
        if key.startswith(('CARGO_', 'RUST', 'BRYNJA_REQUIRE_', 'LLVM_PROFILE_', 'LD_')):
            if key not in ('CARGO_HOME', 'RUSTUP_HOME'):
                env.pop(key)
    env['RUSTFLAGS'] = '-Zsanitizer=address -C target-feature=' + flags
    env['ASAN_OPTIONS'] = 'detect_leaks=1:halt_on_error=1:exitcode=1'
    env['LSAN_OPTIONS'] = 'exitcode=23'
    env['CARGO_TARGET_DIR'] = str(directory)
    for name in REQUIRED:
        env['BRYNJA_REQUIRE_' + name] = '1'
    return env


def validate(result, package, tests, kernel):
    output = result.stdout + '\n' + result.stderr
    if result.returncode != 0:
        raise RuntimeError(f'{package}: sanitizer execution failed ({result.returncode})\n{output}')
    if any(marker in output for marker in ('ERROR: AddressSanitizer', 'ERROR: LeakSanitizer',
                                           'LeakSanitizer has encountered a fatal error')):
        raise RuntimeError(f'{package}: sanitizer diagnostic\n{output}')
    lines = set(result.stdout.splitlines())
    for test in tests:
        if 'test ' + test + ' ... ok' not in lines:
            raise RuntimeError(f'{package}: missing passing test: {test}')
    if package == 'brynja-crypto-cpu' and (
            'HARDENED_KECCAK_BATCH_NATIVE: ' + kernel + '; pairs=1024') not in lines:
        raise RuntimeError('missing actual hardened Keccak SIMD marker')


def main():
    flags, kernel, target = native_host()
    with tempfile.TemporaryDirectory(prefix='brynja-hardened-batch-asan-') as directory:
        env = environment(flags, directory)
        for package, features, selection, tests in SUITES:
            print('ASan/LSan: ' + package, flush=True)
            command = ['cargo', '+nightly-2026-09-11', 'test', '--locked', '--offline',
                       '-p', package, '--features', features, '--target', target,
                       '--lib', selection, '--', '--show-output']
            result = subprocess.run(command, cwd=ROOT, env=env, text=True,
                                    capture_output=True, timeout=900, check=False)
            validate(result, package, tests, kernel)
            print(result.stdout, end='', flush=True)
    print('Hardened multibuffer ASan/forced LeakSanitizer: PASS; six layers; ' + kernel)


if __name__ == '__main__':
    main()
