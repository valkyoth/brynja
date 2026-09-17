#!/usr/bin/env python3
"""Dedicated SHA512 development checks; Intel SDE is external, never native evidence."""
import argparse
import os
from pathlib import Path
import re
import subprocess
import tempfile
import x86_sha512_package

ROOT = Path(__file__).resolve().parents[2]
TARGET = 'x86_64-unknown-linux-gnu'
FEATURES = 'static-execution,runtime-execution,hardened-execution'


def run(command, environment, markers=()):
    print('RUN: ' + ' '.join(map(str, command)), flush=True)
    result = subprocess.run(command, cwd=ROOT, env=environment, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=600)
    if result.returncode or any(marker not in result.stdout for marker in markers):
        raise RuntimeError(f'failed execution or missing acceptance marker: {command}\n{result.stdout[-16000:]}')
    print(result.stdout, end='', flush=True)
    return result.stdout


def sanitizer(environment):
    env = dict(environment)
    env['RUSTFLAGS'] = '-Zsanitizer=address -C target-feature=+sha512,+avx2,+avx'
    env['ASAN_OPTIONS'] = 'detect_leaks=1:halt_on_error=1:exitcode=1'
    env['LSAN_OPTIONS'] = 'exitcode=23'
    base = ['cargo', '+nightly-2026-09-11', 'test', '--locked', '--offline',
            '--target', TARGET, '-p', 'brynja-crypto-cpu', '--features', FEATURES, '--lib']
    run(base + ['dedicated_sha512', '--', '--nocapture'], env,
        ('DEDICATED_X86_SHA512: blocks=1024; quarantine=PASS',
         'DEDICATED_X86_SHA512_RUNTIME: KAT; exact identity; revocation=PASS'))
    run(base + ['hardened_execution::tests', '--', '--nocapture'], env,
        ('HARDENED_KERNEL_EXECUTION: X86Sha512; blocks=512',
         'scratch_regions_clear_on_explicit_wipe_and_unwind ... ok'))
    print('Dedicated SHA512 ASan/LSan: PASS (SDE emulated; leak checking forced)')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sde', type=Path, required=True,
                        help='owner-licensed Intel SDE sde64 executable (Arrow Lake model)')
    parser.add_argument('--asan', action='store_true',
                        help='also run the pinned nightly sanitizer lane; leaks/errors fail closed')
    args = parser.parse_args()
    sde = args.sde.resolve(strict=True)
    if not sde.is_file() or not os.access(sde, os.X_OK):
        parser.error('--sde must be an executable file')
    env = os.environ.copy()
    for name in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS', 'CARGO_BUILD_TARGET',
                 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER'):
        env.pop(name, None)
    # Rust's SHA512 feature implies AVX2. No AVX-512 prerequisite is assumed.
    env['RUSTFLAGS'] = '-C target-feature=+sha512,+avx2,+avx,+sha,+sse2'
    env['BRYNJA_REQUIRE_X86_SHA512'] = '1'
    # Cargo parses this as shell words. Do not accept ambiguous executable paths.
    if any(character.isspace() for character in str(sde)):
        parser.error('use an SDE path without whitespace')
    env['CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER'] = str(sde) + ' -arl --'
    with tempfile.TemporaryDirectory(prefix='brynja-x86-sha512-') as temporary:
        for compiler in ('1.90.0', '1.98.1'):
            destination = Path(temporary) / compiler
            env['CARGO_TARGET_DIR'] = str(destination)
            cargo = ['cargo', '+' + compiler]
            base = cargo + ['test', '--locked', '--offline', '--target', TARGET,
                            '-p', 'brynja-crypto-cpu', '--features', FEATURES, '--lib']
            for flags in ('', '+sha,+avx2', '+sha512,-avx2', '+sha512,-avx'):
                negative = dict(env, RUSTFLAGS=('-C target-feature=' + flags if flags else ''))
                run(base + ['dedicated_sha512_requires_its_own_complete_bundle', '--', '--nocapture'],
                    negative, ('dedicated_sha512_requires_its_own_complete_bundle ... ok',))
            for profile in ([], ['--release']):
                run(base + profile + ['dedicated_sha512', '--', '--nocapture'], env,
                    ('DEDICATED_X86_SHA512: blocks=1024; quarantine=PASS',
                     'DEDICATED_X86_SHA512_RUNTIME: KAT; exact identity; revocation=PASS'))
                run(base + profile + ['hardened_execution::tests', '--', '--nocapture'], env,
                    ('HARDENED_KERNEL_EXECUTION: X86Sha512; blocks=512',
                     'scratch_regions_clear_on_explicit_wipe_and_unwind ... ok'))
            run(cargo + ['rustc', '--locked', '--offline', '--release', '--target', TARGET,
                          '-p', 'brynja-crypto-cpu', '--features', FEATURES, '--lib', '--',
                          '--emit=asm,llvm-ir,mir'], env)
            artifacts = destination / TARGET / 'release/deps'
            assembly = '\n'.join(path.read_text() for path in artifacts.glob('brynja_crypto_cpu-*.s'))
            for instruction in ('vsha512msg1', 'vsha512msg2', 'vsha512rnds2'):
                if not re.search(r'^\s*' + instruction + r'\s', assembly, re.M):
                    raise RuntimeError('missing emitted instruction: ' + instruction)
            if 'compress_sha512' not in assembly or 'BRYNJA_SECRET_BEGIN' not in assembly:
                raise RuntimeError('ordinary/secret dedicated codegen symbol absent')
            print(f'DEDICATED_X86_SHA512_CODEGEN: {compiler}; three instructions; ordinary/secret symbols')
            for fixture, marker in (
                ('sha2-execution', 'SHA-2 ordinary execution acceptance: PASS; named=240; general=4590'),
                ('sha2-hardened-execution', 'SHA-2 hardened execution acceptance: PASS; named=240; general=4590'),
            ):
                run(cargo + ['run', '--locked', '--offline', '--release', '--target', TARGET,
                              '--manifest-path', f'assurance/{fixture}/Cargo.toml', '--', 'static'], env,
                    (marker, 'wide=Static(X86Sha512)'))
        if args.asan:
            env['CARGO_TARGET_DIR'] = str(Path(temporary) / 'asan')
            sanitizer(env)
    x86_sha512_package.check(sde, env)
    print('Dedicated x86 SHA512 development acceptance: PASS (SDE emulated; NOT native qualification)')


if __name__ == '__main__':
    main()
