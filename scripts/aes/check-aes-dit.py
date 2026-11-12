#!/usr/bin/env python3
"""Bounded DIT policy/restoration checks, never a timing or physical-security claim."""
import argparse
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile

SPEC = importlib.util.spec_from_file_location('static', Path(__file__).with_name('check-aes-static.py'))
STATIC = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STATIC)
MARKER = 'AES_DIT_NATIVE_PASS: startup all-widths expansion encrypt decrypt nested unwind quarantine prior-off prior-on'


def validate(output, native):
    STATIC.validate_tests(output, 5 if native else 4)
    lines = output.splitlines()
    if lines.count(MARKER) != int(native) or 'AES_DIT_NATIVE_UNAVAILABLE' in lines:
        raise ValueError('DIT execution marker absent, repeated or unsupported')


def validate_absent(output):
    STATIC.validate_tests(output, 6)
    lines = output.splitlines()
    if lines.count('AES_DIT_HOSTED_ABSENT_PASS') != 1 or 'AES_DIT_HOSTED_PRESENT_PASS' in lines:
        raise ValueError('DIT-unavailable hardware path was not exercised')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--toolchain', choices=('1.90.0', '1.99.1'), required=True)
    parser.add_argument('--qemu-aarch64', action='store_true')
    args = parser.parse_args()
    for key in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTUP_TOOLCHAIN', 'RUSTC',
                'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'CARGO_BUILD_TARGET', 'RUSTDOCFLAGS'):
        if os.environ.get(key):
            raise ValueError(f'remove ambient {key}')
    mode = 'arm-qemu' if args.qemu_aarch64 else 'native'
    base = STATIC.ROOT/'target/aes-dit'
    base.mkdir(parents=True, exist_ok=True)
    artifacts = Path(tempfile.mkdtemp(prefix=f'{mode}-{args.toolchain}-', dir=base))
    print(f'Artifacts: {artifacts}', flush=True)
    env = dict(os.environ, RUSTUP_AUTO_INSTALL='0', CARGO_TARGET_DIR=str(base/f'build-{mode}-{args.toolchain}'))
    target = []
    if args.qemu_aarch64:
        target = ['--target', 'aarch64-unknown-linux-musl']
        env['CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER'] = 'rust-lld'
        env['CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUNNER'] = 'qemu-aarch64 -cpu max'
    command = ['cargo', f'+{args.toolchain}', 'test', '--locked', '--offline', *target]
    output = STATIC.run([*command, '-p', 'brynja-crypto-cpu', '--features', 'aes-runtime-execution',
                         '--lib', 'aes::dit::', '--', '--show-output', '--test-threads=1'], env, artifacts, 'scope')
    validate(output, args.qemu_aarch64)
    if args.qemu_aarch64:
        # No DIT on this emulated CPU: default AES still works, Require rejects.
        env['CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUNNER'] = 'qemu-aarch64 -cpu cortex-a53'
        output = STATIC.run([*command, '-p', 'brynja-crypto-cpu-std', '--features', 'aes-runtime-execution',
                             '--lib', 'aes::tests::', '--', '--show-output', '--test-threads=1'], env, artifacts, 'without-dit')
        validate_absent(output)
    print(f'AES_DIT_PASS: {mode} {args.toolchain}', flush=True)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f'AES DIT FAIL: {error}')
        raise SystemExit(2) from error
