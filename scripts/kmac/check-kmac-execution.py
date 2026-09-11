#!/usr/bin/env python3
"""Independent byte/bit KMAC execution campaign; native modes are explicit."""
import argparse
import importlib.util
import os
from pathlib import Path
import platform
import re
import subprocess
import kmac_execution_policy as policy

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = 'assurance/kmac-execution/Cargo.toml'


def oracle_module():
    spec = importlib.util.spec_from_file_location('kmac_oracle', ROOT / 'scripts/kmac/check-kmac-differential.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def official(oracle):
    text = (ROOT / 'crates/brynja-mac-kmac/tests/official_vectors.rs').read_text()
    rows = re.findall(r'check_(fixed|xof)_(128|256)\(\s*&(short|long),\s*(b""|CUSTOM),\s*"([A-F0-9]+)",\s*\);', text)
    if len(rows) != 12:
        raise RuntimeError('all twelve official KMAC examples are required')
    cases = []
    for form, strength, size, domain, value in rows:
        key, message = bytes(range(0x40, 0x60)), bytes(range(4 if size == 'short' else 200))
        custom = b'' if domain == 'b""' else b'My Tagged Application'
        expected = bytes.fromhex(value)
        bits = len(expected) * 8
        actual = oracle.kmac(168 if strength == '128' else 136,
            oracle.oracle.byte_bits(key), oracle.oracle.byte_bits(message),
            oracle.oracle.byte_bits(custom), bits, form == 'xof')
        if actual != expected:
            raise RuntimeError('independent oracle disagrees with an official KMAC example')
        name = ('kmacxof' if form == 'xof' else 'kmac') + strength
        cases.append((name, key, len(key)*8, custom, len(custom)*8, message, len(message)*8, bits, expected))
    return cases


def execute(command, env, request=None, success=True):
    result = subprocess.run(command, cwd=ROOT, env=env, input=request, text=True,
                            capture_output=True, timeout=600, check=False)
    if (result.returncode == 0) != success or 'panicked at' in result.stderr:
        raise RuntimeError(f'KMAC campaign command failed: {command}\n{result.stdout}\n{result.stderr}')
    return result


def campaign(mode, environment=None, target=None, toolchain='1.98.1'):
    env = dict(os.environ if environment is None else environment)
    oracle = oracle_module()
    oracle.verify_oracle()
    cases = official(oracle) + oracle.cases()
    request = '\n'.join(
        f'{name} {kb} {key.hex() or "-"} {cb} {custom.hex() or "-"} '
        f'{mb} {message.hex() or "-"} {ob}'
        for name, key, kb, custom, cb, message, mb, ob, _ in cases) + '\n'
    command = ['cargo', '+' + toolchain, 'run', '--locked', '--offline', '--quiet', '--release',
               '--manifest-path', MANIFEST]
    if target:
        command += ['--target', target]
    command += ['--', mode]
    result = execute(command, env, request)
    if result.stdout.splitlines() != [value.hex() for *_, value in cases]:
        raise RuntimeError('KMAC independent arbitrary-bit output mismatch')
    route = 'Portable' if mode in ('portable', 'prefer-portable') else (
        'X86Keccak' if target is None and platform.machine() in ('x86_64', 'AMD64') else 'ArmKeccak')
    if 'KMAC_EXECUTION_ROUTE: ' not in result.stderr or route not in result.stderr:
        raise RuntimeError('missing KMAC execution route')
    for invalid in (
        'kmac128 1 80 0 - 0 - 8\n', 'kmacxof256 0 - 0 - 0 - 4096\n',
        'unknown 0 - 0 - 0 - 8\n', 'kmac128 0 - 0 - 0 - 8 trailing\n',
        'kmac128 0 - 0 - 0 - 18446744073709551616\n',
    ):
        if execute(command, env, invalid, False).stdout:
            raise RuntimeError('malformed KMAC request leaked partial output')
    print(f'KMAC hardened execution oracle: PASS; mode={mode}; cases={len(cases)}; kernel={route}', flush=True)


def native_environment(arm=False):
    env = dict(os.environ)
    for name in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS', 'CARGO_BUILD_TARGET'):
        if env.get(name):
            raise RuntimeError('unexpected native compilation override: ' + name)
    if arm:
        if platform.machine() not in ('aarch64', 'arm64'):
            raise RuntimeError('native Arm campaign requires an Arm host')
        # Hosted OS feature detection and the required-mode suite run BEFORE
        # compiling global target features. No native ISA assumption from uname.
        campaign('hosted', env)
        flags = '+neon,+sha2,+sha3'
    else:
        if platform.system() != 'Linux' or platform.machine() != 'x86_64':
            raise RuntimeError('native x86 campaign requires Linux x86_64')
        info = Path('/proc/cpuinfo').read_text()
        flags = [line.split(':', 1)[1].split() for line in info.splitlines() if line.startswith('flags')]
        if not flags or not all('avx2' in row for row in flags):
            raise RuntimeError('AVX2 not available on every reported processor')
        flags = '+avx2'
    env['RUSTFLAGS'] = '-C target-feature=' + flags
    return env


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    native = parser.add_mutually_exclusive_group()
    native.add_argument('--native-x86', action='store_true')
    native.add_argument('--native-arm', action='store_true')
    native.add_argument('--qemu', action='store_true')
    native.add_argument('--asan', action='store_true')
    parser.add_argument('--write-review', action='store_true')
    parser.add_argument('--policy-only', action='store_true')
    args = parser.parse_args()
    policy.validate(write=args.write_review)
    if args.write_review or args.policy_only:
        return
    if args.asan:
        env = native_environment(False)
        env['RUSTFLAGS'] += ' -Zsanitizer=address'
        campaign('static', env, toolchain='nightly-2026-09-11')
        return
    campaign('portable')
    campaign('prefer-portable')
    if args.native_x86 or args.native_arm:
        env = native_environment(args.native_arm)
        campaign('static', env)
        campaign('prefer', env)
    if args.qemu:
        env = dict(os.environ, RUSTFLAGS='-C linker=rust-lld',
                   CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUNNER='qemu-aarch64 -cpu max')
        campaign('hosted', env, 'aarch64-unknown-linux-musl')
        env['RUSTFLAGS'] += ' -C target-feature=+neon,+sha2,+sha3'
        campaign('static', env, 'aarch64-unknown-linux-musl')
        campaign('prefer', env, 'aarch64-unknown-linux-musl')


if __name__ == '__main__':
    main()
