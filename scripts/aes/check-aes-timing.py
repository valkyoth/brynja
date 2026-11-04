#!/usr/bin/env python3
"""Bounded Linux x86_64 timing observation. Preserve alarms; never retry-to-pass."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tomllib

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'hmac'))
import hmac_timing as statistics
import hmac_verifiers as verifier

ROOT = verifier.ROOT
FIXTURE = ROOT / 'assurance/aes-timing'
MODES = ('encrypt-key', 'encrypt-block', 'decrypt-key', 'decrypt-block', 'public-key', 'public-block')
SAMPLES = 512
REPEAT = 4
LIMIT = 10.0
MARKER = 'AES timing screen: 6 campaigns; 512 pairs; 4 repetitions; zero alarms'


def require(condition, message):
    if not condition:
        raise ValueError('AES timing: ' + message)


def policy():
    manifest = tomllib.loads((FIXTURE / 'Cargo.toml').read_text())
    require(manifest == {
        'package': {'name': 'brynja-aes-timing', 'version': '0.0.0', 'edition': '2024',
                    'rust-version': '1.90', 'publish': False},
        'workspace': {},
        'dependencies': {'brynja-crypto': {'path': '../../crates/brynja-crypto', 'default-features': False}},
        'profile': {'release': {'opt-level': 3, 'lto': 'fat', 'codegen-units': 1,
                                'overflow-checks': True, 'panic': 'abort'}},
    }, 'fixture build policy changed')
    require(statistics.SAMPLES == SAMPLES and statistics.LIMIT == LIMIT, 'statistical policy changed')


def openssl_block(key, block, decrypt, env):
    require(len(key) == len(block) == 16, 'oracle width changed')
    command = ['openssl', 'enc', '-aes-128-ecb', '-nopad', '-nosalt', '-K', key.hex()]
    if decrypt:
        command.append('-d')
    result = subprocess.run(command, input=block, cwd=ROOT, env=env,
                            capture_output=True, timeout=30)
    require(result.returncode == 0 and not result.stderr and len(result.stdout) == 16,
            'independent block oracle failed')
    return result.stdout


def oracle_preflight(env):
    # Pin the external oracle route with the same independently published block
    # in both directions before asking it about synthetic measurement inputs.
    key = bytes(range(16))
    plain = bytes.fromhex('00112233445566778899aabbccddeeff')
    cipher = bytes.fromhex('69c4e0d86a7b0430d8cdb78070b4c55a')
    require(openssl_block(key, plain, False, env) == cipher and
            openssl_block(key, cipher, True, env) == plain, 'oracle known-answer control failed')


def preflight(output, env):
    oracle_preflight(env)
    expected = []
    for mode in MODES:
        for cls in (0, 1):
            secret = bytes([0xff if cls else 0]) * 16
            fixed = b'\x37' * 16
            key, block = (secret, fixed) if mode.endswith('-key') else (fixed, secret)
            result = openssl_block(key, block, mode.startswith('decrypt-'), env)
            expected.append(f'VECTOR {mode} {cls} {result.hex()}')
    require(output.splitlines() == expected + ['AES_TIMING_END preflight'],
            'measurement operation correctness preflight failed')


def parse(output):
    lines = output.splitlines()
    require(len(lines) == len(MODES) * SAMPLES + 1 and lines[-1] == 'AES_TIMING_END measure',
            'sample population/completion changed')
    rows = []
    cursor = 0
    for mode in MODES:
        pairs = []
        for sample in range(SAMPLES):
            fields = lines[cursor].split()
            cursor += 1
            require(len(fields) == 5 and fields[:3] == ['SAMPLE', mode, str(sample)],
                    'sample identity/order changed')
            require(all(re.fullmatch(r'[1-9][0-9]{0,18}', n) for n in fields[3:]),
                    'invalid timing value')
            pairs.append(tuple(int(n) for n in fields[3:]))
        rows.append({'mode': mode, **statistics.screen(pairs)})
    return rows


def finish(output):
    rows = parse(output)
    signals = sum(row['signal'] for row in rows)
    print(json.dumps({'campaigns': rows, 'signals': signals}, allow_nan=False), flush=True)
    if signals:
        raise ValueError('AES timing alarm: investigate retained samples; do not retry-to-pass')
    print(MARKER, flush=True)
    print('Observation only; not constant-time, cache, cross-target or independent qualification', flush=True)


def collect(binary, env):
    for phase in ('preflight', 'measure'):
        result = subprocess.run([str(binary), phase], cwd=ROOT, env=env,
                                capture_output=True, text=True, timeout=300)
        print(result.stdout, end='', flush=True)
        require(result.returncode == 0 and not result.stderr, 'measurement process failed: ' + result.stderr[-2000:])
        if phase == 'preflight':
            preflight(result.stdout, env)
            print('Independent AES timing preflight: PASS', flush=True)
        else:
            finish(result.stdout)


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    require(platform.system() == 'Linux' and platform.machine() == 'x86_64', 'unsupported host')
    policy()
    with verifier.cargo_environment.private_directory(ROOT) as temporary:
        env = verifier.environment(Path(temporary))
        env.update(RUSTUP_AUTO_INSTALL='0', CARGO_NET_OFFLINE='true')
        verifier.run(['cargo', '+1.99.1', 'build', '--release', '--locked', '--offline',
                      '--manifest-path', str(FIXTURE / 'Cargo.toml')], env)
        binary = Path(env['CARGO_TARGET_DIR']) / 'release/brynja-aes-timing'
        affinity = os.sched_getaffinity(0)
        cpu = min(affinity)
        print(json.dumps({'kind': 'author-operated-AES-timing-screen',
                          'host': platform.platform(), 'logical_cpu': cpu,
                          'compiler': verifier.run(['rustc', '+1.99.1', '-vV'], env).strip(),
                          'oracle': verifier.run(['openssl', 'version'], env).strip(),
                          'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                          'samples_per_class': SAMPLES, 'repetitions': REPEAT,
                          'alarm_threshold': LIMIT, 'warmup_pairs': 32,
                          'claim': 'synthetic host observation; not constant-time or release qualification'}), flush=True)
        try:
            os.sched_setaffinity(0, {cpu})
            collect(binary, env)
        finally:
            os.sched_setaffinity(0, affinity)


if __name__ == '__main__':
    main()
