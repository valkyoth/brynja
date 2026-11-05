#!/usr/bin/env python3
"""Bounded AES-192/256 host screen. Retain alarms; never retry-to-pass."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import subprocess

spec = importlib.util.spec_from_file_location('aes_timing_base', Path(__file__).with_name('check-aes-timing.py'))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
require, verifier = base.require, base.verifier
SAMPLES, REPEAT, WARMUP, LIMIT = 512, 4, 32, 10.0
MODES = ('encrypt-key', 'encrypt-block', 'decrypt-key', 'decrypt-block', 'public-key', 'public-block')
CAMPAIGNS = tuple((bits, owner, mode) for bits in (192, 256)
                  for owner in ('ephemeral', 'cached', 'cached-import')
                  for mode in (('import-key',) if owner == 'cached-import' else MODES))
HEADER = f'AES_WIDE_TIMING_POLICY {SAMPLES} {REPEAT} {WARMUP}'
MARKER = 'AES wide timing screen: 26 campaigns; 512 pairs; 4 repetitions; zero alarms'


def openssl_block(key, block, decrypt, env):
    require(len(key) in (24, 32) and len(block) == 16, 'wide oracle width changed')
    command = ['openssl', 'enc', f'-aes-{len(key) * 8}-ecb', '-nopad', '-nosalt', '-K', key.hex()]
    if decrypt:
        command.append('-d')
    result = subprocess.run(command, input=block, cwd=base.ROOT, env=env,
                            capture_output=True, timeout=30)
    require(result.returncode == 0 and not result.stderr and len(result.stdout) == 16,
            'independent wide block oracle failed')
    return result.stdout


def oracle_preflight(env):
    # Published SP 800-38A first block pairs already used by the public fixture.
    plain = bytes.fromhex('6bc1bee22e409f96e93d7e117393172a')
    for key_hex, cipher_hex in (
        ('8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b', 'bd334f1d6e45f25ff712a214571fa5cc'),
        ('603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4', 'f3eed1bdb5d2a03c064b5a7e3db181f8'),
    ):
        key, cipher = bytes.fromhex(key_hex), bytes.fromhex(cipher_hex)
        require(openssl_block(key, plain, False, env) == cipher and
                openssl_block(key, cipher, True, env) == plain, 'wide oracle known-answer control failed')


def preflight(output, env):
    oracle_preflight(env)
    expected = [HEADER]
    for bits, owner, mode in CAMPAIGNS:
        for cls in (0, 1):
            value = 0xff if cls else 0
            key = bytes([value if mode.endswith('-key') else 0x37]) * (bits // 8)
            block = bytes([value if mode.endswith('-block') else 0x37]) * 16
            result = openssl_block(key, block, mode.startswith('decrypt-'), env)
            expected.append(f'VECTOR {bits} {owner} {mode} {cls} {result.hex()}')
    require(output.splitlines() == expected + ['AES_WIDE_TIMING_END preflight'],
            'wide measurement correctness preflight failed')


def parse(output):
    lines = output.splitlines()
    require(len(lines) == len(CAMPAIGNS) * SAMPLES + 2 and lines[0] == HEADER
            and lines[-1] == 'AES_WIDE_TIMING_END measure', 'wide population/policy/completion changed')
    rows, cursor = [], 1
    for bits, owner, mode in CAMPAIGNS:
        pairs = []
        for sample in range(SAMPLES):
            fields = lines[cursor].split()
            cursor += 1
            require(len(fields) == 7 and fields[:5] == ['SAMPLE', str(bits), owner, mode, str(sample)],
                    'wide sample identity/order changed')
            require(all(re.fullmatch(r'[1-9][0-9]{0,18}', n) for n in fields[5:]), 'invalid wide timing value')
            pairs.append(tuple(int(n) for n in fields[5:]))
        rows.append({'bits': bits, 'owner': owner, 'mode': mode, **base.statistics.screen(pairs)})
    return rows


def finish(output):
    rows = parse(output)
    signals = sum(row['signal'] for row in rows)
    print(json.dumps({'campaigns': rows, 'signals': signals}, allow_nan=False), flush=True)
    if signals:
        raise ValueError('AES wide timing alarm: investigate retained samples; do not retry-to-pass')
    print(MARKER, flush=True)
    print('Observation only; not constant-time, cache, cross-target or independent qualification', flush=True)


def collect(binary, env):
    for phase in ('preflight', 'measure'):
        result = subprocess.run([str(binary), phase], cwd=base.ROOT, env=env,
                                capture_output=True, text=True, timeout=300)
        print(result.stdout, end='', flush=True)
        require(result.returncode == 0 and not result.stderr, 'wide measurement process failed: ' + result.stderr[-2000:])
        if phase == 'preflight':
            preflight(result.stdout, env)
            print('Independent AES wide timing preflight: PASS', flush=True)
        else:
            finish(result.stdout)


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    require(platform.system() == 'Linux' and platform.machine() == 'x86_64', 'unsupported host')
    base.policy()
    require(base.statistics.SAMPLES == SAMPLES and base.statistics.LIMIT == LIMIT, 'wide statistical policy changed')
    with verifier.cargo_environment.private_directory(base.ROOT) as temporary:
        env = verifier.environment(Path(temporary))
        env.update(RUSTUP_AUTO_INSTALL='0', CARGO_NET_OFFLINE='true')
        verifier.run(['cargo', '+1.99.1', 'build', '--release', '--locked', '--offline',
                      '--manifest-path', str(base.FIXTURE / 'Cargo.toml'), '--bin', 'brynja-aes-wide-timing'], env)
        binary = Path(env['CARGO_TARGET_DIR']) / 'release/brynja-aes-wide-timing'
        affinity = os.sched_getaffinity(0)
        cpu = min(affinity)
        print(json.dumps({'kind': 'author-operated-AES-wide-timing-screen',
                          'host': platform.platform(), 'logical_cpu': cpu,
                          'compiler': verifier.run(['rustc', '+1.99.1', '-vV'], env).strip(),
                          'oracle': verifier.run(['openssl', 'version'], env).strip(),
                          'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                          'samples_per_class': SAMPLES, 'repetitions': REPEAT,
                          'alarm_threshold': LIMIT, 'warmup_pairs': WARMUP,
                          'claim': 'synthetic host observation; not constant-time or release qualification'}), flush=True)
        try:
            os.sched_setaffinity(0, {cpu})
            collect(binary, env)
        finally:
            os.sched_setaffinity(0, affinity)


if __name__ == '__main__':
    main()
