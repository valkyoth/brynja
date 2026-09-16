#!/usr/bin/env python3
"""Independent public-vector campaign through hardened SHA-3/SHAKE/cSHAKE batches.

Standalone development tooling, not a release gate or native qualification receipt.
"""
import argparse
import importlib.util
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/sha3'))
import keccak_batch_native as native
spec = importlib.util.spec_from_file_location('ordinary_keccak_oracle', ROOT / 'scripts/sha3/check-keccak-batch.py')
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)
FIXTURE = ROOT / 'assurance/hardened-keccak-batch'
MARKER = (r'HARDENED_KECCAK_BATCH: batches=(\d+); vector_calls=(\d+); '
          r'profiles=secret,declassified,public; cleanup=drop,declassify,staging')


def run(command, cwd=ROOT, env=None, data=None, success=True):
    result = subprocess.run(command, cwd=cwd, env=env, input=data, text=True, capture_output=True, timeout=600)
    if (result.returncode == 0) != success:
        raise ValueError(f'command failed: {command}\n{result.stdout[-3000:]}\n{result.stderr[-6000:]}')
    return result


def environment(features):
    env = dict(os.environ)
    for key in tuple(env):
        if key.startswith(('CARGO_', 'RUST', 'BRYNJA_REQUIRE_')) and key not in ('CARGO_HOME', 'RUSTUP_HOME'):
            env.pop(key)
    env['RUSTFLAGS'] = '' if features is None else '-C target-feature=' + features
    return env


def corpus():
    data, answers = oracle.corpus()  # Cross-checks the oracle against its pinned NIST vectors.
    lines, expected = data.splitlines(), list(answers)
    if len(lines) != 256 or len(expected) != 256:
        raise ValueError('base Keccak corpus drift')
    for mask in range(16):
        requests, outputs = lines[mask].split(';'), expected[mask].split(';')
        lines.append(';'.join(request if mask & (1 << lane) else '-' for lane, request in enumerate(requests)))
        expected.append(';'.join(output if mask & (1 << lane) else '-' for lane, output in enumerate(outputs)))
    return lines, expected


def validate(result, expected, mode):
    if result.returncode or result.stdout.splitlines() != expected:
        raise ValueError('hardened Keccak independent oracle mismatch or failed execution')
    matches = [re.fullmatch(MARKER, line) for line in result.stderr.splitlines()]
    matches = [match for match in matches if match]
    if len(matches) != 1 or int(matches[0][1]) != len(expected) or not expected:
        raise ValueError('hardened Keccak completion/count marker')
    calls = int(matches[0][2])
    if (mode == 'portable' and calls != 0) or (mode != 'portable' and calls == 0):
        raise ValueError('hardened Keccak actual SIMD route')
    return calls


def malformed(binary, env):
    cases = ('x', 'shake128 1 0 0 8 80 - -', 'sha3-256 0 1 0 256 - 01 -',
             'sha3-256 0 0 0 257 - - -', 'shake128 999999999999999999999 0 0 8 - - -',
             'shake128 8 0 0 8 éé - -', 'cshake128 0 1 0 8 - 80 -',
             'cshake256 0 0 1 8 - - 80', 'shake128 0 0 0 32769 - - -',
             'shake256 8 0 0 8 - - -')
    requests = [';'.join([case] * 4) for case in cases]
    requests += ['-;-;-', '-;-;-;-;-', 'a' * 100001]
    for data in requests:
        result = run([str(binary), 'portable'], env=env, data=data + '\n', success=False)
        if result.stdout or 'panicked' in result.stderr or 'Error:' not in result.stderr:
            raise ValueError('malformed hardened Keccak request did not reject cleanly')
    print('Hardened Keccak fixture: thirteen malformed requests rejected')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lane', choices=native.LANES)
    args = parser.parse_args()
    features = native.host(args.lane)[1] if args.lane else None
    env = environment(features)
    lines, expected = corpus()
    with tempfile.TemporaryDirectory(prefix='brynja-hardened-keccak-oracle-') as directory:
        env['CARGO_TARGET_DIR'] = directory
        for command in ('test', 'clippy', 'build'):
            args = ['cargo', '+1.98.1', command, '--locked', '--offline', '--release']
            if command == 'clippy':
                args += ['--all-targets', '--', '-D', 'warnings']
            run(args, cwd=FIXTURE, env=env)
        binary = Path(directory) / 'release/brynja-hardened-keccak-batch-fixture'
        for mode in ('portable', 'prefer', 'required') if features else ('portable',):
            # Sparse extra cases intentionally include workloads below SIMD width.
            selected = lines[:256] if mode == 'required' else lines
            answers = expected[:256] if mode == 'required' else expected
            result = run([str(binary), mode], env=env, data='\n'.join(selected) + '\n')
            calls = validate(result, answers, mode)
            print(f'Hardened Keccak oracle: PASS; batches={len(answers)}; mode={mode}; vector_calls={calls}', flush=True)
        malformed(binary, env)


if __name__ == '__main__':
    main()
