#!/usr/bin/env python3
"""Independent public-vector campaign through distinct hardened batch APIs.

Portable by default; --lane verifies the matching native host and also exercises
preferred/required SIMD. Development acceptance only; no release-gate changes.
"""
import argparse
import os
from pathlib import Path
import re
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/sha2'))
import sha512_batch_acceptance as oracle
native = oracle.load('hardened_oracle_host', 'capture-sha512-batch-native.py')

FIXTURE = ROOT / 'assurance/hardened-sha512-batch'
MARKER = (r'HARDENED_SHA512_BATCH: batches=(\d+); vector_calls=(\d+); '
          r'profiles=secret,declassified,public; cleanup=drop,declassify')


def validate(result, expected, mode):
    if result.returncode or result.stdout.splitlines() != expected:
        raise ValueError('hardened batch independent oracle mismatch or failed execution')
    matches = [re.fullmatch(MARKER, line) for line in result.stderr.splitlines()]
    matches = [match for match in matches if match]
    if len(matches) != 1 or int(matches[0][1]) != len(expected) or not expected:
        raise ValueError('hardened batch completion/count marker')
    calls = int(matches[0][2])
    if (mode == 'portable' and calls != 0) or (mode != 'portable' and calls == 0):
        raise ValueError('hardened batch actual SIMD route')
    return calls


def malformed(binary, env):
    slot = 'sha512:8:ff'
    requests = ('x', ';'.join(['sha512:1:01'] * 4), ';'.join(['t384:0:'] * 4),
                ';'.join(['t0:0:'] * 4), ';'.join(['t512:0:'] * 4),
                ';'.join(['sha512:32769:00'] * 4), ';'.join(['sha512:8:éé'] * 4),
                ';'.join(['sha512:8:'] * 4), ';'.join([slot] * 5), 'a' * 66001)
    for request in requests:
        result = oracle.run([str(binary), 'portable'], env=env, data=request + '\n', success=False)
        if result.stdout or 'panicked at' in result.stderr or 'Error:' not in result.stderr:
            raise ValueError('malformed hardened fixture request did not reject cleanly')
    print('Hardened SHA-512 batch fixture: ten malformed requests rejected')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lane', choices=native.LANES)
    args = parser.parse_args()
    features = native.host(args.lane)[1] if args.lane else None
    env = dict(os.environ)
    for key in tuple(env):
        if key.startswith(('CARGO_', 'RUST', 'BRYNJA_REQUIRE_')) and key not in ('CARGO_HOME', 'RUSTUP_HOME'):
            env.pop(key)
    env['RUSTFLAGS'] = '' if features is None else '-C target-feature=' + features
    requests, expected = oracle.corpus()
    with tempfile.TemporaryDirectory(prefix='brynja-hardened-sha512-oracle-') as directory:
        env['CARGO_TARGET_DIR'] = directory
        for command in ('test', 'clippy', 'build'):
            args = ['cargo', '+1.98.1', command, '--locked', '--offline', '--release']
            if command == 'clippy':
                args += ['--all-targets', '--', '-D', 'warnings']
            oracle.run(args, cwd=FIXTURE, env=env)
        binary = Path(directory) / 'release/brynja-hardened-sha512-batch-fixture'
        for mode in ('portable', 'prefer', 'required') if features else ('portable',):
            # First 256 cases exercise sparse/short inputs, deliberately ineligible
            # for required SIMD. Remaining cases have four >=128-byte messages.
            data = requests if mode != 'required' else '\n'.join(requests.splitlines()[256:]) + '\n'
            answers = expected if mode != 'required' else expected[256:]
            result = oracle.run([str(binary), mode], env=env, data=data)
            calls = validate(result, answers, mode)
            print(f'Hardened SHA-512 batch oracle: PASS; batches={len(answers)}; mode={mode}; vector_calls={calls}', flush=True)
        malformed(binary, env)


if __name__ == '__main__':
    main()
