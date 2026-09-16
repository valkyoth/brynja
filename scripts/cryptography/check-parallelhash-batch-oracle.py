#!/usr/bin/env python3
"""Independent arbitrary-bit oracle for threaded hardened ParallelHash batches.

Standalone development execution, not native qualification or a release gate.
"""
import argparse
import importlib.util
from pathlib import Path
import re
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/sha3'))
import keccak_batch_native as native


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


oracle = load('parallel_batch_oracle', ROOT / 'scripts/parallelhash/check-parallelhash-differential.py')
common = load('parallel_batch_tools', Path(__file__).with_name('check-hardened-keccak-batch-oracle.py'))
run, environment = common.run, common.environment
FIXTURE = ROOT / 'assurance/parallelhash-batch-oracle'
MARKER = (r'PARALLELHASH_BATCH_ORACLE: cases=(\d+); vector_calls=(\d+); workers=(\d+); '
          r'max_thread_width=(\d+); profiles=public,secret; cleanup=drop,scratch')


def select(cases, mode):
    # Require applies to every group: exclude empty and incomplete final groups
    # on both four-lane AVX2 and two-lane NEON (group capacity remains four).
    if mode != 'required':
        return cases
    return [case for case in cases if (leaves := (case[4] + case[5] * 8 - 1) // (case[5] * 8)) > 0
            and leaves % 4 == 0]


def encode(cases):
    return '\n'.join(f'{algorithm} {cbits} {custom.hex() or "-"} {mbits} {message.hex() or "-"} {block} {obits}'
                     for algorithm, custom, cbits, message, mbits, block, obits, _ in cases) + '\n'


def validate(result, expected, mode, workers):
    if result.returncode or result.stdout.splitlines() != expected or not expected:
        raise ValueError('threaded ParallelHash oracle mismatch or failed/empty execution')
    matches = [re.fullmatch(MARKER, line) for line in result.stderr.splitlines()]
    matches = [match for match in matches if match]
    if len(matches) != 1 or int(matches[0][1]) != len(expected):
        raise ValueError('threaded ParallelHash completion/count marker')
    _, calls, configured, observed = map(int, matches[0].groups())
    if configured != workers or observed != workers:
        raise ValueError('threaded ParallelHash worker coverage')
    if (mode == 'portable' and calls != 0) or (mode != 'portable' and calls == 0):
        raise ValueError('threaded ParallelHash actual SIMD route')
    return calls


def malformed(binary, env):
    cases = ('parallel128 0 - 0 - 0 8', 'unknown 0 - 0 - 1 8',
             'parallel128 0 - 0 - 1 4096', 'parallel128 1 80 0 - 1 8',
             'parallel256 0 - 1 80 1 8', 'parallelxof128 0 - 8 éé 1 8',
             'parallel128 0 - 32769 - 1 8', 'parallel128 0 - 8 - 1 8',
             'parallel128 0 - 0 - 1025 8', 'parallel128 0 - 0 - 1 8 extra')
    for data in cases:
        result = run([str(binary), 'portable', '3'], env=env, data=data + '\n', success=False)
        if result.stdout or 'panicked' in result.stderr or 'Error:' not in result.stderr:
            raise ValueError('malformed threaded oracle request did not reject cleanly')
    for workers in ('0', '4'):
        run([str(binary), 'portable', workers], env=env, data='', success=False)
    print('Threaded ParallelHash fixture: ten malformed requests and two worker bounds rejected')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lane', choices=native.LANES)
    args = parser.parse_args()
    features = native.host(args.lane)[1] if args.lane else None
    env = environment(features)
    cases = oracle.cases()
    if len(cases) != 256:
        raise ValueError('ParallelHash corpus drift')
    with tempfile.TemporaryDirectory(prefix='brynja-parallel-batch-oracle-') as directory:
        env['CARGO_TARGET_DIR'] = directory
        for command in ('test', 'clippy', 'build'):
            args = ['cargo', '+1.98.1', command, '--locked', '--offline', '--release']
            if command == 'clippy':
                args += ['--all-targets', '--', '-D', 'warnings']
            run(args, cwd=FIXTURE, env=env)
        binary = Path(directory) / 'release/brynja-parallelhash-batch-oracle-fixture'
        for mode in ('portable', 'prefer', 'required') if features else ('portable',):
            selected = select(cases, mode)
            expected = [case[-1].hex() for case in selected]
            for workers in (1, 2, 3):
                result = run([str(binary), mode, str(workers)], env=env, data=encode(selected))
                calls = validate(result, expected, mode, workers)
                print(f'Threaded ParallelHash oracle: PASS; cases={len(selected)}; mode={mode}; workers={workers}; vector_calls={calls}', flush=True)
        malformed(binary, env)


if __name__ == '__main__':
    main()
