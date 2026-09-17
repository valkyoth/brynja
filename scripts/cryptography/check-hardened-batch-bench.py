#!/usr/bin/env python3
"""Comparative hardened-batch timings; development only, never a release gate."""
import argparse
import importlib.util
from pathlib import Path
import re
import tempfile

spec = importlib.util.spec_from_file_location('hardened_bench_common', Path(__file__).with_name('check-hardened-keccak-batch-oracle.py'))
common = importlib.util.module_from_spec(spec)
spec.loader.exec_module(common)
FIXTURE = common.ROOT / 'assurance/hardened-batch-bench'
ALGORITHMS = {
    'sha256': {'sha224': 64, 'sha256': 64},
    'sha512': {name: 128 for name in ('sha384', 'sha512', 'sha512-224', 'sha512-256',
                                     'sha512-t17', 'sha512-t224', 'sha512-t256', 'sha512-t511')},
    'keccak': {'sha3-224': 144, 'sha3-256': 136, 'sha3-384': 104, 'sha3-512': 72,
               'shake128': 168, 'shake256': 136, 'cshake128': 168, 'cshake256': 136},
}
MARKER = ('HARDENED_BATCH_BENCHMARK: PASS; cases=640; samples=7; threshold=1; '
          'timing=digest,validate,drop; independent_review=NO')
ROW = (r'HARDENED_BATCH_BENCH: family=(\w+); algorithm=([a-z0-9-]+); bytes=(\d+); '
       r'lanes=(\d+); shape=(balanced|ragged); mode=(portable|prefer); samples=7; '
       r'portable_ns=([1-9][0-9]*); selected_ns=([1-9][0-9]*); vector_calls=(\d+); kernel=(None|Avx2|Neon)')


def cases():
    return {(family, name, length, lanes, shape)
            for family, algorithms in ALGORITHMS.items() for name, block in algorithms.items()
            for length in (0, block, 4096, 16384)
            for lanes in range(1, 9 if family == 'sha256' else 5)
            for shape in ('balanced', 'ragged')}


def expected_calls(key, mode, arm):
    family, name, length, lanes, shape = key
    if mode == 'portable':
        return 0
    width = (4 if arm else 8) if family == 'sha256' else (2 if arm else 4)
    if family == 'keccak':
        return None if lanes >= width else 0  # Each active message has at least padding.
    lengths = [max(0, length - (lane if shape == 'ragged' else 0)) for lane in range(lanes)]
    return 7 * sum(min(lengths[group:group + width]) // ALGORITHMS[family][name]
                   for group in range(0, lanes - width + 1, width))


def validate(result, mode, arm):
    lines = result.stdout.splitlines()
    if result.returncode or not lines or lines[-1] != MARKER:
        raise ValueError('benchmark failed or incomplete')
    expected, seen, slower = cases(), set(), 0
    for line in lines[:-1]:
        match = re.fullmatch(ROW, line)
        if not match:
            raise ValueError('benchmark row malformed')
        family, name, length, lanes, shape, actual_mode, baseline, selected, calls, kernel = match.groups()
        key = (family, name, int(length), int(lanes), shape)
        if key not in expected or key in seen or actual_mode != mode:
            raise ValueError('benchmark coverage/identity/mode')
        seen.add(key)
        calls = int(calls)
        wanted = expected_calls(key, mode, arm)
        if (wanted is None and (calls == 0 or calls % 7)) or (wanted is not None and calls != wanted):
            raise ValueError('benchmark actual vector work')
        if kernel != (('Neon' if arm else 'Avx2') if calls else 'None'):
            raise ValueError('benchmark kernel identity')
        slower += int(selected) >= int(baseline)
    if seen != expected:
        raise ValueError('benchmark workloads missing')
    return slower


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lane', choices=common.native.LANES)
    args = parser.parse_args()
    cpu, features = common.native.host(args.lane) if args.lane else ('unqualified generic host', None)
    env = common.environment(features)
    mode, arm = ('prefer' if features else 'portable'), features == '+neon'
    with tempfile.TemporaryDirectory(prefix='brynja-hardened-batch-bench-') as directory:
        env['CARGO_TARGET_DIR'] = directory
        for action in ('test', 'clippy', 'build'):
            command = ['cargo', '+1.98.1', action, '--locked', '--offline', '--release']
            if action == 'clippy':
                command += ['--all-targets', '--', '-D', 'warnings']
            common.run(command, cwd=FIXTURE, env=env)
        binary = Path(directory) / 'release/brynja-hardened-batch-bench'
        result = common.run([str(binary), mode], env=env)
        slower = validate(result, mode, arm)
        print(f'Hardened benchmark environment: lane={args.lane or "generic"}; cpu={cpu}; features={features or "none"}')
        print(common.run(['rustc', '+1.98.1', '-vV'], env=env).stdout, end='')
        print(result.stdout, end='')
        for arguments in ([], ['required'], ['portable', 'extra']):
            bad = common.run([str(binary), *arguments], env=env, success=False)
            if bad.stdout or 'expected portable|prefer' not in bad.stderr:
                raise ValueError('invalid benchmark arguments did not reject cleanly')
        print(f'Comparative hardened benchmark: 640 workloads checked; selected_not_faster={slower}; no universal speedup or side-channel claim')


if __name__ == '__main__':
    main()
