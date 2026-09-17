#!/usr/bin/env python3
"""Compare threaded hardened batches to local scheduled portable ParallelHash."""
import argparse
import importlib.util
from pathlib import Path
import re
import tempfile

spec = importlib.util.spec_from_file_location('parallel_bench_common', Path(__file__).with_name('check-parallelhash-batch-oracle.py'))
common = importlib.util.module_from_spec(spec)
spec.loader.exec_module(common)
ALGORITHMS = {'parallel128': (168, 256), 'parallel256': (136, 256),
              'parallelxof128': (168, 4099), 'parallelxof256': (136, 4099)}
MARKER = ('PARALLELHASH_BATCH_BENCHMARK: PASS; cases=96; samples=7; root=portable; '
          'threshold=1; timing=hash,threads,validate,drop; independent_review=NO')
ROW = (r'PARALLELHASH_BATCH_BENCH: algorithm=(\w+); bytes=(\d+); block=(\d+); '
       r'workers=(\d+); output_bits=(\d+); mode=(portable|prefer); selected_kernel=(None|Avx2|Neon); '
       r'samples=7; scheduled_ns=([1-9][0-9]*); threaded_ns=([1-9][0-9]*); groups=(\d+); '
       r'thread_width=(\d+); accelerated_leaves=(\d+); vector_calls=(\d+)')


def cases():
    return {(name, size, block, workers) for name in ALGORITHMS
            for size in (0, 65, 4096, 16387) for block in (64, 1024) for workers in (1, 2, 4)}


def accounting(key, mode, arm):
    name, size, block, workers = key
    leaves = (size + block - 1) // block
    groups = (leaves + 3) // 4
    accelerated, calls = 0, 0
    if mode == 'prefer':
        width = 2 if arm else 4
        lengths = [min(block, size - offset) for offset in range(0, size, block)]
        accelerated = leaves // width * width
        # Each leaf is SHAKE with a 32/64-byte CV (below its sponge rate).
        # Full-width groups share input permutations including suffix padding.
        calls = 7 * sum(min(lengths[start:start + width]) // ALGORITHMS[name][0] + 1
                        for start in range(0, leaves - width + 1, width))
    return groups, min(groups, workers), accelerated, calls


def validate(result, mode, arm):
    lines = result.stdout.splitlines()
    if result.returncode or not lines or lines[-1] != MARKER:
        raise ValueError('ParallelHash benchmark failed or incomplete')
    expected, seen, slower = cases(), set(), 0
    for line in lines[:-1]:
        match = re.fullmatch(ROW, line)
        if not match:
            raise ValueError('ParallelHash benchmark malformed row')
        name, size, block, workers, bits, actual_mode, kernel, baseline, threaded, *counts = match.groups()
        key = (name, int(size), int(block), int(workers))
        if key not in expected or key in seen or actual_mode != mode:
            raise ValueError('ParallelHash benchmark coverage/identity/mode')
        if int(bits) != ALGORITHMS[name][1] or kernel != (('Neon' if arm else 'Avx2') if mode == 'prefer' else 'None'):
            raise ValueError('ParallelHash benchmark output/kernel identity')
        if tuple(map(int, counts)) != accounting(key, mode, arm):
            raise ValueError('ParallelHash benchmark actual thread/leaf/vector accounting')
        seen.add(key)
        slower += int(threaded) >= int(baseline)
    if seen != expected:
        raise ValueError('ParallelHash benchmark missing workloads')
    return slower


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lane', choices=common.native.LANES)
    args = parser.parse_args()
    cpu, features = common.native.host(args.lane) if args.lane else ('unqualified generic host', None)
    env = common.environment(features)
    mode = 'prefer' if features else 'portable'
    with tempfile.TemporaryDirectory(prefix='brynja-parallel-batch-bench-') as directory:
        env['CARGO_TARGET_DIR'] = directory
        for action in ('test', 'clippy', 'build'):
            command = ['cargo', '+1.98.1', action, '--locked', '--offline', '--release', '--bin', 'benchmark']
            if action == 'clippy':
                command += ['--all-targets', '--', '-D', 'warnings']
            common.run(command, cwd=common.FIXTURE, env=env)
        binary = Path(directory) / 'release/benchmark'
        result = common.run([str(binary), mode], env=env)
        slower = validate(result, mode, features == '+neon')
        print(f'ParallelHash benchmark environment: lane={args.lane or "generic"}; cpu={cpu}; features={features or "none"}')
        print(common.run(['rustc', '+1.98.1', '-vV'], env=env).stdout, end='')
        print(result.stdout, end='')
        for arguments in ([], ['required'], ['portable', 'extra']):
            bad = common.run([str(binary), *arguments], env=env, success=False)
            if bad.stdout or 'expected portable|prefer' not in bad.stderr:
                raise ValueError('invalid benchmark arguments did not reject cleanly')
        print(f'Threaded ParallelHash benchmark: 96 workloads checked; threaded_not_faster={slower}; no universal speedup or core-utilization claim')


if __name__ == '__main__':
    main()
