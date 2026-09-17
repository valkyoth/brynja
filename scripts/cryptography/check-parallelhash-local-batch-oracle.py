#!/usr/bin/env python3
"""Independent scheduled/streaming ParallelHash oracle; not a release gate."""
import argparse
import importlib.util
from pathlib import Path
import re
import tempfile

spec = importlib.util.spec_from_file_location('parallel_local_common', Path(__file__).with_name('check-parallelhash-batch-oracle.py'))
common = importlib.util.module_from_spec(spec)
spec.loader.exec_module(common)
LAYOUTS = ('scheduled', 'stream-byte', 'stream-block', 'stream-tail')
MARKER = (r'PARALLELHASH_LOCAL_ORACLE: cases=(\d+); vector_calls=(\d+); '
          r'layout=([a-z-]+); profiles=public,secret; cleanup=drop,scratch,stream')


def validate(result, expected, mode, layout):
    if result.returncode or result.stdout.splitlines() != expected or not expected:
        raise ValueError('local ParallelHash oracle mismatch or failed/empty execution')
    matches = [re.fullmatch(MARKER, line) for line in result.stderr.splitlines()]
    matches = [match for match in matches if match]
    if len(matches) != 1 or int(matches[0][1]) != len(expected) or matches[0][3] != layout:
        raise ValueError('local ParallelHash completion/count/layout marker')
    calls = int(matches[0][2])
    if (mode == 'portable' and calls != 0) or (mode != 'portable' and calls == 0):
        raise ValueError('local ParallelHash actual SIMD route')
    return calls


def malformed(binary, env):
    cases = ('parallel128 0 - 0 - 0 8', 'unknown 0 - 0 - 1 8',
             'parallel128 0 - 0 - 1 4096', 'parallel128 1 80 0 - 1 8',
             'parallel256 0 - 1 80 1 8', 'parallelxof128 0 - 8 éé 1 8',
             'parallel128 0 - 32769 - 1 8', 'parallel128 0 - 8 - 1 8',
             'parallel128 0 - 0 - 1025 8', 'parallel128 0 - 0 - 1 8 extra')
    for layout in LAYOUTS:
        for data in cases:
            result = common.run([str(binary), 'portable', layout], env=env, data=data + '\n', success=False)
            if result.stdout or 'panicked' in result.stderr or 'Error:' not in result.stderr:
                raise ValueError('malformed local oracle request did not reject cleanly')
    for mode, layout in (('invalid', 'scheduled'), ('portable', 'invalid')):
        common.run([str(binary), mode, layout], env=env, data='', success=False)
    print('Local ParallelHash fixture: forty malformed requests and two mode/layout errors rejected')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lane', choices=common.native.LANES)
    args = parser.parse_args()
    features = common.native.host(args.lane)[1] if args.lane else None
    env = common.environment(features)
    cases = common.oracle.cases()
    if len(cases) != 256:
        raise ValueError('ParallelHash corpus drift')
    with tempfile.TemporaryDirectory(prefix='brynja-parallel-local-oracle-') as directory:
        env['CARGO_TARGET_DIR'] = directory
        for command in ('test', 'clippy', 'build'):
            command_args = ['cargo', '+1.98.1', command, '--locked', '--offline', '--release', '--bin', 'local']
            if command == 'clippy':
                command_args += ['--all-targets', '--', '-D', 'warnings']
            common.run(command_args, cwd=common.FIXTURE, env=env)
        binary = Path(directory) / 'release/local'
        for mode in ('portable', 'prefer', 'required') if features else ('portable',):
            selected = common.select(cases, mode)
            expected = [case[-1].hex() for case in selected]
            for layout in LAYOUTS:
                result = common.run([str(binary), mode, layout], env=env, data=common.encode(selected))
                calls = validate(result, expected, mode, layout)
                print(f'Local ParallelHash oracle: PASS; cases={len(selected)}; mode={mode}; layout={layout}; vector_calls={calls}', flush=True)
        malformed(binary, env)


if __name__ == '__main__':
    main()
