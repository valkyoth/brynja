"""Standalone native runtime capture contract; not a release/tag admission rule."""
import importlib.util
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


common = load('native_capture_common', 'check-parallelhash-batch-oracle.py')
suites = load('native_capture_suites', 'check-hardened-batch-asan.py')
batch_bench = load('native_capture_batch_bench', 'check-hardened-batch-bench.py')
parallel_bench = load('native_capture_parallel_bench', 'check-parallelhash-batch-bench.py')
LANES = common.native.LANES
ORACLES = {
    'sha256_oracle': ('check-hardened-sha256-batch-oracle.py', 'Hardened SHA-224/256 batch oracle', 'batches', (384, 384, 128)),
    'sha512_oracle': ('check-hardened-sha512-batch-oracle.py', 'Hardened SHA-512 batch oracle', 'batches', (4846, 4846, 4590)),
    'keccak_oracle': ('check-hardened-keccak-batch-oracle.py', 'Hardened Keccak oracle', 'batches', (272, 272, 256)),
    'parallel_oracle': ('check-parallelhash-batch-oracle.py', 'Threaded ParallelHash oracle', 'cases', (256, 256, 48)),
    'local_oracle': ('check-parallelhash-local-batch-oracle.py', 'Local ParallelHash oracle', 'cases', (256, 256, 48)),
}
CLAIMS = dict(native='operator-self-attested', owner_review='pending',
              profile='hardened-multibuffer-runtime-comparisons', independent_review=False,
              fips_validated=False, migration_safety='deployment obligation; not independently proven',
              excluded=['Miri', 'Kani', 'sanitizers', 'compiler-cleanup matrix', 'independent pentest'])


def target(lane):
    if lane not in LANES:
        raise ValueError('unknown native lane')
    return ('aarch64-apple-darwin' if lane == 'apple-m2-aarch64' else
            ('x86_64' if lane.endswith('x86_64') else 'aarch64') + '-unknown-linux-gnu')


def commands(lane):
    result = {}
    for package, features, selection, _ in suites.SUITES:
        result[package] = ['cargo', '+1.98.1', 'test', '--locked', '--offline', '--release',
                           '-p', package, '--no-default-features', '--features', features,
                           '--target', target(lane), '--lib', selection, '--', '--show-output']
    for key, (filename, *_) in ORACLES.items():
        result[key] = ['python3', 'scripts/cryptography/' + filename, '--lane', lane]
    for key, filename in (('batch_bench', 'check-hardened-batch-bench.py'),
                          ('parallel_bench', 'check-parallelhash-batch-bench.py')):
        result[key] = ['python3', 'scripts/cryptography/' + filename, '--lane', lane]
    result['package'] = ['python3', 'scripts/cryptography/check-hardened-batch-package.py',
                         '--toolchain', '1.98.1', '--target', target(lane), '--simd']
    return result


def validate_result(key, text, lane):
    if not isinstance(text, str) or not text or len(text) > 4_000_000:
        raise ValueError('missing/oversized capture output: ' + key)
    lines = text.splitlines()
    kernel = 'Avx2' if lane.endswith('x86_64') else 'Neon'
    if key.startswith('brynja-'):
        tests = next(tests for package, _, _, tests in suites.SUITES if package == key)
        for test in tests:
            if lines.count('test ' + test + ' ... ok') != 1:
                raise ValueError('native test missing or duplicated: ' + test)
        if len(re.findall(r'^test result: ok\. [1-9][0-9]* passed; 0 failed;.*$', text, re.M)) != 1:
            raise ValueError('native suite result missing')
        if key == 'brynja-crypto-cpu' and lines.count('HARDENED_KECCAK_BATCH_NATIVE: ' + kernel + '; pairs=1024') != 1:
            raise ValueError('native permutation execution missing')
    elif key in ORACLES:
        _, prefix, unit, counts = ORACLES[key]
        variants = ('; workers=1', '; workers=2', '; workers=3') if key == 'parallel_oracle' else (
            tuple('; layout=' + layout for layout in ('scheduled', 'stream-byte', 'stream-block', 'stream-tail'))
            if key == 'local_oracle' else ('',))
        found = []
        for mode, count in zip(('portable', 'prefer', 'required'), counts):
            for variant in variants:
                pattern = re.escape(f'{prefix}: PASS; {unit}={count}; mode={mode}{variant}; vector_calls=') + r'(\d+)'
                matches = [re.fullmatch(pattern, line) for line in lines]
                matches = [match for match in matches if match]
                if len(matches) != 1 or (int(matches[0][1]) == 0) != (mode == 'portable'):
                    raise ValueError('native oracle count/mode/actual route: ' + key)
                found.append(matches[0][0])
        if sum(line.startswith(prefix + ':') for line in lines) != len(found):
            raise ValueError('extra oracle campaign: ' + key)
    elif key in ('batch_bench', 'parallel_bench'):
        checker = batch_bench if key == 'batch_bench' else parallel_bench
        prefix = 'HARDENED_BATCH_BENCH' if key == 'batch_bench' else 'PARALLELHASH_BATCH_BENCH'
        # Drivers also print host/compiler context; retain it in the artifact.
        output = '\n'.join(line for line in lines if line.startswith(prefix)) + '\n'
        checker.validate(subprocess.CompletedProcess([], 0, output, ''), 'prefer', kernel == 'Neon')
    elif key == 'package':
        marker = ('Hardened batch package acceptance: PASS; ownership=137; substitutions/conversions=16; '
                  f'1.98.1; {target(lane)}; simd=True')
        if lines.count(marker) != 1 or lines.count('Packaged cleanup/dispatch compiled mutants: 43 rejected') != 1:
            raise ValueError('native package acceptance missing')
        for package, *_ in suites.SUITES:
            if lines.count('Packaged hardened tests/doctests: PASS; ' + package) != 1:
                raise ValueError('packaged crate coverage missing')
    else:
        raise ValueError('unknown capture step')


def validate(record):
    expected = {'schema', 'version', 'lane', 'commit', 'tree', 'compiler', 'cpu', 'features',
                'python', 'started_utc', 'finished_utc', 'results', 'claims'}
    if set(record) != expected or type(record['schema']) is not int or record['schema'] != 1 or record['version'] != '0.24.48':
        raise ValueError('capture schema/version')
    lane = record['lane']
    expected_target = target(lane)
    if any(not isinstance(record[key], str) or not re.fullmatch('[0-9a-f]{40}', record[key]) for key in ('commit', 'tree')):
        raise ValueError('capture commit/tree')
    if record['features'] != ('+avx,+avx2' if lane.endswith('x86_64') else '+neon'):
        raise ValueError('capture feature bundle')
    if not isinstance(record['compiler'], str) or not {'release: 1.98.1', 'host: ' + expected_target} <= set(record['compiler'].splitlines()):
        raise ValueError('capture compiler/host')
    if not isinstance(record['cpu'], str) or not record['cpu'].strip() or not isinstance(record['python'], str) or not re.fullmatch(r'3\.(?:1[1-9]|[2-9][0-9])\.\d+', record['python']):
        raise ValueError('capture CPU/Python context')
    from datetime import datetime
    for key in ('started_utc', 'finished_utc'):
        datetime.strptime(record[key], '%Y-%m-%dT%H:%M:%SZ')
    if record['finished_utc'] < record['started_utc']:
        raise ValueError('capture time ordering')
    if record['claims'] != CLAIMS or any(record['claims'][key] is not False for key in ('independent_review', 'fips_validated')):
        raise ValueError('capture overclaim')
    plan = commands(lane)
    if set(record['results']) != set(plan):
        raise ValueError('capture steps missing/extra')
    for key, command in plan.items():
        result = record['results'][key]
        if set(result) != {'command', 'exit_code', 'output'} or type(result['exit_code']) is not int or result['exit_code'] != 0 or result['command'] != command:
            raise ValueError('capture command/status: ' + key)
        validate_result(key, result['output'], lane)
