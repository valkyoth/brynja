#!/usr/bin/env python3
"""Synthetic capture/tamper regressions; never manufacture qualification evidence."""
import contextlib
import copy
import io
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

import hardened_batch_native as native

capture = native.load('hardened_capture_test', 'capture-hardened-batch-native.py')
bench = native.load('hardened_capture_bench_test', 'test-hardened-batch-bench.py')
parallel = native.load('hardened_capture_parallel_test', 'test-parallelhash-batch-bench.py')


def rejects(call):
    try:
        call()
    except (ValueError, RuntimeError, FileExistsError, subprocess.TimeoutExpired):
        return
    raise AssertionError('invalid native capture accepted')


def outputs(lane):
    kernel = 'Avx2' if lane.endswith('x86_64') else 'Neon'
    result = {}
    for package, _, _, tests in native.suites.SUITES:
        result[package] = '\n'.join('test ' + test + ' ... ok' for test in tests)
        result[package] += f'\ntest result: ok. {len(tests)} passed; 0 failed; 0 ignored;\n'
    result['brynja-crypto-cpu'] += 'HARDENED_KECCAK_BATCH_NATIVE: ' + kernel + '; pairs=1024\n'
    for key, (_, prefix, unit, counts) in native.ORACLES.items():
        variants = ('; workers=1', '; workers=2', '; workers=3') if key == 'parallel_oracle' else (
            ('; layout=scheduled', '; layout=stream-byte', '; layout=stream-block', '; layout=stream-tail')
            if key == 'local_oracle' else ('',))
        result[key] = '\n'.join(
            f'{prefix}: PASS; {unit}={count}; mode={mode}{variant}; vector_calls={0 if mode == "portable" else 1}'
            for mode, count in zip(('portable', 'prefer', 'required'), counts) for variant in variants)
    result['batch_bench'] = bench.synthetic('prefer', kernel == 'Neon')
    result['parallel_bench'] = parallel.synthetic('prefer', kernel == 'Neon')
    result['package'] = '\n'.join('Packaged hardened tests/doctests: PASS; ' + package
                                  for package, *_ in native.suites.SUITES)
    result['package'] += '\nPackaged cleanup/dispatch compiled mutants: 11 rejected\n'
    result['package'] += ('Hardened batch package acceptance: PASS; ownership=129; substitutions/conversions=16; '
                          f'1.98.1; {native.target(lane)}; simd=True\n')
    return result


def record(lane):
    output = outputs(lane)
    return dict(schema=1, version='0.24.48', lane=lane, commit='a' * 40, tree='b' * 40,
                compiler='release: 1.98.1\nhost: ' + native.target(lane), cpu='synthetic test CPU',
                features='+avx,+avx2' if lane.endswith('x86_64') else '+neon', python='3.13.0',
                started_utc='2026-09-17T00:00:00Z', finished_utc='2026-09-17T00:01:00Z',
                results={key: dict(command=command, exit_code=0, output=output[key])
                         for key, command in native.commands(lane).items()}, claims=copy.deepcopy(native.CLAIMS))


def validation():
    count = 0
    for lane in native.LANES:
        original = record(lane)
        native.validate(original)
        for key, value in (('schema', True), ('version', '0.24.47'), ('lane', 'unknown'),
                           ('commit', 'bad'), ('tree', 'bad'), ('features', '+avx2'),
                           ('compiler', 'release: 1.90.0\nhost: ' + native.target(lane)),
                           ('cpu', ''), ('python', '3.9.0'), ('finished_utc', '2026-09-16T00:00:00Z')):
            changed = copy.deepcopy(original)
            changed[key] = value
            rejects(lambda: native.validate(changed))
            count += 1
        for key, value in (('owner_review', 'approved'), ('native', 'independently-verified'),
                           ('independent_review', True), ('independent_review', 0),
                           ('fips_validated', True), ('excluded', [])):
            changed = copy.deepcopy(original)
            changed['claims'][key] = value
            rejects(lambda: native.validate(changed))
            count += 1
        for key in original['results']:
            for mutation in ('missing', 'command', 'status', 'bool_status', 'empty', 'duplicate'):
                changed = copy.deepcopy(original)
                if mutation == 'missing':
                    del changed['results'][key]
                elif mutation == 'command':
                    changed['results'][key]['command'] = ['true']
                elif mutation == 'status':
                    changed['results'][key]['exit_code'] = 1
                elif mutation == 'bool_status':
                    changed['results'][key]['exit_code'] = False
                elif mutation == 'empty':
                    changed['results'][key]['output'] = ''
                else:
                    changed['results'][key]['output'] *= 2
                rejects(lambda: native.validate(changed))
                count += 1
        for key in native.ORACLES:
            changed = copy.deepcopy(original)
            changed['results'][key]['output'] = changed['results'][key]['output'].replace('vector_calls=1', 'vector_calls=0')
            rejects(lambda: native.validate(changed))
            count += 1
        for package, _, _, tests in native.suites.SUITES:
            for test in tests:
                changed = copy.deepcopy(original)
                changed['results'][package]['output'] = changed['results'][package]['output'].replace('test ' + test + ' ... ok', '')
                rejects(lambda: native.validate(changed))
                count += 1
    print(f'Hardened native capture schema/results: {count} tamper cases rejected across four lanes')


def orchestration():
    lane = 'amd-x86_64'
    original = record(lane)
    plan = native.commands(lane)
    observed = []
    fake_host = lambda _lane: (original['cpu'], original['features'])

    def child(command, env):
        if command == ['rustc', '+1.98.1', '-vV']:
            return original['compiler']
        key = next(key for key, expected in plan.items() if command == expected)
        observed.append(key)
        assert env['RUSTFLAGS'] == '-C target-feature=+avx,+avx2'
        assert 'CARGO_BUILD_TARGET' not in env and 'RUSTC_WRAPPER' not in env and 'LD_PRELOAD' not in env
        assert all(env['BRYNJA_REQUIRE_' + name] == '1' for name in native.suites.REQUIRED)
        return original['results'][key]['output']

    with tempfile.TemporaryDirectory(prefix='brynja-native-capture-tests-') as directory, \
            patch.object(native.common.native, 'host', side_effect=fake_host), \
            patch.object(capture, 'run', side_effect=child), \
            patch.object(capture, 'snapshot', return_value=(original['commit'], original['tree'])), \
            patch.dict('os.environ', {'CARGO_BUILD_TARGET': 'wrong', 'RUSTC_WRAPPER': 'false', 'LD_PRELOAD': 'ignored'}), \
            contextlib.redirect_stdout(io.StringIO()):
        destination = Path(directory) / 'synthetic-only.json'
        args = SimpleNamespace(lane=lane, output=destination, attest_native=True)
        capture.capture(args)
        native.validate(json.loads(destination.read_text()))
        assert observed == list(plan)
        rejects(lambda: capture.capture(args))  # No overwrite of prior evidence.
        args.output = Path(directory) / 'must-not-exist.json'
        args.attest_native = False
        rejects(lambda: capture.capture(args))
        args.attest_native = True
        with patch.object(capture, 'snapshot', side_effect=ValueError('dirty checkout')):
            rejects(lambda: capture.capture(args))
        with patch.object(capture, 'snapshot', side_effect=[(original['commit'], original['tree']), ('c' * 40, original['tree'])]):
            rejects(lambda: capture.capture(args))
        with patch.object(capture, 'run', side_effect=RuntimeError('command failed')):
            rejects(lambda: capture.capture(args))
        with patch.object(capture, 'run', side_effect=subprocess.TimeoutExpired(['cargo'], 1800)):
            rejects(lambda: capture.capture(args))
        assert not args.output.exists()
    # The real subprocess wrapper must honor status even when stdout says PASS.
    with patch.object(capture.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, 'PASS', 'failed')):
        rejects(lambda: capture.run(['cargo'], {}))
    print('Hardened native capture orchestration: sequential steps, environment, attestation, drift, no-overwrite and command failures PASS')


if __name__ == '__main__':
    validation()
    orchestration()
