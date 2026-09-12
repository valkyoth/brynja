#!/usr/bin/env python3
"""Collect ordinary operational SHA-1 evidence; never authorize secret use."""
import argparse
import hashlib
import importlib.util
import json
import os
import platform
from pathlib import Path

import cpu_policy as policy

spec = importlib.util.spec_from_file_location('candidate_capture',
    Path(__file__).with_name('capture-sha1-cpu-native.py'))
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)


def capture(args):
    if not args.attest_native:
        raise ValueError('operator must attest native execution, not QEMU')
    policy.validate()
    if native.run(['git', 'status', '--porcelain']):
        raise ValueError('capture requires a clean committed candidate')
    if args.output.exists():
        raise ValueError('refusing to overwrite evidence')
    commit = native.run(['git', 'rev-parse', 'HEAD'])
    before = {p: hashlib.sha256((policy.ROOT / p).read_bytes()).hexdigest() for p in policy.BOUND}
    cpu, features = native.host(args.lane)
    compiler = native.run(['rustc', '+1.98.1', '-vV'])
    env = dict(os.environ)
    for name in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS', 'CARGO_BUILD_TARGET'):
        env.pop(name, None)
    env['RUSTUP_TOOLCHAIN'] = '1.98.1'
    results = {}
    test = ['cargo', '+1.98.1', 'test', '--locked', '--offline', '--release']
    results['hosted'] = native.run(test + ['-p', 'brynja-legacy-sha1-std',
        '--features', 'runtime-execution', '--test', 'execution', '--', '--nocapture', '--test-threads=1'], env)
    results['portable'] = native.run(test + ['-p', 'brynja-legacy-sha1',
        '--features', 'execution', '--test', 'execution'], env)
    env['RUSTFLAGS'] = '-C target-feature=' + features
    results['static'] = native.run(test + ['-p', 'brynja-legacy-sha1', '--features', 'execution',
        '--lib', '--test', 'execution', '--', '--nocapture', '--test-threads=1'], env)
    results['packaged'] = native.run(['python3', 'scripts/sha1/check-sha1-package.py', '--execution'], env)
    backend = 'legacy-x86-sha1' if native.LANES[args.lane] == 'x86' else 'legacy-aarch64-sha1'
    if f'SHA1_OPERATIONAL: {backend}; normal build; public only' not in results['static']:
        raise ValueError('required static kernel execution was not observed')
    hosted = 'None' if native.LANES[args.lane] == 'x86' else 'Some(Aarch64Sha1)'
    if 'SHA1_HOSTED_OPERATIONAL: ' + hosted not in results['hosted']:
        raise ValueError('hosted selection did not match the platform disposition')
    if 'test result: ok. 4 passed' not in results['static'] or 'Independent operational SHA-1 corpus: 1135' not in results['packaged']:
        raise ValueError('native acceptance coverage is incomplete')
    if native.run(['git', 'status', '--porcelain']) or native.run(['git', 'rev-parse', 'HEAD']) != commit:
        raise ValueError('candidate changed during capture')
    policy.validate()
    after = {p: hashlib.sha256((policy.ROOT / p).read_bytes()).hexdigest() for p in policy.BOUND}
    if before != after:
        raise ValueError('native source bindings changed')
    record = dict(schema=1, version='0.24.41', lane=args.lane, commit=commit,
        compiler=compiler, cpu=cpu, system=platform.system(), static_features=features,
        source_sha256=before, results=results, native='operator-self-attested',
        profile='ordinary-public-only', hardened='portable-only',
        independent_review=False, fips_validated=False,
        disposition='pending owner review; correctness is not migration or side-channel proof')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x', encoding='utf-8') as output:
        json.dump(record, output, indent=2)
        output.write('\n')
    print(f'Native ordinary SHA-1 capture: PASS; {args.lane}; commit={commit}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('lane', choices=native.LANES)
    parser.add_argument('output', type=Path)
    parser.add_argument('--attest-native', action='store_true')
    capture(parser.parse_args())
