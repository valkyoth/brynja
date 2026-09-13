#!/usr/bin/env python3
"""Collect a clean, committed native hardened SHA-1 candidate for owner review."""
import argparse
import json
import platform
from pathlib import Path
import hardened_native as native


def capture(args):
    native.require(args.attest_native, 'operator must attest native, not QEMU')
    native.policy.validate()
    native.require(not args.output.exists(), 'refusing to overwrite evidence')
    native.require(not native.host.run(['git', 'status', '--porcelain']), 'clean committed candidate required')
    commit = native.host.run(['git', 'rev-parse', 'HEAD'])
    before = native.policy.hashes()
    cpu, features = native.host.host(args.lane)
    env = native.clean_environment()
    compiler = native.host.run(['rustc', '+1.98.1', '-vV'], env)
    results = native.collect(args.lane, features, env)
    native.require(not native.host.run(['git', 'status', '--porcelain']), 'candidate became dirty')
    native.require(native.host.run(['git', 'rev-parse', 'HEAD']) == commit, 'commit changed')
    native.policy.validate()
    native.require(native.policy.hashes() == before, 'source changed during capture')
    record = dict(schema=1, version='0.24.42', lane=args.lane, commit=commit,
        compiler=compiler, cpu=cpu, system=platform.system(), static_features=features,
        source_sha256=before, results=results, native='operator-self-attested',
        profile='hardened-legacy-only', owned_memory_regions=7, independent_review=False,
        fips_validated=False, register_erasure=False,
        disposition='pending owner review; native correctness is not migration or side-channel proof')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x', encoding='utf-8') as file:
        json.dump(record, file, indent=2)
        file.write('\n')
    print(f'Native hardened SHA-1 capture: PASS; {args.lane}; commit={commit}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('lane', choices=native.LANES)
    parser.add_argument('output', type=Path)
    parser.add_argument('--attest-native', action='store_true')
    capture(parser.parse_args())
