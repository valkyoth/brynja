#!/usr/bin/env python3
"""Capture reviewed ordinary Keccak multibuffer tests and comparative timings."""
import argparse
import json
from pathlib import Path
import platform
import sys
import keccak_batch_native as native


def capture(args):
    if not args.attest_native: raise ValueError('native operator attestation required')
    native.policy.validate()
    run = native.command.run
    if run(['git', 'status', '--porcelain']).strip() or args.output.exists():
        raise ValueError('clean committed checkout and new output required')
    commit = run(['git', 'rev-parse', 'HEAD']).strip()
    sources = native.policy.snapshot()
    cpu, features = native.host(args.lane)
    compiler = run(['rustc', '+1.98.1', '-vV']).strip()
    env = native.environment()
    base = ['cargo', '+1.98.1', 'test', '--locked', '--offline', '--release']
    results = {}
    results['hosted'] = run(base + ['-p', 'brynja-crypto-cpu-std', '--features', 'keccak-batch', '--lib', 'keccak_batch'], env)
    results['portable'] = run(base + ['-p', 'brynja-hash-sha3', '--features', 'batch-execution', '--lib', 'batch'], env)
    env = native.environment(features)
    results['vector'] = run(base + ['-p', 'brynja-crypto-cpu', '-p', 'brynja-hash-sha3',
        '--features', 'brynja-crypto-cpu/keccak-batch,brynja-hash-sha3/batch-execution',
        '--lib', 'batch', '--', '--show-output'], env)
    for mode in ('portable', 'prefer', 'required'):
        results['oracle_' + mode] = run([sys.executable, 'scripts/sha3/check-keccak-batch.py', '--mode', mode], env)
    results['packaged'] = run([sys.executable, 'scripts/sha3/test-keccak-batch-package.py', '--native'], env)
    results['codegen'] = run([sys.executable, 'scripts/sha3/check-keccak-batch-codegen.py'], env)
    results['benchmark'] = run(['cargo', '+1.98.1', 'run', '--locked', '--offline', '--release',
        '--manifest-path', 'assurance/keccak-batch/Cargo.toml', '--', 'prefer', '--benchmark'], env)
    if (run(['git', 'status', '--porcelain']).strip() or run(['git', 'rev-parse', 'HEAD']).strip() != commit
            or native.policy.snapshot() != sources):
        raise ValueError('source changed during capture')
    record = dict(schema=1, version='0.24.47', lane=args.lane, commit=commit, compiler=compiler,
        cpu=cpu, system=platform.system(), features=features, source_sha512=sources, results=results,
        native='operator-self-attested', profile='ordinary-public-only', independent_review=False,
        fips_validated=False, migration_safety='deployment obligation; not independently proven')
    native.validate(record, sources)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x') as output:
        json.dump(record, output, indent=2)
        output.write('\n')
    print(f'Native ordinary Keccak batch capture: PASS; {args.lane}; commit={commit}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('lane', choices=native.LANES)
    parser.add_argument('output', type=Path)
    parser.add_argument('--attest-native', action='store_true')
    capture(parser.parse_args())
