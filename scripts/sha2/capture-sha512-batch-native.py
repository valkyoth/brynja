#!/usr/bin/env python3
"""Self-attested native ordinary batch correctness and comparative performance."""
import argparse
import json
import os
from pathlib import Path
import platform
import sys
import sha512_batch_acceptance as acceptance
import sha512_batch_policy as policy

LANES = ('amd-x86_64', 'intel-x86_64', 'aws-aarch64', 'apple-m2-aarch64')


def host(lane):
    machine = platform.machine().lower()
    if lane.endswith('x86_64'):
        if machine not in ('x86_64', 'amd64') or platform.system() != 'Linux': raise ValueError('wrong native platform')
        cpu = Path('/proc/cpuinfo').read_text()
        vendor = 'AuthenticAMD' if lane.startswith('amd') else 'GenuineIntel'
        flags = [set(line.split(':', 1)[1].split()) for line in cpu.splitlines() if line.startswith('flags')]
        if vendor not in cpu or not flags or not all({'avx', 'avx2'} <= row for row in flags):
            raise ValueError('every enumerated CPU needs the exact vendor/AVX2 bundle')
        return vendor, '+avx,+avx2'
    if machine not in ('aarch64', 'arm64'): raise ValueError('wrong native architecture')
    if lane == 'apple-m2-aarch64':
        if platform.system() != 'Darwin': raise ValueError('Apple lane requires Darwin')
        cpu = acceptance.run(['sysctl', '-n', 'machdep.cpu.brand_string']).stdout.strip()
        if 'Apple M2' not in cpu: raise ValueError('Apple M2 lane required')
        if acceptance.run(['sysctl', '-n', 'hw.optional.neon']).stdout.strip() != '1': raise ValueError('NEON missing')
        dedicated = acceptance.run(['sysctl', '-n', 'hw.optional.arm.FEAT_SHA512']).stdout.strip() == '1'
        return cpu, '+neon' + (',+sha3' if dedicated else '')
    if platform.system() != 'Linux': raise ValueError('AWS Arm lane requires Linux')
    flags = [set(line.split(':', 1)[1].split()) for line in Path('/proc/cpuinfo').read_text().splitlines() if line.startswith('Features')]
    if not flags or not all('asimd' in row for row in flags): raise ValueError('NEON missing on enumerated CPU')
    dedicated = all('sha512' in row for row in flags)
    return 'operator-labelled AWS Arm; provider identity not authenticated', '+neon' + (',+sha3' if dedicated else '')


def capture(args):
    if not args.attest_native: raise ValueError('native operator attestation required')
    policy.validate()
    if acceptance.run(['git', 'status', '--porcelain']).stdout.strip() or args.output.exists():
        raise ValueError('clean committed checkout and new output required')
    commit = acceptance.run(['git', 'rev-parse', 'HEAD']).stdout.strip()
    sources = policy.snapshot()
    cpu, features = host(args.lane)
    compiler = acceptance.run(['rustc', '+1.98.1', '-vV']).stdout.strip()
    env = dict(os.environ, RUSTUP_TOOLCHAIN='1.98.1')
    for key in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS', 'CARGO_BUILD_TARGET', 'BRYNJA_REQUIRE_SHA512_BATCH'):
        env.pop(key, None)
    results = {}
    results['hosted'] = acceptance.run(['cargo', '+1.98.1', 'test', '--locked', '--offline', '--release',
        '-p', 'brynja-crypto-cpu-std', '--features', 'sha512-batch', '--lib', 'sha512_batch'], env=env).stdout
    results['portable'] = acceptance.run(['cargo', '+1.98.1', 'test', '--locked', '--offline', '--release',
        '-p', 'brynja-hash-sha2', '--features', 'batch512-execution', '--test', 'batch512'], env=env).stdout
    env['RUSTFLAGS'] = '-C target-feature=' + features
    env['BRYNJA_REQUIRE_SHA512_BATCH'] = '1'
    results['vector'] = acceptance.run(['cargo', '+1.98.1', 'test', '--locked', '--offline', '--release',
        '-p', 'brynja-hash-sha2', '--features', 'batch512-execution', '--test', 'batch512', '--', '--nocapture'], env=env).stdout
    kernel = 'Avx2' if args.lane.endswith('x86_64') else 'Neon'
    if 'SHA512_BATCH_VECTOR: ' + kernel + '; calls=' not in results['vector']: raise ValueError('actual vector execution absent')
    results['packaged_oracle'] = acceptance.run([sys.executable, 'scripts/sha2/check-sha512-batch.py', '--native', '--package'], env=env).stdout
    results['codegen'] = acceptance.run([sys.executable, 'scripts/sha2/check-sha512-batch-codegen.py'], env=env).stdout
    results['benchmark'] = acceptance.run(['cargo', '+1.98.1', 'run', '--locked', '--offline', '--release',
        '--manifest-path', 'assurance/sha512-batch/Cargo.toml', '--', 'required', '--benchmark'], env=env).stdout
    if results['benchmark'].count('SHA512_BATCH_BENCH:') != 8: raise ValueError('incomplete comparative benchmark')
    if (acceptance.run(['git', 'status', '--porcelain']).stdout.strip()
            or acceptance.run(['git', 'rev-parse', 'HEAD']).stdout.strip() != commit or policy.snapshot() != sources):
        raise ValueError('source changed during capture')
    record = dict(schema=1, version='0.24.46', lane=args.lane, commit=commit, compiler=compiler,
        cpu=cpu, system=platform.system(), features=features, source_sha512=sources, results=results,
        native='operator-self-attested', profile='ordinary-public-only', independent_review=False,
        fips_validated=False, migration_safety='deployment obligation; not independently proven')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x') as output: json.dump(record, output, indent=2); output.write('\n')
    print(f'Native ordinary SHA-512-family batch capture: PASS; {args.lane}; commit={commit}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('lane', choices=LANES)
    parser.add_argument('output', type=Path)
    parser.add_argument('--attest-native', action='store_true')
    capture(parser.parse_args())
