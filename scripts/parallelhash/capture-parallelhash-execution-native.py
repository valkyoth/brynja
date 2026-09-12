#!/usr/bin/env python3
"""Collect one clean, native ParallelHash lane; never infer CPU support from flags."""
import argparse
import json
import platform
from pathlib import Path
import sys
import parallelhash_execution_native as evidence


def kernel_command():
    return ['cargo', '+1.98.1', 'test', '--locked', '--offline', '-p', 'brynja-crypto-cpu',
            '--features', 'hardened-execution', '--lib', 'hardened_execution::keccak::tests',
            '--', '--show-output', '--test-threads=1']


def x86_features(text):
    rows = [line.split(':', 1)[1].split() for line in text.splitlines()
            if ':' in line and line.split(':', 1)[0].strip() == 'flags']
    evidence.require(rows and all({'avx2', 'xsave'} <= set(row) for row in rows),
                     'AVX2 and XSAVE on every reported CPU')


def capture(lane, output):
    shared, host, require = evidence.shared, evidence.host, evidence.require
    env = host.clean_environment()
    expected = {'linux-x86_64': ('Linux', 'x86_64'), 'linux-aarch64': ('Linux', 'aarch64'),
                'apple-aarch64': ('Darwin', 'arm64')}[lane]
    require((platform.system(), platform.machine()) == expected, 'ParallelHash native lane mismatch')
    commit = shared.git(evidence.ROOT, 'rev-parse', 'HEAD').decode().strip()
    require(not shared.git(evidence.ROOT, 'status', '--porcelain', '--untracked-files=all').strip(), 'clean capture checkout')
    target, kernel = evidence.LANES[lane]
    compiler = host.execute(['rustc', '+1.98.1', '-vV'], env)
    shared.compiler(compiler, target)
    if lane == 'apple-aarch64':
        cpu = host.execute(['sysctl', '-n', 'machdep.cpu.brand_string'], env).strip()
        require(host.execute(['sysctl', '-n', 'hw.optional.arm.FEAT_SHA3'], env).strip() == '1', 'Apple SHA3 features')
    else:
        with Path('/proc/cpuinfo').open() as stream:
            info = stream.read(shared.LIMIT + 1)
        require(len(info) <= shared.LIMIT, 'CPU info bound')
        if lane == 'linux-x86_64':
            x86_features(info)
            fields = ('model name',)
        else:
            fields = ('CPU implementer', 'CPU architecture', 'CPU part', 'CPU revision')
        cpu = '; '.join(sorted({' '.join(line.split()) for line in info.splitlines() if line.startswith(fields)}))
    before = evidence.sources(evidence.ROOT)
    command = [sys.executable, 'scripts/parallelhash/check-parallelhash-execution-differential.py']
    results = {'baseline': host.execute(command, env)}
    if kernel == 'ArmKeccak':
        # Hosted OS-wide authority must succeed before globally specializing a binary.
        results['hosted'] = host.execute([*command, '--native'], env)
    static_env = dict(env, RUSTFLAGS='-C target-feature=' +
                      ('+avx2' if kernel == 'X86Keccak' else '+neon,+sha2,+sha3'))
    results['static'] = host.execute([*command, '--static'], static_env)
    results['kernel_tests'] = host.execute(kernel_command(), static_env)
    record = {'schema': 1, 'commit': commit, 'lane': lane, 'target': target, 'kernel': kernel,
              'cpu': cpu, 'os': platform.system() + ' ' + platform.release(), 'compiler': compiler,
              'sources': before, 'results': {name: text.replace(str(evidence.ROOT), '<checkout>')
                                           for name, text in results.items()},
              'native_attestation': 'operator asserts native, not QEMU'}
    evidence.record_check(record, lane, commit, before)
    require(evidence.sources(evidence.ROOT) == before, 'source changed during capture')
    require(shared.git(evidence.ROOT, 'rev-parse', 'HEAD').decode().strip() == commit and
            not shared.git(evidence.ROOT, 'status', '--porcelain', '--untracked-files=all').strip(), 'checkout changed during capture')
    with output.open('x', encoding='utf-8') as stream:
        json.dump(record, stream, indent=2, sort_keys=True)
        stream.write('\n')
    print(f'Native hardened ParallelHash capture: PASS; {lane}; commit={commit}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('lane', choices=evidence.LANES)
    parser.add_argument('output', type=Path)
    parser.add_argument('--attest-native', required=True, action='store_true')
    args = parser.parse_args()
    capture(args.lane, args.output)
