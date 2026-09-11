#!/usr/bin/env python3
"""Capture one native hardened Keccak lane after a clean exceptional retest."""
import argparse
import json
import platform
from pathlib import Path
import sys
import keccak_hardened_native as evidence


def kernel_command():
    # libtest's nocapture mode can append stdout to its unterminated test-name
    # prefix. Captured successful output gives markers their own complete lines.
    return [
        'cargo', '+1.98.1', 'test', '--locked', '--offline', '-p', 'brynja-crypto-cpu',
        '--features', 'hardened-execution', '--lib', 'hardened_execution::keccak::tests',
        '--', '--show-output', '--test-threads=1']


def capture(lane, output):
    host, shared = evidence.host, evidence.shared
    env = host.clean_environment()
    require = evidence.require
    expected = {'linux-x86_64': ('Linux', 'x86_64'), 'linux-aarch64': ('Linux', 'aarch64'),
                'apple-aarch64': ('Darwin', 'arm64')}[lane]
    require((platform.system(), platform.machine()) == expected, 'Keccak native lane mismatch')
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
            flags = [line.split(':', 1)[1].split() for line in info.splitlines()
                     if ':' in line and line.split(':', 1)[0].strip() == 'flags']
            require(flags and all('avx2' in row for row in flags), 'AVX2 on every reported CPU')
            fields = ('model name',)
        else:
            fields = ('CPU implementer', 'CPU architecture', 'CPU part', 'CPU revision')
        cpu = '; '.join(sorted({' '.join(line.split()) for line in info.splitlines() if line.startswith(fields)}))
    before = evidence.sources(evidence.ROOT)
    # Arm packaged tests first establish hosted OS-wide authority and execute
    # the entire hosted suite, before any globally target-specialized binary.
    option = '--native-x86' if kernel == 'X86Keccak' else '--native-arm'
    results = {'package': host.execute([sys.executable, 'scripts/sha3/check-keccak-hardened.py', option], env)}
    static_env = dict(env, RUSTFLAGS='-C target-feature=' +
                      ('+avx2' if kernel == 'X86Keccak' else '+neon,+sha2,+sha3'))
    results['kernel_tests'] = host.execute(kernel_command(), static_env)
    results = {name: text.replace(str(evidence.ROOT), '<checkout>')
               for name, text in results.items()}
    record = {'schema': 1, 'commit': commit, 'lane': lane, 'target': target, 'kernel': kernel,
              'cpu': cpu, 'os': platform.system() + ' ' + platform.release(), 'compiler': compiler,
              'sources': before, 'results': results, 'native_attestation': 'operator asserts native, not QEMU'}
    evidence.record_check(record, lane, commit, before)
    require(evidence.sources(evidence.ROOT) == before, 'source changed during capture')
    require(shared.git(evidence.ROOT, 'rev-parse', 'HEAD').decode().strip() == commit and
            not shared.git(evidence.ROOT, 'status', '--porcelain', '--untracked-files=all').strip(), 'checkout changed during capture')
    with output.open('x', encoding='utf-8') as stream:
        json.dump(record, stream, indent=2, sort_keys=True)
        stream.write('\n')
    print(f'Native hardened Keccak capture: PASS; {lane}; commit={commit}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('lane', choices=evidence.LANES)
    parser.add_argument('output', type=Path)
    parser.add_argument('--attest-native', required=True, action='store_true')
    args = parser.parse_args()
    capture(args.lane, args.output)
