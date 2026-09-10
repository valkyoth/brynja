#!/usr/bin/env python3
"""Capture native results after retest; operator separately reviews the artifact."""
import argparse
import json
import platform
from pathlib import Path
import hardened_native_evidence as evidence
import hardened_native_host as host


def capture(lane, output):
    env = host.clean_environment()
    require = evidence.require
    commit = evidence.git(host.ROOT, 'rev-parse', 'HEAD').decode().strip()
    require(not evidence.git(host.ROOT, 'status', '--porcelain', '--untracked-files=all').strip(), 'capture requires clean committed source')
    target, kernels = evidence.LANES[lane]
    expected = {'linux-x86_64': ('Linux', 'x86_64'),
                'linux-aarch64': ('Linux', 'aarch64'), 'apple-aarch64': ('Darwin', 'arm64')}[lane]
    require((platform.system(), platform.machine()) == expected, 'host lane mismatch')
    compiler = host.execute(['rustc', '+1.98.1', '-vV'], env)
    evidence.compiler(compiler, target)
    if lane == 'linux-x86_64':
        identity = host.x86_host()
    elif lane == 'apple-aarch64':
        identity = host.execute(['sysctl', '-n', 'machdep.cpu.brand_string'], env).strip()
    else:
        with Path('/proc/cpuinfo').open() as stream:
            cpu = stream.read(evidence.LIMIT + 1)
        require(len(cpu) <= evidence.LIMIT, 'CPU identity exceeds bound')
        # Exclude hostnames, serial numbers and addresses from archived identity.
        identity = '; '.join(sorted({' '.join(line.split()) for line in cpu.splitlines()
                                    if line.startswith(('CPU implementer', 'CPU architecture', 'CPU part', 'CPU revision'))}))
    require(bool(identity), 'missing native CPU identity')
    before = evidence.sources(host.ROOT)
    command = ['cargo', '+1.98.1', 'run', '--locked', '--offline', '--release',
               '--manifest-path', 'assurance/sha2-hardened-execution/Cargo.toml', '--']
    results = {'portable': host.execute([*command, 'portable'], env)}
    if len(kernels) == 2:
        # Hosted authority checks OS feature support BEFORE static-feature entry.
        results['hosted'] = host.execute([*command, 'hosted'], env)
        require('narrow=Runtime(ArmSha256); wide=Runtime(ArmSha512)' in
                results['hosted'].splitlines(), 'hosted feature proof must precede static entry')
    static_env = dict(env, RUSTFLAGS='-C target-feature=' +
                      ('+sha,+sse2' if len(kernels) == 1 else '+neon,+sha2,+sha3'))
    results['static'] = host.execute([*command, 'static', *(['narrow'] if len(kernels) == 1 else [])], static_env)
    results['kernel_tests'] = host.execute([
        'cargo', '+1.98.1', 'test', '--locked', '--offline', '-p', 'brynja-crypto-cpu',
        '--all-features', '--lib', 'hardened_execution', '--', '--nocapture', '--test-threads=1'], static_env)
    record = {'schema': 1, 'capture_commit': commit, 'lane': lane, 'target': target,
              'cpu': identity, 'os': platform.system() + ' ' + platform.release(),
              'compiler': compiler, 'sources': before, 'kernels': kernels,
              'results': results, 'native_attestation': 'operator asserts native, not QEMU'}
    evidence.validate_record(record, lane, commit, before)
    require(evidence.sources(host.ROOT) == before, 'source changed during capture')
    require(evidence.git(host.ROOT, 'rev-parse', 'HEAD').decode().strip() == commit and
            not evidence.git(host.ROOT, 'status', '--porcelain', '--untracked-files=all').strip(), 'checkout changed during capture')
    with output.open('x', encoding='utf-8') as stream:
        json.dump(record, stream, indent=2, sort_keys=True)
        stream.write('\n')
    print('Native hardened SHA-2 capture: PASS; ' + lane + '; commit=' + commit)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('lane', choices=evidence.LANES)
    parser.add_argument('output', type=Path)
    parser.add_argument('--attest-native', action='store_true', required=True,
                        help='operator confirms this is a native host, not QEMU/emulation')
    args = parser.parse_args()
    capture(args.lane, args.output)
