#!/usr/bin/env python3
"""Inspect legacy host lifecycle, keyed handoffs and retained dispatch, not whole-worker erasure."""
import argparse
import json
from pathlib import Path
import re

import legacy_hmac_timing_runner as runner
import legacy_hmac_hosted_lifecycle as hosted

ROOT = runner.ROOT
FIXTURE = ROOT / 'assurance/legacy-hmac-hosted-cleanup/Cargo.toml'
TARGETS = ('x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-gnu', 'aarch64-apple-darwin')
FEATURES = {'x86_64-unknown-linux-gnu': '+sha,+sse2,+avx2',
            'aarch64-unknown-linux-gnu': '+neon,+sha2', 'aarch64-apple-darwin': '+neon,+sha2'}


def emit(directory, compiler, target, panic, simd=True, fixture=FIXTURE, hosted_manifest=None, legacy_manifest=None):
    hosted.require(compiler in ('1.90.0', '1.99.1') and target in TARGETS
                   and panic in ('abort', 'unwind'), 'unreviewed legacy hosted compiler profile')
    env = runner.environment(directory)
    env['CARGO_PROFILE_RELEASE_PANIC'] = panic
    env['RUSTFLAGS'] = '-C symbol-mangling-version=v0' + (' -C target-feature=' + FEATURES[target] if simd else '')
    if target == 'aarch64-apple-darwin':
        env['MACOSX_DEPLOYMENT_TARGET'] = '11.0'
    metadata = json.loads(runner.run(['cargo', '+' + compiler, 'metadata', '--manifest-path', str(fixture),
        '--locked', '--offline', '--format-version', '1', '--filter-platform', target], env))
    hosted.graph(metadata, fixture, hosted_manifest, legacy_manifest)
    artifacts = {}
    for package in ('brynja-legacy-hmac-std', 'brynja-legacy-hmac-hosted-cleanup'):
        runner.run(['cargo', '+' + compiler, 'rustc', '--manifest-path', str(fixture), '--locked', '--offline',
                    '--release', '--lib', '--target', target, '-p', package, '--', '--emit=llvm-ir'], env)
        files = list((directory / 'target' / target / 'release/deps').glob(package.replace('-', '_') + '-*.ll'))
        hosted.require(len(files) == 1, 'ambiguous legacy hosted artifact')
        llvm = files[0].read_text()
        expected = 'arm64-apple-macosx11.0.0' if target == TARGETS[-1] else target
        hosted.require(re.findall(r'!"rustc version ([\d.]+) ', llvm) == [compiler]
                       and re.findall(r'^target triple = "([^"]+)"$', llvm, re.M) == [expected],
                       'legacy hosted artifact compiler/target mismatch')
        artifacts[package] = llvm
    return artifacts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--toolchain', action='append', choices=('1.90.0', '1.99.1'))
    parser.add_argument('--target', choices=TARGETS, default=TARGETS[0])
    parser.add_argument('--generic', action='store_true')
    args = parser.parse_args()
    for compiler in args.toolchain or ('1.90.0', '1.99.1'):
        for panic in ('abort', 'unwind'):
            with runner.cargo_environment.private_directory(ROOT) as directory:
                artifacts = emit(Path(directory), compiler, args.target, panic, not args.generic)
                hosted.validate(artifacts, args.target, panic)
            print(f'Legacy HMAC host lifecycle, authority, keyed admission/storage and retained dispatch: PASS; '
                  f'{compiler}; {args.target}; panic={panic}; simd={not args.generic}; '
                  'no complete worker/output or native qualification', flush=True)


if __name__ == '__main__':
    main()
