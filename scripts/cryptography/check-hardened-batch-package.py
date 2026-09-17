#!/usr/bin/env python3
"""Package-external hardened batch acceptance; never publishes or changes gates.

Portable by default. --simd requires the operator to establish the compiled
target-feature bundle on the executing native machine or emulator. This is
development evidence, not native qualification or independent review.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

import hardened_batch_package_cases as cases

ROOT = Path(__file__).resolve().parents[2]
FEATURES = {
    'brynja-crypto-cpu': ['sha256-hardened-batch', 'sha512-hardened-batch', 'keccak-hardened-batch'],
    'brynja-hash-sha2': ['hardened-batch-execution', 'hardened-batch512-execution'],
    'brynja-hash-sha3': ['hardened-batch-execution'],
    'brynja-crypto-cpu-std': ['sha256-hardened-batch', 'sha512-hardened-batch', 'keccak-hardened-batch'],
    'brynja-hash-parallel': ['hardened-batch-execution'],
    'brynja-hash-parallel-std': ['runtime-batch-execution'],
}
ORDINARY = {
    'brynja-crypto-cpu': ['sha256-batch', 'sha512-batch', 'keccak-batch'],
    'brynja-hash-sha2': ['batch-execution', 'batch512-execution'],
    'brynja-hash-sha3': ['batch-execution'],
    'brynja-crypto-cpu-std': ['sha256-batch', 'sha512-batch', 'keccak-batch'],
}


def run(command, cwd, environment):
    return subprocess.run(command, cwd=cwd, env=environment, capture_output=True,
                          text=True, timeout=600)


def require_success(result):
    if result.returncode:
        raise ValueError('packaged batch command failed:\n' + result.stdout[-4000:] + result.stderr[-6000:])


def require_rejection(result, code):
    # Parse actual rustc diagnostics, not a matching substring in source snippets.
    errors = []
    for line in result.stdout.splitlines():
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if record.get('reason') == 'compiler-message':
            message = record['message']
            if message.get('level') == 'error':
                errors.append((message.get('code') or {}).get('code'))
    if not result.returncode or not errors or set(errors) != {code}:
        raise ValueError(f'negative did not fail exclusively with {code}: {errors}\n' + result.stderr[-3000:])


def manifest(roots, ordinary=False):
    text = '[package]\nname="hardened-batch-external"\nversion="0.0.0"\nedition="2024"\n[workspace]\n[dependencies]\n'
    for name, features in FEATURES.items():
        selected = features + (ORDINARY.get(name, []) if ordinary else [])
        text += f'{name} = {{ path = {json.dumps(str(roots[name]))}, default-features = false, features = {json.dumps(selected)} }}\n'
    text += '\n[patch.crates-io]\n'
    for name, path in roots.items():
        text += f'{name} = {{ path = {json.dumps(str(path))} }}\n'
    return text


def validate_graph(metadata, roots, consumer, ordinary=False):
    expected = set(roots) | {'hardened-batch-external'}
    if {p['name'] for p in metadata['packages']} != expected:
        raise ValueError('unexpected packaged dependency closure')
    packages = {p['id']: p for p in metadata['packages']}
    for node in metadata['resolve']['nodes']:
        package = packages[node['id']]
        name = package['name']
        directory = consumer if name == 'hardened-batch-external' else roots[name]
        if package['source'] is not None or Path(package['manifest_path']).resolve() != (directory / 'Cargo.toml').resolve():
            raise ValueError('dependency escaped packaged closure: ' + name)
        if not ordinary and set(node['features']) & set(ORDINARY.get(name, [])):
            raise ValueError('hardened-only consumer enabled ordinary batching: ' + name)


def probes(source, command, consumer, env, subjects):
    # Generated Rust source from the fixed cases module, not runtime secret
    # material. cargo check needs these plaintext type/trait probes on disk;
    # execute() confines them to its TemporaryDirectory consumer.
    count = 0
    for label, positive, negative, diagnostic in subjects:
        try:
            source.write_text('#![forbid(unsafe_code)]\n' + positive)
            require_success(run(command, consumer, env))
            source.write_text('#![forbid(unsafe_code)]\n' + negative)
            require_rejection(run(command, consumer, env), diagnostic)
        except ValueError as error:
            raise ValueError(label + ': ' + str(error)) from error
        count += 1
    return count


def compiled_regressions(roots, cargo, env, args):
    count = 0
    for name, relative, before, after, test, occurrences in cases.compiled_mutants(args.simd):
        path = roots[name] / relative
        original = path.read_text()
        if original.count(before) != occurrences:
            raise ValueError('packaged mutation anchor drift: ' + relative)
        command = [*cargo, 'test', '--locked', '--offline', '--release',
                   '--no-default-features', '--features', ','.join(FEATURES[name]),
                   '--target', args.target, '--lib', test, '--', '--exact']
        baseline = run(command, roots[name], env)
        require_success(baseline)
        if 'test result: ok. 1 passed;' not in baseline.stdout:
            raise ValueError('packaged regression test did not execute: ' + test)
        try:
            path.write_text(original.replace(before, after))
            rejected = run(command, roots[name], env)
            if not rejected.returncode or 'test result: FAILED. 0 passed; 1 failed;' not in rejected.stdout:
                raise ValueError('packaged mutant survived or did not execute: ' + test + '\n' + rejected.stderr[-2000:])
        finally:
            path.write_text(original)
        require_success(run(command, roots[name], env))
        count += 1
    print(f'Packaged cleanup/dispatch compiled mutants: {count} rejected', flush=True)


def execute(args, destination):
    sys.path.insert(0, str(ROOT / 'scripts/sha3'))
    spec = importlib.util.spec_from_file_location('batch_packages', ROOT / 'scripts/sha3/check-sha3-execution.py')
    shared = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(shared)
    shared.PACKAGES = (*shared.PACKAGES, 'brynja-hash-parallel', 'brynja-hash-parallel-std')
    env = dict(os.environ, RUSTUP_TOOLCHAIN=args.toolchain, CARGO_TARGET_DIR=str(destination / 'target'))
    for key in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS', 'CARGO_BUILD_TARGET'):
        env.pop(key, None)
    # Inherited enforcement flags must not turn a portable baseline into a false failure.
    for key in tuple(env):
        if key.startswith('BRYNJA_REQUIRE_'):
            env.pop(key)
    flags = ''
    if args.simd:
        flags = '-C target-feature=' + ('+avx,+avx2' if args.target.startswith('x86_64-') else '+neon')
        for family in ('SHA256_HARDENED_BATCH', 'SHA512_HARDENED_BATCH', 'KECCAK_HARDENED_BATCH',
                       'HARDENED_KECCAK_LEAF', 'HOSTED_HARDENED_BATCH', 'PARALLELHASH_BATCH'):
            env['BRYNJA_REQUIRE_' + family] = '1'
    if args.target == 'aarch64-unknown-linux-musl':
        flags += ' -C linker=rust-lld'
    env['RUSTFLAGS'] = env['RUSTDOCFLAGS'] = flags.strip()
    _, roots = shared.package(destination, env)
    consumer = destination / 'hardened-consumer'
    (consumer / 'src').mkdir(parents=True)
    (consumer / 'Cargo.toml').write_text(manifest(roots))
    source = consumer / 'src/lib.rs'
    original = cases.examples(roots)
    source.write_text(original)
    cargo = ['cargo', '+' + args.toolchain]
    require_success(run([*cargo, 'generate-lockfile', '--offline'], consumer, env))
    result = run([*cargo, 'metadata', '--locked', '--offline', '--format-version', '1'], consumer, env)
    require_success(result)
    validate_graph(json.loads(result.stdout), roots, consumer)
    # Keep every crate's own published examples, lifecycle tests and route probes.
    for name, features in FEATURES.items():
        patch = manifest(roots).split('[patch.crates-io]')[1]
        path = roots[name] / 'Cargo.toml'
        path.write_text(path.read_text() + '\n[workspace]\n[patch.crates-io]' + patch)
        require_success(run([*cargo, 'generate-lockfile', '--offline'], roots[name], env))
        for profile in ([], ['--release']):
            command = [*cargo, 'test', '--locked', '--offline', '--no-default-features',
                       '--features', ','.join(features), '--target', args.target, *profile]
            require_success(run(command + ['--lib'], roots[name], env))
            require_success(run(command + ['--doc'], roots[name], env))
        print('Packaged hardened tests/doctests: PASS; ' + name, flush=True)
    for profile in ([], ['--release']):
        require_success(run([*cargo, 'test', '--locked', '--offline', '--target', args.target, *profile, '--doc'], consumer, env))
    compiled_regressions(roots, cargo, env, args)
    command = [*cargo, 'check', '--locked', '--offline', '--target', args.target, '--message-format=json']
    try:
        count = probes(source, command, consumer, env, cases.boundaries())
        source.write_text("fn require<T: Send>() {} pub fn probe() { require::<brynja_hash_parallel::execution::batch::TransferredLeaves<'static, 'static, 'static>>(); }")
        require_success(run(command, consumer, env))
        (consumer / 'Cargo.toml').write_text(manifest(roots, ordinary=True))
        require_success(run([*cargo, 'generate-lockfile', '--offline'], consumer, env))
        result = run([*cargo, 'metadata', '--locked', '--offline', '--format-version', '1'], consumer, env)
        require_success(result)
        validate_graph(json.loads(result.stdout), roots, consumer, ordinary=True)
        separate = probes(source, command, consumer, env, cases.substitutions())
    finally:
        source.write_text(original)
    print(f'Hardened batch package acceptance: PASS; ownership={count}; substitutions/conversions={separate}; '
          f'{args.toolchain}; {args.target}; simd={args.simd}', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--toolchain', default='1.98.1')
    parser.add_argument('--target', default='x86_64-unknown-linux-gnu')
    parser.add_argument('--simd', action='store_true')
    args = parser.parse_args()
    if not args.target.startswith(('x86_64-', 'aarch64-')):
        parser.error('supported execution targets are x86_64 and aarch64')
    with tempfile.TemporaryDirectory(prefix='brynja-hardened-batch-package-') as directory:
        execute(args, Path(directory))


if __name__ == '__main__':
    main()
