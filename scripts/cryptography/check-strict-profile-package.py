#!/usr/bin/env python3
"""Opt-in packaged strict-profile development checks; never publishes or changes gates.

Run on a native supported GNU/Linux host. --simd requires an explicit deployment
attestation; it sets complete build-wide features and checks native test markers.
Mutation tests modify only extracted temporary package sources, never the checkout.
This is author regression evidence, not independent or native release qualification.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
FEATURES = {
    'brynja-crypto-cpu-std': ['strict-batch', 'strict-sha2-acceleration',
        'strict-sha3-acceleration', 'strict-kmac-acceleration', 'strict-tuplehash-acceleration'],
    'brynja-hash-parallel-std': ['strict-acceleration'],
    'brynja-legacy-sha1-std': ['strict-acceleration'],
    'brynja-legacy-md5-std': ['strict-acceleration'],
}
MARKERS = {
    'brynja-crypto-cpu-std': 'native_tuple_boundaries_bits_item_identity_and_protected_storage ... ok',
    'brynja-hash-parallel-std': 'actual_parallel_single_and_simd_waves_match_all_identities ... ok',
    'brynja-legacy-sha1-std': 'native_required_route_bits_padding_and_million_bytes ... ok',
    'brynja-legacy-md5-std': 'required_simd_matches_all_lanes_bits_and_boundaries ... ok',
}
# Exact failure markers ensure a non-compiling mutant cannot count as rejection.
MUTANTS = (
    ('brynja-crypto-cpu-std', 'src/protected_memory/platform/sys.rs',
     'unsafe { super::mlock2(base.as_ptr().cast(), len, 0) }', '0',
     'protected_memory::platform::tests::native_mapping_is_guarded_resident_dump_excluded_and_not_inherited'),
    ('brynja-crypto-cpu-std', 'src/protected_memory/platform/sys.rs',
     'super::mlock2(base.as_ptr().cast(), len, 0)', 'super::mlock2(base.as_ptr().cast(), len, 1)',
     'protected_memory::platform::tests::native_mapping_is_guarded_resident_dump_excluded_and_not_inherited'),
    ('brynja-crypto-cpu-std', 'src/strict_batch/mod.rs', 'self.output.clear();',
     'core::hint::black_box(&mut self.output);', 'strict_batch::tests::native::sparse_outputs'),
    ('brynja-crypto-cpu-std', 'src/strict_batch/worker.rs',
     'brynja_core::copy_secret_region', 'discard_secret_region', 'strict_batch::tests::native::native_batch_routes'),
    ('brynja-crypto-cpu-std', 'src/strict_tuplehash/compiled/worker.rs',
     'brynja_core::copy_secret_region', 'discard_secret_region', 'strict_tuplehash::compiled::tests::native::native_tuple'),
    ('brynja-hash-parallel-std', 'src/strict_execution/compiled.rs',
     'self.quarantined = true;', 'self.quarantined = false;', 'strict_execution::compiled::tests::native::worker_root_faults'),
    ('brynja-legacy-sha1-std', 'src/strict_execution/compiled.rs',
     'self.quarantined = true;', 'self.quarantined = false;', 'strict_execution::compiled::tests::native::failures_clear_protected_output'),
    ('brynja-legacy-md5-std', 'src/strict_execution/batch/worker.rs',
     'brynja_core::copy_secret_region', 'discard_secret_region', 'strict_execution::batch::tests::native::required_simd'),
)


def run(command, cwd, env):
    return subprocess.run(command, cwd=cwd, env=env, text=True,
                          capture_output=True, timeout=600)


def require(result):
    if result.returncode:
        raise ValueError('packaged strict command failed:\n' + result.stdout[-6000:] + result.stderr[-6000:])


def execute(args, destination):
    sys.path.insert(0, str(ROOT / 'scripts/sha3'))
    spec = importlib.util.spec_from_file_location('strict_packages', ROOT / 'scripts/sha3/check-sha3-execution.py')
    shared = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(shared)
    shared.PACKAGES = (*shared.PACKAGES, 'brynja-hash-parallel', 'brynja-hash-parallel-std',
        'brynja-legacy-sha1', 'brynja-legacy-sha1-std', 'brynja-legacy-md5', 'brynja-legacy-md5-std')
    env = dict(os.environ, RUSTUP_TOOLCHAIN=args.toolchain, CARGO_TARGET_DIR=str(destination / 'target'))
    for key in tuple(env):
        if key in ('RUSTFLAGS', 'RUSTDOCFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'CARGO_BUILD_TARGET') or key.startswith('BRYNJA_REQUIRE_'):
            env.pop(key)
    if args.simd:
        flags = '+avx2,+sha,+sse2' if platform.machine() == 'x86_64' else '+neon,+sha2,+sha3'
        env['RUSTFLAGS'] = env['RUSTDOCFLAGS'] = '-C target-feature=' + flags
    _, roots = shared.package(destination, env)
    patches = '\n[workspace]\n[patch.crates-io]\n' + ''.join(
        f'{name} = {{path={json.dumps(str(path))}}}\n' for name, path in roots.items())
    cargo = ['cargo', '+' + args.toolchain]
    for name, features in FEATURES.items():
        manifest = roots[name] / 'Cargo.toml'
        manifest.write_text(manifest.read_text() + patches)
        require(run([*cargo, 'generate-lockfile', '--offline'], roots[name], env))
        for profile in ([], ['--release']):
            command = [*cargo, 'test', '--locked', '--offline', '--no-default-features',
                       '--features', ','.join(features), *profile]
            result = run(command + ['--lib', 'strict_'], roots[name], env)
            require(result)
            if 'test result: ok.' not in result.stdout or 'running 0 tests' in result.stdout:
                raise ValueError('packaged strict tests did not execute: ' + name)
            if args.simd and MARKERS[name] not in result.stdout:
                raise ValueError('native strict marker absent: ' + name + '\n' + result.stdout)
            require(run(command + ['--doc', 'strict_'], roots[name], env))
        print('Packaged strict debug/release tests and ownership doctests: PASS; ' + name, flush=True)
    if not args.simd:
        return
    count = 0
    for name, relative, before, after, test in MUTANTS:
        path = roots[name] / relative
        original = path.read_text()
        if before not in original:
            raise ValueError('stale strict mutant: ' + relative)
        mutant = original.replace(before, after)
        if after == 'discard_secret_region':
            mutant += '\nfn discard_secret_region(_: &mut [u8], _: &[u8]) -> Result<(), ()> { Ok(()) }\n'
        for profile in ([], ['--release']):
            command = [*cargo, 'test', '--locked', '--offline', '--no-default-features',
                       '--features', ','.join(FEATURES[name]), *profile, '--lib', test]
            baseline = run(command, roots[name], env)
            require(baseline)
            if 'test result: ok. 1 passed;' not in baseline.stdout:
                raise ValueError('strict mutant test not uniquely selected: ' + test)
            try:
                path.write_text(mutant)
                result = run(command, roots[name], env)
                if not result.returncode or 'test result: FAILED. 0 passed; 1 failed;' not in result.stdout:
                    raise ValueError('strict mutant survived or failed compilation: ' + relative + '\n' + result.stdout[-3000:] + result.stderr[-3000:])
            finally:
                path.write_text(original)
            require(run(command, roots[name], env))
            count += 1
    print(f'Packaged strict compiled cleanup/output/quarantine regressions: {count} rejected', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--toolchain', default='1.98.1')
    parser.add_argument('--simd', action='store_true')
    parser.add_argument('--attest-native-features', action='store_true')
    args = parser.parse_args()
    if args.simd and not args.attest_native_features:
        parser.error('--simd requires --attest-native-features')
    if platform.system() != 'Linux' or platform.machine() not in ('x86_64', 'aarch64') or platform.libc_ver()[0] != 'glibc':
        parser.error('strict native package execution requires supported GNU/Linux')
    with tempfile.TemporaryDirectory(prefix='brynja-strict-package-') as temporary:
        execute(args, Path(temporary))


if __name__ == '__main__':
    main()
