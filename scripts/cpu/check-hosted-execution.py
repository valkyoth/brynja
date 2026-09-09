#!/usr/bin/env python3
"""Package-external hosted authority, compiled regressions and source binding."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[2]
CPU = 'brynja-crypto-cpu'
HOST = 'brynja-crypto-cpu-std'
PACKAGES = ('brynja-core', 'brynja-hash-core', 'brynja-hash-sha2', CPU, HOST)
FIXTURE = 'assurance/hosted-cpu-execution'
REVIEW = ROOT / 'security/hosted-cpu-execution-reviewed.json'
COMMAND = 'python3 scripts/cpu/check-hosted-execution.py'


def validate(write=False):
    manifests = {name: tomllib.loads((ROOT / 'crates' / name / 'Cargo.toml').read_text())
                 for name in (CPU, HOST)}
    if manifests[CPU].get('features') != {
            'default': [], 'static-execution': [], 'runtime-execution': ['static-execution']}:
        raise ValueError('CPU execution features changed')
    if manifests[CPU].get('dependencies') or manifests[HOST].get('features') != {
            'default': [], 'runtime-execution': ['brynja-crypto-cpu/runtime-execution']}:
        raise ValueError('hosted execution must remain default-off and isolated')
    for owner, module in ((CPU, 'runtime_execution'), (HOST, 'execution')):
        source = (ROOT / 'crates' / owner / 'src/lib.rs').read_text()
        if f'#[cfg(feature = "runtime-execution")]\npub mod {module};' not in source:
            raise ValueError('public module lost its feature gate')
    if COMMAND not in (ROOT / 'scripts/checks.sh').read_text().splitlines():
        raise ValueError('hosted acceptance missing from repository gate')
    memory = ['scripts/zeroization/check-zeroization-miri.sh',
              'scripts/zeroization/check-zeroization-sanitizer.sh']
    for name in memory:
        source = (ROOT / name).read_text()
        for command in ('-p brynja-crypto-cpu --features runtime-execution --lib runtime_execution',
                        '-p brynja-crypto-cpu-std --features runtime-execution --lib execution'):
            if command not in source:
                raise ValueError('hosted authority dynamic analysis missing')
    inputs = [Path(__file__), ROOT / 'scripts/checks.sh',
              ROOT / 'docs/hosted-cpu-execution.md', ROOT / 'scripts/repository/unsafe_policy.py',
              *(ROOT / name for name in memory)]
    for owner in (CPU, HOST):
        crate = ROOT / 'crates' / owner
        inputs += [crate / 'Cargo.toml', *sorted((crate / 'src').rglob('*.rs'))]
    fixture = ROOT / FIXTURE
    inputs += [fixture / 'Cargo.toml', fixture / 'Cargo.lock', *sorted((fixture / 'src').glob('*.rs'))]
    expected = {'milestone': '0.24.32', 'sha256': {
        str(path.relative_to(ROOT)).replace('\\', '/'):
        hashlib.sha256(path.read_bytes().replace(b'\r\n', b'\n')).hexdigest() for path in inputs}}
    if write:
        REVIEW.write_text(json.dumps(expected, indent=2, sort_keys=True) + '\n')
    if json.loads(REVIEW.read_text()) != expected:
        raise ValueError('hosted authority changed; reopen review')


def run(args, cwd, env, *, success=True):
    result = subprocess.run(args, cwd=cwd, env=env, text=True, capture_output=True, timeout=240)
    if (result.returncode == 0) != success:
        raise RuntimeError(f'{args}\n{result.stdout}\n{result.stderr}')
    return result


def isolated(root):
    workspace = root / 'workspace'
    workspace.mkdir()
    # The just-checked local source is trusted input, not an external corpus.
    shutil.copyfile(ROOT / 'Cargo.toml', workspace / 'Cargo.toml')
    for name in PACKAGES:
        shutil.copytree(ROOT / 'crates' / name, workspace / 'crates' / name,
                        ignore=shutil.ignore_patterns('target'))
    manifest = (workspace / 'Cargo.toml').read_text().replace(
        'default-members = ["crates/brynja"]\n', '')
    (workspace / 'Cargo.toml').write_text(manifest)
    return workspace


def package_consumer(root, workspace, env):
    env = dict(env, CARGO_TARGET_DIR=str(root / 'package-target'))
    run(['cargo', 'package', '--workspace', '--offline', '--allow-dirty', '--no-verify'], workspace, env)
    package_roots = {}
    for name in PACKAGES:
        version = tomllib.loads((workspace / 'crates' / name / 'Cargo.toml').read_text())['package']['version']
        archive = root / 'package-target/package' / f'{name}-{version}.crate'
        with tarfile.open(archive) as bundle:
            bundle.extractall(root / 'packages', filter='data')
        package_roots[name] = root / 'packages' / f'{name}-{version}'
    consumer = root / 'consumer'
    shutil.copytree(ROOT / FIXTURE, consumer, ignore=shutil.ignore_patterns('target'))
    path = consumer / 'Cargo.toml'
    source = path.read_text().replace('path = "../../crates/brynja-crypto-cpu-std", ', '')
    source += '\n[patch.crates-io]\n' + '\n'.join(
        f'{name} = {{ path = "{location.as_posix()}" }}' for name, location in package_roots.items())
    path.write_text(source + '\n')
    return consumer


def compiled_mutations(workspace, env):
    owner = workspace / 'crates' / CPU / 'src/runtime_execution/mod.rs'
    host = workspace / 'crates' / HOST / 'src/execution/mod.rs'
    platform = workspace / 'crates' / HOST / 'src/execution/platform.rs'
    features = workspace / 'crates' / HOST / 'src/execution/features.rs'
    cases = [
        (owner, 'Health::Testing => return Err(Error::NotReady),', 'Health::Testing => {}'),
        (owner, 'Health::Quarantined => return Err(Error::Quarantined),', 'Health::Quarantined => {}'),
        (owner, 'self.generation.get() != generation', 'false'),
        (owner, 'Health::Quarantined\n        });', 'Health::Healthy\n        });'),
        (host, 'mode == Mode::Prefer', 'mode == Mode::Require'),
        (platform, 'if !architecture {', 'if false {'),
        (platform, 'if !features {', 'if false {'),
        (platform, 'if !migration {', 'if false {'),
        (features, 'self.sha && self.sse2', 'self.sha || self.sse2'),
        (features, 'self.avx && self.avx2', 'self.avx || self.avx2'),
        (features, 'self.neon && self.sha2', 'self.neon || self.sha2'),
        (features, 'self.neon && self.sha3', 'self.neon || self.sha3'),
    ]
    for path, before, after in cases:
        source = path.read_text()
        if source.count(before) != 1:
            raise ValueError(f'stale hosted mutant: {before}')
        try:
            path.write_text(source.replace(before, after, 1))
            package = CPU if path == owner else HOST
            filter_name = 'runtime_execution' if package == CPU else 'execution'
            command = ['cargo', 'test', '--offline', '-p', package, '--features', 'runtime-execution',
                       '--lib', filter_name]
            run([*command, '--no-run'], workspace, env)
            result = run(command, workspace, env, success=False)
            if 'test result: FAILED' not in result.stdout:
                raise ValueError('mutant did not fail a behavioral assertion')
        finally:
            path.write_text(source)
    print(f'Hosted authority rejects {len(cases)} compiled lifecycle/selection regressions')


def operational_mutations(workspace, env, extra):
    owner = workspace / 'crates' / CPU / 'src/runtime_execution/mod.rs'
    operations = workspace / 'crates' / CPU / 'src/runtime_execution/operations.rs'
    host_tests = workspace / 'crates' / HOST / 'src/execution/tests.rs'
    command = ['cargo', 'test', '--offline', '-p', HOST, '--features', 'runtime-execution',
               '--lib', *extra]
    original = owner.read_text()
    for call in ('operations::sha256(self.owner.kernel, state, block)',
                 'operations::sha512(self.owner.kernel, state, block)',
                 'operations::keccak(self.owner.kernel, state)'):
        if original.count(call) != 1:
            raise ValueError('stale operational no-op mutant')
        try:
            owner.write_text(original.replace(call, 'Ok(())'))
            run([*command, '--no-run'], workspace, env)
            result = run([*command, 'real_platform_selection'], workspace, env, success=False)
            if 'test result: FAILED' not in result.stdout:
                raise ValueError('operational no-op did not fail a digest assertion')
        finally:
            owner.write_text(original)
    ops, tests = operations.read_text(), host_tests.read_text()
    probe = '''
#[test]
fn injected_failed_kat_retains_quarantine_without_fallback() -> Result<(), Error> {
    for mode in [Mode::Prefer, Mode::Require] {
        for kernel in [Kernel::ArmSha256, Kernel::ArmSha512, Kernel::ArmKeccak] {
            let owner = Authority::new(kernel, mode)?;
            assert_eq!(owner.report().route, Route::Accelerated);
            assert_eq!(owner.report().health, Some(Health::Quarantined));
            assert!(matches!(owner.session(), Err(Error::Kernel(KernelError::Quarantined))));
        }
    }
    Ok(())
}
'''
    try:
        # Execute actual kernels but force the answer comparison to fail.
        if ops.count('&& state ==') != 3:
            raise ValueError('stale direct KAT corruption probe')
        operations.write_text(ops.replace('&& state ==', '&& core::hint::black_box(false) && state =='))
        host_tests.write_text(tests + probe)
        run([*command, 'injected_failed_kat'], workspace, env)
        owner.write_text(original.replace('owner.complete_startup(operations::known_answer(kernel));',
                                          'owner.complete_startup(true);'))
        run([*command, '--no-run'], workspace, env)
        result = run([*command, 'injected_failed_kat'], workspace, env, success=False)
        if 'test result: FAILED' not in result.stdout:
            raise ValueError('KAT-entry bypass did not fail the quarantine assertion')
    finally:
        owner.write_text(original)
        operations.write_text(ops)
        host_tests.write_text(tests)
    print('Generic Arm execution rejects three operational no-ops and a KAT-entry bypass')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write-review', action='store_true')
    parser.add_argument('--policy-only', action='store_true')
    parser.add_argument('--qemu', action='store_true')
    args = parser.parse_args()
    validate(args.write_review)
    if args.write_review or args.policy_only:
        return
    with tempfile.TemporaryDirectory(prefix='brynja-hosted-execution-') as directory:
        root = Path(directory)
        shutil.copyfile(ROOT / 'rust-toolchain.toml', root / 'rust-toolchain.toml')
        env = dict(os.environ)
        for key in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS', 'CARGO_TARGET_DIR'):
            env.pop(key, None)
        workspace = isolated(root)
        consumer = package_consumer(root, workspace, env)
        extra = []
        if args.qemu:
            env['RUSTFLAGS'] = '-C linker=rust-lld'
            env['CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUNNER'] = 'qemu-aarch64 -cpu max'
            extra = ['--target', 'aarch64-unknown-linux-musl']
        for profile in ([], ['--release']):
            run(['cargo', 'test', '--offline', *profile, *extra], consumer, env)
            run(['cargo', 'test', '--offline', '-p', CPU, '-p', HOST, '--features',
                 'runtime-execution', *profile, *extra,
                 *(['--lib', '--tests'] if args.qemu else [])], workspace, env)
        result = run(['cargo', 'run', '--offline', '--release', *extra], consumer, env)
        if args.qemu and 'operational kernels: 3' not in result.stdout:
            raise ValueError('QEMU max must execute all three generic AArch64 routes')
        print(result.stdout, end='')
        run(['cargo', 'clippy', '--offline', '--all-targets', *extra, '--',
             '-A', 'clippy::chunks_exact_to_as_chunks', '-D', 'warnings'], consumer, env)
        if not args.qemu:
            compiled_mutations(workspace, env)
        else:
            operational_mutations(workspace, env, extra)
        # Feature absence must prevent downstream import, not merely execution.
        manifest = consumer / 'Cargo.toml'
        original = manifest.read_text()
        manifest.write_text(original.replace(', features = ["runtime-execution"]', ''))
        result = run(['cargo', 'check', '--offline', *extra], consumer, env, success=False)
        if 'unresolved import' not in result.stderr or 'execution' not in result.stderr:
            raise ValueError('default-off negative failed for an unrelated reason')


if __name__ == '__main__':
    main()
