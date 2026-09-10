#!/usr/bin/env python3
"""Normal-package static CPU authority acceptance; never sets evidence cfgs."""
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
import static_execution_docs

ROOT = Path(__file__).resolve().parents[2]
CPU = ROOT / 'crates/brynja-crypto-cpu'
FIXTURE = ROOT / 'assurance/static-cpu-execution'
REVIEW = ROOT / 'security/static-cpu-execution-reviewed.json'


def validate(write=False):
    static_execution_docs.validate(ROOT)
    manifest = tomllib.loads((CPU / 'Cargo.toml').read_text())
    if manifest.get('features') != {'default': [], 'static-execution': [], 'runtime-execution': ['static-execution'],
            'hardened-execution': ['static-execution', 'dep:brynja-core']} or manifest.get('dependencies') != {
                'brynja-core': {'workspace': True, 'optional': True}}:
        raise RuntimeError('static CPU boundary permits only the opt-in first-party clearing owner')
    library = (CPU / 'src/lib.rs').read_text()
    if '#[cfg(feature = "static-execution")]\npub mod static_execution;' not in library:
        raise RuntimeError('static module lost its explicit feature gate')
    driver = (ROOT / 'scripts/checks.sh').read_text()
    required = 'python3 scripts/cpu/check-static-execution.py'
    if required not in driver.splitlines():
        raise RuntimeError('static package acceptance is not in the repository gate')
    memory_scripts = [ROOT / 'scripts/zeroization/check-zeroization-miri.sh',
                      ROOT / 'scripts/zeroization/check-zeroization-sanitizer.sh']
    for script in memory_scripts:
        if '-p brynja-crypto-cpu --features static-execution --lib static_authority' not in script.read_text():
            raise RuntimeError('static authority lost its dynamic-analysis campaign')
    inputs = [*sorted((CPU / 'src').rglob('*.rs')), CPU / 'Cargo.toml',
              *sorted((FIXTURE / 'src').rglob('*.rs')), FIXTURE / 'Cargo.toml', FIXTURE / 'Cargo.lock',
              Path(__file__), ROOT / 'scripts/checks.sh', ROOT / 'docs/static-cpu-execution.md',
              *memory_scripts, *(ROOT / name for name in static_execution_docs.FILES),
              ROOT / 'scripts/cpu/static_execution_docs.py']
    expected = {'milestone': '0.24.31', 'sha256': {str(p.relative_to(ROOT)):
        hashlib.sha256(p.read_bytes().replace(b'\r\n', b'\n')).hexdigest() for p in inputs}}
    if write:
        REVIEW.write_text(json.dumps(expected, sort_keys=True, indent=2) + '\n')
    if json.loads(REVIEW.read_text()) != expected:
        raise RuntimeError('static execution source changed; reopen review')


def run(args, *, cwd=ROOT, env=None, success=True):
    if args[0] == 'cargo':
        toolchain = tomllib.loads((ROOT / 'rust-toolchain.toml').read_text())['toolchain']['channel']
        args = ['cargo', '+' + toolchain, *args[1:]]
    result = subprocess.run(args, cwd=cwd, env=env, text=True, capture_output=True, timeout=180)
    if (result.returncode == 0) != success:
        raise RuntimeError(f'unexpected command result: {args}\n{result.stdout}\n{result.stderr}')
    return result


def environment(flags=''):
    env = dict(os.environ)
    for key in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS'):
        env.pop(key, None)
    env['RUSTFLAGS'] = flags
    return env


def package(root):
    env = environment()
    env['CARGO_TARGET_DIR'] = str(root / 'build')
    run(['cargo', 'package', '--locked', '--offline', '--allow-dirty', '--no-verify',
         '-p', 'brynja-core', '-p', 'brynja-crypto-cpu'], env=env)
    archive = root / 'build/package/brynja-crypto-cpu-0.1.1.crate'
    # Input is the just-built local Cargo artifact, never a remote corpus.
    with tarfile.open(archive) as bundle:
        bundle.extractall(root / 'package', filter='data')
    core_version = tomllib.loads((ROOT / 'crates/brynja-core/Cargo.toml').read_text())['package']['version']
    with tarfile.open(root / 'build/package' / f'brynja-core-{core_version}.crate') as bundle:
        bundle.extractall(root / 'package', filter='data')
    cpu = root / 'package/brynja-crypto-cpu-0.1.1'
    core = root / 'package' / f'brynja-core-{core_version}'
    manifest = cpu / 'Cargo.toml'
    manifest.write_text(manifest.read_text() + '\n[patch.crates-io]\nbrynja-core = { path = "' + core.as_posix() + '" }\n')
    run(['cargo', 'generate-lockfile', '--offline'], cwd=cpu, env=env)
    return cpu


def check_package(root, cpu, *, flags='', target=None, runner=None):
    consumer = root / 'consumer'
    consumer.mkdir(exist_ok=True)
    shutil.copytree(FIXTURE / 'src', consumer / 'src', dirs_exist_ok=True)
    manifest = (FIXTURE / 'Cargo.toml').read_text().replace('../../crates/brynja-crypto-cpu', cpu.as_posix())
    core = next((root / 'package').glob('brynja-core-*'))
    manifest += '\n[patch.crates-io]\nbrynja-core = { path = "' + core.as_posix() + '" }\n'
    (consumer / 'Cargo.toml').write_text(manifest)
    shutil.copyfile(FIXTURE / 'Cargo.lock', consumer / 'Cargo.lock')
    env = environment(flags)
    if runner:
        env['CARGO_TARGET_' + target.upper().replace('-', '_') + '_RUNNER'] = runner
    extra = ['--target', target] if target else []
    # The trusted packaged closure adds an unused optional local patch record.
    # Assemble its lock once offline, then keep --locked on actual checks.
    run(['cargo', 'generate-lockfile', '--offline'], cwd=consumer, env=env)
    if not flags:
        # A normal downstream crate cannot access the module without opting in.
        manifest_path = consumer / 'Cargo.toml'
        gated = manifest.replace(', features = ["static-execution"]', '')
        if gated == manifest:
            raise RuntimeError('stale default-off feature mutation')
        manifest_path.write_text(gated)
        try:
            result = run(['cargo', 'check', '--locked', '--offline'], cwd=consumer,
                         env=env, success=False)
            if 'unresolved import' not in result.stderr or 'static_execution' not in result.stderr:
                raise RuntimeError('default-off import failed for an unrelated reason:\n' + result.stderr)
        finally:
            manifest_path.write_text(manifest)
    for profile in ([], ['--release']):
        run(['cargo', 'test', '--locked', '--offline', *profile, *extra], cwd=consumer, env=env)
        run(['cargo', 'test', '--locked', '--offline', '--features', 'static-execution',
             '--lib', *profile, *extra, 'static_authority'], cwd=cpu, env=env)
    run(['cargo', 'clippy', '--locked', '--offline', '--all-targets', *extra,
         '--', '-A', 'clippy::chunks_exact_to_as_chunks', '-D', 'warnings'], cwd=consumer, env=env)
    if flags:
        startup_mutation(cpu, env, extra)


def startup_mutation(cpu, env, extra):
    """A corrupted actual KAT must fail; skipping it must fail the negative test."""
    operations = cpu / 'src/static_execution/operations.rs'
    owner = cpu / 'src/static_execution/mod.rs'
    tests = cpu / 'src/static_execution/tests.rs'
    old_ops, old_owner, old_tests = operations.read_text(), owner.read_text(), tests.read_text()
    probe = '''
#[test]
fn injected_kat_failure_is_quarantined() -> Result<(), Error> {
    let mut exercised = false;
    for kernel in Kernel::ALL {
        if kernel.check_compiled_target().is_err() { continue; }
        exercised = true;
        let authority = Authority::new(kernel)?;
        assert_eq!(authority.report().health, Health::Quarantined);
        assert_eq!(authority.session().err(), Some(Error::Quarantined));
    }
    assert!(exercised);
    Ok(())
}
'''
    try:
        # Preserve real kernel execution but force a failed answer comparison.
        operations.write_text(old_ops.replace('&& state ==', '&& core::hint::black_box(false) && state =='))
        tests.write_text(old_tests + probe)
        command = ['cargo', 'test', '--locked', '--offline', '--features', 'static-execution',
                   '--lib', *extra, 'injected_kat_failure']
        run(command, cwd=cpu, env=env)
        marker = 'owner.complete_startup(operations::known_answer(kernel));'
        if old_owner.count(marker) != 1:
            raise RuntimeError('stale KAT-entry mutation')
        owner.write_text(old_owner.replace(marker, 'owner.complete_startup(true);'))
        run(['cargo', 'check', '--locked', '--offline', '--features', 'static-execution', *extra], cwd=cpu, env=env)
        result = run(command, cwd=cpu, env=env, success=False)
        if 'test result: FAILED' not in result.stdout:
            raise RuntimeError('KAT-entry mutant failed without behavioral rejection')
    finally:
        operations.write_text(old_ops)
        owner.write_text(old_owner)
        tests.write_text(old_tests)


def mutations(cpu):
    path = cpu / 'src/static_execution/mod.rs'
    original = path.read_text()
    # All run without extra ISA: lifecycle model failures precede instructions.
    pairs = [
        ('Health::Testing => return Err(Error::NotReady),', 'Health::Testing => {}'),
        ('Health::Testing => return Err(Error::NotReady),', 'Health::Testing => return Err(Error::Quarantined),'),
        ('Health::Quarantined => return Err(Error::Quarantined),', 'Health::Quarantined => {}'),
        ('Health::Quarantined\n        });', 'Health::Healthy\n        });'),
        ('self.generation.get() != generation', 'false'),
    ]
    count = 0
    for before, after in pairs:
        if original.count(before) != 1:
            raise RuntimeError('stale lifecycle mutation: ' + before)
        path.write_text(original.replace(before, after))
        try:
            run(['cargo', 'check', '--offline', '--features', 'static-execution'], cwd=cpu, env=environment())
            result = run(['cargo', 'test', '--offline', '--features', 'static-execution', '--lib',
                         'static_authority_'], cwd=cpu, env=environment(), success=False)
            if 'test result: FAILED' not in result.stdout:
                raise RuntimeError('mutation failed without a test assertion')
            count += 1
        finally:
            path.write_text(original)
    kernel = cpu / 'src/static_execution/kernel.rs'
    original = kernel.read_text()
    for before in ('if !architecture', 'if !features'):
        kernel.write_text(original.replace(before, 'if false'))
        try:
            run(['cargo', 'check', '--offline', '--features', 'static-execution'], cwd=cpu, env=environment())
            result = run(['cargo', 'test', '--offline', '--features', 'static-execution', '--lib',
                         'static_authority_rejects_incomplete'], cwd=cpu, env=environment(), success=False)
            if 'test result: FAILED' not in result.stdout:
                raise RuntimeError('feature mutant did not fail before instruction entry')
            count += 1
        finally:
            kernel.write_text(original)
    return count


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--native-x86', action='store_true', help='operator confirms complete SHA/AVX2 platform contract')
    parser.add_argument('--qemu', action='store_true')
    parser.add_argument('--write-review', action='store_true')
    parser.add_argument('--policy-only', action='store_true')
    args = parser.parse_args()
    validate(args.write_review)
    static_execution_docs.regressions(ROOT)
    if args.write_review or args.policy_only:
        print('Static execution source binding: PASS')
        return
    with tempfile.TemporaryDirectory(prefix='brynja-static-package-') as temporary:
        root = Path(temporary)
        cpu = package(root)
        check_package(root, cpu)
        count = mutations(cpu)
        if args.native_x86:
            check_package(root, cpu, flags='-C target-feature=+sha,+sse2,+avx,+avx2')
        if args.qemu:
            check_package(root, cpu, flags='-C target-feature=+neon,+sha2,+sha3 -C linker=rust-lld',
                          target='aarch64-unknown-linux-musl', runner='qemu-aarch64 -cpu max')
    print(f'Static authority package, public vectors, quarantine and {count} compiled regressions: PASS')


if __name__ == '__main__':
    main()
