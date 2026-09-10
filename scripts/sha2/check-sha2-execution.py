#!/usr/bin/env python3
"""Normal packaged SHA-2 routes: vectors, ownership and compiled regressions."""
import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import tomllib
import sha2_execution_faults

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = 'assurance/sha2-execution'
PACKAGES = ('brynja-core', 'brynja-hash-core', 'brynja-crypto-cpu',
            'brynja-hash-sha2', 'brynja-crypto-cpu-std')
REVIEW = ROOT / 'scripts/sha2/sha2-execution-reviewed.toml'


def run(command, cwd, env, *, success=True):
    result = subprocess.run(command, cwd=cwd, env=env, capture_output=True,
                            text=True, timeout=600)
    if (result.returncode == 0) != success:
        raise RuntimeError(f'{command}\n{result.stdout}\n{result.stderr}')
    return result


def validate():
    source = ROOT / 'crates/brynja-hash-sha2/src/execution'
    for path in source.glob('*.rs'):
        text = path.read_text()
        code = '\n'.join(line.split('//')[0] for line in text.splitlines())
        if len(text.splitlines()) > 500 or any(token in code for token in
                ('unsafe', 'std::', 'alloc::', 'Vec<', 'Box<', 'static mut', 'unwrap(', 'expect(')):
            raise ValueError(f'execution boundary regression: {path.name}')
    for name, expected in tomllib.loads(REVIEW.read_text())['files'].items():
        actual = hashlib.sha256((ROOT / name).read_bytes().replace(b'\r\n', b'\n')).hexdigest()
        if actual != expected:
            raise ValueError(f'ordinary SHA-2 execution changed; review {name}')
    driver = (ROOT / 'scripts/checks.sh').read_text().splitlines()
    if 'python3 scripts/sha2/check-sha2-execution.py' not in driver:
        raise ValueError('packaged execution gate missing')


def package(destination, env, fixture_name='sha2-execution'):
    # Only trusted project-owned paths and Cargo archives are handled here.
    workspace = destination / 'workspace'
    workspace.mkdir()
    shutil.copyfile(ROOT / 'rust-toolchain.toml', destination / 'rust-toolchain.toml')
    shutil.copyfile(ROOT / 'Cargo.toml', workspace / 'Cargo.toml')
    manifest = (workspace / 'Cargo.toml').read_text().replace(
        'default-members = ["crates/brynja"]', 'default-members = ["crates/brynja-hash-sha2"]')
    (workspace / 'Cargo.toml').write_text(manifest)
    for name in PACKAGES:
        shutil.copytree(ROOT / 'crates' / name, workspace / 'crates' / name,
                        ignore=shutil.ignore_patterns('target'))
    roots = {}
    run(['cargo', 'package', '--workspace', '--offline', '--allow-dirty', '--no-verify'], workspace, env)
    for name in PACKAGES:
        version = tomllib.loads((workspace / 'crates' / name / 'Cargo.toml').read_text())['package']['version']
        archive = Path(env['CARGO_TARGET_DIR']) / 'package' / f'{name}-{version}.crate'
        with tarfile.open(archive) as bundle:
            bundle.extractall(destination / 'packages', filter='data')
        roots[name] = destination / 'packages' / f'{name}-{version}'
    for name in (fixture_name, 'general-sha512-t'):
        shutil.copytree(ROOT / 'assurance' / name, destination / 'assurance' / name,
                        ignore=shutil.ignore_patterns('target'))
    # include_str! reads the same committed, bounded official/oracle corpora.
    shutil.copytree(ROOT / 'crates/brynja-hash-sha2/tests/vectors',
                    destination / 'crates/brynja-hash-sha2/tests/vectors')
    for name in (fixture_name, 'general-sha512-t'):
        path = destination / 'assurance' / name / 'Cargo.toml'
        text = path.read_text()
        for package_name, root in roots.items():
            text = text.replace(f'../../crates/{package_name}"', root.as_posix() + '"')
        text += '\n[patch.crates-io]\n' + '\n'.join(
            f'{package_name} = {{ path = "{root.as_posix()}" }}' for package_name, root in roots.items())
        path.write_text(text + '\n')
    return destination / 'assurance' / fixture_name, roots


def negatives(consumer, env):
    path = consumer / 'src/main.rs'
    original = path.read_text()
    snippets = (
        ('let mut h = api::Sha256::new(api::Execution::portable()).unwrap(); let _ = h.finalize(); h.update(b"x").unwrap();', 'E0382'),
        ('fn send<T: Send>() {} send::<api::Sha512>();', 'E0277'),
        ('fn sync<T: Sync>() {} sync::<api::Sha512>();', 'E0277'),
        ('let h = api::Sha256::new(api::Execution::portable()).unwrap(); let _ = h.clone();', 'E0599'),
        ('let _: brynja_hash_sha2::Sha224Digest = api::Sha256::hash(api::Execution::portable(), b"a").unwrap().digest;', 'E0308'),
        ('let _ = brynja_hash_sha2::HardenedSha256::new(api::Execution::portable());', 'E0061'),
        ('let _: api::Execution = api::Route::Portable.into();', 'E0277'),
    )
    try:
        for snippet, diagnostic in snippets:
            path.write_text(original + '\nfn forbidden() {' + snippet + '}\n')
            result = run(['cargo', 'check', '--offline'], consumer, env, success=False)
            if f'error[{diagnostic}]' not in result.stderr:
                raise ValueError('ownership negative failed for the wrong reason: ' + result.stderr)
    finally:
        path.write_text(original)
    print('Seven packaged identity, ownership and secret-route negatives rejected')


def mutations(consumer, roots, env):
    leaf = roots['brynja-hash-sha2'] / 'src/execution'
    cases = (
        ('engine.rs', '*self = candidate;', 'let _ = candidate;'),
        ('engine.rs', 'self.finalize_inner(partial, bits,', 'self.finalize_inner(None, bits,'),
        ('general.rs', 'parameter.initial_words()', '[0; 8]'),
        ('mod.rs', 'count.checked_add(1)', 'count.checked_add(0)'),
        ('route.rs', 'crate::compress::compress(state, block)', '{ let _ = (state, block); }'),
        ('route.rs', 'crate::compress64::compress(state, block)', '{ let _ = (state, block); }'),
    )
    for name, before, after in cases:
        path = leaf / name
        original = path.read_text()
        if before not in original:
            raise ValueError(f'mutation site missing: {name}')
        try:
            path.write_text(original.replace(before, after))
            for profile in ([], ['--release']):
                result = run(['cargo', 'run', '--offline', *profile, '--', 'portable'], consumer, env, success=False)
                if 'acceptance failed:' not in result.stderr:
                    raise ValueError('mutant did not fail at runtime: ' + result.stderr)
        finally:
            path.write_text(original)
    print('Twelve compiled no-op, partial-bit, wrong-IV and false-work mutants rejected')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--policy-only', action='store_true')
    parser.add_argument('--qemu', action='store_true')
    parser.add_argument('--native-x86', action='store_true')
    args = parser.parse_args()
    validate()
    if args.policy_only:
        return
    with tempfile.TemporaryDirectory(prefix='brynja-sha2-execution-') as directory:
        destination = Path(directory)
        env = dict(os.environ, CARGO_TARGET_DIR=str(destination / 'target'))
        for key in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS', 'CARGO_BUILD_TARGET'):
            env.pop(key, None)
        consumer, roots = package(destination, env)
        for profile in ([], ['--release']):
            for mode in ('portable', 'prefer'):
                result = run(['cargo', 'run', '--offline', *profile, '--', mode], consumer, env)
                if 'named=240; general=4590' not in result.stdout:
                    raise ValueError('incomplete packaged acceptance')
        run(['cargo', 'clippy', '--offline', '--all-targets', '--', '-D', 'warnings',
             '-A', 'clippy::chunks_exact_to_as_chunks'], consumer, env)
        negatives(consumer, env)
        mutations(consumer, roots, env)
        if args.native_x86:
            env['RUSTFLAGS'] = '-C target-feature=+sha,+sse2'
            command = ['cargo', 'run', '--offline', '--release', '--', 'static', 'narrow']
            run(command, consumer, env)
            sha2_execution_faults.exercise(consumer, roots, env, command, run, hosted=False, wide=False)
        if args.qemu:
            env['CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUNNER'] = 'qemu-aarch64 -cpu max'
            for mode, flags in (('hosted', '-C linker=rust-lld'),
                                ('static', '-C linker=rust-lld -C target-feature=+neon,+sha2,+sha3')):
                env['RUSTFLAGS'] = flags
                result = run(['cargo', 'run', '--offline', '--release', '--target',
                              'aarch64-unknown-linux-musl', '--', mode], consumer, env)
                print(result.stdout, end='')
                command = ['cargo', 'run', '--offline', '--release', '--target',
                           'aarch64-unknown-linux-musl', '--', mode]
                for wide in (False, True):
                    sha2_execution_faults.exercise(consumer, roots, env, command, run, hosted=mode == 'hosted', wide=wide)
    print('Complete ordinary SHA-2 packaged execution: PASS')


if __name__ == '__main__':
    main()
