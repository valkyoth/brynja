#!/usr/bin/env python3
"""Native resident regression job; not strict admission or release qualification."""
import argparse
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[2]
PACKAGES = ('brynja-crypto-cpu', 'brynja-crypto-cpu-std', 'brynja-hash-parallel-std',
            'brynja-legacy-sha1-std', 'brynja-legacy-md5-std')
FEATURES = '+neon,+sha2,+sha3,+aes'
PROFILES = (
    ('keyed', ('brynja-crypto-cpu-std',),
     'macos-resident-acceleration,macos-resident-kmac-acceleration,macos-resident-tuplehash-acceleration',
     'check-macos-resident-codegen.py', ('--keyed',)),
    ('batch', ('brynja-crypto-cpu-std',), 'macos-resident-batch',
     'check-macos-resident-batch-codegen.py', ()),
    ('parallel', ('brynja-hash-parallel-std',), 'macos-resident-acceleration',
     'check-macos-resident-parallel-codegen.py', ()),
    ('legacy', ('brynja-legacy-sha1-std', 'brynja-legacy-md5-std'), 'macos-resident-acceleration',
     'check-macos-legacy-resident-codegen.py', ()),
)
PACKAGE_CHECKS = (
    ('check-macos-resident-package.py', '--accelerated', '--keyed'),
    ('check-macos-resident-batch-package.py',),
    ('check-macos-resident-parallel-package.py',),
    ('check-macos-legacy-resident-package.py',),
)


def run(command, env):
    print('RUN:', ' '.join(map(str, command)), flush=True)
    subprocess.run(command, cwd=ROOT, env=env, check=True, timeout=1800)


def environment():
    env = dict(os.environ)
    for key in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS',
                'CARGO_BUILD_TARGET', 'CARGO_TARGET_DIR', 'CARGO_BUILD_BUILD_DIR'):
        env.pop(key, None)
    env['RUSTFLAGS'] = '-C target-feature=' + FEATURES
    env['CARGO_INCREMENTAL'] = '0'
    return env


def require_host():
    if (platform.system(), platform.machine()) != ('Darwin', 'arm64'):
        raise ValueError('resident CI requires native Apple Silicon macOS')
    # Refuse ISA assumptions merely from the runner label. No fallback/skipping.
    for name in ('FEAT_SHA256', 'FEAT_SHA512', 'FEAT_SHA3', 'FEAT_AES'):
        result = subprocess.check_output(['sysctl', '-n', 'hw.optional.arm.' + name], text=True)
        if result.strip() != '1':
            raise ValueError('resident CI missing required instruction capability: ' + name)


def execute(stage, directory):
    require_host()
    compiler = tomllib.loads((ROOT / 'rust-toolchain.toml').read_text())['toolchain']['channel']
    cargo = ['cargo', '+' + compiler]
    env = environment()
    run([*cargo, 'fetch', '--locked'], env)
    packages = [arg for name in PACKAGES for arg in ('-p', name)]
    if stage in ('all', 'tests'):
        for profile in ([], ['--release']):
            run([*cargo, 'test', '--locked', '--offline', *packages,
                 '--all-features', *profile], env)
        run([*cargo, 'clippy', '--locked', '--offline', *packages,
             '--all-features', '--all-targets', '--', '-D', 'warnings',
             '-A', 'clippy::chunks_exact_to_as_chunks'], env)
    if stage in ('all', 'codegen'):
        for panic in ('abort', 'unwind'):
            for name, crates, features, checker, args in PROFILES:
                target = directory / (name + '-' + panic)
                scoped = dict(env, CARGO_TARGET_DIR=str(target),
                              RUSTFLAGS=env['RUSTFLAGS'] + ' -C panic=' + panic + ' --emit=llvm-ir,asm')
                selected = [arg for crate in crates for arg in ('-p', crate)]
                run([*cargo, 'build', '--locked', '--offline', '--release', *selected,
                     '--no-default-features', '--features', features], scoped)
                extra = ['--panic', panic] if name == 'parallel' else []
                run([sys.executable, 'scripts/cryptography/' + checker,
                     str(target / 'release/deps'), *args, *extra], scoped)
    if stage in ('all', 'packages'):
        for checker, *args in PACKAGE_CHECKS:
            run([sys.executable, 'scripts/cryptography/' + checker,
                 '--toolchain', compiler, *args], env)
    print('Native resident CI: PASS; bounded development checks only', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage', choices=('all', 'tests', 'codegen', 'packages'), default='all')
    parser.add_argument('--artifacts', type=Path, help='retain emitted artifacts in a new directory')
    args = parser.parse_args()
    # No stale emit population from another profile/compiler may be reused.
    if args.artifacts is not None:
        args.artifacts.mkdir(parents=True, exist_ok=False)
        execute(args.stage, args.artifacts.resolve())
    else:
        with tempfile.TemporaryDirectory(prefix='brynja-darwin-ci-') as directory:
            execute(args.stage, Path(directory))
