#!/usr/bin/env python3
"""Cross-build or memory-model-test isolated placement; no native admission."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

import windows_enclave_retained_build as base


def command(directory, target, level, testing):
    args = ['rustc', '+1.98.1', '--edition=2024', '--target', target,
            '--crate-name', 'retained_placement', '-D', 'warnings',
            '-C', 'opt-level=' + level, '-C', 'overflow-checks=yes',
            '-C', 'panic=' + ('unwind' if testing else 'abort'),
            '-L', 'dependency=' + str(directory)]
    for name, filename in [('brynja_hash_sha2', 'libbrynja_hash_sha2.rlib'),
                           ('persistent_result', 'libpersistent_result_normal.rlib'),
                           ('retained_digest', 'libretained_digest_normal.rlib')]:
        args += ['--extern', name + '=' + str(directory / filename)]
    return args + [str(directory / 'retained_placement.rs')] + (
        ['--test', '-o', str(directory / ('placement.exe' if os.name == 'nt' else 'placement'))]
        if testing else ['--crate-type', 'rlib', '-o', str(directory / 'libretained_placement.rlib')])


def run(args, timeout=90):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)


def miri_manifest(directory, placement_source=None):
    """Use real first-party crates, isolated from workspace feature unification."""
    for name in ('persistent_result', 'retained_digest', 'retained_placement'):
        path = directory / name
        path.mkdir(parents=True, exist_ok=True)
        source = placement_source if name == 'retained_placement' and placement_source else base.SOURCE / (name + '.rs')
        manifest = ['[package]', f'name = "{name}"', 'version = "0.0.0"', 'edition = "2024"',
                    '[workspace]', '[lib]', 'path = ' + json.dumps(str(source)),
                    '[dependencies]']
        for dep in ('brynja-core', 'brynja-hash-sha2'):
            manifest.append(dep + ' = { path = ' + json.dumps(str(base.ROOT / 'crates' / dep)) +
                            ', default-features = false }')
        for dep in ('persistent_result', 'retained_digest'):
            if name == dep:
                break
            manifest.append(dep + ' = { path = ' + json.dumps(str(directory / dep)) + ' }')
        if name == 'persistent_result':
            cfgs = ', '.join(json.dumps('cfg(' + cfg + ')') for cfg in base.VARIANTS.values() if cfg)
            manifest += ['[lints.rust]', 'unexpected_cfgs = { level = "deny", check-cfg = [' + cfgs + '] }']
        (path / 'Cargo.toml').write_text('\n'.join(manifest) + '\n')
    return directory / 'retained_placement' / 'Cargo.toml'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--miri', action='store_true')
    args = parser.parse_args()
    directory = args.directory.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    target = 'x86_64-pc-windows-msvc'
    if args.miri:
        manifest = miri_manifest(directory)
        tool = 'nightly-2026-09-11'
        commands = [['cargo', '+' + tool, 'generate-lockfile', '--offline', '--manifest-path', str(manifest)],
                    ['cargo', '+' + tool, 'miri', 'test', '--locked', '--offline',
                     '--manifest-path', str(manifest), '--lib']]
        env = os.environ.copy()
        for key in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'CARGO_BUILD_TARGET', 'MIRIFLAGS'):
            env.pop(key, None)
        env['MIRIFLAGS'] = '-Zmiri-strict-provenance'
        env['CARGO_TARGET_DIR'] = str(directory / 'build')
        for index, invocation in enumerate(commands):
            result = subprocess.run(invocation, env=env, capture_output=True, text=True, timeout=180)
            (directory / f'miri-{index}.stdout').write_text(result.stdout)
            (directory / f'miri-{index}.stderr').write_text(result.stderr)
            print(result.stdout, end='')
            print(result.stderr, end='')
            result.check_returncode()
        target = 'host-miri-strict-provenance'
    else:
        tool = '1.98.1'
        commands = base.build(directory, target)
        for name in ('retained_placement.rs', 'retained_placement_tests.rs'):
            shutil.copyfile(base.SOURCE / name, directory / name)
        invocation = command(directory, target, '2', False)
        result = run(invocation)
        if result.returncode:
            raise RuntimeError(result.stderr)
        commands.append(invocation)
    paths = set(base.SOURCES) | {
        'assurance/windows-enclave-probe/retained_placement.rs',
        'assurance/windows-enclave-probe/retained_placement_tests.rs',
        'scripts/cryptography/windows_enclave_placement_build.py',
        'scripts/cryptography/test-windows-enclave-retained-placement.py'}
    record = {'native_executed': False, 'strict_qualified': False, 'target': target,
              'miri': args.miri,
              'miriflags': '-Zmiri-strict-provenance' if args.miri else None,
              'commands': commands,
              'rustc': subprocess.check_output(['rustc', '+' + tool, '-vV'], text=True),
              'source_sha256': {p: hashlib.sha256((base.ROOT / p).read_bytes()).hexdigest() for p in sorted(paths)},
              'archives_sha256': {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                  for p in sorted(directory.glob('*.rlib'))}}
    (directory / 'placement-build.json').write_text(json.dumps(record, indent=2) + '\n')
    print('Retained placement check: PASS; native execution/strict qualification: NO')


if __name__ == '__main__':
    main()
