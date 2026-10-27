#!/usr/bin/env python3
"""Build pristine extracted lean packages; no crypto/native qualification claim."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tomllib
from unittest.mock import patch

import facade_cargo_environment as environment
import package_contents as contents

ROOT = Path(__file__).resolve().parents[2]
sys.path.append(str(ROOT / 'scripts/cpu'))
spec = importlib.util.spec_from_file_location('lean_host_package', ROOT / 'scripts/cpu/check-hosted-execution.py')
host = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host)


def run(command, cwd, env):
    environment.check(cwd, env)
    result = subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True, timeout=240)
    contents.require(result.returncode == 0, str(command) + '\n' + result.stdout[-4000:] + result.stderr[-4000:])
    return result.stdout


def snapshot(roots):
    return {str(path): hashlib.sha256(path.read_bytes()).hexdigest()
            for root in roots.values() for path in root.rglob('*') if path.is_file()}


def manifest(consumer, roots, hosted, all_features=True):
    selected = contents.MIGRATED if hosted else contents.MIGRATED - contents.HOSTED
    text = '[workspace]\n[package]\nname="lean-package-consumer"\nversion="0.0.0"\nedition="2024"\n[dependencies]\n'
    for name in sorted(selected):
        data = tomllib.loads((roots[name] / 'Cargo.toml').read_text())
        features = sorted(data.get('features', {})) if all_features else []
        text += (f'{name}={{version="={data["package"]["version"]}",default-features=false,'
                 f'features={json.dumps(features)}}}\n')
    text += '[patch.crates-io]\n' + ''.join(
        f'{name}={{path={json.dumps(str(path))}}}\n' for name, path in sorted(roots.items()))
    (consumer / 'Cargo.toml').write_text(text)
    (consumer / 'src/lib.rs').write_text('#![no_std]\n' + ''.join(
        f'pub use {name.replace("-", "_")};\n' for name in sorted(selected)))


def execute(root, toolchain, bare_target):
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(('CARGO_', 'RUST', 'BRYNJA_'))}
    # Only the existing registry cache supplies the separately audited adapter
    # dependency. Reject executable ambient Cargo configs; never fetch here.
    env['CARGO_HOME'] = os.environ.get('CARGO_HOME', str(Path.home() / '.cargo'))
    env['CARGO_TARGET_DIR'] = str(root / 'target')
    names = tuple(sorted(set(host.PACKAGES) | contents.MIGRATED))
    with patch.object(host, 'PACKAGES', names):
        workspace = host.isolated(root)
    cargo = ['cargo', '+' + toolchain]
    run(cargo + ['package', '--workspace', '--offline', '--allow-dirty', '--no-verify'], workspace, env)
    roots = {}
    for name in names:
        version = tomllib.loads((workspace / 'crates' / name / 'Cargo.toml').read_text())['package']['version']
        prefix = f'{name}-{version}'
        archive = root / 'target/package' / (prefix + '.crate')
        with tarfile.open(archive) as bundle:
            members = bundle.getmembers()
            paths = [Path(member.name) for member in members]
            contents.require(len(paths) == len(set(paths)) and all(
                path.parts and path.parts[0] == prefix and '..' not in path.parts
                and not path.is_absolute() and member.isfile()
                for path, member in zip(paths, members)), 'unsafe archive')
            if name in contents.MIGRATED:
                contents.check(ROOT / 'crates' / name / 'Cargo.toml',
                               [path.relative_to(prefix).as_posix() for path in paths])
            bundle.extractall(root / 'packages', filter='data')
        roots[name] = root / 'packages' / prefix
        print(f'Pristine archive: {name}; {len(members)} files; {archive.stat().st_size} compressed bytes', flush=True)
    original = snapshot(roots)
    consumer = root / 'consumer'
    (consumer / 'src').mkdir(parents=True)
    manifest(consumer, roots, hosted=True)
    doc = json.loads(run(cargo + ['metadata', '--offline', '--format-version=1'], consumer, env))
    for package in doc['packages']:
        if package['name'].startswith('brynja-'):
            contents.require(package['name'] in roots and package['source'] is None
                             and Path(package['manifest_path']) == roots[package['name']] / 'Cargo.toml',
                             'consumer resolved a non-archive Brynja dependency')
    for profile in ([], ['--release']):
        run(cargo + ['build', '--offline', *profile], consumer, env)
    manifest(consumer, roots, hosted=False, all_features=False)
    run(cargo + ['build', '--offline', '--target', bare_target], consumer, env)
    # Generic bare x86 has a soft-float ABI; enabled hardware assembly is a
    # type-check lane, not a claim that every accelerated kernel can codegen.
    manifest(consumer, roots, hosted=False)
    run(cargo + ['check', '--offline', '--target', bare_target], consumer, env)
    contents.require(snapshot(roots) == original, 'build changed extracted dependency inputs')
    print(f'Lean package builds: PASS; {len(contents.MIGRATED)} extracted crates debug/release; '
          f'{len(contents.MIGRATED - contents.HOSTED)} portable no_std builds/all-feature no_std checks; '
          'no repository fixture overlay')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--toolchain', default='1.99.1')
    parser.add_argument('--bare-target', default='x86_64-unknown-none')
    args = parser.parse_args()
    with environment.private_directory(ROOT) as raw:
        execute(Path(raw), args.toolchain, args.bare_target)


if __name__ == '__main__':
    main()
