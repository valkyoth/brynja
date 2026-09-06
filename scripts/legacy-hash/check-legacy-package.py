#!/usr/bin/env python3
"""Replay frozen real consumer source against four inspected .crate archives."""
import os
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path, PurePosixPath

import legacy_acceptance as policy

CLOSURE = {'brynja-core': '0.9.0', 'brynja-hash-core': '0.1.0',
           'brynja-legacy-sha1': '0.1.0', 'brynja-legacy-md5': '0.1.0'}


def unpack(archive, destination, prefix):
    seen, total = set(), 0
    with tarfile.open(archive) as handle:
        for member in handle:
            path = PurePosixPath(member.name)
            total += member.size
            if (not member.isfile() or path.is_absolute() or '..' in path.parts
                    or not path.parts or path.parts[0] != prefix or '\\' in member.name
                    or ':' in member.name or member.size < 0
                    or any(part in ('', '.', '..') for part in member.name.split('/'))
                    or path in seen or len(seen) >= 1024 or total > 16 * 1024 * 1024):
                raise ValueError('invalid or unbounded crate archive')
            seen.add(path)
            file = destination / path
            file.parent.mkdir(parents=True, exist_ok=True)
            stream = handle.extractfile(member)
            if stream is None:
                raise ValueError('missing regular archive body')
            data = stream.read(member.size + 1)
            if len(data) != member.size:
                raise ValueError('archive size differs')
            file.write_bytes(data)


def main():
    with tempfile.TemporaryDirectory(prefix='brynja-legacy-package-') as temporary:
        root = Path(temporary)
        env = dict(os.environ, CARGO_TARGET_DIR=str(root / 'target'))
        command = ['cargo', 'package', '--locked', '--offline', '--allow-dirty', '--no-verify']
        for package in CLOSURE:
            command += ['-p', package]
        subprocess.run(command, cwd=policy.ROOT, env=env, check=True, timeout=180)
        for package, version in CLOSURE.items():
            prefix = f'{package}-{version}'
            unpack(root / 'target/package' / (prefix + '.crate'), root / 'unpacked', prefix)
            for path in (policy.ROOT / 'crates' / package / 'src').rglob('*.rs'):
                relative = path.relative_to(policy.ROOT / 'crates' / package)
                if (root / 'unpacked' / prefix / relative).read_bytes() != path.read_bytes():
                    raise ValueError('packaged Rust differs from frozen source')
        consumer = root / 'consumer'
        shutil.copytree(policy.ROOT / policy.FIXTURE, consumer,
                        ignore=shutil.ignore_patterns('target', 'Cargo.lock'))
        manifest = '[package]\nname="legacy-packaged-fixture"\nversion="0.0.0"\nedition="2024"\n[workspace]\n[dependencies]\n'
        for family in ('sha1', 'md5'):
            manifest += f'brynja-legacy-{family} = {{ version="=0.1.0", default-features=false }}\n'
        manifest += '[patch.crates-io]\n'
        for package, version in CLOSURE.items():
            manifest += f'{package} = {{ path="../unpacked/{package}-{version}" }}\n'
        # Preserve the fixture's library crate name for its unchanged binary.
        manifest += '[lib]\nname="brynja_legacy_hash_public_api_fixture"\n'
        (consumer / 'Cargo.toml').write_text(manifest)
        for command in (['cargo', 'generate-lockfile', '--offline'],
                        ['cargo', 'test', '--locked', '--offline'],
                        ['cargo', 'run', '--locked', '--offline']):
            subprocess.run(command, cwd=consumer, env=env, check=True, timeout=180)
    print('Four packaged legacy-closure archives replay the frozen consumer: PASS; no upload')


if __name__ == '__main__':
    main()
