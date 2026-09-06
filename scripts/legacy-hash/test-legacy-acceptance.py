#!/usr/bin/env python3
"""Structural corruption, real digest mismatch and hostile archive regressions."""
import importlib.util
import io
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path

import legacy_acceptance as policy


def main():
    policy.validate()
    mutations = [
        (f'{policy.FIXTURE}/src/profiles.rs', 'finalize_bits_secret', 'omitted_bits_secret'),
        (f'{policy.FIXTURE}/src/profiles.rs', 'assert_eq!(output, [0; $size])', 'assert!(true)'),
        (f'{policy.FIXTURE}/src/profiles.rs', 'PublicDeclassification::acknowledge()', 'implicit_authority()'),
        (f'{policy.FIXTURE}/src/profiles.rs', 'for chunk in [1, 7, 31, 64, 113]', 'for chunk in [64]'),
        (f'{policy.FIXTURE}/Cargo.toml', 'default-features = false', 'default-features = true'),
        ('crates/brynja-legacy-md5/src/hardened.rs', 'collisions', 'digests'),
        ('crates/brynja-legacy-sha1/src/ordinary.rs', 'collision', 'digest'),
        ('scripts/checks.sh', 'python3 scripts/legacy-hash/check-legacy-acceptance.py', 'true'),
    ]
    gates = ['.github/workflows/ci.yml', 'scripts/checks.sh', 'scripts/ci/check-rust-version-matrix.sh',
             'scripts/assurance/check-bare-metal.sh', 'scripts/zeroization/check-zeroization-miri.sh',
             'scripts/zeroization/check-zeroization-sanitizer.sh']
    for path, old, new in mutations:
        with tempfile.TemporaryDirectory(prefix='brynja-legacy-mutation-') as temporary:
            root = Path(temporary)
            for name in set(policy.FILES + gates):
                destination = root / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(policy.ROOT / name, destination)
            file = root / path
            original = file.read_text()
            assert old in original
            file.write_text(original.replace(old, new))
            try:
                policy.validate(root, hashes=False)
            except ValueError:
                continue
            raise AssertionError(f'accepted structural corruption: {path}: {old}')
    with tempfile.TemporaryDirectory(prefix='brynja-legacy-live-') as temporary:
        root = Path(temporary)
        fixture = root / 'consumer'
        shutil.copytree(policy.ROOT / policy.FIXTURE, fixture, ignore=shutil.ignore_patterns('target'))
        manifest = fixture / 'Cargo.toml'
        manifest.write_text(manifest.read_text().replace('../../crates', str(policy.ROOT / 'crates')))
        subprocess.run(['cargo', 'run', '--locked', '--offline'], cwd=fixture, check=True, timeout=120)
        data = fixture / 'fixtures/representative.txt'
        data.write_bytes(data.read_bytes() + b'changed real file\n')
        result = subprocess.run(['cargo', 'run', '--locked', '--offline'], cwd=fixture,
                                capture_output=True, text=True, timeout=120)
        assert result.returncode != 0 and 'assertion' in result.stderr, 'changed file was accepted'
    spec = importlib.util.spec_from_file_location('legacy_package', policy.ROOT / 'scripts/legacy-hash/check-legacy-package.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for name, kind in (('../escape', tarfile.REGTYPE), ('/absolute', tarfile.REGTYPE),
                       ('pkg/file', tarfile.SYMTYPE), ('other/file', tarfile.REGTYPE),
                       ('pkg/file:stream', tarfile.REGTYPE), ('pkg/./file', tarfile.REGTYPE),
                       ('pkg//file', tarfile.REGTYPE), ('pkg/dir\\file', tarfile.REGTYPE)):
        with tempfile.TemporaryDirectory(prefix='brynja-legacy-archive-') as temporary:
            root = Path(temporary)
            archive = root / 'test.crate'
            with tarfile.open(archive, 'w') as handle:
                member = tarfile.TarInfo(name)
                member.type = kind
                member.size = 0
                handle.addfile(member, io.BytesIO())
            try:
                module.unpack(archive, root / 'out', 'pkg')
            except ValueError:
                continue
            raise AssertionError('unsafe archive accepted')
    print('Legacy acceptance rejects 8 structural corruptions, changed real-file output, and 8 unsafe archives')


if __name__ == '__main__':
    main()
