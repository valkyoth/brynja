#!/usr/bin/env python3
"""Structural corruption, real digest mismatch and hostile archive regressions."""
import importlib.util
import io
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path
from unittest.mock import patch

import legacy_acceptance as policy


def panic_profiles():
    spec = importlib.util.spec_from_file_location(
        'legacy_panic_profiles', policy.ROOT / 'scripts/legacy-hash/check-panic-profiles.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    historical = policy.ROOT / policy.FIXTURE / 'Cargo.lock'
    current = policy.ROOT / policy.CURRENT / 'Cargo.lock'
    before = historical.read_bytes(), current.read_bytes()
    assert before[0] != before[1], 'regression requires distinct historical/current locks'
    for mode in ('success', 'lock-error', 'missing-marker', 'wrong-leaf-strategy'):
        seen, directories = [], []

        def run(command, *, cwd, env, **kwargs):
            assert '--locked' in command and '--offline' in command and '--release' in command
            assert (cwd / 'Cargo.lock').read_bytes() == before[1]
            assert (cwd / 'src/lib.rs').read_bytes() == (policy.ROOT / policy.FIXTURE / 'src/lib.rs').read_bytes()
            selected = Path(env['CARGO_TARGET_DIR']).name
            expected = 'abort' if selected == 'abort' else 'unwind'
            assert command[-2:] == ['--', expected]
            assert env.get('CARGO_PROFILE_RELEASE_PANIC') == (None if selected == 'default' else selected)
            seen.append(selected)
            directories.append(cwd)
            stderr = '\n'.join(
                f'Running rustc --crate-name brynja_legacy_{leaf} '
                + ('-C panic=abort' if expected == 'abort' else '') for leaf in ('sha1', 'md5'))
            if mode == 'wrong-leaf-strategy':
                stderr += '\nRunning rustc --crate-name brynja_legacy_md5 -C panic=abort'
            return subprocess.CompletedProcess(command, 1 if mode == 'lock-error' else 0,
                '' if mode == 'missing-marker' else f'downstream release profile: {expected}: PASS', stderr)

        with patch.object(module.subprocess, 'run', side_effect=run):
            if mode == 'success':
                module.main()
                assert seen == ['default', 'unwind', 'abort']
            else:
                try:
                    module.main()
                except ValueError:
                    pass
                else:
                    raise AssertionError('panic profile accepted ' + mode)
                assert seen == ['default']
        assert all(not directory.exists() for directory in directories)
        assert (historical.read_bytes(), current.read_bytes()) == before
    print('Panic profiles use the current lock, preserve frozen inputs and reject three execution failures')


def main():
    policy.validate()
    panic_profiles()
    mutations = [
        (f'{policy.FIXTURE}/src/profiles.rs', 'finalize_bits_secret', 'omitted_bits_secret'),
        (f'{policy.FIXTURE}/src/profiles.rs', 'assert_eq!(output, [0; $size])', 'assert!(true)'),
        (f'{policy.FIXTURE}/src/profiles.rs', 'PublicDeclassification::acknowledge()', 'implicit_authority()'),
        (f'{policy.FIXTURE}/src/profiles.rs', 'for chunk in [1, 7, 31, 64, 113]', 'for chunk in [64]'),
        (f'{policy.FIXTURE}/Cargo.toml', 'default-features = false', 'default-features = true'),
        (f'{policy.CURRENT}/Cargo.toml', '../src/lib.rs', '../src/profiles.rs'),
        (f'{policy.CURRENT}/Cargo.toml', '../src/main.rs', '../src/lib.rs'),
        (f'{policy.CURRENT}/Cargo.toml', 'default-features = false', 'default-features = true'),
        ('crates/brynja-legacy-md5/src/hardened.rs', 'collisions', 'digests'),
        ('crates/brynja-legacy-sha1/src/ordinary.rs', 'collision', 'digest'),
        ('scripts/checks.sh', 'python3 scripts/legacy-hash/check-legacy-acceptance.py', 'true'),
        ('scripts/legacy-hash/check-legacy-acceptance.py', "policy.execute('python3', 'scripts/legacy-hash/check-panic-profiles.py', timeout=600)", 'pass'),
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
        manifest = fixture / 'current/Cargo.toml'
        manifest.write_text(manifest.read_text().replace('../../../crates', str(policy.ROOT / 'crates')))
        subprocess.run(['cargo', 'run', '--locked', '--offline'], cwd=manifest.parent, check=True, timeout=120)
        data = fixture / 'fixtures/representative.txt'
        data.write_bytes(data.read_bytes() + b'changed real file\n')
        result = subprocess.run(['cargo', 'run', '--locked', '--offline'], cwd=manifest.parent,
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
    print('Legacy acceptance rejects 12 structural corruptions, changed real-file output, and 8 unsafe archives')


if __name__ == '__main__':
    main()
