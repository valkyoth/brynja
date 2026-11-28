"""Check retained native runs against the candidate inputs; do not claim a new execution."""
import hashlib
from pathlib import Path
import re

from poly1305_native_replay import ROOT, TARGETS, VERSIONS

RECORD = ROOT / 'assurance/poly1305/v0.31.2-native.tsv'
RV64 = 'riscv64gc-unknown-linux-gnu'


def source_digest(root):
    paths = set()
    for crate in ('core', 'crypto-cpu', 'mac-poly1305', 'cipher-chacha', 'aead-chacha20poly1305'):
        base = root / 'crates' / ('brynja-' + crate)
        paths.add(base / 'Cargo.toml')
        paths.update((base / 'src').rglob('*'))
        paths.update(base.glob('build.rs'))
    for fixture in ('poly1305', 'chacha20poly1305'):
        base = root / 'assurance' / fixture
        paths.update(base / name for name in ('Cargo.toml', 'Cargo.lock'))
        for folder in ('src', 'tests', 'examples'):
            paths.update(p for p in (base / folder).rglob('*') if '__pycache__' not in p.parts)
    paths.update(root / p for p in (
        'Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', 'rfc/rfc8439.txt',
        'crates/brynja-mac-poly1305/tests/data/rfc8439.tsv',
        'scripts/cryptography/check-chacha20poly1305-vectors.py',
        'scripts/cryptography/poly1305_native_replay.py',
        'scripts/cryptography/check-poly1305-packages.py', 'scripts/hkdf/check-hkdf-public-api.py'))
    h = hashlib.sha256()
    for path in sorted(paths):
        if path.is_symlink():
            raise ValueError(f'unexpected linked input: {path}')
        if not path.is_dir():
            h.update(path.relative_to(root).as_posix().encode() + b'\0' + hashlib.sha256(path.read_bytes()).digest())
    return h.hexdigest()


def validate(record, source):
    header, *lines = record.splitlines()
    if header != 'source-sha256 ' + source:
        raise ValueError('production or replay inputs changed: reopen native evidence')
    expected = {(target, version) for target in (*TARGETS, RV64) for version in VERSIONS}
    seen = set()
    for line in lines:
        target, version, vectors, other = line.split()
        if (target, version) not in expected:
            raise ValueError('unexpected or duplicate native observation')
        expected.remove((target, version))
        for artifact in (vectors, other):
            if not re.fullmatch('[0-9a-f]{64}', artifact) or artifact in seen:
                raise ValueError('invalid or reused executable digest')
            seen.add(artifact)
    if expected:
        raise ValueError('missing native platform/compiler observation')


if __name__ == '__main__':
    validate(RECORD.read_text(), source_digest(ROOT))
    print('Native production MAC/paired records current: 4 platforms, both endpoints; RV64 standalone only.')
