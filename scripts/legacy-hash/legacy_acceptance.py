"""Frozen portable legacy consumer/source boundary; no backend admission."""
import hashlib
import subprocess
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = 'assurance/legacy-hash-public-api'
HASHES = 'scripts/legacy-hash/legacy-reviewed.toml'
FILES = [f'{FIXTURE}/{name}' for name in (
    'Cargo.toml', 'Cargo.lock', 'src/lib.rs', 'src/main.rs', 'src/profiles.rs',
    'src/vectors.rs', 'fixtures/representative.txt', 'fixtures/archive-index.json',
)] + [f'crates/brynja-legacy-{family}/{path}' for family in ('sha1', 'md5') for path in (
    'Cargo.toml', 'README.md', 'src/lib.rs', 'src/ordinary.rs', 'src/hardened.rs',
    'src/engine.rs', 'src/compress.rs', 'src/owner.rs', 'src/output.rs', 'tests/api.rs',
)] + [f'scripts/legacy-hash/{name}' for name in (
    'legacy_acceptance.py', 'check-legacy-acceptance.py', 'check-legacy-package.py',
    'test-legacy-acceptance.py', 'check-legacy-isolation.py',
    'check-legacy-vectors.py',
)]


def read(root, path):
    file = root / path
    if not file.is_file() or file.is_symlink():
        raise ValueError(f'not a regular frozen input: {path}')
    return file.read_bytes()


def validate(root=ROOT, hashes=True):
    loaded = {path: read(root, path) for path in FILES}
    manifest = tomllib.loads(loaded[f'{FIXTURE}/Cargo.toml'].decode())
    if manifest['package']['publish'] is not False or 'workspace' not in manifest:
        raise ValueError('fixture is not package-external and unpublished')
    if set(manifest['dependencies']) != {'brynja-legacy-sha1', 'brynja-legacy-md5'}:
        raise ValueError('legacy fixture acquired a non-legacy dependency')
    for dep in manifest['dependencies'].values():
        if dep.get('version') != '=0.1.0' or dep.get('default-features') is not False:
            raise ValueError('fixture pin or default-feature boundary')
    if b'source =' in loaded[f'{FIXTURE}/Cargo.lock']:
        raise ValueError('external fixture dependency')
    for path, source in loaded.items():
        if path.endswith('.rs') and len(source.splitlines()) > 500:
            raise ValueError('source exceeds 500 lines')
    profiles = loaded[f'{FIXTURE}/src/profiles.rs'].decode()
    for token in ('check_additional_bytes', 'check_additional_bits', 'message_bits',
                  'finalize_bits_secret', 'digest_bits_secret', 'digest_secret',
                  'finalize_secret', 'finalize_bits_public', 'finalize_public',
                  'finalize_bits', 'PublicDeclassification::acknowledge()',
                  'assert_eq!(output, [0; $size])', 'assert_eq!(output, [0xa5; 1])',
                  'for chunk in [1, 7, 31, 64, 113]', 'drop(hardened)'):
        if token not in profiles:
            raise ValueError(f'portable profile lost: {token}')
    for name in ('FILES', 'BITS'):
        if f'for (data,' not in loaded[f'{FIXTURE}/src/lib.rs'].decode() or f'vectors::{name}' not in loaded[f'{FIXTURE}/src/lib.rs'].decode():
            raise ValueError('acceptance corpus not executed')
    for family in ('sha1', 'md5'):
        for name in ('lib.rs', 'ordinary.rs', 'hardened.rs'):
            source = loaded[f'crates/brynja-legacy-{family}/src/{name}'].decode().split('#[cfg(test)]')[0]
            if 'collision' not in source:
                raise ValueError('public collision warning removed')
    for path, token in (
        ('scripts/checks.sh', 'python3 scripts/legacy-hash/check-legacy-acceptance.py'),
        ('scripts/checks.sh', 'python3 scripts/legacy-hash/test-legacy-acceptance.py'),
        ('scripts/ci/check-rust-version-matrix.sh', FIXTURE + '/Cargo.toml'),
        ('scripts/assurance/check-bare-metal.sh', FIXTURE + '/Cargo.toml'),
        ('scripts/zeroization/check-zeroization-miri.sh', FIXTURE + '/Cargo.toml'),
        ('scripts/zeroization/check-zeroization-sanitizer.sh', FIXTURE + '/Cargo.toml'),
        ('.github/workflows/ci.yml', FIXTURE + '/Cargo.toml'),
    ):
        if token not in read(root, path).decode():
            raise ValueError(f'mandatory acceptance gate missing: {path}')
    if hashes:
        expected = tomllib.loads(read(root, HASHES).decode())['files']
        if set(expected) != set(FILES):
            raise ValueError('incomplete frozen inventory')
        for path, data in loaded.items():
            if hashlib.sha256(data).hexdigest() != expected[path]:
                raise ValueError(f'portable reference changed: {path}')


def inventory():
    return '[files]\n' + ''.join(f'"{p}" = "{hashlib.sha256(read(ROOT,p)).hexdigest()}"\n' for p in FILES)


def execute(*args, root=ROOT, timeout=180):
    return subprocess.run(list(args), cwd=root, check=True, timeout=timeout)
