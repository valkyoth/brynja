"""Reject stale current facade consumers without running Cargo."""
from pathlib import Path
from unittest.mock import patch


def check(metadata):
    metadata.check_current_fixture_versions()
    read = Path.read_text
    count = 0
    for fixture in ('sha2-public-api', 'sha3-public-api', 'cshake-public-api',
                    'sp800185-public-api', 'tuplehash-public-api', 'parallelhash-public-api',
                    'hash-final-acceptance', 'sp800185-final', 'kmac-public-api'):
        base = metadata.ROOT / 'assurance' / fixture
        manifest = read(base / 'Cargo.toml')
        lock = read(base / 'Cargo.lock')
        version = metadata.tomllib.loads(read(metadata.ROOT / 'crates/brynja/Cargo.toml'))['package']['version']
        block = f'name = "brynja"\nversion = "{version}"'
        assert lock.count(block) == 1
        cases = (
            ('Cargo.toml', manifest.replace('version = "=' + version + '"', 'version = "=0.0.0"')),
            ('Cargo.toml', manifest.replace('../../crates/brynja"', '../../crates/wrong"')),
            ('Cargo.toml', manifest.replace('default-features = false', 'default-features = true')),
            ('Cargo.lock', lock.replace(block, 'name = "brynja"\nversion = "0.0.0"')),
            ('Cargo.lock', lock.replace(block, 'name = "missing-brynja"\nversion = "' + version + '"')),
            ('Cargo.lock', lock + '\n[[package]]\n' + block + '\n'),
            ('Cargo.lock', lock.replace(block, block + '\nsource = "registry+https://example.invalid"')),
        )
        if fixture in ('hash-final-acceptance', 'sp800185-final'):
            cases = cases[3:]  # This combined consumer inherits the facade indirectly.
        elif fixture == 'kmac-public-api':
            cases = (cases[1], *cases[3:])  # Existing path-only dependency.
        for name, changed in cases:
            assert changed != read(base / name)

            def altered(path, *args, **kwargs):
                return changed if path == base / name else read(path, *args, **kwargs)

            with patch.object(Path, 'read_text', altered):
                try:
                    metadata.check_current_fixture_versions()
                except ValueError as error:
                    assert str(error) == 'current facade fixture version/source mismatch: ' + fixture
                    count += 1
                else:
                    raise AssertionError('accepted stale/foreign facade fixture: ' + fixture)
    metadata.check_current_fixture_versions()
    print(f'Current facade fixtures reject {count} version/source/default-feature regressions')
    tuplehash_review(metadata)


def tuplehash_review(metadata):
    """Exercise the real preflight, including missing and stale review pins."""
    policy = metadata.tuplehash_policy
    path = policy.PUBLIC_MANIFEST
    for missing in (False, True):
        hashes = dict(policy.HASHES)
        if missing:
            del hashes[path]
        else:
            hashes[path] = '0' * 64
        with patch.object(policy, 'HASHES', hashes):
            try:
                metadata.check_all()
            except policy.TupleHashPolicyError:
                pass
            else:
                raise AssertionError('TupleHash fixture review drift escaped preflight')
    print('TupleHash preflight rejects missing and stale fixture review pins')
