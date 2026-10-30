"""Reject stale current facade consumers without running Cargo."""
from pathlib import Path
import shutil
import tempfile
from unittest.mock import patch


def sha3_external_cases(driver):
    """Downstream tests do not require test files in published archives."""
    original_root = driver.ROOT
    names = ('execution_cases/mod.rs', 'cshake_execution_cases/mod.rs',
             'vectors/nist-bit-selected.txt', 'vectors/cshake-execution.txt')
    main = (original_root / 'assurance/sha3-execution/src/main.rs').read_text()
    for broken in (None, *names, 'missing-path', 'duplicate-path'):
        with tempfile.TemporaryDirectory(prefix='brynja-sha3-external-cases-') as directory:
            root = Path(directory)
            consumer = root / 'consumer'
            (consumer / 'src').mkdir(parents=True)
            source = main
            path = '#[path = "../../../crates/brynja-hash-sha3/tests/execution_cases/mod.rs"]'
            if broken == 'missing-path':
                source = source.replace(path, '')
            elif broken == 'duplicate-path':
                source += '\n' + path
            (consumer / 'src/main.rs').write_text(source)
            for name in names:
                if name == broken:
                    continue
                target = root / 'crates/brynja-hash-sha3/tests' / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(original_root / 'crates/brynja-hash-sha3/tests' / name, target)
            with patch.object(driver, 'ROOT', root):
                if broken is not None:
                    try:
                        driver.external_cases(consumer)
                    except (ValueError, FileNotFoundError):
                        pass
                    else:
                        raise AssertionError('accepted missing/ambiguous external fixture: ' + broken)
                    assert (consumer / 'src/main.rs').read_text() == source
                    continue
                driver.external_cases(consumer)
            copied = sorted(p.relative_to(consumer / 'cases').as_posix()
                            for p in (consumer / 'cases').rglob('*') if p.is_file())
            assert copied == sorted(names)
            for name in names:
                assert (consumer / 'cases' / name).read_bytes() == (
                    original_root / 'crates/brynja-hash-sha3/tests' / name).read_bytes()
            rewritten = (consumer / 'src/main.rs').read_text()
            assert '../../../crates/' not in rewritten
            for name in ('execution_cases', 'cshake_execution_cases'):
                assert f'#[path = "../cases/{name}/mod.rs"]' in rewritten
            assert not (root / 'packages').exists(), 'fixture staging wrote into package area'
    print('SHA-3 external fixtures retain exact case/vector bytes and reject six missing/ambiguous inputs')


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
