#!/usr/bin/env python3
"""Mutation rejection for frozen legacy closure, claims and native reuse."""
import shutil
import tempfile
from pathlib import Path
import legacy_final_acceptance as policy


def main():
    policy.validate()
    mutations = [
        (policy.CLAIMS, 'fully-implemented', 'pending'),
        (policy.CLAIMS, 'independent_review = false', 'independent_review = true'),
        (policy.CLAIMS, 'fips_validated = false', 'fips_validated = true'),
        (policy.CLAIMS, 'collision_resistant = false', 'collision_resistant = true'),
        (policy.CLAIMS, 'modern_default = false', 'modern_default = true'),
        (policy.CLAIMS, 'hardened_simd = false', 'hardened_simd = true'),
        (policy.CLAIMS, 'accelerated_admissions = []', 'accelerated_admissions = ["avx2"]'),
        (policy.CLAIMS, 'historical-review-only', 'fresh-native-run'),
        (policy.FROZEN, 'v0.24.20', 'v0.24.22'),
        (policy.SNAPSHOT, '15faddd', '25faddd'),
        ('assurance/legacy-hash-public-api/src/vectors.rs', '0xda, 0x39', '0xdb, 0x39'),
        ('crates/brynja-core/Cargo.toml', '0.9.0', '0.9.1'),
        ('crates/brynja-legacy-sha1/src/compress.rs', 'wrapping_add', 'saturating_add'),
        ('crates/brynja-legacy-md5/src/compress.rs', 'wrapping_add', 'saturating_add'),
        (policy.FIXTURE + '/Cargo.toml', 'publish = false', 'publish = true'),
        (policy.FIXTURE + '/Cargo.toml', 'unsafe_code = "forbid"', 'unsafe_code = "allow"'),
        (policy.FIXTURE + '/src/lib.rs', 'comparisons != 160', 'comparisons != 159'),
        (policy.FIXTURE + '/src/lib.rs', 'brynja_legacy_hash_public_api_fixture::acceptance()', '()'),
        (policy.FIXTURE + '/src/batch.rs', 'secret.expose() != wanted.as_flattened()', 'false'),
        (policy.FIXTURE + '/src/batch.rs', 'output != [[0; 16]; 8]', 'false'),
    ]
    for path in ('scripts/checks.sh', 'scripts/ci/check-rust-version-matrix.sh',
                 'scripts/assurance/check-bare-metal.sh', '.github/workflows/ci.yml',
                 'scripts/zeroization/check-zeroization-miri.sh',
                 'scripts/zeroization/check-zeroization-sanitizer.sh'):
        token = 'python3 scripts/legacy-hash/check-legacy-final-acceptance.py' if path == 'scripts/checks.sh' else policy.FIXTURE + '/Cargo.toml'
        mutations.append((path, token, 'omitted'))
    for lane in policy.MD5_CAPTURES:
        mutations.append((f'assurance/md5-observations/v0.24.22/{lane}.json', 'unadmitted', 'admitted'))
    with tempfile.TemporaryDirectory(prefix='brynja-final-legacy-') as directory:
        root = Path(directory)
        paths = set(policy.inventory()) | {policy.HASHES}
        import tomllib
        for record in tomllib.loads(policy.read(policy.ROOT, policy.SNAPSHOT)).values():
            paths.update(record['files'])
        paths.update(path for path, _, _ in mutations)
        for path in paths:
            destination = root / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(policy.ROOT / path, destination)
        policy.validate(root)
        for invalid in ('../outside', str(root / policy.CLAIMS)):
            try:
                policy.read(root, invalid)
            except ValueError:
                pass
            else:
                raise AssertionError('accepted out-of-root input')
        # A trusted platform alias above the root is not a repository symlink.
        alias = root / 'platform-alias'
        try:
            alias.symlink_to(root, target_is_directory=True)
        except (OSError, NotImplementedError):
            pass  # Some Windows runners do not grant symlink creation.
        else:
            try:
                policy.read(root, 'platform-alias/' + policy.CLAIMS)
            except ValueError:
                pass
            else:
                raise AssertionError('accepted repository-owned symlink')
            assert policy.read(alias / policy.FIXTURE, 'claims.toml') == policy.read(root, policy.CLAIMS)
            alias.unlink()
        for path, old, new in mutations:
            file = root / path
            original = file.read_text(encoding='utf-8')
            if old not in original:
                raise AssertionError('inert mutation: ' + path)
            file.write_text(original.replace(old, new), encoding='utf-8')
            try:
                try:
                    policy.validate(root, hashes=False)
                except (ValueError, KeyError):
                    pass
                else:
                    raise AssertionError('accepted regression: ' + path + ': ' + old)
            finally:
                file.write_text(original, encoding='utf-8')
    print(f'Final legacy acceptance rejects {len(mutations)} frozen, source, claim, route and coverage regressions')


if __name__ == '__main__':
    main()
