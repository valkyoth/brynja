#!/usr/bin/env python3
"""Mutation rejection for frozen legacy closure, claims and native reuse."""
import shutil
import tempfile
import io
from unittest.mock import patch
from pathlib import Path
import legacy_final_acceptance as policy
import final_batch_mutations


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
        (policy.FIXTURE + '/src/batch.rs', '!output_matches(secret.expose(), wanted.as_flattened())?', 'false'),
        (policy.FIXTURE + '/src/batch.rs', 'Ok(actual.ct_eq(expected).expose_public())', 'Ok(actual == expected)'),
        (policy.FIXTURE + '/src/lib.rs', 'fn dynamic_neighbor_drop_unwind_clears_live_secret_output()', 'fn omitted_neighbor_unwind()'),
        (policy.FIXTURE + '/src/lib.rs', 'fn dynamic_full_width_comparison_rejects_every_mismatch()', 'fn omitted_comparison()'),
        (policy.FIXTURE + '/src/batch.rs', 'output != [[0; 16]; 8]', 'false'),
        (policy.FIXTURE + '/src/batch.rs', 'wanted.map(|lane| lane.map(|byte| !byte))', 'wanted'),
        ('scripts/legacy-hash/test-legacy-final-acceptance.py', 'final_batch_mutations.run_tests()', '()'),
        ('scripts/legacy-hash/test-legacy-final-acceptance.py', '\n    final_batch_mutations.run_tests()\n', '\n    pass\n'),
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
        # Simulate growth after the path's size check, without huge allocation.
        (root / 'read-bound.txt').write_bytes(b'old')
        with patch.object(policy, 'MAX_INPUT_BYTES', 1024):
            stream = io.BytesIO(b'x' * 4096)
            with patch.object(stream, 'read', wraps=stream.read) as actual_read, \
                    patch.object(Path, 'open', return_value=stream) as opened:
                try:
                    policy.read(root, 'read-bound.txt')
                except ValueError:
                    pass
                else:
                    raise AssertionError('accepted growth past the actual-read bound')
                opened.assert_called_once_with('rb')
                actual_read.assert_called_once_with(1025)
        with patch.object(policy, 'MAX_INPUT_BYTES', 4), \
                patch.object(Path, 'open', return_value=io.BytesIO(b'x\r\nz')):
            assert policy.read(root, 'read-bound.txt') == 'x\nz'
        with patch.object(Path, 'open', return_value=io.BytesIO(b'a\r\nb\rc\n')):
            assert policy.read(root, policy.FIXTURE + '/Cargo.lock') == 'a\nb\nc\n'
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
    final_batch_mutations.run_tests()


if __name__ == '__main__':
    main()
