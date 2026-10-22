"""Current facade and SP 800-185 review bindings in the cheap preflight."""

from pathlib import Path
import tomllib
from unittest.mock import patch


def check(metadata):
    # The caller forbids subprocesses. Exercise real validators and require their
    # precise errors, not a rejection caused by some other stale review.
    metadata.check_all()
    policy = metadata.sha256_policy
    read_text = Path.read_text
    manifest = metadata.ROOT / policy.CRYPTO_MANIFEST
    hmac = 'brynja-mac-hmac = { workspace = true }\n'
    assert read_text(manifest).count(hmac) == 1

    def missing_hmac(path, *args, **kwargs):
        value = read_text(path, *args, **kwargs)
        return value.replace(hmac, '') if path == manifest else value

    with patch.object(Path, 'read_text', missing_hmac):
        try:
            metadata.check_all()
        except policy.Sha256PolicyError as error:
            assert str(error) == 'brynja-crypto SHA-256 ownership changed', str(error)
        else:
            raise AssertionError('portable SHA-2 facade inventory escaped metadata preflight')
    metadata.check_all()

    policy = metadata.execution_acceptance
    read = policy.read
    review = read(metadata.ROOT, policy.HASHES)
    hashes = tomllib.loads(review)['files']
    count = 0
    for source in (policy.FIXTURE / 'Cargo.lock', Path('scripts/checks.sh'),
                   Path('scripts/ci/check-rust-version-matrix.sh')):
        line = f'"{source.as_posix()}" = "{hashes[source.as_posix()]}"'
        assert review.count(line) == 1
        for mode in ('missing', 'stale', 'source'):
            metadata.check_all()

            def changed(root, path):
                value = read(root, path)
                if path == source and mode == 'source':
                    return value + '\n# unreviewed acceptance input\n'
                if path == policy.HASHES and mode != 'source':
                    replacement = '' if mode == 'missing' else (
                        f'"{source.as_posix()}" = "' + '0' * 64 + '"')
                    return value.replace(line, replacement)
                return value

            with patch.object(policy, 'read', side_effect=changed):
                try:
                    metadata.check_all()
                except policy.ExecutionError as error:
                    assert str(error) == 'execution acceptance changed; reopen review', str(error)
                    count += 1
                else:
                    raise AssertionError(f'SP 800-185 {mode} binding escaped preflight: {source}')
    metadata.check_all()
    print('Final metadata rejects the missing HMAC facade dependency without subprocesses')
    print(f'Final metadata rejects {count} SP 800-185 lock/driver review regressions without subprocesses')
