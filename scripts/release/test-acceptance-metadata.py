#!/usr/bin/env python3
"""Final metadata checks reject stale docs without launching build campaigns."""
import importlib.util
import copy
import json
from pathlib import Path
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location(
    'acceptance_metadata', Path(__file__).with_name('check-acceptance-metadata.py'))
metadata = importlib.util.module_from_spec(spec)
spec.loader.exec_module(metadata)


def main():
    with patch('subprocess.run', side_effect=AssertionError('unexpected process')), \
            patch('subprocess.check_call', side_effect=AssertionError('unexpected process')):
        metadata.check_all()
        parallel = metadata.parallelhash_policy
        for missing in (False, True):
            hashes = dict(parallel.HASHES)
            fixture = Path('assurance/parallelhash-public-api/Cargo.toml')
            if missing:
                del hashes[fixture]
            else:
                hashes[fixture] = 'e22082db08e6154420d2d6fc05267e844dc1d767c6c7cd3922e464efe00ad724'
            with patch.object(parallel, 'HASHES', hashes):
                try:
                    metadata.check_all()
                except parallel.ParallelHashPolicyError:
                    pass
                else:
                    raise AssertionError('stale or missing ParallelHash facade-fixture binding accepted')
        # Reproduce the actual pre-rustdoc MD5 pin that escaped the local-family
        # checks but failed the cross-family acceleration review in GitHub.
        contract = metadata.acceleration_availability
        original_contract_read = contract.read
        for missing in (False, True):
            document = json.loads(original_contract_read(metadata.ROOT, contract.REVIEW))
            source = 'crates/brynja-legacy-md5/src/batch/execution.rs'
            if missing:
                del document['sha256'][source]
            else:
                document['sha256'][source] = 'f3dd8c62c846520fd6b30045dd9525229c7775974470a9432b3a7ff94aa7729a'

            def stale_acceleration_read(root, name):
                if name == contract.REVIEW:
                    return json.dumps(document).encode()
                return original_contract_read(root, name)

            with patch.object(contract, 'read', side_effect=stale_acceleration_read):
                try:
                    metadata.check_all()
                except ValueError as error:
                    assert 'availability contract/source closure changed' in str(error)
                else:
                    raise AssertionError('stale or missing cross-family acceleration binding accepted')
        # Reproduce the stale shared package-helper pin seen in CI, in each
        # consuming MD5 review. Exercise the real validators, not mocked passes.
        original_read = Path.read_text
        source = 'scripts/md5/check-md5-package.py'
        for review, key in (
            ('scripts/md5/md5-reviewed.toml', 'sha256'),
            ('scripts/md5/md5-cpu-reviewed.toml', 'files'),
            ('scripts/md5/execution-reviewed.json', 'sha256'),
        ):
            for missing in (False, True):
                hashes = dict(metadata.verifier_review(review, key))
                if missing:
                    del hashes[source]
                else:
                    hashes[source] = '0' * 64
                if review.endswith('.json'):
                    broken = json.dumps({'schema': 1, key: hashes})
                else:
                    broken = '[' + key + ']\n' + ''.join(
                        f'"{name}" = "{value}"\n' for name, value in hashes.items())

                def altered_read(path, *args, **kwargs):
                    if path == metadata.ROOT / review:
                        return broken
                    return original_read(path, *args, **kwargs)

                # Operational JSON uses read_bytes; keep both real read paths
                # covered without mutating the actual checkout.
                original_bytes = Path.read_bytes

                def altered_bytes(path):
                    if path == metadata.ROOT / review:
                        return broken.encode()
                    return original_bytes(path)

                with patch.object(Path, 'read_text', altered_read), \
                        patch.object(Path, 'read_bytes', altered_bytes):
                    try:
                        metadata.check_all()
                    except ValueError as error:
                        assert any(message in str(error) for message in (
                            'MD5 reviewed', 'CPU hash', 'CPU source changed',
                            'MD5 execution reviewed')), str(error)
                    else:
                        raise AssertionError('stale or missing MD5 package binding accepted')
        read_review = metadata.verifier_review
        for review, key in metadata.VERIFIER_REVIEWS:
            for script in metadata.VERIFIERS:
                for missing in (False, True):
                    hashes = dict(read_review(review, key))
                    if missing:
                        del hashes[script]
                    else:
                        hashes[script] = '0' * 64

                    def altered(path, selected_key):
                        return hashes if path == review else read_review(path, selected_key)

                    with patch.object(metadata, 'verifier_review', side_effect=altered):
                        try:
                            metadata.check_all()
                        except ValueError as error:
                            assert 'verifier review hash drift' in str(error)
                            assert review in str(error) and script in str(error)
                        else:
                            raise AssertionError('missing or stale verifier binding accepted')
        model = metadata.api_profile_model
        for reader, mutate in (
            ('read_policy', lambda value: value['schema'].update(surface_register_sha256='0' * 64)),
            ('read_surfaces', lambda value: value.update(policy_sha256='0' * 64)),
        ):
            value = copy.deepcopy(getattr(model, reader)())
            mutate(value)
            with patch.object(model, reader, return_value=value):
                try:
                    metadata.check_all()
                except model.ProfileError as error:
                    assert 'reopen review' in str(error)
                else:
                    raise AssertionError('stale API surface binding accepted')
        for name in ('REGISTER', 'COVERAGE'):
            for exists in (True, False):
                stale = Mock(name='stale metadata')
                stale.is_file.return_value = exists
                stale.read_bytes.return_value = b'stale'
                with patch.object(model, name, stale):
                    try:
                        metadata.check_all()
                    except model.ProfileError as error:
                        assert 'API-profile metadata is stale' in str(error)
                    else:
                        raise AssertionError('missing or stale API metadata accepted')
        for module, path in (
            (metadata.sha2_public_api, metadata.sha2_public_api.LEAF_README),
            (metadata.sha2_public_api, metadata.sha2_public_api.FACADE_README),
            (metadata.sha3_public_api, metadata.sha3_public_api.FACADE_README),
        ):
            with patch.dict(module.EXPECTED_SHA256, {path: '0' * 64}):
                try:
                    metadata.check_all()
                except module.AcceptancePolicyError as error:
                    assert 'hash drift' in str(error)
                else:
                    raise AssertionError('stale README accepted')
        for module in (metadata.final_acceptance, metadata.portable_acceptance):
            hashes = module.expected_hashes(metadata.ROOT)
            hashes['README.md'] = '0' * 64
            with patch.object(module, 'expected_hashes', return_value=hashes):
                try:
                    metadata.check_all()
                except RuntimeError as error:
                    assert 'hash drift' in str(error)
                else:
                    raise AssertionError('stale root README accepted')
    gate = (metadata.ROOT / 'scripts/release/validate-release-metadata.sh').read_text()
    for name in ('check', 'test'):
        assert '\npython3 scripts/release/' + name + '-acceptance-metadata.py\n' in gate
    print('Final metadata rejects five stale README bindings and six API-profile regressions without crypto execution')
    print('Shared verifier preflight rejects 28 stale or missing review bindings without crypto execution')
    print('Final metadata rejects six stale/missing MD5 package-helper bindings without crypto execution')
    print('Final metadata rejects the stale MD5 rustdoc acceleration pin and missing binding without crypto execution')
    print('Final metadata rejects stale/missing ParallelHash facade-fixture bindings without crypto execution')


if __name__ == '__main__':
    main()
