#!/usr/bin/env python3
"""Final metadata checks reject stale docs without launching build campaigns."""
import importlib.util
import copy
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


if __name__ == '__main__':
    main()
