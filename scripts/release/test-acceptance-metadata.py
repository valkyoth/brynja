#!/usr/bin/env python3
"""Final metadata checks reject stale docs without launching build campaigns."""
import importlib.util
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    'acceptance_metadata', Path(__file__).with_name('check-acceptance-metadata.py'))
metadata = importlib.util.module_from_spec(spec)
spec.loader.exec_module(metadata)


def main():
    with patch('subprocess.run', side_effect=AssertionError('unexpected process')), \
            patch('subprocess.check_call', side_effect=AssertionError('unexpected process')):
        metadata.check_all()
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
    print('Final metadata rejects five stale README bindings without crypto execution')


if __name__ == '__main__':
    main()
