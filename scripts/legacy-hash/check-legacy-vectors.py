#!/usr/bin/env python3
"""Recompute every frozen digest without calling Brynja's Rust implementation."""
import hashlib
import importlib.util
import re

import legacy_acceptance as policy


def main():
    text = policy.read(policy.ROOT, policy.FIXTURE + '/src/vectors.rs').decode()
    files, bits = text.split('pub(crate) static BITS: &[BitVector] = &[', 1)
    arrays = re.findall(r'&\[\s*((?:0x[0-9a-f]{2},?\s*)*)\]', files)
    expected = [bytes.fromhex(''.join(re.findall(r'0x([0-9a-f]{2})', a))) for a in arrays]
    messages = [b'', b'abc'] + [policy.read(policy.ROOT, policy.FIXTURE + '/fixtures/' + name)
                               for name in ('representative.txt', 'archive-index.json')]
    actual = [h(data, usedforsecurity=False).digest() for data in messages for h in (hashlib.sha1, hashlib.md5)]
    if expected != actual or len(expected) != 8:
        raise ValueError('frozen file digest differs from independent hashlib')
    oracles = []
    for family in ('sha1', 'md5'):
        path = policy.ROOT / f'scripts/{family}/check-{family}-differential.py'
        spec = importlib.util.spec_from_file_location(f'legacy_{family}_oracle', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        oracles.append(module.oracle)
    array = r'&\[\s*((?:0x[0-9a-f]{2},?\s*)*)\]'
    pattern = r'\(\s*' + array + r',\s*([0-8]),\s*' + array + r',\s*' + array + r',\s*\),'
    records = re.findall(pattern, bits)
    if len(records) != 16:
        raise ValueError('missing canonical frozen bit vectors')
    for raw, width, sha1, md5 in records:
        data, digest1, digest2 = [bytes.fromhex(''.join(re.findall(r'0x([0-9a-f]{2})', value)))
                                for value in (raw, sha1, md5)]
        length = (len(data) - 1) * 8 + int(width) if data else 0
        for oracle, expected in zip(oracles, (digest1, digest2), strict=True):
            if oracle(data, length) != expected.hex():
                raise ValueError('frozen bit digest differs from independent oracle')
    print('All 40 frozen SHA-1/MD5 file and bit digests independently recomputed: PASS')


if __name__ == '__main__':
    main()
