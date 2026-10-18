"""Owner-pinned evidence identity, separate from result/source validation.

BRYNJA_NATIVE_REVIEW_SHA256 must come from the operator or protected runner
configuration, never from candidate code, its workflow, or a computed default.
This binds an approved observation snapshot; it is NOT runner attestation.
"""
import os
import re

import native_review_io as io

REVIEW = 'security/native-reuse/evidence-approval.json'
ENVIRONMENT = 'BRYNJA_NATIVE_REVIEW_SHA256'
INDEXES = {
    'sha2-hardened': 'security/sha2-hardened-native.json',
    'sha1-hardened': 'security/sha1-hardened-native.json',
    'md5-execution': 'security/md5-execution-native.json',
    'md5-hardened': 'security/md5-hardened-native.json',
    'keccak-hardened': 'security/keccak-hardened-native.json',
    'kmac-execution': 'security/kmac-execution-native.json',
    'tuplehash-execution': 'security/tuplehash-execution-native.json',
    'parallelhash-execution': 'security/parallelhash-execution-native.json',
}


def receipt(root, head):
    expected = os.environ.get(ENVIRONMENT, '')
    io.require(re.fullmatch('[0-9a-f]{64}', expected) is not None,
               'native evidence approval missing: set ' + ENVIRONMENT +
               ' only to an independently owner-approved manifest digest')
    raw = io.committed(root, REVIEW, head)
    io.require(io.sha(raw) == expected, 'native evidence approval digest mismatch')
    review = io.document(raw)
    io.require(set(review) == {'schema', 'purpose', 'status', 'reviewed_commit', 'families',
                              'validation_changes'},
               'native evidence approval fields')
    io.require(type(review['schema']) is int and review['schema'] == 1 and
               review['purpose'] == 'native-observation-integrity' and
               review['status'] == 'owner-approved', 'native evidence review pending/invalid')
    anchor = io.revision(review['reviewed_commit'])
    io.require(anchor != head, 'candidate cannot be its own reviewed evidence snapshot')
    io.git(root, 'merge-base', '--is-ancestor', anchor, head)
    io.require(isinstance(review['families'], list) and review['families'] and
               all(isinstance(name, str) for name in review['families']) and
               len(set(review['families'])) == len(review['families']) and
               set(review['families']) <= set(INDEXES), 'native evidence approval family scope')
    changes = review['validation_changes']
    io.require(isinstance(changes, dict) and set(changes) <= set(review['families']),
               'validation review family scope')
    for entries in changes.values():
        io.require(isinstance(entries, dict), 'validation review entries')
        for name, row in entries.items():
            io.relative(name)
            io.require((name.startswith('scripts/') and name.endswith(('.py', '.sh', '.toml', '.json'))
                        or name.startswith('security/') and name.endswith('-reviewed.json')),
                       'validation review cannot exempt production/build inputs')
            io.require(isinstance(row, dict) and set(row) == {'before', 'after'} and
                       all(isinstance(v, str) and re.fullmatch('[0-9a-f]{64}', v) for v in row.values())
                       and row['before'] != row['after'], 'validation review digest pair')
    return review


def validate(family, root=io.ROOT, head=None):
    io.clean(root)
    if head is None:
        head = io.git(root, 'rev-parse', 'HEAD').decode().strip()
    review = receipt(root, head)
    io.require(family in review['families'], 'native family not approved')
    anchor = review['reviewed_commit']

    def unchanged(name):
        previous = io.historical(root, anchor, name)
        io.require(io.committed(root, name, head) == previous,
                   'approved native index/artifact changed: ' + name)
        return previous

    index = io.document(unchanged(INDEXES[family]))
    rows = index['captures' if family == 'sha1-hardened' else 'lanes']
    io.require(isinstance(rows, dict) and rows, 'empty approved native index')
    captures = set()
    for row in rows.values():
        raw = unchanged(row['path' if family == 'sha1-hardened' else 'artifact'])
        io.require(io.sha(raw) == row['sha256'], 'approved native artifact checksum')
        record = io.document(raw)
        capture = io.revision(record['capture_commit' if family == 'sha2-hardened' else 'commit'])
        io.git(root, 'merge-base', '--is-ancestor', capture, anchor)
        captures.add(capture)
    io.require(len(captures) == 1, 'inconsistent approved capture commits')
    io.clean(root)
    io.require(io.git(root, 'rev-parse', 'HEAD').decode().strip() == head,
               'checkout changed during evidence approval')
    return {'capture_commit': captures.pop(), 'reviewed_commit': anchor,
            'validation_changes': review['validation_changes'].get(family, {})}


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--family', choices=tuple(INDEXES))
    args = parser.parse_args()
    for family in (args.family,) if args.family else INDEXES:
        validate(family)
    print('Native evidence identity: owner-approved snapshot unchanged; not runner attestation')


if __name__ == '__main__':
    main()
