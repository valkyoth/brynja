#!/usr/bin/env python3
"""Exact owner-reviewed test/tooling delta; never a filename-based exemption."""
import argparse
import sys

import native_review_io as io
from native_review_families import FAMILIES, Family

REVIEW = 'security/native-reuse/v0.24.49-review.json'


def schema(review):
    io.require(set(review) == {'schema', 'capture_commit', 'reviewed_commit', 'owner_review',
                              'changes', 'verification'}, 'review fields')
    io.require(type(review['schema']) is int and review['schema'] == 1, 'review schema')
    io.require(review['owner_review'] == 'accepted-test-tooling-equivalence', 'review pending')
    io.revision(review['capture_commit'])
    io.revision(review['reviewed_commit'])
    io.require(isinstance(review['changes'], dict) and bool(review['changes']), 'review changes')
    io.relative(review['verification'])
    for name, row in review['changes'].items():
        io.relative(name)
        io.require(set(row) == {'before', 'after', 'disposition', 'production_prefix'}, 'change fields')
        for key in ('before', 'after'):
            value = row[key]
            io.require((key == 'before' and value is None) or
                       isinstance(value, str) and len(value) == 64 and
                       all(c in '0123456789abcdef' for c in value), 'change digest')
        io.require(row['disposition'] in ('test-only', 'test-module', 'review-tooling'), 'disposition')
        io.require(row['production_prefix'] is None or
                   row['disposition'] == 'test-module' and isinstance(row['production_prefix'], str),
                   'production prefix review')


def check_changes(root, review):
    old_names = io.names(root, review['capture_commit'])
    for name, row in review['changes'].items():
        before = (io.historical(root, review['capture_commit'], name) if name in old_names else None)
        after = io.historical(root, review['reviewed_commit'], name)
        io.require((None if before is None else io.sha(before)) == row['before'] and
                   io.sha(after) == row['after'] and before != after, 'reviewed bytes: ' + name)
        marker = row['production_prefix']
        if row['disposition'] == 'test-module':
            io.require(marker is not None and before is not None, 'missing production prefix')
            marker = marker.encode()
            io.require(before.count(marker) == after.count(marker) == 1 and
                       before.split(marker)[0] == after.split(marker)[0],
                       'production prefix changed: ' + name)


def check_protected(root, review, head):
    def selected(commit):
        return {n: v for n, v in io.tree(root, commit).items() if io.protected(n)}
    old, reviewed, current = map(selected, (review['capture_commit'], review['reviewed_commit'], head))
    io.require(current == reviewed and set(old) <= set(reviewed),
               'unreviewed implementation/build input change')
    for name, expected in reviewed.items():
        io.require(expected.startswith(('100644 blob ', '100755 blob ')), 'nonregular protected input')
        if old.get(name) != expected:
            io.require(name in review['changes'] and
                       review['changes'][name]['disposition'] in ('test-only', 'test-module'),
                       'unreviewed original implementation/build delta: ' + name)


def check_closure(root, review, current, captured, digest):
    reviewed_names = io.names(root, review['reviewed_commit'])
    io.require(set(current) <= reviewed_names and set(captured) <= set(current),
               'unreviewed native input addition/removal')
    for name, value in current.items():
        after = io.historical(root, review['reviewed_commit'], name)
        io.require(digest(name, after) == value, 'unreviewed native input: ' + name)
        if captured.get(name) != value:
            io.require(name in review['changes'], 'native delta missing exact review: ' + name)


def validate(family, root=io.ROOT):
    io.clean(root)
    head = io.git(root, 'rev-parse', 'HEAD').decode().strip()
    review_raw = io.committed(root, REVIEW, head)
    review = io.document(review_raw)
    schema(review)
    io.git(root, 'merge-base', '--is-ancestor', review['capture_commit'], review['reviewed_commit'])
    io.git(root, 'merge-base', '--is-ancestor', review['reviewed_commit'], head)
    check_changes(root, review)
    check_protected(root, review, head)
    adapter = Family(family, root)
    captured, count = adapter.records(review, head)
    check_closure(root, review, adapter.sources(), captured, adapter.digest)
    from native_review_checks import validate_receipt
    validate_receipt(root, review, review_raw, head)
    io.clean(root)
    io.require(io.git(root, 'rev-parse', 'HEAD').decode().strip() == head,
               'checkout changed during native validation')
    print(f'{family} native evidence: PASS via exact reviewed test/tooling carry-forward; '
          f'{count} original records at {review["capture_commit"]}; '
          f'implementation unchanged through {review["reviewed_commit"]} and current checked inputs. '
          'Not a fresh native capture, independent review, or certification.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--family', choices=tuple(FAMILIES), required=True)
    try:
        validate(parser.parse_args().family)
    except (ValueError, KeyError, TypeError, OSError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
