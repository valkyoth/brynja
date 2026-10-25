#!/usr/bin/env python3
"""Reconcile 16 saved author timing observations; does not run or approve tests."""
import argparse
import json
from pathlib import Path
import re
import subprocess

import legacy_hmac_timing_review as review
import legacy_hmac_timing_runner as runner


def git(*args):
    return subprocess.check_output(['git', *args], cwd=runner.ROOT, stderr=subprocess.PIPE, timeout=30)


def blobs(revision, paths, missing=False):
    review.require(re.fullmatch('[0-9a-f]{40}', revision) is not None, 'full source commit required')
    review.require(git('cat-file', '-t', revision) == b'commit\n', 'source revision is not a commit')
    result = {}
    for name in paths:
        try:
            result[name] = git('show', revision + ':' + name)
        except subprocess.CalledProcessError:
            if not missing:
                raise
            result[name] = None
    return result


def collect(linux, apple, anchor_commit):
    review.require(not git('status', '--porcelain', '--untracked-files=normal'), 'commit the candidate first')
    head = git('rev-parse', 'HEAD').decode().strip()
    review.require(re.fullmatch('[0-9a-f]{40}', anchor_commit) is not None, 'full source anchor required')
    git('merge-base', '--is-ancestor', anchor_commit, head)
    # Metadata only: no builds, native programs or commands taken from records.
    with runner.cargo_environment.private_directory(runner.ROOT) as raw:
        hashes = runner.sources(runner.environment(Path(raw)))
    current = {name: (runner.ROOT / name).read_bytes() for name in hashes}
    review.require({name: review.sha(data) for name, data in current.items()} == hashes, 'sources changed during review')
    anchor = blobs(anchor_commit, hashes)
    observations, captured = [], {}
    for directory, target, routes, prefix in (
            (linux, 'x86_64-unknown-linux-gnu', ('portable', 'static', 'linux-protected', 'linux-compiled'), 'linux-'),
            (apple, 'aarch64-apple-darwin', ('portable', 'static', 'macos-resident', 'macos-compiled'), '')):
        expected = {prefix + route + '-' + family + '.json' for route in routes for family in ('md5', 'sha1')}
        # The Linux directory can also hold subdirectories/bundles, not extra observations.
        review.require({p.name for p in directory.glob('*.json')} == expected, 'missing or extra host observations')
        for route in routes:
            for family in ('md5', 'sha1'):
                path = directory / (prefix + route + '-' + family + '.json')
                review.require(path.is_file() and not path.is_symlink(), 'missing/aliased observation')
                review.require(path.stat().st_size <= 2 * 1024 * 1024, 'oversized observation')
                raw = path.read_bytes()
                document = review.load(raw)
                source_head = document['head']
                if source_head not in captured:
                    review.require(isinstance(source_head, str) and re.fullmatch('[0-9a-f]{40}', source_head),
                                   'full capture HEAD required')
                    git('merge-base', '--is-ancestor', source_head, anchor_commit)
                    captured[source_head] = blobs(source_head, hashes, missing=True)
                row = review.validate(document, route, family, target, current, anchor, captured[source_head])
                observations.append({**row, 'observation': str(path), 'observation_sha256': review.sha(raw)})
    review.require(not git('status', '--porcelain', '--untracked-files=normal')
                   and git('rev-parse', 'HEAD').decode().strip() == head
                   and all(review.sha((runner.ROOT / name).read_bytes()) == digest for name, digest in hashes.items()),
                   'candidate changed during review')
    return {'schema': 1, 'kind': 'author-legacy-hmac-timing-reconciliation', 'candidate': head,
            'source_anchor': anchor_commit,
            'claim': 'diagnostic source/statistics reconciliation only; not constant-time proof, native qualification, independent approval or authenticated runner evidence',
            'source_anchor_meaning': 'matches observed bytes; NOT a replacement capture HEAD or approved review commit',
            'binary_digest_limit': 'recorded compiler/executable digests are not reauthenticated; original binaries are not supplied',
            'reviewer_sha256': {str(path.relative_to(runner.ROOT)): review.sha(path.read_bytes()) for path in
                               (Path(__file__), Path(review.__file__))},
            'current_sources_sha256': hashes, 'observations': observations}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--linux', required=True, type=Path)
    parser.add_argument('--apple', required=True, type=Path)
    parser.add_argument('--source-anchor', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    review.require(not args.output.exists() and not args.output.is_symlink(), 'refusing to replace report')
    document = collect(args.linux, args.apple, args.source_anchor)
    with args.output.open('x') as stream:
        json.dump(document, stream, indent=2, allow_nan=False)
        stream.write('\n')
    print('Legacy HMAC timing: 16 author observations reconciled; NOT release approval; ' + str(args.output))


if __name__ == '__main__':
    main()
