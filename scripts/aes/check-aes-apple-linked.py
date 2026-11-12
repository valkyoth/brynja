#!/usr/bin/env python3
"""Offline scoped review of an identity-bound retained Apple executable."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys

SPEC = importlib.util.spec_from_file_location('apple_linked_review',
    Path(__file__).with_name('aes_apple_linked_kernels.py'))
review = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(review)
SPEC_CLEANUP = importlib.util.spec_from_file_location('apple_cleanup_review',
    Path(__file__).with_name('aes_apple_linked_cleanup.py'))
cleanup_review = importlib.util.module_from_spec(SPEC_CLEANUP)
SPEC_CLEANUP.loader.exec_module(cleanup_review)
SPEC_SESSIONS = importlib.util.spec_from_file_location('apple_sessions_review',
    Path(__file__).with_name('aes_apple_linked_sessions.py'))
sessions_review = importlib.util.module_from_spec(SPEC_SESSIONS)
SPEC_SESSIONS.loader.exec_module(sessions_review)
SPEC_CONSTRUCTORS = importlib.util.spec_from_file_location('apple_constructors_review',
    Path(__file__).with_name('aes_apple_linked_constructors.py'))
constructors_review = importlib.util.module_from_spec(SPEC_CONSTRUCTORS)
SPEC_CONSTRUCTORS.loader.exec_module(constructors_review)
SPEC_CACHED = importlib.util.spec_from_file_location('apple_cached_review',
    Path(__file__).with_name('aes_apple_linked_cached.py'))
cached_review = importlib.util.module_from_spec(SPEC_CACHED)
SPEC_CACHED.loader.exec_module(cached_review)
SPEC_EPHEMERAL_PUBLIC = importlib.util.spec_from_file_location('apple_ephemeral_public_review',
    Path(__file__).with_name('aes_apple_linked_ephemeral_public.py'))
ephemeral_public_review = importlib.util.module_from_spec(SPEC_EPHEMERAL_PUBLIC)
SPEC_EPHEMERAL_PUBLIC.loader.exec_module(ephemeral_public_review)
SPEC_EPHEMERAL_SECRET = importlib.util.spec_from_file_location('apple_ephemeral_secret_review',
    Path(__file__).with_name('aes_apple_linked_ephemeral_secret.py'))
ephemeral_secret_review = importlib.util.module_from_spec(SPEC_EPHEMERAL_SECRET)
SPEC_EPHEMERAL_SECRET.loader.exec_module(ephemeral_secret_review)
SPEC_STARTUP = importlib.util.spec_from_file_location('apple_static_startup_review',
    Path(__file__).with_name('aes_apple_startup_static.py'))
startup_review = importlib.util.module_from_spec(SPEC_STARTUP)
SPEC_STARTUP.loader.exec_module(startup_review)
SPEC_HOSTED_STARTUP = importlib.util.spec_from_file_location('apple_hosted_startup_review',
    Path(__file__).with_name('aes_apple_startup_hosted.py'))
hosted_startup_review = importlib.util.module_from_spec(SPEC_HOSTED_STARTUP)
SPEC_HOSTED_STARTUP.loader.exec_module(hosted_startup_review)


def check(path, expected, *, cleanup=None, sessions=None, constructors=None, cached=None,
          ephemeral_public=None, ephemeral_secret=None, static_startup=None, hosted_startup=None):
    configs = [c for c in (cleanup, sessions, constructors, cached, ephemeral_public, ephemeral_secret, static_startup, hosted_startup) if c is not None]
    review.require(len(configs) <= 1, 'choose one scoped review')
    config = configs[0] if configs else None
    if config is not None:
        review.require(isinstance(config, tuple) and len(config) == 3, 'invalid review configuration')
        cleanup_review.configuration(*config)
    review.require(re.fullmatch('[0-9a-f]{64}', expected) is not None, 'invalid expected SHA-256')
    path = Path(path).absolute()
    review.require(path.is_file() and not any(p.is_symlink() for p in (path, *path.parents)),
                   'missing/nonregular/symlinked executable')
    with path.open('rb') as stream:
        image = stream.read(review.LIMIT + 1)
    review.require(len(image) <= review.LIMIT, 'oversized executable')
    review.require(hashlib.sha256(image).hexdigest() == expected, 'capture hash mismatch')
    if hosted_startup is not None:
        return hosted_startup_review.inspect(image, *hosted_startup)
    if static_startup is not None:
        return startup_review.inspect(image, *static_startup)
    if ephemeral_secret is not None:
        return ephemeral_secret_review.inspect(image, *ephemeral_secret)
    if ephemeral_public is not None:
        return ephemeral_public_review.inspect(image, *ephemeral_public)
    if cached is not None:
        return cached_review.inspect(image, *cached)
    if constructors is not None:
        return constructors_review.inspect(image, *constructors)
    if sessions is not None:
        return sessions_review.inspect(image, *sessions)
    return review.inspect(image) if cleanup is None else cleanup_review.inspect(image, *cleanup)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('--sha256', required=True, help='binary hash from the retained native capture')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--review-cleanup', action='store_true', help='also review clear and retained destruction bodies')
    group.add_argument('--review-sessions', action='store_true', help='also review session calls, including cleanup and bound unwind import')
    group.add_argument('--review-constructors', action='store_true', help='also review raw/cached constructors and copy, including session dependencies')
    group.add_argument('--review-cached', action='store_true', help='also review cached public/secret callers and constructor dependencies')
    group.add_argument('--review-ephemeral-public', action='store_true', help='also review retained per-operation public callers and cached dependencies')
    group.add_argument('--review-ephemeral-secret', action='store_true', help='also review retained per-operation secret callers and public dependencies')
    group.add_argument('--review-static-startup', action='store_true', help='review isolated static startup, KAT constants, kernels and system comparison import')
    group.add_argument('--review-hosted-startup', action='store_true', help='review hosted startup and bound detector/cache; not OS lifetime guarantees')
    parser.add_argument('--compiler', choices=('1.90.0', '1.99.1'))
    parser.add_argument('--panic', choices=('abort', 'unwind'))
    parser.add_argument('--admission', choices=('static', 'hosted'))
    args = parser.parse_args()
    try:
        config = (args.compiler, args.panic, args.admission)
        scoped = any((args.review_cleanup, args.review_sessions, args.review_constructors,
                      args.review_cached, args.review_ephemeral_public, args.review_ephemeral_secret,
                      args.review_static_startup, args.review_hosted_startup))
        review.require(all(config) if scoped else not any(config),
                       'scoped review requires all configuration fields; body-only review takes none')
        result = check(args.binary, args.sha256, cleanup=config if args.review_cleanup else None,
                       sessions=config if args.review_sessions else None,
                       constructors=config if args.review_constructors else None,
                       cached=config if args.review_cached else None,
                       ephemeral_public=config if args.review_ephemeral_public else None,
                       ephemeral_secret=config if args.review_ephemeral_secret else None,
                       static_startup=config if args.review_static_startup else None,
                       hosted_startup=config if args.review_hosted_startup else None)
    except (OSError, ValueError) as error:
        print(error, file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
